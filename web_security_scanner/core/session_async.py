"""Authentication & session management for authenticated DAST scans.

The scanner is otherwise fully anonymous: every probe is an unauthenticated
request, so protected zones (dashboards, admin panels, anything behind a login
form) are invisible. This module adds three capabilities on top of
:class:`~web_security_scanner.core.scanner_core_async.AsyncScannerCore`:

* **Form-based login** — POST credentials to a login URL once, up front; the
  resulting ``Set-Cookie`` (``JSESSIONID`` / ``sessionid`` / …) is captured by
  the shared :class:`aiohttp.CookieJar` and auto-attached to every subsequent
  request, recon crawl and payload probe.
* **Static session material** — seed cookies from ``--session-cookie`` flags or a
  Netscape / JSON cookie-jar file, or a bearer token, without any login round
  trip.
* **Token auth** — extract a JWT / opaque token from the login JSON response
  (dotted path) and attach it as an ``Authorization: Bearer …`` header on every
  request.

Session lifecycle: when a probe response looks logged-out (401/403, a redirect
back to the login page, or a configured body marker) the manager re-authenticates
once — rate-limited by a cooldown and serialised by a lock so a burst of
concurrent probes triggers at most one re-login.

No secret is logged: credentials live only in the config object and the
outgoing request body; :func:`web_security_scanner.core.manifest_async` redacts
them from the reproducibility manifest.
"""

from __future__ import annotations

import asyncio
import dataclasses
import http.cookiejar
import json
import logging
import time
import urllib.parse
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

from .scanner_core_async import AsyncScannerCore, ScanConfig

_LOG = logging.getLogger(__name__)

# Reserved role name for the scan's primary identity (the pre-existing
# single-``AsyncScannerCore`` flow). Never a key in ``IdentityPool``'s
# secondary-identity dict -- it always resolves to the pool's ``primary_core``.
PRIMARY_ROLE = "A"

# Keys accepted from a --session-config file / config dict, mapped straight onto
# SessionConfig fields. Anything else is ignored with a warning.
_DEFAULT_LOGGED_OUT_STATUSES = (401, 403)


def _walk_dotted(obj: Any, path: str) -> Any:
    """Return the value at a dotted ``path`` inside nested dicts/lists, or None.

    ``data.access_token`` -> ``obj["data"]["access_token"]``; numeric segments
    index into lists (``tokens.0``). Missing / wrong-typed segments yield
    ``None`` rather than raising.
    """
    cur = obj
    for seg in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(seg)
        elif isinstance(cur, list) and (seg.isdigit() or (seg[:1] == "-" and seg[1:].isdigit())):
            idx = int(seg)
            cur = cur[idx] if -len(cur) <= idx < len(cur) else None
        else:
            return None
        if cur is None:
            return None
    return cur


@dataclass
class SessionConfig:
    """Everything needed to obtain and keep an authenticated session."""

    # ---- form / token login -----------------------------------------------
    login_url: str | None = None
    username: str | None = None
    password: str | None = None
    username_field: str = "username"
    password_field: str = "password"
    extra_fields: dict[str, str] = field(default_factory=dict)
    method: str = "POST"
    submit_type: str = "form"                 # "form" (urlencoded) | "json"
    # Extract a token from the login JSON response body at this dotted path.
    token_json_path: str | None = None
    # Or supply a token/header value directly (no login round trip).
    token: str | None = None
    token_header: str = "Authorization"
    token_prefix: str = "Bearer "

    # ---- static session material ----------------------------------------
    static_cookies: dict[str, str] = field(default_factory=dict)
    cookie_jar_file: str | None = None

    # ---- lifecycle ------------------------------------------------------
    logged_out_statuses: tuple[int, ...] = _DEFAULT_LOGGED_OUT_STATUSES
    logged_out_markers: list[str] = field(default_factory=list)
    reauth_url_contains: str | None = None
    reauth: bool = True
    reauth_cooldown: float = 15.0
    # Abort the scan (instead of warn-and-continue) if authentication fails.
    required: bool = False

    # ---- multi-identity (cross-session) analysis -------------------------
    # Secondary, concurrently-authenticated identities keyed by role name
    # (e.g. ``"B"``), each a raw dict accepted by ``SessionConfig.from_dict``.
    # Populated only via ``--session-config`` (JSON/YAML has no size limit a
    # CLI flag would): every entry independently logs in with its own
    # credentials/cookie jar and is driven through :class:`IdentityPool`,
    # which testers reach as ``config['identity_pool']`` (see
    # ``IDORTester._cross_session_check`` for the consumer). The primary
    # identity described by *this* ``SessionConfig`` is always role ``"A"``
    # (:data:`PRIMARY_ROLE`); this dict must not repeat that key.
    identities: dict[str, dict[str, Any]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.method = (self.method or "POST").upper()
        self.submit_type = (self.submit_type or "form").lower()
        if self.submit_type not in ("form", "json"):
            raise ValueError(
                f"session submit_type must be 'form' or 'json', got {self.submit_type!r}"
            )
        self.logged_out_statuses = tuple(int(s) for s in self.logged_out_statuses)
        # A login URL that resolves to a redirect-back target: default the
        # logged-out detector to that same URL's path.
        if self.login_url and self.reauth_url_contains is None:
            self.reauth_url_contains = urllib.parse.urlparse(self.login_url).path or None
        if PRIMARY_ROLE in self.identities:
            raise ValueError(
                f"session identities must not reuse the reserved primary role "
                f"{PRIMARY_ROLE!r}"
            )

    # ---- construction --------------------------------------------------

    @property
    def active(self) -> bool:
        """True when this config actually does something."""
        return bool(
            self.login_url or self.token or self.static_cookies or self.cookie_jar_file
        )

    @property
    def does_form_login(self) -> bool:
        return bool(self.login_url and self.username is not None)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SessionConfig:
        known = {f.name for f in fields(cls)}
        clean: dict[str, Any] = {}
        for key, value in (data or {}).items():
            if key in known:
                clean[key] = value
            else:
                _LOG.warning("ignoring unknown session config key %r", key)
        return cls(**clean)

    @classmethod
    def from_file(cls, path: str | Path) -> SessionConfig:
        text = Path(path).read_text(encoding="utf-8")
        data = _parse_structured(text, str(path))
        if not isinstance(data, dict):
            raise ValueError(f"session config {path} must be a JSON/YAML object")
        return cls.from_dict(data)


def _parse_structured(text: str, hint: str = "") -> Any:
    """Parse JSON, falling back to YAML (both are valid; JSON is a YAML subset)."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    try:
        import yaml  # pyyaml is already a dependency (languages.yaml)
    except ImportError as exc:  # pragma: no cover - pyyaml is vendored
        raise ValueError(
            f"{hint or 'config'} is not valid JSON and PyYAML is unavailable"
        ) from exc
    return yaml.safe_load(text)


class SessionManager:
    """Obtains, injects and refreshes the authenticated session on a core."""

    def __init__(
        self,
        cfg: SessionConfig,
        *,
        on_event: Callable[[str], Awaitable[None]] | None = None,
    ) -> None:
        self.cfg = cfg
        self._on_event = on_event
        self._lock = asyncio.Lock()
        self._last_attempt = 0.0
        self._authenticated = False
        self.reauth_count = 0

    async def _emit(self, message: str) -> None:
        _LOG.info(message)
        if self._on_event is not None:
            try:
                await self._on_event(message)
            except Exception:  # pragma: no cover - event bus best-effort
                pass

    # ---- static material ------------------------------------------------

    def apply_static(self, core: Any, target_url: str | None = None) -> None:
        """Seed static cookies / jar file / direct token onto ``core``.

        Synchronous — call after ``core.start()`` (the session and its jar must
        exist) and before the first probe. ``target_url`` is the scan target;
        static cookies with no domain of their own are scoped to it.
        """
        session = getattr(core, "session", None)
        jar = getattr(session, "cookie_jar", None)

        if self.cfg.token:
            value = self.cfg.token
            if self.cfg.token_prefix and not value.startswith(self.cfg.token_prefix):
                value = f"{self.cfg.token_prefix}{value}"
            core.set_auth_header(self.cfg.token_header, value)

        if jar is None:
            return

        response_url = self._jar_scope_url(target_url)
        if self.cfg.static_cookies:
            jar.update_cookies(dict(self.cfg.static_cookies), response_url)

        if self.cfg.cookie_jar_file:
            self._load_cookie_jar_file(jar, self.cfg.cookie_jar_file, response_url)

    def _jar_scope_url(self, target_url: str | None = None) -> Any:
        from yarl import URL

        return URL(target_url or self.cfg.login_url or "http://localhost/")

    @staticmethod
    def _load_cookie_jar_file(jar: Any, path: str, response_url: Any) -> None:
        from yarl import URL

        p = Path(path)
        raw = p.read_text(encoding="utf-8")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            data = None

        if isinstance(data, list):  # [{name,value,domain,path}, ...]
            by_domain: dict[str, dict[str, str]] = {}
            for c in data:
                if not isinstance(c, dict) or "name" not in c:
                    continue
                dom = c.get("domain") or ""
                by_domain.setdefault(dom, {})[str(c["name"])] = str(c.get("value", ""))
            for dom, cookies in by_domain.items():
                scope = URL(f"http://{dom.lstrip('.')}/") if dom else response_url
                jar.update_cookies(cookies, scope)
            return
        if isinstance(data, dict):  # {name: value}
            jar.update_cookies({str(k): str(v) for k, v in data.items()}, response_url)
            return

        # Netscape / Mozilla cookies.txt
        cj = http.cookiejar.MozillaCookieJar()
        cj.load(str(p), ignore_discard=True, ignore_expires=True)
        by_domain2: dict[str, dict[str, str]] = {}
        for c in cj:
            by_domain2.setdefault(c.domain, {})[c.name] = c.value or ""
        for dom, cookies in by_domain2.items():
            scope = URL(f"http://{dom.lstrip('.')}/") if dom else response_url
            jar.update_cookies(cookies, scope)
        if not by_domain2:
            _LOG.warning("cookie jar file %s yielded no cookies", path)

    # ---- form / token login ------------------------------------------

    def _build_login_kwargs(self) -> dict[str, Any]:
        body = dict(self.cfg.extra_fields)
        if self.cfg.username is not None:
            body[self.cfg.username_field] = self.cfg.username
        if self.cfg.password is not None:
            body[self.cfg.password_field] = self.cfg.password
        return {"json": body} if self.cfg.submit_type == "json" else {"data": body}

    @staticmethod
    def _jar_snapshot(core: Any) -> set[tuple[str, str]]:
        """``{(name, value)}`` of the cookie jar — so a refreshed value counts
        as a change, not just a new name."""
        jar = getattr(getattr(core, "session", None), "cookie_jar", None)
        if jar is None:
            return set()
        try:
            return {(m.key, m.value) for m in jar}
        except Exception:  # pragma: no cover - defensive
            return set()

    def _login_looks_failed(self, result: dict[str, Any]) -> bool:
        status = int(result.get("status_code", 0) or 0)
        if status == 0 or status in self.cfg.logged_out_statuses:
            return True
        text = result.get("text", "") or ""
        return any(m and m in text for m in self.cfg.logged_out_markers)

    async def authenticate(self, core: Any, *, force: bool = False) -> bool:
        """Perform (or refresh) the login. Returns True on success.

        Serialised by a lock and rate-limited by ``reauth_cooldown`` so a burst
        of concurrent probes that all see a logged-out response triggers a single
        re-login. ``force`` bypasses the cooldown (used for the initial login).
        """
        if not self.cfg.does_form_login:
            # Nothing to do beyond static material — treat as "authenticated".
            self._authenticated = True
            return True

        async with self._lock:
            now = time.monotonic()
            if not force and (now - self._last_attempt) < self.cfg.reauth_cooldown:
                # Another concurrent probe already re-logged inside the cooldown
                # window; ride its result instead of hammering the login form.
                return self._authenticated
            self._last_attempt = now

            before = self._jar_snapshot(core)
            kwargs = self._build_login_kwargs()
            try:
                result = await core.request(
                    self.cfg.method, self.cfg.login_url,
                    use_cache=False, allow_redirects=True,
                    _reauth_retry=True,  # never recurse the re-auth hook on the login call
                    **kwargs,
                )
            except Exception as exc:  # noqa: BLE001 - login failure must not crash the scan
                await self._emit(f"Authentication request failed: {exc}")
                self._authenticated = False
                return False

            status = int(result.get("status_code", 0) or 0)
            after = self._jar_snapshot(core)
            new_cookies = {name for name, _v in (after - before)}

            token_ok = False
            if self.cfg.token_json_path:
                token_ok = self._extract_token(core, result)

            # Success: the login endpoint did not answer with a failure signal
            # AND we came away with something usable — a fresh/rotated cookie,
            # an extracted token, or (lacking both) simply a clean 2xx/3xx.
            not_failed = not self._login_looks_failed(result)
            success = not_failed and (
                bool(new_cookies) or token_ok or (200 <= status < 400)
            )
            self._authenticated = success
            # Count only *real* re-login round-trips: not the forced initial
            # login, and not the cooldown-suppressed no-ops above (which return
            # early). A burst of concurrent logged-out probes therefore bumps
            # this by exactly one.
            if success and not force:
                self.reauth_count += 1
            if success:
                bits = []
                if new_cookies:
                    bits.append("cookie(s): " + ", ".join(sorted(new_cookies)))
                if token_ok:
                    bits.append(f"token header {self.cfg.token_header}")
                await self._emit("Authenticated — session established ("
                                 + "; ".join(bits) + ")")
            else:
                await self._emit(
                    f"Authentication failed (login status={status}, "
                    f"new cookies={sorted(new_cookies) or 'none'}, "
                    f"token={'ok' if token_ok else 'none'})"
                )
            return success

    def _extract_token(self, core: Any, result: dict[str, Any]) -> bool:
        text = result.get("text", "") or ""
        try:
            payload = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return False
        raw = _walk_dotted(payload, self.cfg.token_json_path or "")
        if not raw:
            return False
        value = str(raw)
        if self.cfg.token_prefix and not value.startswith(self.cfg.token_prefix):
            value = f"{self.cfg.token_prefix}{value}"
        core.set_auth_header(self.cfg.token_header, value)
        return True

    # ---- lifecycle detection ----------------------------------------

    def looks_logged_out(self, result: dict[str, Any] | None) -> bool:
        if not result or not self.cfg.reauth or not self.cfg.does_form_login:
            return False
        status = int(result.get("status_code", 0) or 0)
        if status in self.cfg.logged_out_statuses:
            return True
        final_url = str(result.get("url", "") or "")
        if self.cfg.reauth_url_contains and self.cfg.reauth_url_contains in final_url:
            return True
        text = result.get("text", "") or ""
        return any(marker and marker in text for marker in self.cfg.logged_out_markers)

    async def maybe_reauth(self, core: Any, result: dict[str, Any] | None) -> bool:
        """Re-authenticate if ``result`` looks logged-out. Returns True if it did."""
        if not self.looks_logged_out(result):
            return False
        await self._emit("Session appears to have expired — re-authenticating")
        return await self.authenticate(core)


@dataclass(slots=True)
class IdentityContext:
    """One fully-independent authenticated identity: its own transport, cookie
    jar and :class:`SessionManager`.

    Distinct from the scan's primary identity (``role == PRIMARY_ROLE``,
    reusing the orchestrator's pre-existing ``AsyncScannerCore``) in that a
    *secondary* context owns a brand-new ``AsyncScannerCore`` -- a separate
    ``aiohttp.ClientSession`` with its own connector and
    :class:`aiohttp.CookieJar`, so Role B's cookies/bearer token can never leak
    into Role A's requests or vice versa. This is the concrete mechanism that
    makes an authenticated cross-session diff (e.g.
    ``IDORTester._cross_session_check``) possible: the same GET, fired through
    two contexts with two different logged-in users, is directly comparable.
    """

    role: str
    core: AsyncScannerCore
    manager: SessionManager

    async def close(self) -> None:
        """Release this identity's transport. Idempotent (``core.close`` is)."""
        await self.core.close()


class IdentityPool:
    """Owns every *secondary* authenticated identity for a scan and starts
    them concurrently alongside the pre-existing primary identity.

    The primary identity (role :data:`PRIMARY_ROLE`, ``"A"``) is **not**
    managed here -- it stays exactly the single shared
    :class:`~...core.scanner_core_async.AsyncScannerCore` /
    :class:`SessionManager` pair the orchestrator already builds, so a scan
    with no ``identities`` configured is byte-identical to the pre-multi-
    identity behaviour (no new object is even constructed). This class only
    comes into play when ``SessionConfig.identities`` is non-empty, and it
    resolves role ``"A"`` back to that same primary core via :meth:`get` so
    tester code can address both roles uniformly.

    Each secondary identity gets its own ``AsyncScannerCore`` (own
    ``aiohttp.ClientSession`` + ``CookieJar`` + auth-header dict) built from a
    *copy* of the scan's base :class:`~...core.scanner_core_async.ScanConfig`
    (``dataclasses.replace`` -- same timeouts/proxy/SSRF policy, independent
    mutable fields), authenticated with its own :class:`SessionConfig`. Login
    round trips run concurrently (``asyncio.gather``) since they are
    independent network calls against (typically) the same login endpoint
    with different credentials.
    """

    def __init__(
        self,
        primary_core: AsyncScannerCore,
        *,
        on_event: Callable[[str], Awaitable[None]] | None = None,
    ) -> None:
        self.primary_core = primary_core
        self._on_event = on_event
        self._secondary: dict[str, IdentityContext] = {}

    @property
    def roles(self) -> list[str]:
        """All identity roles known to this pool, primary included."""
        return [PRIMARY_ROLE, *sorted(self._secondary)]

    @property
    def secondary_roles(self) -> list[str]:
        """Role names of every started secondary identity (primary excluded)."""
        return sorted(self._secondary)

    def get(self, role: str) -> AsyncScannerCore | None:
        """The :class:`AsyncScannerCore` authenticated as ``role``, or ``None``
        if that role was never started (e.g. a scan run without
        ``identities`` configured, or a typo'd role name)."""
        if role == PRIMARY_ROLE:
            return self.primary_core
        ctx = self._secondary.get(role)
        return ctx.core if ctx else None

    async def start_one(
        self,
        role: str,
        cfg: SessionConfig,
        base_config: ScanConfig,
        *,
        target_url: str | None = None,
    ) -> IdentityContext:
        """Stand up and authenticate a single secondary identity.

        Mirrors the primary-identity bootstrap in
        ``WebSecurityScanner._authenticate`` (apply static material, then form
        login if configured) but against a freshly-built, fully independent
        ``AsyncScannerCore`` so this identity's cookies/token never touch the
        primary session's jar. Best-effort: a failed login is logged (never
        raised) and the context is still returned/stored so a scan does not
        abort over one secondary identity a target happens to reject -- the
        consuming tester is expected to check ``manager._authenticated``
        (via ``SessionManager.authenticate``'s return value, already observed
        here) before trusting a diff against this role.
        """
        core = AsyncScannerCore(dataclasses.replace(base_config))
        await core.start()
        manager = SessionManager(cfg, on_event=self._on_event)
        try:
            manager.apply_static(core, target_url)
        except Exception as exc:  # noqa: BLE001 - a bad jar file must not abort the scan
            _LOG.error("identity %r: failed to apply static session material: %s", role, exc)
        if cfg.does_form_login:
            await manager.authenticate(core, force=True)
        core.attach_session_manager(manager)
        ctx = IdentityContext(role=role, core=core, manager=manager)
        self._secondary[role] = ctx
        return ctx

    async def start_all(
        self,
        identities: dict[str, dict[str, Any]],
        base_config: ScanConfig,
        *,
        target_url: str | None = None,
    ) -> None:
        """Start every secondary identity in ``identities`` concurrently.

        ``identities`` is ``SessionConfig.identities`` from the *primary*
        session config: ``{role: raw_session_config_dict}``. No-op for an
        empty dict, so callers can invoke this unconditionally.
        """
        if not identities:
            return
        await asyncio.gather(*(
            self.start_one(role, SessionConfig.from_dict(raw), base_config,
                           target_url=target_url)
            for role, raw in identities.items()
        ))

    async def close(self) -> None:
        """Close every secondary identity's transport. Never raises: teardown
        must not fail a scan that otherwise completed. The primary core is
        the orchestrator's responsibility and is not touched here."""
        for ctx in self._secondary.values():
            try:
                await ctx.close()
            except Exception as exc:  # noqa: BLE001 - best-effort teardown
                _LOG.debug("identity %r: error closing session: %s", ctx.role, exc)
