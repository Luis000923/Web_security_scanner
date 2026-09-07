"""Phase 4 — headless-browser reconnaissance and DOM-XSS taint tracing.

Everything here is **optional**: Playwright is imported lazily and, when it is
not installed, :class:`BrowserRecon` degrades to a no-op that reports
``available is False``. Nothing in the rest of the scanner imports Playwright
directly, so the pure-``asyncio`` HTTP pipeline keeps working unchanged in
environments where the browser stack is absent.

Two capabilities are provided in a single page visit:

* **SPA route discovery** — the initial JavaScript is executed and every
  ``XHR``/``fetch`` request the app fires is intercepted. Same-origin request
  URLs (and the query parameters they carry) plus anchors/forms rendered by the
  client become new tester targets.

* **DOM-based XSS detection** — an instrumentation script is injected with
  ``add_init_script`` *before* any page script runs. It wraps the common
  dangerous sinks (``eval``, ``Function``, ``document.write``, ``innerHTML`` /
  ``outerHTML``, ``insertAdjacentHTML``, string ``setTimeout`` / ``setInterval``)
  and, whenever a value flowing into one of them still contains a marker taken
  from a client-controlled source (``location.search`` / ``location.hash`` /
  ``document.referrer``), it calls back into Python. Each callback is recorded
  as a DOM-XSS finding in the existing telemetry / vulnerability format.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlparse, urlunparse

try:  # pragma: no cover - exercised only where Playwright is installed
    from playwright.async_api import async_playwright
except Exception:  # ImportError, or a broken partial install
    async_playwright = None  # type: ignore[assignment]


# Unique, inert token planted in client-controlled sources. If it re-appears
# verbatim inside a dangerous sink the data reached execution unsanitised.
DOM_XSS_CANARY = "wss4domxsscanary7413"

# Sinks the instrumentation hooks. Kept in sync with ``_INSTRUMENTATION`` below
# for documentation / test assertions.
MONITORED_SINKS = (
    "eval", "Function", "document.write", "document.writeln",
    "innerHTML", "outerHTML", "insertAdjacentHTML",
    "setTimeout", "setInterval",
)

# Injected via add_init_script; runs in the page before any site script. It only
# *observes* — values are passed straight through to the original sink.
_INSTRUMENTATION = r"""
(() => {
  if (window.__wssDomXssHooked) return;
  window.__wssDomXssHooked = true;

  const report = (data) => {
    try { window.__wssDomXssReport(JSON.stringify(data)); } catch (e) {}
  };

  const sources = () => {
    const out = [];
    try { if (location.search) out.push(['location.search', location.search]); } catch (e) {}
    try { if (location.hash) out.push(['location.hash', location.hash]); } catch (e) {}
    try { if (document.referrer) out.push(['document.referrer', document.referrer]); } catch (e) {}
    return out;
  };

  const taintedBy = (value) => {
    if (typeof value !== 'string' || value.length < 3) return null;
    for (const [name, raw] of sources()) {
      const stripped = raw.replace(/^[?#]/, '');
      let decoded = stripped;
      try { decoded = decodeURIComponent(stripped); } catch (e) {}
      for (const needle of [raw, stripped, decoded]) {
        if (needle && needle.length >= 3 && value.indexOf(needle) !== -1) {
          return name;
        }
      }
    }
    return null;
  };

  const flag = (sink, value) => {
    try {
      const source = taintedBy(value);
      if (source) {
        report({
          sink: sink,
          source: source,
          sample: String(value).slice(0, 240),
          url: location.href,
        });
      }
    } catch (e) {}
  };

  // --- function-style sinks ------------------------------------------------
  const nativeEval = window.eval;
  window.eval = function (code) { flag('eval', code); return nativeEval.apply(this, arguments); };

  const NativeFunction = window.Function;
  const HookedFunction = function (...args) {
    if (args.length) flag('Function', args[args.length - 1]);
    return NativeFunction.apply(this, args);
  };
  HookedFunction.prototype = NativeFunction.prototype;
  window.Function = HookedFunction;

  const wrapTimer = (original, name) => function (handler) {
    if (typeof handler === 'string') flag(name, handler);
    return original.apply(this, arguments);
  };
  window.setTimeout = wrapTimer(window.setTimeout, 'setTimeout');
  window.setInterval = wrapTimer(window.setInterval, 'setInterval');

  // --- document sinks ----------------------------------------------------
  const nativeWrite = document.write.bind(document);
  document.write = function (markup) { flag('document.write', markup); return nativeWrite(markup); };
  const nativeWriteln = document.writeln.bind(document);
  document.writeln = function (markup) { flag('document.writeln', markup); return nativeWriteln(markup); };

  // --- element markup sinks --------------------------------------------
  for (const prop of ['innerHTML', 'outerHTML']) {
    const desc = Object.getOwnPropertyDescriptor(Element.prototype, prop);
    if (desc && desc.set) {
      Object.defineProperty(Element.prototype, prop, {
        configurable: true,
        enumerable: desc.enumerable,
        get: desc.get,
        set: function (value) { flag(prop, value); return desc.set.call(this, value); },
      });
    }
  }

  const nativeIAH = Element.prototype.insertAdjacentHTML;
  if (nativeIAH) {
    Element.prototype.insertAdjacentHTML = function (position, markup) {
      flag('insertAdjacentHTML', markup);
      return nativeIAH.call(this, position, markup);
    };
  }
})();
"""


@dataclass
class DomXssFinding:
    """One source -> sink flow observed by the instrumentation."""

    url: str
    sink: str
    source: str
    sample: str
    param: str | None = None

    def to_vulnerability(self) -> dict[str, Any]:
        """Render into the scanner's ``VULNERABILITY_FOUND`` payload shape."""
        return {
            "type": "DOM-based XSS",
            "name": "DOM-based Cross-Site Scripting",
            "url": self.url,
            "parameter": self.param or self.source,
            "payload": self.sample,
            "severity": "high",
            "confidence": "HIGH",
            "evidence": (
                f"Client-controlled data from {self.source} reached the "
                f"{self.sink} sink without sanitisation."
            ),
            "detector": "browser-dom-xss",
        }


@dataclass
class BrowserReconResult:
    """Aggregate output of a :meth:`BrowserRecon.explore` pass."""

    available: bool = True
    visited: list[str] = field(default_factory=list)
    discovered_urls: set[str] = field(default_factory=set)
    xhr_endpoints: set[str] = field(default_factory=set)
    params_by_url: dict[str, list[str]] = field(default_factory=dict)
    dom_xss: list[DomXssFinding] = field(default_factory=list)
    error: str | None = None


class BrowserRecon:
    """Headless-browser recon + DOM-XSS tracer (Playwright, async API).

    Construction never touches Playwright. :meth:`explore` is a no-op returning
    ``available=False`` when the dependency is missing, so callers can invoke it
    unconditionally.
    """

    def __init__(
        self,
        *,
        nav_timeout: float = 15.0,
        settle_time: float = 2.0,
        max_pages: int = 6,
        same_origin_only: bool = True,
        logger: logging.Logger | None = None,
        scope: Any | None = None,
    ) -> None:
        self.nav_timeout = max(1.0, nav_timeout)
        self.settle_time = max(0.0, settle_time)
        self.max_pages = max(1, max_pages)
        self.same_origin_only = same_origin_only
        self._log = logger or logging.getLogger(__name__)
        # Optional object exposing ``host_in_scope(host) -> bool`` (ScopeEngine).
        self._scope = scope

    @staticmethod
    def available() -> bool:
        """True when Playwright's async API could be imported."""
        return async_playwright is not None

    # ---- helpers ----------------------------------------------------------

    def _in_scope(self, url: str, origin_host: str) -> bool:
        host = urlparse(url).hostname or ""
        if not host:
            return False
        if self._scope is not None:
            try:
                return bool(self._scope.host_in_scope(host))
            except Exception:  # noqa: BLE001 - never let scoping crash recon
                pass
        if self.same_origin_only:
            return host == origin_host
        return host == origin_host or host.endswith("." + origin_host)

    @staticmethod
    def _split_params(url: str) -> tuple[str, list[str]]:
        parsed = urlparse(url)
        names = [k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)]
        canonical = urlunparse(parsed._replace(fragment=""))
        return canonical, names

    def _nav_targets(self, base_url: str, params_by_url: dict[str, list[str]]) -> list[str]:
        """Base URL plus canary-tagged variants that seed the taint sources."""
        targets = [base_url, f"{base_url}#{DOM_XSS_CANARY}"]
        seen_params: set[str] = set()
        for url, names in params_by_url.items():
            for name in names:
                if name in seen_params:
                    continue
                seen_params.add(name)
                sep = "&" if urlparse(url).query else "?"
                targets.append(f"{url}{sep}{name}={DOM_XSS_CANARY}")
                if len(targets) >= self.max_pages:
                    return targets[: self.max_pages]
        # Even with no known params, probe the most common source name.
        sep = "&" if urlparse(base_url).query else "?"
        targets.append(f"{base_url}{sep}q={DOM_XSS_CANARY}")
        return targets[: self.max_pages]

    # ---- main entrypoint -------------------------------------------------

    async def explore(
        self, base_url: str, seed_params: dict[str, list[str]] | None = None
    ) -> BrowserReconResult:
        """Drive a headless browser over ``base_url`` and collect the results.

        Any Playwright/runtime failure is caught and surfaced through
        ``result.error`` rather than propagated — browser recon is strictly
        additive and must never abort the HTTP scan.
        """
        if not self.available():
            self._log.info(
                "Playwright not installed; skipping browser recon / DOM-XSS pass. "
                "Install with: pip install playwright && playwright install chromium"
            )
            return BrowserReconResult(available=False)

        result = BrowserReconResult()
        origin_host = urlparse(base_url).hostname or ""
        params_by_url = dict(seed_params or {})

        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True)
                context = await browser.new_context(ignore_https_errors=True)

                findings: list[DomXssFinding] = []

                async def _on_report(payload: str) -> None:
                    try:
                        data = json.loads(payload)
                    except (TypeError, ValueError):
                        return
                    findings.append(DomXssFinding(
                        url=str(data.get("url") or base_url),
                        sink=str(data.get("sink") or "unknown"),
                        source=str(data.get("source") or "unknown"),
                        sample=str(data.get("sample") or "")[:240],
                    ))

                await context.expose_function("__wssDomXssReport", _on_report)
                await context.add_init_script(_INSTRUMENTATION)

                def _on_request(request: Any) -> None:
                    try:
                        rtype = request.resource_type
                        url = request.url
                    except Exception:  # noqa: BLE001
                        return
                    if rtype not in ("xhr", "fetch"):
                        return
                    if not self._in_scope(url, origin_host):
                        return
                    canonical, names = self._split_params(url)
                    result.xhr_endpoints.add(canonical)
                    result.discovered_urls.add(canonical)
                    if names:
                        params_by_url.setdefault(canonical, [])
                        for n in names:
                            if n not in params_by_url[canonical]:
                                params_by_url[canonical].append(n)

                context.on("request", _on_request)

                page = await context.new_page()
                page.set_default_navigation_timeout(self.nav_timeout * 1000)

                for target in self._nav_targets(base_url, params_by_url):
                    try:
                        await page.goto(target, wait_until="networkidle")
                    except Exception as exc:  # noqa: BLE001 - timeouts, nav aborts
                        self._log.debug("browser nav to %s failed: %s", target, exc)
                        try:
                            await page.goto(target, wait_until="domcontentloaded")
                        except Exception:  # noqa: BLE001
                            continue
                    if self.settle_time:
                        await asyncio.sleep(self.settle_time)
                    result.visited.append(target)
                    await self._harvest_dom(page, origin_host, result)

                await context.close()
                await browser.close()

                result.dom_xss = findings
                result.params_by_url = params_by_url
        except Exception as exc:  # noqa: BLE001 - Playwright runtime / browser missing
            self._log.warning("Browser recon failed (%s): %s", type(exc).__name__, exc)
            result.error = f"{type(exc).__name__}: {exc}"

        return result

    async def _harvest_dom(
        self, page: Any, origin_host: str, result: BrowserReconResult
    ) -> None:
        """Pull client-rendered anchors and form actions off the live DOM."""
        try:
            hrefs = await page.eval_on_selector_all(
                "a[href]", "els => els.map(e => e.href)"
            )
        except Exception:  # noqa: BLE001
            hrefs = []
        try:
            actions = await page.eval_on_selector_all(
                "form[action]", "els => els.map(e => e.action)"
            )
        except Exception:  # noqa: BLE001
            actions = []
        for raw in list(hrefs) + list(actions):
            if not raw or not str(raw).startswith(("http://", "https://")):
                continue
            if not self._in_scope(str(raw), origin_host):
                continue
            canonical, names = self._split_params(str(raw))
            result.discovered_urls.add(canonical)
            if names:
                result.params_by_url.setdefault(canonical, [])
                for n in names:
                    if n not in result.params_by_url[canonical]:
                        result.params_by_url[canonical].append(n)
