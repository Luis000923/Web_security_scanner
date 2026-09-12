# Threats to validity — SSRF guard (`core/scanner_core_async.py`)

The scanner issues arbitrary attacker-influenced URLs (open-redirect follow,
crawled links, header/cookie/body-reflected redirects). Without a guard the
HTTP client itself becomes an SSRF primitive against the operator's own host —
classically the cloud metadata service at `169.254.169.254`. This document
records what the guard blocks, what it deliberately does not, the one
DNS-rebinding gap it closes, and the tests that pin each claim.

Scope: `PinnedResolver`, `AsyncScannerCore._assert_ip_allowed`,
`_assert_public_url`, `_resolve_host`, and the redirect loop in
`_request_following`. Out of scope: `session_async.py` (auth) and
`telemetry_async.py` — neither issues outbound target requests.

---

## What is blocked

**B1 — Direct connection to a private/loopback/link-local/reserved address.**
Every socket the scanner opens is resolved through `PinnedResolver`, which
calls `_assert_ip_allowed` on each candidate address before handing it to
aiohttp. `_ip_is_blocked` rejects `is_private`, `is_loopback`, `is_link_local`,
`is_reserved`, `is_multicast`, `is_unspecified` (`_BLOCKED_IP_PREDICATES`).
An IP literal in the URL is checked the same way — it never goes through DNS,
so `PinnedResolver.resolve` validates it directly (scanner_core_async.py:110-117).

*Test:* `test_redirect_to_metadata_ip_is_blocked`,
`test_relative_redirect_to_loopback_is_blocked` (tests/test_core_async.py).

**B2 — Redirect to a non-vetted host.** `_request_following`'s redirect loop
calls `_assert_public_url` on every `Location` target before following it
(unless `allow_redirects=False`, used deliberately by e.g. the open-redirect
tester). A target-controlled 30x to an internal address or hostname aborts the
whole request with `SSRFRedirectError`; the internal endpoint is never
contacted.

*Test:* `test_redirect_to_metadata_ip_is_blocked` (asserts the metadata IP
never appears in `core.session.requests`), `test_request_marks_only_the_first_hop_as_trusted`.

**B3 — DNS rebinding between the guard's check and the socket connect
(TOCTOU).** This is the interesting one and the reason `PinnedResolver` exists
at all rather than a plain pre-flight hostname check. A naive guard resolves
the hostname, validates the address, then hands the *name* back to the HTTP
client — which resolves it a second time when it opens the socket. An
attacker controlling the zone (or a fast-TTL rebinding service) answers the
first lookup with a public IP and the second with `127.0.0.1` or
`169.254.169.254`; the guard's check and the actual connection see different
data.

`PinnedResolver` closes this by being the *only* thing that resolves names for
the scanner's connector (`_build_connector`, scanner_core_async.py:414-450):
`_resolve_host` resolves once, the result is what gets vetted, and that exact
IP is what's handed back to aiohttp as a numeric-host `ResolveResult`
(`_addrinfo`, `AI_NUMERICHOST`) — so aiohttp cannot re-resolve it. Check and
connect use the same address by construction; there is no second DNS lookup
for the classic rebinding window to land in.

*Test:* `test_core_async.py` lines ~184-251 exercise `PinnedResolver.resolve`
directly for a name that would answer differently on two lookups, and confirm
the cached/vetted address is what's returned both times;
`test_connector_actually_installs_the_pinned_resolver` pins that this is
actually wired into the live aiohttp connector, not just available as a
class.

**B4 — Injected headers/cookies replayed across a cross-host redirect.**
Adjacent to SSRF proper but same code path: a cross-host redirect drops
caller-supplied headers and cookies rather than replaying an injected
Authorization/Cookie to a third party the target chose.

*Test:* `test_cross_host_redirect_drops_injected_headers_and_cookies`.

**B5 — A previously-trusted hostname resolving to a *different* private
address later in the same scan (was N1, now fixed).** Every redirect target
already goes through `_assert_public_url` unconditionally (no trust
exemption there at all — see N1 below for why this alone doesn't cover the
whole surface), but `_trusted_hosts` itself used to grant a **hostname-keyed**
exemption with no memory of which address had actually been vetted: any
future resolution of an operator-designated hostname to a blocked address was
let through, for the life of the `AsyncScannerCore`. Two operator-visible
requests to the same trusted alias — the crawler revisiting it, or two
distinct top-level targets in one process that happen to share a hostname —
could see different, unrelated addresses accepted under the same trust.

**Fix.** `_assert_ips_allowed` now pins the *exact* address set the first
resolution of a trusted host produced (`_trusted_host_ips: dict[str,
frozenset[str]]`). Every later resolution of that hostname must be a subset of
what was pinned; anything else — the DNS cache entry was evicted
(`_MAX_RESOLVE_CACHE`) and the zone now answers differently, or a rebinding
attempt rides the same alias — is refused with `SSRFRedirectError`, exactly as
if the hostname had never been trusted. All addresses from one resolution are
vetted as a single batch (not one at a time) so a legitimately dual-stack or
multi-A-record trusted host doesn't reject its own second address.
`_trusted_hosts` still decides *whether* an exemption is possible at all (a
target-chosen redirect never qualifies); `_trusted_host_ips` now decides
*which* address that exemption actually covers.

*Test:* `test_trusted_host_rejects_a_later_address_that_was_never_vetted`,
`test_trusted_host_pins_a_dual_stack_resolution_as_one_batch`,
`test_multi_target_scan_cannot_hijack_a_previously_trusted_alias`
(tests/test_core_async.py).

---

## What is *not* blocked (by design or residually)

**N1 — Redirects to a private address are unconditionally blocked, even for
a trusted host — no exemption, no pinning.** `_request_following`'s redirect
loop calls `_assert_public_url(next_url)` on every redirect target before
following it (unless `allow_private_redirects=True`), and that check refuses
*any* blocked address with no reference to `_trusted_hosts` at all
(scanner_core_async.py, `_assert_public_url`). This means the exemption B5
now pins only ever applies to a hostname the operator put **directly** in a
request URL (a top-level target), never to something reached by chasing a
redirect — even a redirect that happens to land back on an already-trusted
hostname is refused. This is fail-safe (it blocks a legitimate case — an
operator's own site redirecting into its own intranet — rather than a
dangerous one), so it is left as-is rather than "fixed": loosening it to let
trusted-alias redirects through would reopen exactly the surface B5 just
closed, for no clear operational need. If an operator's target legitimately
redirects into their own intranet, `--allow-private-redirects` is the explicit
opt-in for that.

**N2 — DNS answers changing *after* the resolve cache is populated, for a
non-trusted host.** `_resolve_host` caches per-hostname resolutions
(`_resolve_cache`, bounded FIFO at `_MAX_RESOLVE_CACHE`). For the common case
(non-trusted redirect target), every subsequent redirect to the same hostname
reuses the cached, already-vetted address — so a later rebinding attempt on
that name has no effect until the cache entry is evicted. This is a
*mitigation*, not a gap, for the redirect-chasing path; it's noted here only
because eviction under memory pressure (`_MAX_RESOLVE_CACHE = 4096` distinct
hosts) causes a re-resolve + re-vet on the next hit, which is the correct
behavior (re-vetting), not a regression.

**N3 — Resolution at the OS/libc level.** `_resolve_host` uses
`loop.getaddrinfo`, i.e. the system resolver (`/etc/resolv.conf`, `/etc/hosts`,
`nsswitch`). A compromised local resolver or a poisoned `/etc/hosts` sits
below this guard entirely; that is host-level compromise, out of scope for an
application-layer SSRF guard.

**N4 — Non-HTTP redirection vectors.** The guard covers HTTP `Location`
redirects followed by `_request_following`. It says nothing about payloads
that induce the *target application* to make its own server-side request
(classic SSRF-via-feature, e.g. a webhook URL field) — that's the vulnerability
class `modules/vulnerability_testers/ssrf_tester_async.py` tests *for*, using
this hardened client as the attacker vantage point. The two are not the same
guard.

---

## Verifying B3 across the warm-up path specifically

`warmup()` (JVM warm-up discard requests, ahead of latency-baseline capture —
see `testbed/THREATS_TO_VALIDITY.md` T1) routes through `request()` →
`_request_following()` like any other call, with `use_cache=False` but the
**same session, same connector, same `PinnedResolver`**. Nothing in `warmup()`
bypasses the redirect loop or the guard — it just discards the response body
and skips telemetry. `test_warmup_blocks_cross_host_redirect_to_metadata_ip`
(tests/test_core_async.py) pins this: a warm-up burst against an endpoint that
302s to `169.254.169.254` aborts with `SSRFRedirectError` and the metadata
address is never dialled, exactly as it isn't for a normal `request()` call in
`test_redirect_to_metadata_ip_is_blocked`.

---

## Conclusion on the TOCTOU question

`PinnedResolver` already pins the vetted IP into a numeric-host
`ResolveResult` before it reaches aiohttp's connector, so there is **no
DNS-rebinding TOCTOU window between the guard's check and the actual
`connect()`** for the general case (B3) — that mitigation was already
implemented, not merely proposed.

The gap that *was* open was adjacent but different in kind: not a race within
one connection attempt, but the **trusted-host exemption persisting across
separate connection attempts** to the same alias without regard to which
address earned that trust (originally logged as N1, fixed as B5 above).
`_trusted_host_ips` closes it by binding the exemption to the (hostname,
address-set) pair actually vetted the first time, rather than to the bare
hostname for the rest of the process. `assert_public_target=True` remains
available as a stricter global override that removes the trusted-host
exemption entirely, independent of this fix.
