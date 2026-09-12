"""Browser-engine resource control: the page semaphore must bound how many
Chromium tabs are alive at once, and every page/context/browser handle must be
closed on success, on navigation failure and on hard error alike.

The fake-Playwright tests need no browser install; the last one exercises the
real Chromium path when Playwright is available.
"""

import asyncio

import pytest

from web_security_scanner.modules.recon.browser_engine import (
    BrowserRecon,
    BrowserReconResult,
)

BASE = "http://target.test/"


class FakePage:
    """Minimal stand-in for a Playwright Page that tracks its own lifecycle."""

    def __init__(self, ledger: "FakeContext", *, fail_nav: bool = False):
        self._ledger = ledger
        self._fail_nav = fail_nav
        self.closed = False

    def set_default_navigation_timeout(self, _ms):
        return None

    async def goto(self, url, **_kw):
        # Hold the slot open long enough for any unbounded fan-out to show up
        # as overlapping in-flight navigations.
        self._ledger.note_navigation_start()
        try:
            await asyncio.sleep(0.02)
            if self._fail_nav:
                raise RuntimeError(f"nav failed: {url}")
        finally:
            self._ledger.note_navigation_end()

    async def eval_on_selector_all(self, _selector, _script):
        return []

    async def close(self):
        self.closed = True
        self._ledger.closed_pages += 1


class FakeContext:
    """Records page creation/closure and the peak in-flight navigation count."""

    def __init__(self, *, fail_nav: bool = False, fail_close: bool = False):
        self.pages: list[FakePage] = []
        self.closed_pages = 0
        self.closed = False
        self.in_flight = 0
        self.peak_in_flight = 0
        self._fail_nav = fail_nav
        self._fail_close = fail_close

    async def new_page(self):
        page = FakePage(self, fail_nav=self._fail_nav)
        self.pages.append(page)
        return page

    def note_navigation_start(self):
        self.in_flight += 1
        self.peak_in_flight = max(self.peak_in_flight, self.in_flight)

    def note_navigation_end(self):
        self.in_flight -= 1

    async def close(self):
        if self._fail_close:
            raise RuntimeError("context close exploded")
        self.closed = True


@pytest.mark.asyncio
@pytest.mark.parametrize("limit", [1, 2, 3])
async def test_semaphore_bounds_concurrent_pages(limit):
    recon = BrowserRecon(
        settle_time=0, max_pages=12, max_concurrent_pages=limit
    )
    context = FakeContext()
    result = BrowserReconResult()
    targets = [f"{BASE}p{i}" for i in range(12)]

    await recon._visit_targets(context, targets, "target.test", result)

    # Never more tabs in flight than the configured ceiling...
    assert context.peak_in_flight <= limit
    assert recon.peak_concurrent_pages <= limit
    # ...but the limit is actually saturated (real parallelism, not accidental
    # serialization), and every target still got visited.
    assert context.peak_in_flight == limit
    assert len(result.visited) == len(targets)


@pytest.mark.asyncio
async def test_every_page_is_closed_after_visits():
    recon = BrowserRecon(settle_time=0, max_pages=8, max_concurrent_pages=3)
    context = FakeContext()
    targets = [f"{BASE}p{i}" for i in range(8)]

    await recon._visit_targets(context, targets, "target.test", BrowserReconResult())

    assert len(context.pages) == len(targets)
    assert all(p.closed for p in context.pages)
    assert context.closed_pages == len(targets)
    # The open-page accounting unwinds back to zero - no leaked slots.
    assert recon._open_pages == 0


@pytest.mark.asyncio
async def test_pages_are_closed_even_when_navigation_fails():
    recon = BrowserRecon(settle_time=0, max_pages=5, max_concurrent_pages=2)
    context = FakeContext(fail_nav=True)
    result = BrowserReconResult()
    targets = [f"{BASE}p{i}" for i in range(5)]

    await recon._visit_targets(context, targets, "target.test", result)

    assert all(p.closed for p in context.pages)
    assert recon._open_pages == 0
    # Both goto attempts failed, so nothing was recorded as visited - but the
    # pass completed instead of propagating the error.
    assert result.visited == []


@pytest.mark.asyncio
async def test_visit_targets_survives_page_creation_failure():
    """A context that cannot hand out pages must not abort the whole pass."""

    class BrokenContext(FakeContext):
        async def new_page(self):
            raise RuntimeError("out of memory")

    recon = BrowserRecon(settle_time=0, max_pages=3, max_concurrent_pages=2)
    result = BrowserReconResult()

    await recon._visit_targets(
        BrokenContext(), [f"{BASE}a", f"{BASE}b"], "target.test", result
    )

    assert result.visited == []
    assert recon._open_pages == 0


@pytest.mark.asyncio
async def test_safe_close_swallows_close_errors():
    recon = BrowserRecon()
    # Must not raise: cleanup runs in finally blocks while other exceptions
    # may already be propagating.
    await recon._safe_close(FakeContext(fail_close=True), "context")


def test_concurrency_limit_is_clamped_to_page_budget():
    # Never more concurrent tabs than the total page budget allows.
    assert BrowserRecon(max_pages=2, max_concurrent_pages=10).max_concurrent_pages == 2
    assert BrowserRecon(max_pages=10, max_concurrent_pages=0).max_concurrent_pages == 1
    assert BrowserRecon(max_pages=10, max_concurrent_pages=4).max_concurrent_pages == 4


@pytest.mark.asyncio
async def test_real_browser_closes_resources_and_respects_limit():
    if not BrowserRecon.available():
        pytest.skip("Playwright not installed")

    from aiohttp import web

    async def handler(_request):
        return web.Response(text="<html><body><a href='/x'>x</a></body></html>",
                            content_type="text/html")

    app = web.Application()
    app.router.add_get("/", handler)
    app.router.add_get("/x", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]

    try:
        recon = BrowserRecon(
            settle_time=0, nav_timeout=10, max_pages=4, max_concurrent_pages=2
        )
        result = await recon.explore(f"http://127.0.0.1:{port}/")

        assert result.available is True and result.error is None
        assert result.visited, "expected at least one successful navigation"
        # Semaphore honoured against a real browser, and every tab released.
        assert recon.peak_concurrent_pages <= 2
        assert recon._open_pages == 0
    finally:
        await runner.cleanup()
