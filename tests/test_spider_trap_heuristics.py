"""Structural spider-trap heuristics: cyclic paths, repeated segments,
high-entropy tokens and repetitive query params — proactive detection that
does not rely solely on the numeric max_urls/max_depth ceilings.
"""

import logging

import pytest

from tests.conftest import MockScanner
from web_security_scanner.modules.recon import (
    TrapVerdict,
    evaluate_url_for_trap,
    has_cyclic_segments,
    has_high_entropy_segment,
    has_repeated_segment_value,
    has_repetitive_query_params,
)
from web_security_scanner.modules.recon.browser_engine import BrowserRecon
from web_security_scanner.modules.web_mapper_async import WebMapperAsync

BASE = "http://target.test/"


# --- pure heuristic functions -----------------------------------------


def test_has_cyclic_segments_detects_repeating_cycle():
    assert has_cyclic_segments("/cat/sub/cat/sub/cat/sub")
    assert has_cyclic_segments("/a/b/a/b/a/b/a/b")
    assert not has_cyclic_segments("/products/electronics/phones")
    assert not has_cyclic_segments("/a/b/c")


def test_has_cyclic_segments_ignores_short_paths():
    # Below the min-repeats window: not enough evidence of a real cycle.
    assert not has_cyclic_segments("/a/b/a")


def test_has_repeated_segment_value_detects_non_adjacent_repeats():
    assert has_repeated_segment_value("/x/page/y/page/z/page/w/page/v/page")
    assert not has_repeated_segment_value("/blog/2024/09/article-title")


def test_has_high_entropy_segment_flags_random_token():
    assert has_high_entropy_segment("/session/9f3ac71e4b2d8a0f7c6e5d4b3a291807/next")
    assert has_high_entropy_segment(
        "/download/a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6/file.zip"
    )


def test_has_high_entropy_segment_spares_ordinary_slugs():
    # Real-world hyphenated SEO slugs must not be flagged - separators break
    # them into short, low-entropy fragments.
    assert not has_high_entropy_segment("/category-electronics-mobile-phones")
    assert not has_high_entropy_segment("/blog/articles-and-news-latest-updates")
    assert not has_high_entropy_segment("/wp-content/uploads/2024/logo.png")


def test_has_repetitive_query_params_detects_repeated_name_and_value():
    assert has_repetitive_query_params("id=1&id=2&id=3&id=4")
    assert has_repetitive_query_params("a=x&b=x&c=x&d=x")
    assert not has_repetitive_query_params("id=1&name=bob&page=2")


def test_evaluate_url_for_trap_end_to_end():
    verdict = evaluate_url_for_trap("http://t/cal/2024/cal/2024/cal/2024")
    assert isinstance(verdict, TrapVerdict)
    assert verdict.is_trap is True
    assert "cyclic" in verdict.reason

    clean = evaluate_url_for_trap("http://t/products/electronics?id=42")
    assert clean.is_trap is False
    assert bool(clean) is False


# --- WebMapperAsync wiring ---------------------------------------------


def _cyclic_trap_responder(method, url, kwargs):
    """Every page links one hop deeper into an /a/b/a/b/... cycle."""
    from urllib.parse import urlparse

    path = urlparse(url).path.rstrip("/") or "/"
    segs = [p for p in path.split("/") if p]
    nxt = "a" if (not segs or segs[-1] != "a") else "b"
    deeper = f"http://trap.test/{'/'.join(segs + [nxt])}"
    return {
        "status_code": 200,
        "text": f'<html><body><a href="{deeper}">deeper</a></body></html>',
        "headers": {"Content-Type": "text/html"},
        "url": url,
    }


async def _noop(self):
    return None


@pytest.mark.asyncio
async def test_crawler_prunes_cyclic_branch_before_visiting(monkeypatch):
    monkeypatch.setattr(WebMapperAsync, "_discover_subdomains", _noop)
    # A generous numeric budget: if the heuristic didn't fire, the crawler
    # would happily keep descending the a/b/a/b/... cycle up to this cap.
    mapper = WebMapperAsync(
        MockScanner(_cyclic_trap_responder), max_urls=10_000, crawl_delay=0
    )

    await mapper.map_website("http://trap.test/a/b/a/b/a", max_depth=50)

    # The heuristic pruned the cyclic branch long before the numeric cap.
    assert mapper.trap_branches_pruned >= 1
    assert len(mapper.visited_urls) < 10_000
    # None of the *visited* URLs should themselves be flagged as cyclic -
    # the trap-shaped continuation was discarded, not crawled first.
    from web_security_scanner.modules.recon import evaluate_url_for_trap as _eval
    assert all(not _eval(u).is_trap for u in mapper.visited_urls)


@pytest.mark.asyncio
async def test_crawler_logs_warning_on_trap_branch(monkeypatch, caplog):
    monkeypatch.setattr(WebMapperAsync, "_discover_subdomains", _noop)
    mapper = WebMapperAsync(
        MockScanner(_cyclic_trap_responder), max_urls=10_000, crawl_delay=0
    )

    with caplog.at_level(logging.WARNING, logger="WebMapperAsync"):
        await mapper.map_website("http://trap.test/a/b/a/b/a", max_depth=50)

    assert any("Spider-trap heuristic" in rec.message for rec in caplog.records)


# --- BrowserRecon wiring -------------------------------------------------


@pytest.mark.asyncio
async def test_browser_recon_discards_trap_shaped_discovered_urls(monkeypatch):
    monkeypatch.setattr(
        "web_security_scanner.modules.recon.browser_engine.async_playwright", None
    )
    recon = BrowserRecon()
    assert recon.available() is False

    is_trap = recon._discard_if_trap(f"{BASE}cal/2024/cal/2024/cal/2024")
    assert is_trap is True
    assert recon.trap_branches_pruned == 1

    not_trap = recon._discard_if_trap(f"{BASE}products?id=42")
    assert not_trap is False
    assert recon.trap_branches_pruned == 1
