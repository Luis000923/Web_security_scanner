import asyncio
import html
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup

from ..events.event_emitter import ScanEventType


class WebMapperAsync:
    """
    Async website structure mapper.

    Self-contained (no sync base class). Crawls the target with a bounded
    number of total pages, an inter-request delay, and depth limiting to
    avoid hammering / DoS-ing the target.
    """

    # Query params that are pure noise for structural mapping (tracking / cache
    # busters / session ids). Dropped during normalization so the same page with
    # different campaign tags is not crawled twice.
    JUNK_PARAMS = {
        'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
        'fbclid', 'gclid', 'msclkid', 'mc_cid', 'mc_eid', 'ref', 'referrer',
        '_', 'cachebuster', 'cb', 'sessionid', 'phpsessid', 'jsessionid',
    }

    # Max distinct URLs to crawl that share the same "structural signature"
    # (path + set of query-param names). Beyond this we assume a spider trap
    # (e.g. page.php?id=1, id=2, id=3, ...) and stop descending into it.
    MAX_URLS_PER_SIGNATURE = 8

    def __init__(self, scanner_core, logger=None, max_urls: int = 1000,
                 max_depth: int = 3, crawl_delay: float = 0.1):
        self.scanner = scanner_core  # AsyncScannerCore
        # Optional: set by WebSecurityScanner so the crawler can report progress.
        self.event_emitter: Any = None
        self.logger = logger or logging.getLogger("WebMapperAsync")
        self.max_urls = max_urls
        self.max_depth = max_depth
        self.crawl_delay = crawl_delay
        # Set when a hard limit (max_urls / signature cap) aborts the crawl early
        # so callers can report "partial map".
        self.limit_reached = False
        self._signature_counts: dict[Any, int] = {}
        self.base_domain: str = ""
        self.visited_urls: set[str] = set()
        self.discovered_subdomains: set[str] = set()
        self.technologies: dict[str, Any] = {}
        self.vulnerabilities: list[Any] = []
        self.site_structure: dict[str, Any] = {
            'domains': {},
            'subdomains': {},
            'directories': {},
            'files': {},
            'forms': [],
            'links': [],
            'external_links': []
        }

    def _is_internal(self, netloc: str) -> bool:
        """
        True if ``netloc`` belongs to the target domain.

        Uses host-part equality / subdomain suffix instead of a naive substring
        check, so ``evil-example.com`` is NOT treated as internal to
        ``example.com``.
        """
        if not netloc or not self.base_domain:
            return False
        host = netloc.split(':')[0].lower()
        base = self.base_domain.split(':')[0].lower()
        return host == base or host.endswith('.' + base)

    def _normalize_url(self, url: str) -> str:
        """
        Canonicalize a URL for de-duplication:
        - drop the fragment (``#section``)
        - drop known tracking / cache-buster / session query params
        - sort the remaining query params
        - strip a trailing slash (except on the root path)

        This keeps ``/page#a``, ``/page#b`` and ``/page?utm_source=x`` from being
        treated as three distinct pages.
        """
        try:
            parsed = urlparse(url)
        except ValueError:
            return url.split('#')[0]
        pairs = [
            (k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)
            if k.lower() not in self.JUNK_PARAMS
        ]
        pairs.sort()
        path = parsed.path.rstrip('/') or '/'
        return urlunparse((parsed.scheme, parsed.netloc, path, '', urlencode(pairs), ''))

    def _signature(self, url: str):
        """Structural fingerprint: (path, sorted tuple of query-param names)."""
        parsed = urlparse(url)
        keys = tuple(sorted(k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)))
        return (parsed.path.rstrip('/'), keys)

    async def map_website(self, base_url: str, max_depth: int | None = None,
                          max_urls: int | None = None) -> dict[str, Any]:
        """Map a full website (async)."""
        if max_depth is not None:
            self.max_depth = max_depth
        if max_urls is not None:
            self.max_urls = max_urls
        self.logger.info(
            f"Starting map of: {base_url} (max_depth={self.max_depth}, max_urls={self.max_urls})"
        )
        parsed = urlparse(base_url)
        self.base_domain = parsed.netloc

        self.logger.info("Discovering subdomains...")
        await self._discover_subdomains()

        self.logger.info("Crawling site structure...")
        await self._crawl_structure(base_url, depth=0, max_depth=self.max_depth)
        if self.limit_reached:
            self.logger.warning(
                f"Crawler abortado preventivamente por límite max_urls "
                f"({self.max_urls}); devolviendo mapa parcial."
            )

        self.logger.info("Analyzing structure...")
        self._analyze_structure()

        map_data = {
            'base_url': base_url,
            'base_domain': self.base_domain,
            'scan_timestamp': datetime.now().isoformat(),
            'subdomains': list(self.discovered_subdomains),
            'structure': self.site_structure,
            'technologies': self.technologies,
            'vulnerabilities': self.vulnerabilities,
            'statistics': self._generate_statistics()
        }
        self.logger.info(f"Map complete: {len(self.visited_urls)} URLs visited")
        return map_data

    async def _discover_subdomains(self):
        """Discover subdomains via CSP headers and bounded DNS brute-force."""
        await self._discover_from_csp_headers()
        await self._discover_from_dns()

    async def _discover_from_csp_headers(self):
        try:
            response = await self.scanner.request("GET", f"https://{self.base_domain}")
            if response and response.get('headers'):
                csp = response['headers'].get('Content-Security-Policy', '')
                for domain in re.findall(r'https?://([a-zA-Z0-9.-]+)', csp):
                    if self._is_internal(domain):
                        self.discovered_subdomains.add(domain)
        except Exception as e:
            self.logger.debug(f"Error analyzing CSP headers: {e}")

    async def _discover_from_dns(self):
        """
        Bounded DNS brute-force for common subdomains, run off the event loop
        with limited concurrency (re-adds coverage the async mapper had dropped).
        """
        try:
            import dns.resolver  # optional dependency
        except Exception:
            self.logger.debug("dnspython not available; skipping DNS brute-force")
            return

        common = [
            'www', 'mail', 'ftp', 'webmail', 'admin', 'api', 'dev', 'staging',
            'test', 'portal', 'vpn', 'blog', 'shop', 'cdn', 'app', 'm',
            'secure', 'ns1', 'ns2', 'smtp', 'pop', 'imap', 'git', 'db',
        ]
        base = self.base_domain.split(':')[0]
        # Strip an existing leading label so we brute-force the registrable base
        root = base[4:] if base.startswith('www.') else base
        sem = asyncio.Semaphore(8)

        async def resolve(sub):
            fqdn = f"{sub}.{root}"
            async with sem:
                try:
                    await asyncio.to_thread(dns.resolver.resolve, fqdn, 'A')
                    self.discovered_subdomains.add(fqdn)
                except Exception:
                    pass

        await asyncio.gather(*(resolve(s) for s in common))

    async def _crawl_structure(self, url: str, depth: int, max_depth: int):
        url_clean = self._normalize_url(url)

        if depth > max_depth or url_clean in self.visited_urls:
            return
        if len(self.visited_urls) >= self.max_urls:
            self.limit_reached = True
            return

        signature = self._signature(url_clean)
        seen = self._signature_counts.get(signature, 0)
        if seen >= self.MAX_URLS_PER_SIGNATURE:
            self.limit_reached = True
            self.logger.warning(
                f"Spider-trap heuristic: >{self.MAX_URLS_PER_SIGNATURE} variants of "
                f"{signature[0] or '/'} ; skipping further descent."
            )
            return
        self._signature_counts[signature] = seen + 1

        self.visited_urls.add(url_clean)
        self.logger.info(f"Mapping URL [{len(self.visited_urls)}]: {url_clean}")
        if self.event_emitter is not None:
            await self.event_emitter.emit(
                ScanEventType.URL_SCANNED,
                current=len(self.visited_urls),
                total=self.max_urls,
                url=url_clean,
            )

        if self.crawl_delay > 0:
            await asyncio.sleep(self.crawl_delay)

        try:
            response = await self.scanner.request("GET", url_clean)
            if not response or response.get('status_code') != 200:
                return

            parsed = urlparse(url_clean)
            self._add_to_structure(parsed)

            text = response.get('text', '')
            if not text:
                return

            # Malformed / adversarial HTML can make the parser spike CPU or
            # raise; cap the work and never let a parse failure kill the crawl.
            try:
                soup = BeautifulSoup(text[:5_000_000], 'html.parser')
            except Exception as e:
                self.logger.debug(f"HTML parse failed for {url_clean}: {e}")
                return

            found_urls = set()
            for link in soup.find_all('a', href=True):
                try:
                    absolute_url_clean = self._normalize_url(urljoin(url_clean, str(link['href'])))
                except ValueError:
                    continue
                parsed_link = urlparse(absolute_url_clean)

                if self._is_internal(parsed_link.netloc) and absolute_url_clean not in found_urls:
                    found_urls.add(absolute_url_clean)
                    self.site_structure['links'].append({
                        'from': url_clean,
                        'to': absolute_url_clean,
                        'text': link.get_text(strip=True)[:50]
                    })
                elif parsed_link.netloc and not self._is_internal(parsed_link.netloc):
                    self.site_structure['external_links'].append({
                        'from': url_clean,
                        'to': absolute_url_clean,
                        'domain': parsed_link.netloc
                    })

            for form in soup.find_all('form'):
                self.site_structure['forms'].append({
                    'url': url_clean,
                    'action': str(form.get('action') or ''),
                    'method': str(form.get('method') or 'GET').upper(),
                    'inputs': len(form.find_all('input'))
                })

            for found_url in found_urls:
                if len(self.visited_urls) >= self.max_urls:
                    self.limit_reached = True
                    break
                await self._crawl_structure(found_url, depth + 1, max_depth)

        except Exception as e:
            self.logger.debug(f"Error crawling {url_clean}: {e}")

    def _add_to_structure(self, parsed_url):
        domain = parsed_url.netloc
        path = parsed_url.path
        if domain not in self.site_structure['domains']:
            self.site_structure['domains'][domain] = {'paths': [], 'files': []}
        if path and path != '/':
            parts = path.split('/')
            if '.' in parts[-1]:
                self.site_structure['domains'][domain]['files'].append(path)
            else:
                self.site_structure['domains'][domain]['paths'].append(path)

    def _analyze_structure(self):
        for domain, data in self.site_structure['domains'].items():
            paths = data['paths']
            if any('wp-content' in p or 'wp-admin' in p for p in paths):
                self.technologies.setdefault(domain, []).append({
                    'name': 'WordPress', 'type': 'CMS',
                    'confidence': 'high', 'evidence': 'WordPress paths detected'
                })
            if any('administrator' in p or 'components' in p for p in paths):
                self.technologies.setdefault(domain, []).append({
                    'name': 'Joomla', 'type': 'CMS',
                    'confidence': 'medium', 'evidence': 'Joomla-like structure'
                })

    def _generate_statistics(self) -> dict[str, Any]:
        return {
            'total_urls': len(self.visited_urls),
            'total_subdomains': len(self.discovered_subdomains),
            'total_domains': len(self.site_structure['domains']),
            'total_forms': len(self.site_structure['forms']),
            'total_internal_links': len(self.site_structure['links']),
            'total_external_links': len(self.site_structure['external_links']),
            'total_technologies': sum(len(t) for t in self.technologies.values()),
            'total_vulnerabilities': len(self.vulnerabilities),
        }

    def generate_map(self, map_data: dict[str, Any], output_path: str | None = None) -> str:
        """Generate an interactive-ish HTML map and return its path."""
        if not output_path:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_dir = Path('reports')
            output_dir.mkdir(exist_ok=True)
            output_path = str(output_dir / f'web_map_{timestamp}.html')

        self.logger.info(f"Generating HTML map: {output_path}")
        html_content = self._generate_html(map_data)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        self.logger.info(f"HTML map generated: {output_path}")
        return str(output_path)

    async def generate_map_async(self, map_data: dict[str, Any], output_path: str | None = None) -> str:
        """
        Non-blocking wrapper around :meth:`generate_map`.

        HTML rendering + disk write are pushed to a worker thread so the event
        loop optimised in Phase 2 is never blocked on synchronous file I/O.
        """
        return await asyncio.to_thread(self.generate_map, map_data, output_path)

    def _generate_html(self, data: dict[str, Any]) -> str:
        def e(value: Any) -> str:
            # Escape (with quoting) every crawled value so a hostile page can't
            # smuggle working markup/JS into the map report a human opens.
            return html.escape(str(value), quote=True)

        urls_html = '<ul>' + ''.join(
            f'<li><a href="{e(u)}" target="_blank" rel="noopener noreferrer">{e(u)}</a></li>'
            for u in sorted(self.visited_urls)
        ) + '</ul>'
        subs = data.get('subdomains', [])
        subs_html = ('<ul>' + ''.join(f'<li>{e(s)}</li>' for s in subs) + '</ul>') if subs else '<p>None found.</p>'
        techs = data.get('technologies', {})
        techs_html = ('<ul>' + ''.join(
            f'<li><b>{e(d)}:</b> {e(", ".join(t["name"] for t in ts))}</li>' for d, ts in techs.items()
        ) + '</ul>') if techs else '<p>None detected.</p>'
        vulns = data.get('vulnerabilities', [])
        vulns_html = ('<ul>' + ''.join(
            f'<li><b>{e(v.get("type", v.get("name", "Unknown")))}:</b> {e(v.get("url", ""))}'
            f'<br><i>Payload: {e(v.get("payload", "N/A"))}</i></li>' for v in vulns
        ) + '</ul>') if vulns else '<p>None found.</p>'

        return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Web Map - {e(data['base_domain'])}</title>
</head>
<body>
    <h1>Website Map</h1>
    <p><b>Domain:</b> {e(data['base_domain'])}</p>
    <p><b>Date:</b> {e(data['scan_timestamp'])}</p>
    <hr>
    <h2>Statistics</h2>
    <p>URLs found: {len(self.visited_urls)}</p>
    <p>Subdomains: {len(subs)}</p>
    <p>Vulnerabilities: {len(vulns)}</p>
    <hr>
    <h2>Discovered URLs</h2>
    {urls_html}
    <hr>
    <h2>Subdomains</h2>
    {subs_html}
    <hr>
    <h2>Technologies</h2>
    {techs_html}
    <hr>
    <h2>Vulnerabilities</h2>
    {vulns_html}
    <hr>
    <p><i>Generated by Web Security Scanner</i></p>
</body>
</html>"""
