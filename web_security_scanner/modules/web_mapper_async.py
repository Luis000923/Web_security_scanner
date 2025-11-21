import asyncio
import logging
import re
import socket
from urllib.parse import urlparse, urljoin
from datetime import datetime
from typing import Dict, Any, Set, List
from bs4 import BeautifulSoup
from .web_mapper import WebMapper

class WebMapperAsync(WebMapper):
    """
    Async version of WebMapper.
    """
    def __init__(self, scanner_core, logger=None):
        super().__init__(scanner_core, logger or logging.getLogger("WebMapperAsync"))
        self.scanner = scanner_core # This is AsyncScannerCore
        
    async def map_website(self, base_url: str, max_depth: int = 3) -> Dict[str, Any]:
        """
        Mapea un sitio web completo (Async).
        """
        self.logger.info(f"Iniciando mapeo de: {base_url}")
        
        parsed = urlparse(base_url)
        self.base_domain = parsed.netloc
        
        # 1. Descubrir subdominios
        self.logger.info("Descubriendo subdominios...")
        await self._discover_subdomains()
        
        # 2. Crawlear estructura
        self.logger.info("Crawleando estructura del sitio...")
        await self._crawl_structure(base_url, depth=0, max_depth=max_depth)
        
        # 3. Analizar estructura
        self.logger.info("Analizando estructura...")
        self._analyze_structure()
        
        # 4. Generar datos
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
        
        self.logger.info(f"Mapeo completado: {len(self.visited_urls)} URLs visitadas")
        return map_data

    async def _discover_subdomains(self):
        """Descubre subdominios (Async wrapper)."""
        # For now, we can run the sync DNS checks in a thread if needed, 
        # or just implement the CSP check which is HTTP based.
        
        # CSP Check
        await self._discover_from_csp_headers()
        
        # We can skip brute force or run it in executor for speed/non-blocking
        # loop = asyncio.get_event_loop()
        # await loop.run_in_executor(None, super()._discover_subdomains) 
        # But super()._discover_subdomains calls _discover_from_csp_headers which calls self.scanner.make_request (sync)
        # So we can't easily reuse the sync brute force if it mixes sync HTTP calls.
        # We'll just do CSP for now to be safe and fast.

    async def _discover_from_csp_headers(self):
        try:
            response = await self.scanner.request("GET", f"https://{self.base_domain}")
            if response and response.get('headers'):
                csp = response['headers'].get('Content-Security-Policy', '')
                domains = re.findall(r'https?://([a-zA-Z0-9.-]+)', csp)
                for domain in domains:
                    if self.base_domain in domain:
                        self.discovered_subdomains.add(domain)
        except Exception as e:
            self.logger.debug(f"Error analizando CSP headers: {e}")

    async def _crawl_structure(self, url: str, depth: int, max_depth: int):
        # Limpiar URL de fragmentos
        url_clean = url.split('#')[0]
        
        if depth > max_depth or url_clean in self.visited_urls:
            return
        
        self.visited_urls.add(url_clean)
        self.logger.info(f"Mapeando URL [{len(self.visited_urls)}]: {url_clean}")
        
        try:
            response = await self.scanner.request("GET", url_clean)
            if not response or response.get('status_code') != 200:
                return
            
            parsed = urlparse(url_clean)
            self._add_to_structure(parsed)
            
            text = response.get('text', '')
            if not text:
                return

            soup = BeautifulSoup(text, 'html.parser')
            
            # Recolectar todas las URLs únicas
            found_urls = set()
            for link in soup.find_all('a', href=True):
                href = link['href']
                absolute_url = urljoin(url_clean, href)
                # Limpiar fragmentos y query strings opcionales
                absolute_url_clean = absolute_url.split('#')[0]
                
                parsed_link = urlparse(absolute_url_clean)
                
                if self.base_domain in parsed_link.netloc and absolute_url_clean not in found_urls:
                    found_urls.add(absolute_url_clean)
                    self.site_structure['links'].append({
                        'from': url_clean,
                        'to': absolute_url_clean,
                        'text': link.get_text(strip=True)[:50]
                    })
                elif parsed_link.netloc and self.base_domain not in parsed_link.netloc:
                    self.site_structure['external_links'].append({
                        'from': url_clean,
                        'to': absolute_url_clean,
                        'domain': parsed_link.netloc
                    })
            
            # Crawlear URLs encontradas de forma secuencial
            for found_url in found_urls:
                await self._crawl_structure(found_url, depth + 1, max_depth)
            
            for form in soup.find_all('form'):
                self.site_structure['forms'].append({
                    'url': url_clean,
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET').upper(),
                    'inputs': len(form.find_all('input'))
                })
                
        except Exception as e:
            self.logger.debug(f"Error crawleando {url_clean}: {e}")
