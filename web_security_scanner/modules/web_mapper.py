#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Web Mapper - Generador de Mapas HTML Interactivos
==================================================

Este módulo genera mapas visuales interactivos en HTML de la estructura
completa de un sitio web, incluyendo:
- Subdominios descubiertos
- Estructura de URLs y directorios
- Tecnologías detectadas
- Vulnerabilidades encontradas
- Gráfico de red interactivo

Tecnologías:
-----------
- Python: Backend y lógica de escaneo
- JavaScript (D3.js): Visualizaciones interactivas
- HTML/CSS: Interfaz responsive
- Chart.js: Gráficos estadísticos

Conexiones:
-----------
- Usado por: scanner_v4.py
- Usa: core/scanner_core.py, modules/technology_detector.py
- Genera: reports/map_[timestamp].html
"""

import json
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Set, Any
import dns.resolver
import socket

class WebMapper:
    """
    Generador de mapas visuales de sitios web.
    
    Descubre y mapea la estructura completa de un sitio web,
    incluyendo subdominios, directorios, archivos y relaciones.
    """
    
    def __init__(self, scanner_core, logger):
        """
        Inicializa el mapeador web.
        
        Args:
            scanner_core: Instancia de ScannerCore para peticiones HTTP
            logger: Logger del sistema
        """
        self.scanner = scanner_core
        self.logger = logger
        self.base_domain = None
        self.visited_urls = set()
        self.discovered_subdomains = set()
        self.url_tree = {}
        self.technologies = {}
        self.vulnerabilities = []
        self.site_structure = {
            'domains': {},
            'subdomains': {},
            'directories': {},
            'files': {},
            'forms': [],
            'links': [],
            'external_links': []
        }
        
    def map_website(self, base_url: str, max_depth: int = 3) -> Dict[str, Any]:
        """
        Mapea un sitio web completo.
        
        Args:
            base_url: URL base del sitio
            max_depth: Profundidad máxima de crawling
            
        Returns:
            Diccionario con toda la estructura mapeada
        """
        self.logger.info(f"Iniciando mapeo de: {base_url}")
        
        # Parsear dominio base
        parsed = urlparse(base_url)
        self.base_domain = parsed.netloc
        
        # 1. Descubrir subdominios
        self.logger.info("Descubriendo subdominios...")
        self._discover_subdomains()
        
        # 2. Crawlear estructura
        self.logger.info("Crawleando estructura del sitio...")
        self._crawl_structure(base_url, depth=0, max_depth=max_depth)
        
        # 3. Analizar estructura
        self.logger.info("Analizando estructura...")
        self._analyze_structure()
        
        # 4. Generar datos para visualización
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
    
    def _discover_subdomains(self):
        """Descubre subdominios usando múltiples técnicas."""
        try:
            # Técnica 1: DNS brute force con subdominios comunes
            common_subdomains = [
                'www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'staging',
                'test', 'api', 'cdn', 'shop', 'store', 'portal', 'support',
                'help', 'docs', 'forum', 'community', 'web', 'secure',
                'vpn', 'remote', 'cloud', 'app', 'mobile', 'dashboard'
            ]
            
            for subdomain in common_subdomains:
                full_domain = f"{subdomain}.{self.base_domain}"
                try:
                    # Intentar resolver DNS
                    answers = dns.resolver.resolve(full_domain, 'A')
                    if answers:
                        self.discovered_subdomains.add(full_domain)
                        self.logger.debug(f"Subdominio encontrado: {full_domain}")
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                    pass
                except Exception as e:
                    self.logger.debug(f"Error resolviendo {full_domain}: {e}")
            
            # Técnica 2: Búsqueda en certificados SSL (simulado)
            self._discover_from_ssl_cert()
            
            # Técnica 3: Búsqueda en CSP headers
            self._discover_from_csp_headers()
            
        except Exception as e:
            self.logger.error(f"Error en descubrimiento de subdominios: {e}")
    
    def _discover_from_ssl_cert(self):
        """Descubre subdominios desde certificados SSL."""
        try:
            # Intentar obtener info del certificado
            import ssl
            context = ssl.create_default_context()
            with socket.create_connection((self.base_domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.base_domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Buscar Subject Alternative Names
                    if 'subjectAltName' in cert:
                        for name_type, name in cert['subjectAltName']:
                            if name_type == 'DNS':
                                if self.base_domain in name:
                                    self.discovered_subdomains.add(name)
                                    self.logger.debug(f"Subdominio desde SSL: {name}")
        except Exception as e:
            self.logger.debug(f"No se pudo analizar certificado SSL: {e}")
    
    def _discover_from_csp_headers(self):
        """Descubre subdominios desde Content-Security-Policy headers."""
        try:
            response = self.scanner.make_request(f"https://{self.base_domain}", method='GET')
            if response:
                csp = response.headers.get('Content-Security-Policy', '')
                # Extraer dominios de CSP
                domains = re.findall(r'https?://([a-zA-Z0-9.-]+)', csp)
                for domain in domains:
                    if self.base_domain in domain:
                        self.discovered_subdomains.add(domain)
                        self.logger.debug(f"Subdominio desde CSP: {domain}")
        except Exception as e:
            self.logger.debug(f"Error analizando CSP headers: {e}")
    
    def _crawl_structure(self, url: str, depth: int, max_depth: int):
        """
        Crawlea la estructura del sitio recursivamente.
        
        Args:
            url: URL a crawlear
            depth: Profundidad actual
            max_depth: Profundidad máxima
        """
        if depth > max_depth or url in self.visited_urls:
            return
        
        self.visited_urls.add(url)
        self.logger.debug(f"Crawleando: {url} (profundidad: {depth})")
        
        try:
            response = self.scanner.make_request(url, method='GET')
            if not response or response.status_code != 200:
                return
            
            # Parsear estructura de URL
            parsed = urlparse(url)
            self._add_to_structure(parsed)
            
            # Buscar links en HTML
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extraer todos los links
            for link in soup.find_all('a', href=True):
                href = link['href']
                absolute_url = urljoin(url, href)
                parsed_link = urlparse(absolute_url)
                
                # Si es del mismo dominio, crawlear
                if self.base_domain in parsed_link.netloc:
                    self.site_structure['links'].append({
                        'from': url,
                        'to': absolute_url,
                        'text': link.get_text(strip=True)[:50]
                    })
                    self._crawl_structure(absolute_url, depth + 1, max_depth)
                else:
                    # Link externo
                    self.site_structure['external_links'].append({
                        'from': url,
                        'to': absolute_url,
                        'domain': parsed_link.netloc
                    })
            
            # Extraer formularios
            for form in soup.find_all('form'):
                self.site_structure['forms'].append({
                    'url': url,
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET').upper(),
                    'inputs': len(form.find_all('input'))
                })
                
        except Exception as e:
            self.logger.debug(f"Error crawleando {url}: {e}")
    
    def _add_to_structure(self, parsed_url):
        """Agrega URL a la estructura del sitio."""
        domain = parsed_url.netloc
        path = parsed_url.path
        
        # Agregar dominio/subdominio
        if domain not in self.site_structure['domains']:
            self.site_structure['domains'][domain] = {
                'paths': [],
                'files': []
            }
        
        # Agregar path
        if path and path != '/':
            parts = path.split('/')
            
            # Detectar si es archivo o directorio
            if '.' in parts[-1]:
                self.site_structure['domains'][domain]['files'].append(path)
            else:
                self.site_structure['domains'][domain]['paths'].append(path)
    
    def _analyze_structure(self):
        """Analiza la estructura descubierta."""
        # Detectar patrones comunes
        for domain, data in self.site_structure['domains'].items():
            # Detectar CMS por estructura de paths
            paths = data['paths']
            
            if any('wp-content' in p or 'wp-admin' in p for p in paths):
                self.technologies[domain] = self.technologies.get(domain, [])
                self.technologies[domain].append({
                    'name': 'WordPress',
                    'type': 'CMS',
                    'confidence': 'high',
                    'evidence': 'WordPress paths detected'
                })
            
            if any('administrator' in p or 'components' in p for p in paths):
                self.technologies[domain] = self.technologies.get(domain, [])
                self.technologies[domain].append({
                    'name': 'Joomla',
                    'type': 'CMS',
                    'confidence': 'medium',
                    'evidence': 'Joomla-like structure'
                })
    
    def _generate_statistics(self) -> Dict[str, Any]:
        """Genera estadísticas del mapeo."""
        return {
            'total_urls': len(self.visited_urls),
            'total_subdomains': len(self.discovered_subdomains),
            'total_domains': len(self.site_structure['domains']),
            'total_forms': len(self.site_structure['forms']),
            'total_internal_links': len(self.site_structure['links']),
            'total_external_links': len(self.site_structure['external_links']),
            'total_technologies': sum(len(techs) for techs in self.technologies.values()),
            'total_vulnerabilities': len(self.vulnerabilities)
        }
    
    def add_vulnerabilities(self, vulnerabilities: List[Dict]):
        """
        Agrega vulnerabilidades encontradas al mapa.
        
        Args:
            vulnerabilities: Lista de vulnerabilidades detectadas
        """
        self.vulnerabilities = vulnerabilities
    
    def add_technologies(self, url: str, technologies: Dict):
        """
        Agrega tecnologías detectadas al mapa.
        
        Args:
            url: URL donde se detectaron
            technologies: Dict con tecnologías detectadas
        """
        parsed = urlparse(url)
        domain = parsed.netloc
        self.technologies[domain] = technologies


    
    # --- Fin de la clase WebMapper ---

    
    def generate_map(self, map_data: Dict[str, Any], output_path: str = None) -> str:
        """
        Genera el mapa HTML interactivo.
        
        Args:
            map_data: Datos del mapeo
            output_path: Ruta donde guardar el HTML
            
        Returns:
            Ruta del archivo HTML generado
        """
        if not output_path:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_dir = Path('reports')
            output_dir.mkdir(exist_ok=True)
            output_path = output_dir / f'web_map_{timestamp}.html'
        
        self.logger.info(f"Generando mapa HTML: {output_path}")
        
        # Generar HTML completo
        html_content = self._generate_html(map_data)
        
        # Guardar archivo
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        self.logger.info(f"Mapa HTML generado: {output_path}")
        return str(output_path)
    
    def _generate_html(self, data: Dict[str, Any]) -> str:
        """Genera el contenido HTML completo - VERSIÓN BÁSICA."""
        
        # Generar lista simple de URLs
        all_urls = []
        for url in sorted(self.visited_urls):
            all_urls.append(url)
        
        urls_html = '<ul>'
        for url in all_urls:
            urls_html += f'<li><a href="{url}" target="_blank">{url}</a></li>'
        urls_html += '</ul>'
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Mapa Web - {data['base_domain']}</title>
</head>
<body>
    <h1>Mapa del Sitio Web</h1>
    <p><b>Dominio:</b> {data['base_domain']}</p>
    <p><b>Fecha:</b> {data['scan_timestamp']}</p>
    
    <hr>
    
    <h2>Estadisticas</h2>
    <p>URLs Encontradas: {len(all_urls)}</p>
    <p>Subdominios: {len(data.get('subdomains', []))}</p>
    <p>Vulnerabilidades: {len(data.get('vulnerabilities', []))}</p>
    
    <hr>
    
    <h2>URLs Descubiertas</h2>
    {urls_html}
    
    <hr>
    
    <h2>Subdominios</h2>
    {'<ul>' + ''.join(f'<li>{sd}</li>' for sd in data.get('subdomains', [])) + '</ul>' if data.get('subdomains') else '<p>No se encontraron subdominios.</p>'}
    
    <hr>
    
    <h2>Tecnologias</h2>
    {'<ul>' + ''.join(f'<li><b>{domain}:</b> {", ".join(t["name"] for t in techs)}</li>' for domain, techs in data.get('technologies', {}).items()) + '</ul>' if data.get('technologies') else '<p>No se detectaron tecnologias.</p>'}
    
    <hr>
    
    <h2>Vulnerabilidades</h2>
    {'<ul>' + ''.join(f'<li><b>{v.get("name", "Unknown")}:</b> {v.get("url", "")}<br><i>Payload: {v.get("payload", "N/A")}</i></li>' for v in data.get('vulnerabilities', [])) + '</ul>' if data.get('vulnerabilities') else '<p>No se encontraron vulnerabilidades.</p>'}
    
    <hr>
    
    <p><i>Generado por Web Security Scanner v4.0</i></p>
</body>
</html>"""
        
        return html
    
    def _get_css(self) -> str:
        """Retorna el CSS para el mapa HTML."""
        return """
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }
        
        .header-info {
            display: flex;
            justify-content: center;
            gap: 30px;
            margin-top: 15px;
        }
        
        .domain {
            font-size: 1.2em;
            font-weight: bold;
            background: rgba(255,255,255,0.2);
            padding: 5px 15px;
            border-radius: 20px;
        }
        
        .timestamp {
            font-size: 0.9em;
            opacity: 0.9;
        }
        
        .tabs {
            display: flex;
            background: #f5f5f5;
            border-bottom: 2px solid #ddd;
            overflow-x: auto;
        }
        
        .tab-button {
            padding: 15px 25px;
            border: none;
            background: transparent;
            cursor: pointer;
            font-size: 1em;
            font-weight: 500;
            transition: all 0.3s;
            white-space: nowrap;
        }
        
        .tab-button:hover {
            background: rgba(102, 126, 234, 0.1);
        }
        
        .tab-button.active {
            background: white;
            border-bottom: 3px solid #667eea;
            color: #667eea;
        }
        
        .tab-content {
            display: none;
            padding: 30px;
            animation: fadeIn 0.5s;
        }
        
        .tab-content.active {
            display: block;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.3s;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
        }
        
        .stat-number {
            font-size: 3em;
            font-weight: bold;
            margin: 10px 0;
        }
        
        .stat-label {
            font-size: 1em;
            opacity: 0.9;
        }
        
        #network-graph {
            width: 100%;
            height: 600px;
            border: 2px solid #ddd;
            border-radius: 10px;
            background: #fafafa;
            margin-bottom: 20px;
        }
        
        .controls {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
        }
        
        .controls button {
            padding: 10px 20px;
            border: none;
            background: #667eea;
            color: white;
            border-radius: 5px;
            cursor: pointer;
            font-size: 1em;
            transition: background 0.3s;
        }
        
        .controls button:hover {
            background: #764ba2;
        }
        
        .subdomain-list, .structure-tree, .tech-list, .vuln-list {
            background: #f9f9f9;
            padding: 20px;
            border-radius: 10px;
            border: 1px solid #ddd;
        }
        
        .subdomain-item, .structure-item, .tech-item, .vuln-item {
            background: white;
            margin: 10px 0;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
            transition: all 0.3s;
        }
        
        .subdomain-item:hover, .structure-item:hover, .tech-item:hover, .vuln-item:hover {
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            transform: translateX(5px);
        }
        
        .severity-critical {
            border-left-color: #ff4444;
        }
        
        .severity-high {
            border-left-color: #ff8800;
        }
        
        .severity-medium {
            border-left-color: #ffbb33;
        }
        
        .severity-low {
            border-left-color: #00C851;
        }
        
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
            margin-left: 10px;
        }
        
        .badge-critical {
            background: #ff4444;
            color: white;
        }
        
        .badge-high {
            background: #ff8800;
            color: white;
        }
        
        .badge-medium {
            background: #ffbb33;
            color: #333;
        }
        
        .badge-low {
            background: #00C851;
            color: white;
        }
        
        .chart-container {
            position: relative;
            height: 400px;
            margin: 20px 0;
        }
        
        .footer {
            background: #f5f5f5;
            padding: 20px;
            text-align: center;
            color: #666;
            border-top: 1px solid #ddd;
        }
        
        .node circle {
            cursor: pointer;
            stroke: #fff;
            stroke-width: 2px;
        }
        
        .node text {
            font-size: 12px;
            pointer-events: none;
        }
        
        .link {
            fill: none;
            stroke: #999;
            stroke-opacity: 0.6;
            stroke-width: 1.5px;
        }
        """
    
    def _generate_overview_html(self, data: Dict) -> str:
        """Genera HTML para la pestaña de resumen."""
        stats = data['statistics']
        
        return f"""
        <h2>📊 Resumen del Escaneo</h2>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">{stats['total_urls']}</div>
                <div class="stat-label">URLs Descubiertas</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{stats['total_subdomains']}</div>
                <div class="stat-label">Subdominios</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{stats['total_domains']}</div>
                <div class="stat-label">Dominios Únicos</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{stats['total_forms']}</div>
                <div class="stat-label">Formularios</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{stats['total_internal_links']}</div>
                <div class="stat-label">Links Internos</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{stats['total_external_links']}</div>
                <div class="stat-label">Links Externos</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{stats['total_technologies']}</div>
                <div class="stat-label">Tecnologías</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{stats['total_vulnerabilities']}</div>
                <div class="stat-label">Vulnerabilidades</div>
            </div>
        </div>
        
        <h3>📈 Gráficos Estadísticos</h3>
        <div class="chart-container">
            <canvas id="overviewChart"></canvas>
        </div>
        """
    
    def _generate_subdomains_html(self, data: Dict) -> str:
        """Genera HTML para la pestaña de subdominios."""
        subdomains = data.get('subdomains', [])
        
        html = "<h2>🌐 Subdominios Descubiertos</h2>"
        html += f"<p>Total: {len(subdomains)} subdominios</p>"
        html += '<div class="subdomain-list">'
        
        for subdomain in subdomains:
            html += f"""
            <div class="subdomain-item">
                <strong>{subdomain}</strong>
                <span class="badge" style="background: #4285f4; color: white;">Activo</span>
            </div>
            """
        
        html += '</div>'
        return html
    
    def _generate_structure_html(self, data: Dict) -> str:
        """Genera HTML para la pestaña de estructura."""
        domains = data['structure']['domains']
        
        html = "<h2>📁 Estructura del Sitio</h2>"
        html += '<div class="structure-tree">'
        
        for domain, info in domains.items():
            html += f"""
            <div class="structure-item">
                <h3>🌐 {domain}</h3>
                <p><strong>Paths:</strong> {len(info['paths'])}</p>
                <p><strong>Files:</strong> {len(info['files'])}</p>
            </div>
            """
        
        html += '</div>'
        return html
    
    def _generate_technologies_html(self, data: Dict) -> str:
        """Genera HTML para la pestaña de tecnologías."""
        technologies = data.get('technologies', {})
        
        html = "<h2>⚙️ Tecnologías Detectadas</h2>"
        html += '<div class="tech-list">'
        
        for domain, techs in technologies.items():
            for tech in techs:
                html += f"""
                <div class="tech-item">
                    <strong>{tech['name']}</strong>
                    <span class="badge" style="background: #00C851; color: white;">{tech['type']}</span>
                    <span class="badge" style="background: #ffbb33; color: #333;">Confianza: {tech['confidence']}</span>
                    <p style="margin-top: 10px; color: #666;">{tech['evidence']}</p>
                </div>
                """
        
        html += '</div>'
        return html
    
    def _generate_vulnerabilities_html(self, data: Dict) -> str:
        """Genera HTML para la pestaña de vulnerabilidades."""
        vulnerabilities = data.get('vulnerabilities', [])
        
        html = "<h2>🔒 Vulnerabilidades Encontradas</h2>"
        html += f"<p>Total: {len(vulnerabilities)} vulnerabilidades</p>"
        html += '<div class="vuln-list">'
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'low').lower()
            html += f"""
            <div class="vuln-item severity-{severity}">
                <strong>{vuln.get('name', 'Unknown')}</strong>
                <span class="badge badge-{severity}">{severity.upper()}</span>
                <p style="margin-top: 10px;"><strong>URL:</strong> {vuln.get('url', 'N/A')}</p>
                <p><strong>Descripción:</strong> {vuln.get('description', 'N/A')}</p>
            </div>
            """
        
        html += '</div>'
        return html
    
    def _get_javascript(self) -> str:
        """Retorna el JavaScript para interactividad."""
        return """
        // Función para cambiar de tab
        function showTab(tabName) {
            // Ocultar todos los tabs
            const tabs = document.querySelectorAll('.tab-content');
            tabs.forEach(tab => tab.classList.remove('active'));
            
            // Desactivar todos los botones
            const buttons = document.querySelectorAll('.tab-button');
            buttons.forEach(btn => btn.classList.remove('active'));
            
            // Mostrar tab seleccionado
            document.getElementById(tabName).classList.add('active');
            event.target.classList.add('active');
            
            // Si es el tab de network, dibujar el grafo
            if (tabName === 'network') {
                setTimeout(() => drawNetworkGraph(), 100);
            }
            
            // Si es el tab de overview, dibujar gráfico
            if (tabName === 'overview') {
                setTimeout(() => drawOverviewChart(), 100);
            }
        }
        
        // Dibujar gráfico de resumen
        function drawOverviewChart() {
            const ctx = document.getElementById('overviewChart');
            if (!ctx) return;
            
            const stats = mapData.statistics;
            
            new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: ['URLs', 'Subdominios', 'Formularios', 'Links Internos', 'Links Externos', 'Tecnologías'],
                    datasets: [{
                        label: 'Cantidad',
                        data: [
                            stats.total_urls,
                            stats.total_subdomains,
                            stats.total_forms,
                            stats.total_internal_links,
                            stats.total_external_links,
                            stats.total_technologies
                        ],
                        backgroundColor: [
                            'rgba(102, 126, 234, 0.8)',
                            'rgba(118, 75, 162, 0.8)',
                            'rgba(255, 136, 0, 0.8)',
                            'rgba(0, 200, 81, 0.8)',
                            'rgba(255, 187, 51, 0.8)',
                            'rgba(68, 133, 244, 0.8)'
                        ],
                        borderColor: [
                            'rgb(102, 126, 234)',
                            'rgb(118, 75, 162)',
                            'rgb(255, 136, 0)',
                            'rgb(0, 200, 81)',
                            'rgb(255, 187, 51)',
                            'rgb(68, 133, 244)'
                        ],
                        borderWidth: 2
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            display: false
                        },
                        title: {
                            display: true,
                            text: 'Estadísticas del Escaneo',
                            font: {
                                size: 18
                            }
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            });
        }
        
        // Dibujar grafo de red con D3.js
        function drawNetworkGraph() {
            const container = document.getElementById('network-graph');
            if (!container) return;
            
            // Limpiar contenedor
            container.innerHTML = '';
            
            const width = container.clientWidth;
            const height = container.clientHeight;
            
            // Preparar datos para D3
            const nodes = [];
            const links = [];
            const nodeSet = new Set();

            function addNode(id, group, type, data = {}) {
                if (!nodeSet.has(id)) {
                    nodes.push({ id, group, type, ...data });
                    nodeSet.add(id);
                }
            }

            function addLink(source, target) {
                links.push({ source, target });
            }
            
            // Nodo raíz (dominio base)
            addNode(mapData.base_domain, 1, 'domain', { label: mapData.base_domain });
            
            // Agregar subdominios
            mapData.subdomains.forEach(subdomain => {
                addNode(subdomain, 2, 'subdomain', { label: subdomain });
                addLink(mapData.base_domain, subdomain);
            });

            // Procesar estructura de directorios y archivos
            if (mapData.structure && mapData.structure.domains) {
                Object.entries(mapData.structure.domains).forEach(([domain, data]) => {
                    // Asegurar que el nodo de dominio existe (puede ser base o subdominio)
                    addNode(domain, domain === mapData.base_domain ? 1 : 2, 'domain', { label: domain });

                    // Procesar directorios
                    data.paths.forEach(path => {
                        if (!path) return;
                        const parts = path.split('/').filter(p => p);
                        let currentPath = domain;
                        
                        parts.forEach((part, index) => {
                            const nodeId = currentPath + '/' + part;
                            addNode(nodeId, 3, 'directory', { label: part, fullPath: path });
                            addLink(currentPath, nodeId);
                            currentPath = nodeId;
                        });
                    });

                    // Procesar archivos
                    data.files.forEach(file => {
                        if (!file) return;
                        const parts = file.split('/').filter(p => p);
                        const fileName = parts.pop();
                        let currentPath = domain;
                        
                        // Reconstruir path padre
                        parts.forEach(part => {
                            const nodeId = currentPath + '/' + part;
                            // Asumimos que los directorios ya fueron procesados, pero por si acaso
                            addNode(nodeId, 3, 'directory', { label: part }); 
                            currentPath = nodeId;
                        });

                        const fileId = currentPath + '/' + fileName;
                        addNode(fileId, 4, 'file', { label: fileName, fullPath: file });
                        addLink(currentPath, fileId);
                    });
                });
            }
            
            // Crear SVG
            const svg = d3.select('#network-graph')
                .append('svg')
                .attr('width', width)
                .attr('height', height)
                .call(d3.zoom().on("zoom", (event) => {
                    g.attr("transform", event.transform);
                }));

            const g = svg.append("g");
            
            // Crear simulación de fuerzas
            const simulation = d3.forceSimulation(nodes)
                .force('link', d3.forceLink(links).id(d => d.id).distance(50))
                .force('charge', d3.forceManyBody().strength(-100))
                .force('center', d3.forceCenter(width / 2, height / 2))
                .force('collide', d3.forceCollide(15));
            
            // Dibujar links
            const link = g.append('g')
                .selectAll('line')
                .data(links)
                .join('line')
                .attr('class', 'link')
                .attr('stroke', '#999')
                .attr('stroke-opacity', 0.6);
            
            // Dibujar nodos
            const node = g.append('g')
                .selectAll('g')
                .data(nodes)
                .join('g')
                .attr('class', 'node')
                .call(d3.drag()
                    .on('start', dragstarted)
                    .on('drag', dragged)
                    .on('end', dragended))
                .on('click', showNodeDetails);
            
            node.append('circle')
                .attr('r', d => {
                    if (d.type === 'domain') return 15;
                    if (d.type === 'subdomain') return 12;
                    if (d.type === 'directory') return 8;
                    return 5;
                })
                .attr('fill', d => {
                    if (d.type === 'domain') return '#667eea';
                    if (d.type === 'subdomain') return '#764ba2';
                    if (d.type === 'directory') return '#4285f4';
                    return '#00C851';
                });
            
            node.append('title')
                .text(d => d.label);
            
            // Actualizar posiciones
            simulation.on('tick', () => {
                link
                    .attr('x1', d => d.source.x)
                    .attr('y1', d => d.source.y)
                    .attr('x2', d => d.target.x)
                    .attr('y2', d => d.target.y);
                
                node
                    .attr('transform', d => `translate(${d.x},${d.y})`);
            });
            
            // Funciones de drag
            function dragstarted(event) {
                if (!event.active) simulation.alphaTarget(0.3).restart();
                event.subject.fx = event.subject.x;
                event.subject.fy = event.subject.y;
            }
            
            function dragged(event) {
                event.subject.fx = event.x;
                event.subject.fy = event.y;
            }
            
            function dragended(event) {
                if (!event.active) simulation.alphaTarget(0);
                event.subject.fx = null;
                event.subject.fy = null;
            }

            function showNodeDetails(event, d) {
                const detailsPanel = document.getElementById('node-details');
                const infoDiv = document.getElementById('node-info');
                detailsPanel.style.display = 'block';
                
                let content = `<p><strong>Tipo:</strong> ${d.type}</p>`;
                content += `<p><strong>Nombre:</strong> ${d.label}</p>`;
                if (d.fullPath) {
                    content += `<p><strong>Ruta Completa:</strong> ${d.fullPath}</p>`;
                }
                
                // Buscar vulnerabilidades asociadas (simple match)
                const vulns = mapData.vulnerabilities.filter(v => v.url && v.url.includes(d.label));
                if (vulns.length > 0) {
                    content += `<p><strong>Vulnerabilidades:</strong> ${vulns.length}</p>`;
                    content += '<ul>';
                    vulns.forEach(v => content += `<li>${v.name}</li>`);
                    content += '</ul>';
                }

                // Tecnologías (si es dominio)
                if (d.type === 'domain' || d.type === 'subdomain') {
                    const techs = mapData.technologies[d.id];
                    if (techs) {
                        content += `<p><strong>Tecnologías:</strong></p><ul>`;
                        techs.forEach(t => content += `<li>${t.name} (${t.type})</li>`);
                        content += '</ul>';
                    }
                }

                infoDiv.innerHTML = content;
            }
        }
        
        // Funciones de control
        function resetZoom() {
            drawNetworkGraph();
        }
        
        function expandAll() {
            alert('Función de expandir en desarrollo');
        }
        
        function collapseAll() {
            alert('Función de colapsar en desarrollo');
        }
        
        // Inicializar
        document.addEventListener('DOMContentLoaded', () => {
            drawOverviewChart();
        });
        """
