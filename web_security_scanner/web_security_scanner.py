#python3
"""
Web Security Scanner - Una herramienta para realizar pruebas básicas de seguridad en sitios web
Este script realiza pruebas para detectar vulnerabilidades comunes como inyección SQL, XSS, y más.
Además, incluye detección de tecnologías utilizadas en el sitio web objetivo.
USO EDUCATIVO SOLAMENTE - No utilizar en sitios web sin autorización explícita.
"""

import requests
import re
import argparse
import sys
import urllib.parse
import json
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib3.exceptions import InsecureRequestWarning
from colorama import Fore, Style, init
import time  
import hashlib
from threading import Lock
from collections import defaultdict
import random
import html
import socket

#módulos personalizados
from banner import print_banner
from redirect_payloads import *
from Tecnologias import TECNOLOGIAS
from js_frameworks import JSframeworks
from cms_fingerprints import CMS_fingerprints
from analytics_patterns import ANALYTICS_PATTERNS
from reporte import generar_reporte_html, generar_reporte_excel, generar_reporte_word, generar_reporte_pdf


# Inicializar colorama para la salida de colores en terminal
init(autoreset=True)

# Suprimir advertencias de SSL
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class ResponseCache:
    """Cache para almacenar respuestas y evitar peticiones duplicadas"""
    def __init__(self, max_size=1000):
        self.cache = {}
        self.max_size = max_size
        self.lock = Lock()
    
    def get_cache_key(self, url, method, data):
        key_data = f"{url}-{method}-{str(sorted(data.items()) if data else '')}"
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def get(self, url, method, data):
        with self.lock:
            key = self.get_cache_key(url, method, data)
            return self.cache.get(key)
    
    def put(self, url, method, data, response):
        with self.lock:
            if len(self.cache) >= self.max_size:
                keys_to_remove = random.sample(list(self.cache.keys()), self.max_size // 4)
                for key in keys_to_remove:
                    del self.cache[key]
            key = self.get_cache_key(url, method, data)
            if response and hasattr(response, 'status_code'):
                self.cache[key] = {
                    'status_code': response.status_code,
                    'text': response.text,
                    'headers': dict(response.headers),
                    'timestamp': time.time()
                }

class PayloadOptimizer:
    """Optimizador de payloads para mejorar la eficiencia"""
    @staticmethod
    def prioritize_payloads(payloads, scan_mode='medium'):
        if scan_mode == 'quick':
            return payloads[:min(10, len(payloads))]
        elif scan_mode == 'slow':
            return payloads
        elif scan_mode == 'fast':
            return payloads[:min(20, len(payloads))]
        else:  # medium
            return payloads[:min(30, len(payloads))]
    
    @staticmethod
    def smart_payload_selection(payloads, technology_info=None):
        if not technology_info:
            return payloads
        prioritized = []
        standard = []
        for payload in payloads:
            if any(tech.lower() in payload.lower() for tech in technology_info.get('databases', [])):
                prioritized.append(payload)
            elif any(tech.lower() in payload.lower() for tech in technology_info.get('languages', [])):
                prioritized.append(payload)
            else:
                standard.append(payload)
        return prioritized + standard

class WebSecurityScanner:
    def __init__(self, url, threads=10, timeout=35, verbose=False):
        self.base_url = url
        self.threads = min(threads, 20)
        self.timeout = timeout
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers = {
            'User-Agent': 'WebSecurityScanner/2.0 (Educational Purpose Only)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3',
            'Connection': 'keep-alive'
        }
        self.forms = []
        self.results = {
            'sql_injection': [],
            'xss': [],
            'nosql_injection': [],
            'open_redirect': [],
            'server_info': {},
            'forms_found': 0,
            'parameters_found': [],
            'technologies': {}
        }
        self.response_cache = ResponseCache()
        self.payload_optimizer = PayloadOptimizer()
        self.baseline_responses = {}
        self.scan_mode = 'medium'
        self.quick_scan = False
        self.stats = {
            'total_requests': 0,
            'cached_responses': 0,
            'vulnerabilities_found': 0
        }
        self.load_technology_signatures()
        self.load_payloads()  # <-- Añade esta línea
        self.subdirectories = set()
        self.subdomains = set()
        self.load_subdir_and_subdomain_wordlists()  # <-- Añade esta línea

    def print_banner(self):
        """Muestra el banner de la herramienta"""
        print_banner()

    def load_payloads(self):
        """Carga los payloads desde archivos JSON ubicados en la carpeta PAYLOAD"""
        try:
            with open('PAYLOAD/payloadsSQL.json', 'r', encoding='utf-8') as f:
                self.payloadsSQL = json.load(f)
            with open('PAYLOAD/payloadsXSS.json', 'r', encoding='utf-8') as f:
                self.payloadsXSS = json.load(f)
            with open('PAYLOAD/payloadsNoSQL.json', 'r', encoding='utf-8') as f:
                self.payloadsNoSQL = json.load(f)
        except Exception as e:
            print(f"{Fore.RED}[!] Error cargando payloads: {e}")
            self.payloadsSQL = []
            self.payloadsXSS = []
            self.payloadsNoSQL = []

    def load_technology_signatures(self):
        """Carga las firmas para la detección de tecnologías"""
        self.tech_signatures = TECNOLOGIAS
        # Crear meta_signatures basado en CMS_fingerprints
        self.meta_signatures = {
            'generator': CMS_fingerprints
        }

    def load_subdir_and_subdomain_wordlists(self):
        """Carga las wordlists de subdirectorios y subdominios desde archivos JSON"""
        try:
            with open('PAYLOAD/subdirectorios.json', 'r', encoding='utf-8') as f:
                self.wordlist_subdirs = json.load(f)
            with open('PAYLOAD/subdominios.json', 'r', encoding='utf-8') as f:
                self.wordlist_subdomains = json.load(f)
        except Exception as e:
            print(f"{Fore.RED}[!] Error cargando wordlists de subdirectorios/subdominios: {e}")
            self.wordlist_subdirs = []
            self.wordlist_subdomains = []

   
    def run_scan(self):
        """Ejecuta el escaneo completo de seguridad"""
        self.print_banner()
        
        try:
            print(f"{Fore.BLUE}[*] Verificando la conexión con el sitio objetivo...")
            response = self.session.get(self.base_url, verify=False, timeout=self.timeout)
            print(f"{Fore.GREEN}[+] Conexión establecida: {response.status_code}")
            
            # Obtener información básica del servidor
            self.collect_server_info(response)
            
            # Detectar tecnologías
            print(f"{Fore.BLUE}[*] Detectando tecnologías utilizadas...")
            self.detect_technologies(response)
            
            # Explorar el sitio y recolectar formularios
            print(f"{Fore.BLUE}[*] Explorando el sitio para encontrar formularios y parámetros...")
            self.crawl_site()
            
            # Mostrar resultados de la exploración
            print(f"{Fore.GREEN}[+] Formularios encontrados: {self.results['forms_found']}")
            
            # Ejecutar pruebas de vulnerabilidades
            print(f"{Fore.BLUE}[*] Iniciando pruebas de vulnerabilidades...")
            self.test_vulnerabilities()
            
            # Mostrar resumen de resultados
            self.show_results()
            
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[!] Error de conexión: {e}")
            sys.exit(1)

    def collect_server_info(self, response):
        """Recopila información básica del servidor"""
        headers = response.headers
        self.results['server_info'] = {
            'server': headers.get('Server', 'No detectado'),
            'x_powered_by': headers.get('X-Powered-By', 'No detectado'),
            'content_type': headers.get('Content-Type', 'No detectado')
        }
        
        print(f"{Fore.GREEN}[+] Información del servidor:")
        print(f"  - Server: {self.results['server_info']['server']}")
        print(f"  - X-Powered-By: {self.results['server_info']['x_powered_by']}")

    def detect_technologies(self, response):
        """Detecta tecnologías web utilizadas en el sitio"""
        detected_tech = {
            'servers': [],
            'languages': [],
            'cms': [],
            'frontend': [],
            'databases': [],
            'js_frameworks': [],
            'analytics': [],
            'misc': []
        }
        
        # Obtener contenido y cabeceras
        html_content = response.text
        headers = response.headers
        
        try:
            # 1. Detección basada en cabeceras HTTP
            for header_name, header_value in headers.items():
                # Detectar servidores
                if 'servers' in self.tech_signatures:
                    for server, patterns in self.tech_signatures['servers'].items():
                        for pattern in patterns:
                            if pattern.lower() in header_value.lower():
                                if server not in detected_tech['servers']:
                                    detected_tech['servers'].append(server)
                
                # Detectar lenguajes
                if 'languages' in self.tech_signatures:
                    for lang, patterns in self.tech_signatures['languages'].items():
                        for pattern in patterns:
                            if pattern.lower() in header_value.lower():
                                if lang not in detected_tech['languages']:
                                    detected_tech['languages'].append(lang)
            
            # 2. Detección basada en contenido HTML
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # 2.1 Detección basada en meta tags
            meta_tags = soup.find_all('meta')
            for meta in meta_tags:
                if meta.get('name') == 'generator' and meta.get('content'):
                    content = meta.get('content').lower()
                    for cms, patterns in self.meta_signatures['generator'].items():
                        for pattern in patterns:
                            if pattern.lower() in content:
                                if cms not in detected_tech['cms']:
                                    detected_tech['cms'].append(cms)
            
            # 2.2 Detección basada en scripts
            scripts = soup.find_all('script')
            for script in scripts:
                script_src = script.get('src', '')
                script_content = script.string if script.string else ''
                
                # Revisar JavaScript frameworks
                if 'js_frameworks' in self.tech_signatures:
                    for framework, patterns in self.tech_signatures['js_frameworks'].items():
                        for pattern in patterns:
                            if (pattern.lower() in script_src.lower() or 
                                (script_content and pattern.lower() in script_content.lower())):
                                if framework not in detected_tech['js_frameworks']:
                                    detected_tech['js_frameworks'].append(framework)
                
                # Revisar frontend frameworks
                if 'frontend' in self.tech_signatures:
                    for framework, patterns in self.tech_signatures['frontend'].items():
                        for pattern in patterns:
                            if (pattern.lower() in script_src.lower() or 
                                (script_content and pattern.lower() in script_content.lower())):
                                if framework not in detected_tech['frontend']:
                                    detected_tech['frontend'].append(framework)
                
                # Revisar analíticas
                if 'analytics' in self.tech_signatures:
                    for analytics, patterns in self.tech_signatures['analytics'].items():
                        for pattern in patterns:
                            if (pattern.lower() in script_src.lower() or 
                                (script_content and pattern.lower() in script_content.lower())):
                                if analytics not in detected_tech['analytics']:
                                    detected_tech['analytics'].append(analytics)
            
            # 2.3 Detección basada en links y CSS
            links = soup.find_all('link')
            for link in links:
                href = link.get('href', '')
                
                # Revisar CMS
                if 'cms' in self.tech_signatures:
                    for cms, patterns in self.tech_signatures['cms'].items():
                        for pattern in patterns:
                            if pattern.lower() in href.lower():
                                if cms not in detected_tech['cms']:
                                    detected_tech['cms'].append(cms)
                
                # Revisar frontend
                if 'frontend' in self.tech_signatures:
                    for framework, patterns in self.tech_signatures['frontend'].items():
                        for pattern in patterns:
                            if pattern.lower() in href.lower():
                                if framework not in detected_tech['frontend']:
                                    detected_tech['frontend'].append(framework)
            
            # 2.4 Detección en todo el HTML
            for category, tech_dict in self.tech_signatures.items():
                if category in detected_tech:
                    for tech, patterns in tech_dict.items():
                        for pattern in patterns:
                            if pattern.lower() in html_content.lower():
                                if tech not in detected_tech[category]:
                                    detected_tech[category].append(tech)
        
        except Exception as e:
            if self.verbose:
                print(f"{Fore.YELLOW}[!] Error en la detección de tecnologías: {e}")
        
        # Guardar tecnologías detectadas en los resultados
        for category, techs in detected_tech.items():
            if techs:
                self.results['technologies'][category] = techs
        
        # Mostrar tecnologías detectadas
        if self.results['technologies']:
            print(f"{Fore.GREEN}[+] Tecnologías detectadas:")
            for category, techs in self.results['technologies'].items():
                if techs:
                    print(f"  - {category.capitalize()}: {', '.join(techs)}")
        else:
            print(f"{Fore.YELLOW}[!] No se detectaron tecnologías")

    def discover_subdirectories(self):
        """Descubre subdirectorios usando fuerza bruta con la wordlist"""
        base = self.base_url.rstrip('/')
        found_dirs = set()
        for path in self.wordlist_subdirs:
            url = f"{base}/{path.strip().lstrip('/')}/"
            try:
                resp = self.session.get(url, verify=False, timeout=self.timeout)
                if resp.status_code < 400:
                    found_dirs.add(url)
                    if self.verbose:
                        print(f"{Fore.GREEN}[+] Subdirectorio encontrado: {url}")
            except Exception:
                continue
        self.subdirectories.update(found_dirs)
        self.results['subdirectories'] = list(self.subdirectories)

    def discover_subdomains(self):
        """Descubre subdominios usando fuerza bruta con la wordlist"""
        found_subdomains = set()
        domain = self.base_url.split('/')[2]
        for prefix in self.wordlist_subdomains:
            subdomain = f"{prefix.strip()}.{domain}"
            try:
                socket.gethostbyname(subdomain)
                found_subdomains.add(subdomain)
                if self.verbose:
                    print(f"{Fore.GREEN}[+] Subdominio encontrado: {subdomain}")
            except Exception:
                continue
        self.subdomains.update(found_subdomains)
        self.results['subdomains'] = list(self.subdomains)

    def crawl_site(self):
        """Explora el sitio para encontrar formularios, parámetros y subdirectorios"""
        try:
            visited = set()
            to_visit = set([self.base_url])
            max_depth = 2  # Puedes ajustar la profundidad máxima de exploración

            for depth in range(max_depth):
                current_level = list(to_visit)
                to_visit = set()
                for url in current_level:
                    if url in visited:
                        continue
                    visited.add(url)
                    try:
                        response = self.session.get(url, verify=False, timeout=self.timeout)
                        self.extract_forms(response.text, url)
                        self.extract_links(response.text, url)
                        self.extract_parameters(url)
                        # Extraer subdirectorios de los enlaces encontrados
                        soup = BeautifulSoup(response.text, 'html.parser')
                        links = soup.find_all('a', href=True)
                        for link in links:
                            href = link.get('href', '')
                            if not href or href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                                continue
                            # Normalizar enlaces relativos
                            if not href.startswith(('http://', 'https://')):
                                if href.startswith('/'):
                                    base = '/'.join(self.base_url.split('/')[:3])
                                    full_url = base + href
                                else:
                                    full_url = url.rstrip('/') + '/' + href
                            else:
                                full_url = href
                            # Solo procesar enlaces del mismo dominio y que sean subdirectorios
                            if self.base_url.split('/')[2] in full_url:
                                if full_url.endswith('/') or full_url.count('/') > 3:
                                    if full_url not in visited:
                                        to_visit.add(full_url)
                                        es_subdirectorio = True
                                        for vurl in visited:
                                            if full_url.startswith(vurl.rstrip('/') + '/'):
                                                es_subdirectorio = False
                                                break
                                        if es_subdirectorio:
                                            self.subdirectories.add(full_url)
                    except Exception as e:
                        if self.verbose:
                            print(f"{Fore.RED}[!] Error durante la exploración de {url}: {e}")
            self.results['forms_found'] = len(self.forms)
            # Llama a fuerza bruta de subdirectorios y subdominios al final del crawling
            self.discover_subdirectories()
            self.discover_subdomains()
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}[!] Error durante la exploración: {e}")

    def extract_forms(self, html_content, url):
        """Extrae formularios del HTML"""
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'GET').upper()
                
                # Manejar URLs relativas
                if action and not action.startswith(('http://', 'https://')):
                    if action.startswith('/'):
                        base = '/'.join(self.base_url.split('/')[:3])
                        action = base + action
                    else:
                        action = url.rstrip('/') + '/' + action
                elif not action:
                    action = url
                
                # Encontrar todos los inputs
                inputs = []
                input_tags = form.find_all(['input', 'textarea', 'select'])
                for input_tag in input_tags:
                    name = input_tag.get('name')
                    if name and input_tag.get('type') != 'submit':
                        inputs.append(name)
                
                if inputs:
                    self.forms.append({
                        'action': action,
                        'method': method,
                        'inputs': inputs
                    })
                    
                    if self.verbose:
                        print(f"{Fore.GREEN}[+] Formulario encontrado en {action} (Método: {method})")
                        print(f"    Parámetros: {', '.join(inputs)}")
            
            self.results['forms_found'] = len(self.forms)
            
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}[!] Error extrayendo formularios: {e}")

    def extract_links(self, html_content, base_url):
        """Extrae enlaces del contenido HTML"""
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            links = soup.find_all('a', href=True)
            
            for link in links:
                href = link.get('href', '')
                if not href or href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                    continue
                    
                # Normalizar enlaces relativos
                if not href.startswith(('http://', 'https://')):
                    if href.startswith('/'):
                        base = '/'.join(self.base_url.split('/')[:3])
                        href = base + href
                    else:
                        href = base_url.rstrip('/') + '/' + href
                
                # Solo procesar enlaces del mismo dominio
                if self.base_url.split('/')[2] in href:
                    self.extract_parameters(href)
                    
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}[!] Error extrayendo enlaces: {e}")

    def extract_parameters(self, url):
        """Extrae parámetros de una URL"""
        try:
            if '?' in url:
                params = url.split('?')[1].split('&')
                for param in params:
                    if '=' in param:
                        param_name = param.split('=')[0]
                        if param_name not in self.results['parameters_found']:
                            self.results['parameters_found'].append(param_name)
                            if self.verbose:
                                print(f"{Fore.GREEN}[+] Parámetro GET encontrado: {param_name} en {url}")
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}[!] Error extrayendo parámetros: {e}")

    def make_request(self, url, method='GET', data=None, allow_redirects=True):
        cached_response = self.response_cache.get(url, method, data)
        if cached_response:
            self.stats['cached_responses'] += 1
            class MockResponse:
                def __init__(self, cached_data):
                    self.status_code = cached_data['status_code']
                    self.text = cached_data['text']
                    self.headers = cached_data['headers']
            return MockResponse(cached_response)
        try:
            self.stats['total_requests'] += 1
            if method.upper() == 'POST':
                response = self.session.post(
                    url, data=data, verify=False, timeout=self.timeout, allow_redirects=allow_redirects
                )
            else:
                response = self.session.get(
                    url, params=data, verify=False, timeout=self.timeout, allow_redirects=allow_redirects
                )
            self.response_cache.put(url, method, data, response)
            return response
        except requests.exceptions.Timeout:
            if self.verbose:
                print(f"{Fore.YELLOW}[!] Timeout en {url}")
            return None
        except requests.exceptions.RequestException as e:
            if self.verbose:
                print(f"{Fore.YELLOW}[!] Error en petición a {url}: {e}")
            return None

    def get_baseline_response(self, form):
        form_key = f"{form['action']}-{form['method']}"
        if form_key not in self.baseline_responses:
            safe_data = {input_name: "test123" for input_name in form['inputs']}
            response = self.make_request(form['action'], form['method'], safe_data)
            if response:
                self.baseline_responses[form_key] = {
                    'status_code': response.status_code,
                    'length': len(response.text),
                    'text_hash': hashlib.md5(response.text.encode()).hexdigest()
                }
        return self.baseline_responses.get(form_key)

    def is_vulnerability_response(self, response, baseline, vulnerability_type):
        if not response or not baseline:
            return False
        if response.status_code != baseline['status_code']:
            return True
        length_diff = abs(len(response.text) - baseline['length'])
        if length_diff > 100:
            return True
        if vulnerability_type == 'sql':
            return self.check_sql_injection_success(response.text)
        elif vulnerability_type == 'xss':
            return self.check_xss_success(response.text)
        elif vulnerability_type == 'nosql':
            return self.check_nosql_injection_success(response.text)
        return False

    def check_xss_success(self, response_text):
        xss_patterns = [
            '<script', 'javascript:', 'onerror=', 'onload=', 'alert(',
            'confirm(', 'prompt(', 'document.cookie', 'eval('
        ]
        response_lower = response_text.lower()
        for pattern in xss_patterns:
            if pattern in response_lower:
                return True
        return False

    def check_sql_injection_success(self, response_text):
        """Verifica si la respuesta indica una vulnerabilidad de inyección SQL"""
        sql_errors = [
            "you have an error in your sql syntax",
            "warning: mysql",
            "unclosed quotation mark after the character string",
            "quoted string not properly terminated",
            "mysql_fetch",
            "mysql_num_rows",
            "pg_query",
            "syntax error",
            "ORA-",
            "SQLite3::",
            "SQLSTATE",
            "Microsoft OLE DB Provider for SQL Server",
            "Incorrect syntax near",
            "Fatal error",
            "ODBC SQL Server Driver",
            "DB2 SQL error",
            "Sybase message",
            "MySQL server version for the right syntax",
            "supplied argument is not a valid MySQL",
            "java.sql.SQLException"
        ]
        response_lower = response_text.lower()
        for error in sql_errors:
            if error in response_lower:
                return True
        return False

    def check_nosql_injection_success(self, response_text):
        """Verifica si la respuesta indica una vulnerabilidad de inyección NoSQL"""
        nosql_errors = [
            "MongoDB", "NoSQL", "TypeError", "cannot convert", "bson", "E11000",
            "ReferenceError", "Uncaught exception", "Cast to ObjectId failed",
            "SyntaxError", "Unexpected token", "invalid json", "DocumentNotFoundError",
            "missing value", "Unterminated string", "Unexpected end of JSON input"
        ]
        response_lower = response_text.lower()
        for error in nosql_errors:
            if error.lower() in response_lower:
                return True
        return False

    def get_severity_and_desc(self, vuln_type):
        if vuln_type == 'sql':
            return 'alta', 'Inyección SQL detectada, puede permitir acceso no autorizado a la base de datos'
        elif vuln_type == 'xss':
            return 'media', 'Vulnerabilidad de Cross-Site Scripting (XSS) detectada'
        elif vuln_type == 'nosql':
            return 'alta', 'Inyección NoSQL detectada, puede permitir acceso no autorizado a la base de datos'
        return 'baja', 'Vulnerabilidad detectada'

    def test_vulnerabilities(self):
        print(f"{Fore.BLUE}[*] Probando vulnerabilidades de inyección SQL...")
        sql_found = self.test_sql_injection_optimized()
        print(f"{Fore.BLUE}[*] Probando vulnerabilidades XSS...")
        xss_found = self.test_xss_optimized()
        print(f"{Fore.BLUE}[*] Probando vulnerabilidades de inyección NoSQL...")
        nosql_found = self.test_nosql_injection_optimized()
        print(f"{Fore.BLUE}[*] Probando vulnerabilidades de redirección abierta...")
        redirect_found = self.test_open_redirect()
        self.stats['vulnerabilities_found'] = sql_found + xss_found + nosql_found + redirect_found

    def test_sql_injection_optimized(self):
        if not self.forms:
            return 0
        vulnerabilities_found = 0
        payloads = self.payload_optimizer.prioritize_payloads(
            self.payloadsSQL, self.scan_mode
        )
        payloads = self.payload_optimizer.smart_payload_selection(
            payloads, self.results.get('technologies')
        )
        print(f"{Fore.BLUE}[*] Probando {len(payloads)} payloads SQL optimizados...")
        for form in self.forms:
            baseline = self.get_baseline_response(form)
            if not baseline:
                continue
            vulnerabilities_found += self._test_form_with_payloads(
                form, payloads, 'sql', 'sql_injection'
            )
            if vulnerabilities_found > 0 and self.scan_mode == 'fast':
                break
        return vulnerabilities_found

    def test_xss_optimized(self):
        if not self.forms:
            return 0
        vulnerabilities_found = 0
        payloads = self.payload_optimizer.prioritize_payloads(
            self.payloadsXSS, self.scan_mode
        )
        print(f"{Fore.BLUE}[*] Probando {len(payloads)} payloads XSS optimizados...")
        for form in self.forms:
            baseline = self.get_baseline_response(form)
            if not baseline:
                continue
            vulnerabilities_found += self._test_form_with_payloads(
                form, payloads, 'xss', 'xss'
            )
            if vulnerabilities_found > 0 and self.scan_mode == 'fast':
                break
        return vulnerabilities_found

    def test_nosql_injection_optimized(self):
        if not self.forms:
            return 0
        vulnerabilities_found = 0
        payloads = self.payload_optimizer.prioritize_payloads(
            self.payloadsNoSQL, self.scan_mode
        )
        print(f"{Fore.BLUE}[*] Probando {len(payloads)} payloads NoSQL optimizados...")
        for form in self.forms:
            baseline = self.get_baseline_response(form)
            if not baseline:
                continue
            vulnerabilities_found += self._test_form_with_payloads(
                form, payloads, 'nosql', 'nosql_injection'
            )
            if vulnerabilities_found > 0 and self.scan_mode == 'fast':
                break
        return vulnerabilities_found

    def _test_form_with_payloads(self, form, payloads, vuln_type, result_key):
        baseline = self.get_baseline_response(form)
        vulnerabilities_found = 0
        def test_payload(payload):
            data = {input_name: payload for input_name in form['inputs']}
            response = self.make_request(form['action'], form['method'], data)
            if response and self.is_vulnerability_response(response, baseline, vuln_type):
                return {
                    'url': form['action'],
                    'method': form['method'],
                    'payload': payload,
                    'parameter': 'multiple'
                }
            return None
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_payload = {
                executor.submit(test_payload, payload): payload 
                for payload in payloads
            }
            for idx, future in enumerate(as_completed(future_to_payload), 1):
                result = future.result()
                payload = future_to_payload[future]
                percent = int((idx / len(payloads)) * 100)
                bar = '█' * (percent // 5)
                if result:
                    vulnerabilities_found += 1
                    severity, desc = self.get_severity_and_desc(vuln_type)
                    self.results[result_key].append({
                        'url': form['action'],
                        'method': form['method'],
                        'payload': payload,
                        'parameter': 'multiple',
                        'severity': severity,
                        'descripcion': desc
                    })
                    status = f"{Fore.RED}VULNERABLE"
                    print(f"{Fore.BLUE}[{percent:3d}%] {bar:<20} {status} - {payload[:50]}{'...' if len(payload) > 50 else ''}")
                    print(f"{Fore.RED}[!] Vulnerabilidad {vuln_type.upper()} en {form['action']}")
                    if self.scan_mode == 'fast':
                        break
                else:
                    status = f"{Fore.GREEN}SEGURO"
                    if self.verbose:
                        print(f"{Fore.BLUE}[{percent:3d}%] {bar:<20} {status}")
        return vulnerabilities_found

    def test_open_redirect(self):
        """Prueba de vulnerabilidades de redirección abierta"""
        found = 0
        try:
            redirect_payloads = redirect
            redirect_params = ['url', 'redirect', 'redirect_to', 'redirecturl', 'return', 'returnurl', 
                              'return_url', 'returnto', 'goto', 'next', 'target', 'link', 'redir']
            for param in self.results['parameters_found']:
                if param.lower() in redirect_params:
                    for payload in redirect_payloads:
                        try:
                            encoded_payload = urllib.parse.quote_plus(payload)
                            params = {param: encoded_payload}
                            response = self.session.get(self.base_url, params=params, verify=False, 
                                                      timeout=self.timeout, allow_redirects=False)
                            if response.status_code in [301, 302, 303, 307, 308]:
                                location = response.headers.get('Location', '')
                                if payload in location or encoded_payload in location:
                                    self.results['open_redirect'].append({
                                        'url': self.base_url,
                                        'parameter': param,
                                        'payload': payload,
                                        'redirected_to': location
                                    })
                                    print(f"{Fore.RED}[!] Posible redirección abierta encontrada en parámetro: {param}")
                                    print(f"    URL: {self.base_url}, Payload: {payload}")
                                    print(f"    Redirección a: {location}")
                                    found += 1
                                    break
                        except Exception as e:
                            if self.verbose:
                                print(f"{Fore.YELLOW}[!] Error al probar redirección abierta: {e}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error en test_open_redirect: {e}")
        return found

    def detect_tech_from_js(self, url):
        """Detecta tecnologías basadas en archivos JavaScript referenciados"""
        try:
            response = self.session.get(url, verify=False, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Analizar archivos JavaScript
            script_tags = soup.find_all('script', src=True)
            for script in script_tags:
                src = script.get('src', '')
                if src:
                    # Normalizar URL relativa
                    if not src.startswith(('http://', 'https://')):
                        if src.startswith('//'):
                            src = 'https:' + src
                        elif src.startswith('/'):
                            base = '/'.join(self.base_url.split('/')[:3])
                            src = base + src
                        else:
                            src = self.base_url.rstrip('/') + '/' + src
                    
                    # Extraer nombre del archivo JS para análisis
                    filename = src.split('/')[-1].lower()
                    
                    # Detectar tecnologías conocidas por nombre de archivo
                    self.detect_tech_from_filename(filename)
        
        except Exception as e:
            if self.verbose:
                print(f"{Fore.YELLOW}[!] Error al analizar archivos JavaScript: {e}")
    
    def detect_tech_from_filename(self, filename):
        """Detecta tecnologías basadas en nombres de archivo"""
        if not 'technologies' in self.results:
            self.results['technologies'] = {}
        
        # Frameworks JavaScript comunes
        js_frameworks = JSframeworks
        
        for tech_key, tech_name in js_frameworks.items():
            if tech_key in filename:
                if not 'js_frameworks' in self.results['technologies']:
                    self.results['technologies']['js_frameworks'] = []
                
                if tech_name not in self.results['technologies']['js_frameworks']:
                    self.results['technologies']['js_frameworks'].append(tech_name)
                    if self.verbose:
                        print(f"{Fore.GREEN}[+] Detectado framework JavaScript: {tech_name}")

    def fingerprint_cms(self, html_content):
        """Identifica huellas digitales de CMS comunes"""
        cms_fingerprints = CMS_fingerprints
        
        detected_cms = []
        
        for cms, patterns in cms_fingerprints.items():
            for pattern in patterns:
                if pattern.lower() in html_content.lower():
                    if cms not in detected_cms:
                        detected_cms.append(cms)
                    break
        
        if detected_cms and not 'cms' in self.results['technologies']:
            self.results['technologies']['cms'] = []
            
        for cms in detected_cms:
            if cms not in self.results['technologies']['cms']:
                self.results['technologies']['cms'].append(cms)
                if self.verbose:
                    print(f"{Fore.GREEN}[+] Detectado CMS: {cms}")

    def identify_analytics_tools(self, html_content):
        """Identifica herramientas de análisis y marketing digital"""
        analytics_patterns = ANALYTICS_PATTERNS
        
        detected_analytics = []
        
        for tool, patterns in analytics_patterns.items():
            for pattern in patterns:
                if pattern.lower() in html_content.lower():
                    if tool not in detected_analytics:
                        detected_analytics.append(tool)
                    break
        
        if detected_analytics and not 'analytics' in self.results['technologies']:
            self.results['technologies']['analytics'] = []
            
        for tool in detected_analytics:
            if tool not in self.results['technologies']['analytics']:
                self.results['technologies']['analytics'].append(tool)
                if self.verbose:
                    print(f"{Fore.GREEN}[+] Detectada herramienta de análisis: {tool}")

    def export_results_json(self, filename='scan_results.json'):
        """Exporta los resultados del escaneo a un archivo JSON"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            print(f"{Fore.GREEN}[+] Resultados exportados a {filename}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error al exportar resultados: {e}")

    def generar_tabla_vulns(self, vulns, campos):
        if not vulns:
            return '<span class="safe">No se encontraron vulnerabilidades.</span>'
        html_table = '<table><tr>' + ''.join(f"<th>{campo.capitalize()}</th>" for campo in campos) + "<th>Gravedad</th><th>Descripción</th></tr>"
        for vuln in vulns:
            html_table += "<tr>" + "".join(
                f"<td>{html.escape(str(vuln.get(campo, '')))}</td>" for campo in campos
            ) + f"<td>{html.escape(str(vuln.get('severity', 'Desconocida')))}</td><td>{html.escape(str(vuln.get('descripcion', '')))}</td></tr>"
        html_table += "</table>"
        return html_table

    def show_results(self):
        """Muestra un resumen de los resultados del escaneo"""
        print(f"\n{Fore.CYAN}╔═══════════════════════════════════════════════════════════╗")
        print(f"{Fore.CYAN}║                    {Fore.GREEN}RESULTADOS DEL ESCANEO{Fore.CYAN}                 ║")
        print(f"{Fore.CYAN}╚═══════════════════════════════════════════════════════════╝")
        
        print(f"\n{Fore.WHITE}Objetivo: {Fore.YELLOW}{self.base_url}")
        print(f"{Fore.WHITE}Información del servidor: {Fore.YELLOW}{self.results['server_info'].get('server', 'No detectado')}")
        print(f"{Fore.WHITE}Tecnología: {Fore.YELLOW}{self.results['server_info'].get('x_powered_by', 'No detectado')}")
        print(f"{Fore.WHITE}Formularios encontrados: {Fore.YELLOW}{self.results['forms_found']}")
        print(f"{Fore.WHITE}Parámetros encontrados: {Fore.YELLOW}{len(self.results['parameters_found'])}")
        
        # Mostrar tecnologías detectadas
        print(f"\n{Fore.WHITE}Tecnologías detectadas:")
        if self.results['technologies']:
            for category, techs in self.results['technologies'].items():
                if techs:
                    print(f"{Fore.BLUE}[*] {category.capitalize()}: {Fore.YELLOW}{', '.join(techs)}")
        else:
            print(f"{Fore.YELLOW}[!] No se detectaron tecnologías")
        
        # Mostrar vulnerabilidades encontradas
        print(f"\n{Fore.WHITE}Vulnerabilidades encontradas:")
        
        if self.results['sql_injection']:
            print(f"{Fore.RED}[!] Inyección SQL: {len(self.results['sql_injection'])}")
            for vuln in self.results['sql_injection'][:3]:  # Mostrar solo las primeras 3
                print(f"  - URL: {vuln['url']}")
                print(f"    Método: {vuln['method']}, Parámetro: {vuln['parameter']}")
            if len(self.results['sql_injection']) > 3:
                print(f"    ...y {len(self.results['sql_injection']) - 3} más")
        else:
            print(f"{Fore.GREEN}[+] Inyección SQL: No se encontraron vulnerabilidades")
        
        if self.results['xss']:
            print(f"{Fore.RED}[!] Cross-Site Scripting (XSS): {len(self.results['xss'])}")
            for vuln in self.results['xss'][:3]:  # Mostrar solo las primeras 3
                print(f"  - URL: {vuln['url']}")
                print(f"    Método: {vuln['method']}, Parámetro: {vuln['parameter']}")
            if len(self.results['xss']) > 3:
                print(f"    ...y {len(self.results['xss']) - 3} más")
        else:
            print(f"{Fore.GREEN}[+] Cross-Site Scripting (XSS): No se encontraron vulnerabilidades")
        
        if self.results['nosql_injection']:
            print(f"{Fore.RED}[!] Inyección NoSQL: {len(self.results['nosql_injection'])}")
            for vuln in self.results['nosql_injection'][:3]:  # Mostrar solo las primeras 3
                print(f"  - URL: {vuln['url']}")
                print(f"    Método: {vuln['method']}, Parámetro: {vuln['parameter']}")
            if len(self.results['nosql_injection']) > 3:
                print(f"    ...y {len(self.results['nosql_injection']) - 3} más")
        else:
            print(f"{Fore.GREEN}[+] Inyección NoSQL: No se encontraron vulnerabilidades")
        
        if self.results['open_redirect']:
            print(f"{Fore.RED}[!] Redirección Abierta: {len(self.results['open_redirect'])}")
            for vuln in self.results['open_redirect'][:3]:  # Mostrar solo las primeras 3
                print(f"  - URL: {vuln['url']}")
                print(f"    Parámetro: {vuln['parameter']}")
                print(f"    Redirección a: {vuln['redirected_to']}")
            if len(self.results['open_redirect']) > 3:
                print(f"    ...y {len(self.results['open_redirect']) - 3} más")
        else:
            print(f"{Fore.GREEN}[+] Redirección Abierta: No se encontraron vulnerabilidades")
        
        print(f"\n{Fore.YELLOW}[!] Nota: Este escaneo es básico y puede generar falsos positivos.")
        print(f"{Fore.YELLOW}    Se recomienda verificar manualmente cada vulnerabilidad reportada.")
        print(f"{Fore.YELLOW}    Este script es solo para fines educativos y pruebas autorizadas.\n")
        


def main():
    """Función principal del programa"""
    parser = argparse.ArgumentParser(description='Web Security Scanner - Una herramienta para pruebas básicas de seguridad web')
    parser.add_argument('-u', '--url', required=True, help='URL del sitio web a escanear (ej. https://example.com)')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Número de hilos para el escaneo (default: 10)')
    parser.add_argument('--timeout', type=int, default=10, help='Tiempo de espera para las solicitudes en segundos (default: 30)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Mostrar información detallada durante el escaneo')
    parser.add_argument('--tech-only', action='store_true', help='Realizar solo la detección de tecnologías')
    parser.add_argument('-o', '--output', help='Nombre del archivo para exportar resultados en formato JSON')
    parser.add_argument('-j', '--json', action='store_true', help='Exportar resultados en formato JSON')
    parser.add_argument('-H', '--html', action='store_true', help='Exportar resultados en formato HTML')
    parser.add_argument('-Sb', '--slow', action='store_true', help='Escaneo bajo (más lento)')
    parser.add_argument('-Sm', '--medium', action='store_true', help='Escaneo medio')
    parser.add_argument('-Sa', '--fast', action='store_true', help='Escaneo alto (más rápido)')
    parser.add_argument('--quick', action='store_true', help='Escaneo rápido (menos payloads)')

    args = parser.parse_args()

    if args.slow:
        threads = 5
        timeout = 2
        scan_mode = 'slow'
    elif args.medium:
        threads = 15
        timeout = 10
        scan_mode = 'medium'
    elif args.fast:
        threads = 30   
        timeout = 10    
        scan_mode = 'fast'
    else:
        threads = args.threads
        timeout = args.timeout
        scan_mode = 'custom'

    quick_scan = args.quick

    scanner = WebSecurityScanner(args.url, threads, timeout, args.verbose)
    scanner.scan_mode = scan_mode
    scanner.quick_scan = quick_scan
    
    try:
        if args.tech_only:
            # Realizar solo detección de tecnologías
            scanner.print_banner()
            print(f"{Fore.BLUE}[*] Ejecutando solo detección de tecnologías...")
            
            try:
                response = scanner.session.get(args.url, verify=False, timeout=scanner.timeout)
                print(f"{Fore.GREEN}[+] Conexión establecida: {response.status_code}")
                
                # Detectar tecnologías
                scanner.detect_technologies(response)
                scanner.fingerprint_cms(response.text)
                scanner.identify_analytics_tools(response.text)
                scanner.detect_tech_from_js(args.url)
                
                # Mostrar resultados de tecnologías
                print(f"\n{Fore.CYAN}╔════════════════════════════════════════════════════════╗")
                print(f"{Fore.CYAN}║           {Fore.GREEN}TECNOLOGÍAS DETECTADAS{Fore.CYAN}                   ║")
                print(f"{Fore.CYAN}╚════════════════════════════════════════════════════════╝")
                
                print(f"\n{Fore.WHITE}Objetivo: {Fore.YELLOW}{scanner.base_url}")
                
                if scanner.results['technologies']:
                    for category, techs in scanner.results['technologies'].items():
                        if techs:
                            print(f"{Fore.BLUE}[*] {category.capitalize()}: {Fore.YELLOW}{', '.join(techs)}")
                else:
                    print(f"{Fore.YELLOW}[!] No se detectaron tecnologías")
                
                # Exportar resultados si se solicitó
                if args.output:
                    scanner.export_results_json(args.output)
                
            except requests.exceptions.RequestException as e:
                print(f"{Fore.RED}[!] Error de conexión: {e}")
                sys.exit(1)
        else:
            # Ejecutar escaneo completo
            scanner.run_scan()
            
            # Exportar resultados según los flags
            if args.json:
                scanner.export_results_json(args.output if args.output else "scan_results.json")
            if args.html:
                generar_reporte_html(scanner.results)
                generar_reporte_excel(scanner.results)
                generar_reporte_word(scanner.results)
                generar_reporte_pdf("scan_results.html")
    
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Escaneo interrumpido por el usuario")
        sys.exit(0)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Escaneo interrumpido por el usuario")
        sys.exit(0)