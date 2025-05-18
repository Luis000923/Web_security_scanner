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
from concurrent.futures import ThreadPoolExecutor
from urllib3.exceptions import InsecureRequestWarning
from colorama import Fore, Style, init
from PAYLOAD import *
from redirect_payloads import *
from Tecnologias import TECNOLOGIAS
from js_frameworks import JSframeworks
from cms_fingerprints import CMS_fingerprints
from analytics_patterns import ANALYTICS_PATTERNS


# Inicializar colorama para la salida de colores en terminal
init(autoreset=True)

# Suprimir advertencias de SSL
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class WebSecurityScanner:
    def __init__(self, url, threads=10, timeout=35, verbose=False):
        self.base_url = url
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers = {
            'User-Agent': 'WebSecurityScanner/1.0 (Educational Purpose Only)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3',
            'Connection': 'close'
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
            'technologies': {}  # Nuevo diccionario para almacenar tecnologías detectadas
        }
        # Cargar firmas de tecnologías
        self.load_technology_signatures()

    def load_technology_signatures(self):
        """Carga las firmas para la detección de tecnologías"""
        # Patrones básicos de tecnologías web comunes
        self.tech_signatures = TECNOLOGIAS

    def print_banner(self):
        """Muestra un banner de inicio del scanner"""
        banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════╗
{Fore.CYAN}║     {Fore.GREEN}WEB SECURITY SCANNER {Fore.YELLOW}v2.1{Fore.CYAN}                             ║
{Fore.CYAN}║                                                           ║
{Fore.CYAN}║      {Fore.RED}creado VIDES_2GA_2025{Fore.CYAN}                                ║
{Fore.CYAN}╚═══════════════════════════════════════════════════════════╝
{Fore.WHITE}URL objetivo: {Fore.YELLOW}{self.base_url}
{Style.RESET_ALL}
"""
        print(banner)

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
        
        # 1. Detección basada en cabeceras HTTP
        for header_name, header_value in headers.items():
            # Detectar servidores
            for server, patterns in self.tech_signatures['servers'].items():
                for pattern in patterns:
                    if pattern.lower() in header_value.lower():
                        if server not in detected_tech['servers']:
                            detected_tech['servers'].append(server)
            
            # Detectar lenguajes
            for lang, patterns in self.tech_signatures['languages'].items():
                for pattern in patterns:
                    if pattern.lower() in header_value.lower():
                        if lang not in detected_tech['languages']:
                            detected_tech['languages'].append(lang)
        
        # 2. Detección basada en contenido HTML
        try:
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
                for framework, patterns in self.tech_signatures['js_frameworks'].items():
                    for pattern in patterns:
                        if (pattern.lower() in script_src.lower() or 
                            (script_content and pattern.lower() in script_content.lower())):
                            if framework not in detected_tech['js_frameworks']:
                                detected_tech['js_frameworks'].append(framework)
                
                # Revisar frontend frameworks
                for framework, patterns in self.tech_signatures['frontend'].items():
                    for pattern in patterns:
                        if (pattern.lower() in script_src.lower() or 
                            (script_content and pattern.lower() in script_content.lower())):
                            if framework not in detected_tech['frontend']:
                                detected_tech['frontend'].append(framework)
                
                # Revisar analíticas
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
                for cms, patterns in self.tech_signatures['cms'].items():
                    for pattern in patterns:
                        if pattern.lower() in href.lower():
                            if cms not in detected_tech['cms']:
                                detected_tech['cms'].append(cms)
                
                # Revisar frontend
                for framework, patterns in self.tech_signatures['frontend'].items():
                    for pattern in patterns:
                        if pattern.lower() in href.lower():
                            if framework not in detected_tech['frontend']:
                                detected_tech['frontend'].append(framework)
            
            # 2.4 Detección en todo el HTML
            for category, tech_dict in self.tech_signatures.items():
                for tech, patterns in tech_dict.items():
                    for pattern in patterns:
                        if pattern.lower() in html_content.lower():
                            if tech not in detected_tech[category] and category in detected_tech:
                                detected_tech[category].append(tech)
        
        except Exception as e:
            if self.verbose:
                print(f"{Fore.YELLOW}[!] Error en la detección de tecnologías: {e}")
        
        # Guardar tecnologías detectadas en los resultados
        for category, techs in detected_tech.items():
            if techs:  # Solo guardar categorías con tecnologías detectadas
                self.results['technologies'][category] = techs
        
        # Mostrar tecnologías detectadas
        if self.results['technologies']:
            print(f"{Fore.GREEN}[+] Tecnologías detectadas:")
            for category, techs in self.results['technologies'].items():
                if techs:
                    print(f"  - {category.capitalize()}: {', '.join(techs)}")
        else:
            print(f"{Fore.YELLOW}[!] No se detectaron tecnologías")

    def crawl_site(self):
        """Explora el sitio para encontrar formularios y parámetros"""
        try:
            response = self.session.get(self.base_url, verify=False, timeout=self.timeout)
            self.extract_forms(response.text, self.base_url)
            self.extract_links(response.text, self.base_url)
            self.extract_parameters(self.base_url)
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}[!] Error durante la exploración: {e}")

    def extract_forms(self, html_content, url):
        """Extrae formularios del HTML"""
        form_regex = re.compile(r'<form.*?action=["\']?([^"\'>]*)["\']?.*?method=["\']?([^"\'>]*)["\']?.*?>(.*?)</form>', re.DOTALL | re.IGNORECASE)
        input_regex = re.compile(r'<input.*?name=["\']?([^"\'>]*)["\']?.*?>', re.DOTALL | re.IGNORECASE)
        
        forms = form_regex.findall(html_content)
        for form in forms:
            action = form[0]
            method = form[1].upper() if form[1] else 'GET'
            
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
            inputs = input_regex.findall(form[2])
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

    def extract_links(self, html_content, base_url):
        """Extrae enlaces del contenido HTML"""
        link_regex = re.compile(r'href=["\']?([^"\'>]*)["\']?', re.IGNORECASE)
        links = link_regex.findall(html_content)
        
        # Filtrar y normalizar enlaces
        for link in links:
            if not link or link.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                continue
                
            # Normalizar enlaces relativos
            if not link.startswith(('http://', 'https://')):
                if link.startswith('/'):
                    base = '/'.join(self.base_url.split('/')[:3])
                    link = base + link
                else:
                    link = base_url.rstrip('/') + '/' + link
            
            # Solo procesar enlaces del mismo dominio
            if self.base_url.split('/')[2] in link:
                self.extract_parameters(link)

    def extract_parameters(self, url):
        """Extrae parámetros de una URL"""
        if '?' in url:
            params = url.split('?')[1].split('&')
            for param in params:
                if '=' in param:
                    param_name = param.split('=')[0]
                    if param_name not in self.results['parameters_found']:
                        self.results['parameters_found'].append(param_name)
                        if self.verbose:
                            print(f"{Fore.GREEN}[+] Parámetro GET encontrado: {param_name} en {url}")

    def test_vulnerabilities(self):
        """Ejecuta todas las pruebas de vulnerabilidades"""
        if not self.forms and not self.results['parameters_found']:
            print(f"{Fore.YELLOW}[!] No se encontraron formularios o parámetros para probar")
            return
        
        print(f"{Fore.BLUE}[*] Probando vulnerabilidades de inyección SQL...")
        self.test_sql_injection()
        
        print(f"{Fore.BLUE}[*] Probando vulnerabilidades XSS...")
        self.test_xss()
        
        print(f"{Fore.BLUE}[*] Probando vulnerabilidades de inyección NoSQL...")
        self.test_nosql_injection()
        
        print(f"{Fore.BLUE}[*] Probando vulnerabilidades de redirección abierta...")
        self.test_open_redirect()

    def test_sql_injection(self):
        """Prueba de vulnerabilidades de inyección SQL"""
        # Payloads de prueba para inyección SQL
        payloads = payloadsSQL
    
        # Probar en formularios
        for form in self.forms:
            for payload in payloads:
                data = {}
                for input_name in form['inputs']:
                    data[input_name] = payload
                
                try:
                    if form['method'] == 'POST':
                        response = self.session.post(form['action'], data=data, verify=False, timeout=self.timeout)
                    else:
                        response = self.session.get(form['action'], params=data, verify=False, timeout=self.timeout)
                    
                    # Verificar respuesta para posibles indicadores de éxito en la inyección
                    if self.check_sql_injection_success(response.text):
                        self.results['sql_injection'].append({
                            'url': form['action'],
                            'method': form['method'],
                            'payload': payload,
                            'parameter': 'multiple'
                        })
                        print(f"{Fore.RED}[!] Posible inyección SQL encontrada en {form['action']}")
                        print(f"    Método: {form['method']}, Payload: {payload}")
                        break
                        
                except Exception as e:
                    if self.verbose:
                        print(f"{Fore.YELLOW}[!] Error al probar inyección SQL: {e}")
        
        # Probar en parámetros GET
        for param in self.results['parameters_found']:
            for payload in payloadsSQL:
                try:
                    params = {param: payload}
                    response = self.session.get(self.base_url, params=params, verify=False, timeout=self.timeout)
                    
                    if self.check_sql_injection_success(response.text):
                        self.results['sql_injection'].append({
                            'url': self.base_url,
                            'method': 'GET',
                            'payload': payload,
                            'parameter': param
                        })
                        print(f"{Fore.RED}[!] Posible inyección SQL encontrada en parámetro GET: {param}")
                        print(f"    URL: {self.base_url}, Payload: {payload}")
                        break
                        
                except Exception as e:
                    if self.verbose:
                        print(f"{Fore.YELLOW}[!] Error al probar inyección SQL en parámetro GET: {e}")

    def check_sql_injection_success(self, response_text):
        """Verifica si la respuesta indica una inyección SQL exitosa"""
        error_patterns = [
            "SQL syntax",
            "mysql_fetch_array",
            "mysql_fetch",
            "mysql_num_rows",
            "mysqli_fetch_array",
            "mysqli_result",
            "Warning: mysql",
            "ORA-",
            "Oracle error",
            "Microsoft SQL Server",
            "PostgreSQL",
            "SQLite3::",
            "DB2 SQL error",
            "Sybase message",
            "Unclosed quotation mark"
        ]
        
        for pattern in error_patterns:
            if pattern.lower() in response_text.lower():
                return True
        return False

    def test_xss(self):
        """Prueba de vulnerabilidades XSS"""
        payloads = payloadsXSS
        
        # Probar en formularios
        for form in self.forms:
            for payload in payloads:
                data = {}
                for input_name in form['inputs']:
                    data[input_name] = payload
                
                try:
                    if form['method'] == 'POST':
                        response = self.session.post(form['action'], data=data, verify=False, timeout=self.timeout)
                    else:
                        response = self.session.get(form['action'], params=data, verify=False, timeout=self.timeout)
                    
                    # Verificar si el payload se refleja en la respuesta
                    if payload in response.text:
                        self.results['xss'].append({
                            'url': form['action'],
                            'method': form['method'],
                            'payload': payload,
                            'parameter': 'multiple'
                        })
                        print(f"{Fore.RED}[!] Posible vulnerabilidad XSS encontrada en {form['action']}")
                        print(f"    Método: {form['method']}, Payload: {payload}")
                        break
                        
                except Exception as e:
                    if self.verbose:
                        print(f"{Fore.YELLOW}[!] Error al probar XSS: {e}")
        
        # Probar en parámetros GET
        for param in self.results['parameters_found']:
            for payload in payloads:
                try:
                    params = {param: payload}
                    response = self.session.get(self.base_url, params=params, verify=False, timeout=self.timeout)
                    
                    if payload in response.text:
                        self.results['xss'].append({
                            'url': self.base_url,
                            'method': 'GET',
                            'payload': payload,
                            'parameter': param
                        })
                        print(f"{Fore.RED}[!] Posible vulnerabilidad XSS encontrada en parámetro GET: {param}")
                        print(f"    URL: {self.base_url}, Payload: {payload}")
                        break
                        
                except Exception as e:
                    if self.verbose:
                        print(f"{Fore.YELLOW}[!] Error al probar XSS en parámetro GET: {e}")

    def test_nosql_injection(self):
        """Prueba de vulnerabilidades de inyección NoSQL"""
        payloads = payloadsNoSQL
        # Probar en formularios
        for form in self.forms:
            for payload in payloads:
                data = {}
                for input_name in form['inputs']:
                    data[input_name] = payload
                
                try:
                    if form['method'] == 'POST':
                        response = self.session.post(form['action'], data=data, verify=False, timeout=self.timeout)
                    else:
                        response = self.session.get(form['action'], params=data, verify=False, timeout=self.timeout)
                    
                    # Verificar respuesta para posibles indicadores de éxito
                    if "mongo" in response.text.lower() or "mongoose" in response.text.lower():
                        self.results['nosql_injection'].append({
                            'url': form['action'],
                            'method': form['method'],
                            'payload': payload,
                            'parameter': 'multiple'
                        })
                        print(f"{Fore.RED}[!] Posible inyección NoSQL encontrada en {form['action']}")
                        print(f"    Método: {form['method']}, Payload: {payload}")
                        break
                        
                except Exception as e:
                    if self.verbose:
                        print(f"{Fore.YELLOW}[!] Error al probar inyección NoSQL: {e}")
        
        # Probar en parámetros GET
        for param in self.results['parameters_found']:
            for payload in payloads:
                try:
                    # Los payloads NoSQL pueden requerir un formato especial
                    if payload.startswith('{') and payload.endswith('}'):
                        # Intentar con parámetros de estilo MongoDB
                        params = {param: payload}
                    else:
                        # Intentar con sintaxis de operador directo
                        params = {param + payload.split('=')[0]: payload.split('=')[1]}
                    
                    response = self.session.get(self.base_url, params=params, verify=False, timeout=self.timeout)
                    
                    if "mongo" in response.text.lower() or "mongoose" in response.text.lower():
                        self.results['nosql_injection'].append({
                            'url': self.base_url,
                            'method': 'GET',
                            'payload': payload,
                            'parameter': param
                        })
                        print(f"{Fore.RED}[!] Posible inyección NoSQL encontrada en parámetro GET: {param}")
                        print(f"    URL: {self.base_url}, Payload: {payload}")
                        break
                        
                except Exception as e:
                    if self.verbose:
                        print(f"{Fore.YELLOW}[!] Error al probar inyección NoSQL en parámetro GET: {e}")

    def test_open_redirect(self):
        """Prueba de vulnerabilidades de redirección abierta"""
        redirect_payloads = redirect
        
        # Buscar parámetros que puedan controlar redirecciones
        redirect_params = ['url', 'redirect', 'redirect_to', 'redirecturl', 'return', 'returnurl', 
                          'return_url', 'returnto', 'goto', 'next', 'target', 'link', 'redir']
        
        # Probar redirecciones en parámetros conocidos
        for param in self.results['parameters_found']:
            if param.lower() in redirect_params:
                for payload in redirect_payloads:
                    try:
                        encoded_payload = urllib.parse.quote_plus(payload)
                        params = {param: encoded_payload}
                        response = self.session.get(self.base_url, params=params, verify=False, timeout=self.timeout, 
                                                  allow_redirects=False)
                        
                        # Verificar si hay redirección a nuestro payload
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
                                break
                                
                    except Exception as e:
                        if self.verbose:
                            print(f"{Fore.YELLOW}[!] Error al probar redirección abierta: {e}")

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
        
        # Opción para exportar resultados
        print(f"{Fore.CYAN}[*] ¿Desea exportar los resultados a un archivo JSON? (s/n): ", end="")
        try:
            choice = input().strip().lower()
            if choice == 's':
                self.export_results_json()
        except:
            pass


def main():
    """Función principal del programa"""
    parser = argparse.ArgumentParser(description='Web Security Scanner - Una herramienta para pruebas básicas de seguridad web')
    parser.add_argument('-u', '--url', required=True, help='URL del sitio web a escanear (ej. https://example.com)')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Número de hilos para el escaneo (default: 10)')
    parser.add_argument('--timeout', type=int, default=10, help='Tiempo de espera para las solicitudes en segundos (default: 30)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Mostrar información detallada durante el escaneo')
    parser.add_argument('--tech-only', action='store_true', help='Realizar solo la detección de tecnologías')
    parser.add_argument('-o', '--output', help='Nombre del archivo para exportar resultados en formato JSON')
    
    args = parser.parse_args()
    
    # Validar URL
    if not args.url.startswith(('http://', 'https://')):
        args.url = 'http://' + args.url
    
    # Iniciar el escaneo
    scanner = WebSecurityScanner(args.url, args.threads, args.timeout, args.verbose)
    
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
            
            # Exportar resultados si se solicitó
            if args.output:
                scanner.export_results_json(args.output)
    
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Escaneo interrumpido por el usuario")
        sys.exit(0)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Escaneo interrumpido por el usuario")
        sys.exit(0)