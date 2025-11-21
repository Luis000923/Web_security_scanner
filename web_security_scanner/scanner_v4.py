"""
Web Security Scanner v4.0 - Enhanced Architecture
Main scanner script with modular design and advanced features
"""

import argparse
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from core.config import Config
from core.logger import setup_logger, ScanLogger
from core.scanner_core import ScannerCore
from modules.technology_detector import TechnologyDetector
from modules.web_mapper import WebMapper
from utils.i18n import i18n
from modules.vulnerability_testers import (
    SQLInjectionTester,
    XSSTester,
    NoSQLInjectionTester,
    SSRFTester,
    CommandInjectionTester,
    PathTraversalTester,
    XXETester,
    CSRFTester,
    IDORTester,
    OpenRedirectTester
)

from banner import print_banner
from colorama import Fore, Style, init

init(autoreset=True)


class WebSecurityScannerV4:
    """Enhanced Web Security Scanner with modular architecture"""
    
    def __init__(self, url: str, config: Config, verbose: bool = False, generate_map: bool = True):
        self.url = url
        self.config = config
        self.verbose = verbose
        self.generate_map = generate_map
        
        # Setup logging
        log_config = config.config.get('logging', {})
        base_logger = setup_logger(
            level=log_config.get('level', 'INFO'),
            log_file=log_config.get('file'),
            max_size=log_config.get('max_size', 10485760),
            backup_count=log_config.get('backup_count', 5)
        )
        self.logger = ScanLogger(base_logger, verbose)
        
        # Initialize scanner core
        self.scanner = ScannerCore(config, self.logger)
        
        # Initialize technology detector
        self.tech_detector = TechnologyDetector(self.logger)
        
        # Initialize web mapper
        if self.generate_map:
            self.web_mapper = WebMapper(self.scanner, self.logger)
        
        # Initialize vulnerability testers
        self.testers = self._initialize_testers()
        
        # Results storage
        self.results = {
            'url': url,
            'technologies': {},
            'vulnerabilities': [],
            'forms': [],
            'parameters': [],
            'statistics': {},
            'web_map': None
        }
    
    def _initialize_testers(self) -> dict:
        """Initialize all vulnerability testers"""
        testers = {}
        
        vuln_config = self.config.config.get('vulnerabilities', {})
        
        # SQL Injection
        if vuln_config.get('sql_injection', {}).get('enabled', True):
            testers['sql_injection'] = SQLInjectionTester(self.scanner, self.config, self.logger)
        
        # XSS
        if vuln_config.get('xss', {}).get('enabled', True):
            testers['xss'] = XSSTester(self.scanner, self.config, self.logger)
        
        # NoSQL Injection
        if vuln_config.get('nosql_injection', {}).get('enabled', True):
            testers['nosql_injection'] = NoSQLInjectionTester(self.scanner, self.config, self.logger)
        
        # SSRF
        if vuln_config.get('ssrf', {}).get('enabled', True):
            testers['ssrf'] = SSRFTester(self.scanner, self.config, self.logger)
        
        # Command Injection
        if vuln_config.get('command_injection', {}).get('enabled', True):
            testers['command_injection'] = CommandInjectionTester(self.scanner, self.config, self.logger)
        
        # Path Traversal
        if vuln_config.get('path_traversal', {}).get('enabled', True):
            testers['path_traversal'] = PathTraversalTester(self.scanner, self.config, self.logger)
        
        # XXE
        if vuln_config.get('xxe', {}).get('enabled', True):
            testers['xxe'] = XXETester(self.scanner, self.config, self.logger)
        
        # CSRF
        if vuln_config.get('csrf', {}).get('enabled', True):
            testers['csrf'] = CSRFTester(self.scanner, self.config, self.logger)
        
        # IDOR
        if vuln_config.get('idor', {}).get('enabled', True):
            testers['idor'] = IDORTester(self.scanner, self.config, self.logger)
        
        # Open Redirect
        if vuln_config.get('open_redirect', {}).get('enabled', True):
            testers['open_redirect'] = OpenRedirectTester(self.scanner, self.config, self.logger)
        
        return testers
    
    def run_scan(self):
        """Execute full security scan"""
        print_banner()
        
        self.logger.info(i18n.get('scanner.starting'))
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}{i18n.get('scanner.target_info', url=self.url)}")
        print(f"{Fore.CYAN}{i18n.get('scanner.testers_info', count=len(self.testers))}")
        print(f"{Fore.CYAN}{'='*60}\n")
        
        # Step 1: Initial connection test
        self._test_connection()
        
        # Step 2: Detect technologies
        if self.config.get('technology_detection.enabled', True):
            self._detect_technologies()
        
        # Step 3: Crawl and discover
        self._crawl_site()
        
        # Step 4: Test vulnerabilities
        self._test_vulnerabilities()
        
        # Step 5: Show results
        self._show_results()
        
        # Step 6: Generate reports
        self._generate_reports()
    
    def _test_connection(self):
        """Test initial connection to target"""
        self.logger.info(i18n.get('scanner.connection_test'))
        print(f"{Fore.BLUE}[*] {i18n.get('scanner.connection_target', url=self.url)}")
        
        response = self.scanner.make_request(self.url, 'GET')
        
        if not response:
            self.logger.error(i18n.get('scanner.connection_failed', url=self.url))
            print(f"{Fore.RED}[!] {i18n.get('scanner.connection_failed', url=self.url)}")
            sys.exit(1)
        
        self.logger.info(i18n.get('scanner.connection_success', status=response.status_code))
        print(f"{Fore.GREEN}[+] {i18n.get('scanner.connection_success', status=response.status_code)}")
    
    def _detect_technologies(self):
        """Detect technologies used by target"""
        self.logger.info(i18n.get('technologies.detecting'))
        print(f"\n{Fore.BLUE}[*] {i18n.get('technologies.detecting')}")
        
        response = self.scanner.make_request(self.url, 'GET')
        
        if response:
            self.results['technologies'] = self.tech_detector.detect_all(response)
            
            print(f"{Fore.GREEN}[+] {i18n.get('technologies.completed_short')}")
            
            # Show detected technologies
            for category, techs in self.results['technologies'].items():
                if techs:
                    print(f"{Fore.CYAN}  {category.replace('_', ' ').title()}: {Fore.YELLOW}{', '.join(str(t) if isinstance(t, str) else t.get('name', 'Unknown') for t in techs)}")
    
    def _crawl_site(self):
        """Crawl site to discover forms and parameters"""
        self.logger.info("Crawling site...")
        print(f"\n{Fore.BLUE}[*] Crawling site...")
        
        # This would be implemented with a proper crawler
        # For now, we'll just analyze the main page
        response = self.scanner.make_request(self.url, 'GET')
        
        if response:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract forms
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', self.url)
                method = form.get('method', 'GET').upper()
                
                # Normalize action URL
                if action and not action.startswith('http'):
                    if action.startswith('/'):
                        from urllib.parse import urlparse
                        parsed = urlparse(self.url)
                        action = f"{parsed.scheme}://{parsed.netloc}{action}"
                    else:
                        action = f"{self.url.rstrip('/')}/{action}"
                
                inputs = []
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    name = input_tag.get('name')
                    if name and input_tag.get('type') != 'submit':
                        inputs.append(name)
                
                if inputs:
                    self.results['forms'].append({
                        'action': action,
                        'method': method,
                        'inputs': inputs
                    })
            
            print(f"{Fore.GREEN}[+] Found {len(self.results['forms'])} forms")
    
    def _test_vulnerabilities(self):
        """Test for vulnerabilities"""
        if not self.results['forms']:
            print(f"{Fore.YELLOW}[!] No forms found, skipping vulnerability tests")
            return
        
        print(f"\n{Fore.BLUE}[*] Testing for vulnerabilities...")
        
        for tester_name, tester in self.testers.items():
            vuln_config = self.config.config['vulnerabilities'].get(tester_name, {})
            max_payloads = vuln_config.get('max_payloads')
            
            self.logger.info(f"Testing {tester_name}...")
            print(f"\n{Fore.BLUE}[*] Testing {tester_name.replace('_', ' ').title()}...")
            
            for form in self.results['forms']:
                vulnerabilities = tester.test_form(form, max_payloads)
                self.results['vulnerabilities'].extend(vulnerabilities)
                
                if vulnerabilities:
                    print(f"{Fore.RED}[!] Found {len(vulnerabilities)} {tester_name} vulnerabilities")
    
    def _show_results(self):
        """Display scan results"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}SCAN RESULTS")
        print(f"{Fore.CYAN}{'='*60}\n")
        
        # Statistics
        stats = self.scanner.get_stats()
        self.results['statistics'] = stats
        
        print(f"{Fore.WHITE}Statistics:")
        print(f"  Total Requests: {Fore.YELLOW}{stats['total_requests']}")
        print(f"  Cached Responses: {Fore.YELLOW}{stats['cached_responses']}")
        print(f"  Failed Requests: {Fore.YELLOW}{stats['failed_requests']}")
        print(f"  Cache Hit Rate: {Fore.YELLOW}{stats.get('cache_hit_rate', 0):.2%}")
        print(f"  Avg Response Time: {Fore.YELLOW}{stats.get('avg_response_time', 0):.2f}s")
        
        # Vulnerabilities summary
        print(f"\n{Fore.WHITE}Vulnerabilities Found: {Fore.RED if self.results['vulnerabilities'] else Fore.GREEN}{len(self.results['vulnerabilities'])}")
        
        if self.results['vulnerabilities']:
            vuln_by_type = {}
            for vuln in self.results['vulnerabilities']:
                vuln_type = vuln['type']
                if vuln_type not in vuln_by_type:
                    vuln_by_type[vuln_type] = []
                vuln_by_type[vuln_type].append(vuln)
            
            for vuln_type, vulns in vuln_by_type.items():
                severity = vulns[0]['severity']
                color = Fore.RED if severity == 'critical' else Fore.YELLOW if severity == 'high' else Fore.CYAN
                print(f"\n{color}[!] {vuln_type}: {len(vulns)} found (Severity: {severity})")
                
                for vuln in vulns[:3]:  # Show first 3
                    print(f"    - URL: {vuln['url']}")
                    print(f"      Method: {vuln['method']}, Payload: {vuln['payload'][:50]}...")
                
                if len(vulns) > 3:
                    print(f"    ... and {len(vulns) - 3} more")
        else:
            print(f"{Fore.GREEN}[+] No vulnerabilities found!")
    
    def _generate_reports(self):
        """Generate scan reports"""
        reporting_config = self.config.config.get('reporting', {})
        formats = reporting_config.get('formats', ['json'])
        
        if 'json' in formats:
            self._save_json_report()
        
        # Generate HTML Web Map
        if self.generate_map and hasattr(self, 'web_mapper'):
            self._generate_web_map()
    
    def _generate_web_map(self):
        """Generate interactive HTML web map"""
        try:
            self.logger.info("Generating web map...")
            print(f"\n{Fore.BLUE}[*] Generating interactive web map...")
            
            # Get max depth from config
            max_depth = self.config.get('scanner.max_depth', 3)
            
            # Map the website
            map_data = self.web_mapper.map_website(self.url, max_depth=max_depth)
            
            # Add technologies and vulnerabilities to map
            self.web_mapper.add_technologies(self.url, self.results['technologies'])
            self.web_mapper.add_vulnerabilities(self.results['vulnerabilities'])
            
            # Update map data with latest info
            map_data['technologies'] = self.web_mapper.technologies
            map_data['vulnerabilities'] = self.web_mapper.vulnerabilities
            
            # Generate HTML
            html_path = self.web_mapper.generate_map(map_data)
            
            print(f"{Fore.GREEN}[+] Web map generated: {html_path}")
            print(f"{Fore.CYAN}[*] Open in browser: file:///{Path(html_path).absolute()}")
            
            self.results['web_map'] = html_path
            
        except Exception as e:
            self.logger.error(f"Error generating web map: {e}")
            print(f"{Fore.RED}[!] Error generating web map: {e}")
    
    def _save_json_report(self):
        """Save results to JSON file"""
        import json
        from datetime import datetime
        
        output_dir = self.config.get('reporting.output_dir', 'reports')
        Path(output_dir).mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{output_dir}/scan_{timestamp}.json"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False, default=str)
            
            print(f"\n{Fore.GREEN}[+] JSON report saved to: {filename}")
            self.logger.info(f"Report saved to {filename}")
        except Exception as e:
            self.logger.error(f"Failed to save report: {e}")
            print(f"{Fore.RED}[!] Failed to save report: {e}")


def main():
    parser = argparse.ArgumentParser(
        description='Web Security Scanner v4.0 - Enhanced Enterprise Edition',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Required arguments
    parser.add_argument('-u', '--url', required=True, help='Target URL to scan')
    
    # Configuration
    parser.add_argument('--config', help='Path to configuration YAML file', default='config.yaml')
    parser.add_argument('--profile', choices=['quick', 'normal', 'deep', 'stealth'],
                       help='Scan profile to use')
    
    # Scan options
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--tech-only', action='store_true', help='Only detect technologies')
    parser.add_argument('--generate-map', action='store_true', default=True,
                       help='Generate interactive HTML web map (default: True)')
    parser.add_argument('--no-map', action='store_true',
                       help='Disable HTML map generation')
    
    # Authentication
    parser.add_argument('--auth-type', choices=['basic', 'bearer', 'session', 'oauth'],
                       help='Authentication type')
    parser.add_argument('--auth-user', help='Username for basic auth')
    parser.add_argument('--auth-pass', help='Password for basic auth')
    parser.add_argument('--auth-token', help='Token for bearer/oauth auth')
    
    # Language
    lang_group = parser.add_mutually_exclusive_group()
    lang_group.add_argument('-es', '--spanish', action='store_true', help='Set language to Spanish')
    lang_group.add_argument('-en', '--english', action='store_true', help='Set language to English')

    # Output
    parser.add_argument('-o', '--output', help='Output file path')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       help='Logging level')
    
    args = parser.parse_args()
    
    # Initialize i18n
    lang_file = Path(__file__).parent / 'languages.yaml'
    i18n.load_languages(str(lang_file))
    
    if args.spanish:
        i18n.set_language('es')
    elif args.english:
        i18n.set_language('en')

    # Load configuration
    config = Config(args.config if Path(args.config).exists() else None)
    
    # Apply profile if specified
    if args.profile:
        config.apply_profile(args.profile)
    
    # Apply log level if specified
    if args.log_level:
        config.set('logging.level', args.log_level)
    
    # Setup authentication
    if args.auth_type:
        config.set('authentication.enabled', True)
        config.set('authentication.type', args.auth_type)
        
        if args.auth_type == 'basic':
            config.set('authentication.credentials', {
                'username': args.auth_user,
                'password': args.auth_pass
            })
        elif args.auth_type in ['bearer', 'oauth']:
            config.set('authentication.credentials', {
                'token': args.auth_token
            })
    
    # Create and run scanner
    try:
        # Determine if map generation should be enabled
        generate_map = args.generate_map and not args.no_map
        
        scanner = WebSecurityScannerV4(args.url, config, args.verbose, generate_map=generate_map)
        
        # Setup authentication if configured
        if config.get('authentication.enabled'):
            auth_type = config.get('authentication.type')
            credentials = config.get('authentication.credentials', {})
            scanner.scanner.set_authentication(auth_type, credentials)
        
        if args.tech_only:
            print_banner()
            scanner._test_connection()
            scanner._detect_technologies()
        else:
            scanner.run_scan()
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
