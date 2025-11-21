"""
Technology Detection Module
Advanced fingerprinting of web technologies, CMS, frameworks, and tools
"""

import re
from typing import Dict, List, Set
from bs4 import BeautifulSoup
from collections import defaultdict

try:
    from ..Tecnologias import TECNOLOGIAS
    from ..cms_fingerprints import CMS_fingerprints
    from ..js_frameworks import JSframeworks
    from ..analytics_patterns import ANALYTICS_PATTERNS
except ImportError:
    from Tecnologias import TECNOLOGIAS
    from cms_fingerprints import CMS_fingerprints
    from js_frameworks import JSframeworks
    from analytics_patterns import ANALYTICS_PATTERNS


try:
    from ..utils.i18n import i18n
except ImportError:
    from utils.i18n import i18n

class TechnologyDetector:
    """Advanced technology detection and fingerprinting"""
    
    def __init__(self, logger):
        self.logger = logger
        self.tech_signatures = TECNOLOGIAS
        self.cms_signatures = CMS_fingerprints
        self.js_signatures = JSframeworks
        self.analytics_signatures = ANALYTICS_PATTERNS
        
        self.detected = defaultdict(set)
        self.confidence_scores = {}
    
    def detect_all(self, response, html_content: str = None) -> Dict[str, List[str]]:
        """
        Perform comprehensive technology detection
        
        Args:
            response: HTTP response object
            html_content: HTML content (optional, will extract from response if not provided)
            
        Returns:
            Dictionary with detected technologies by category
        """
        if html_content is None:
            html_content = response.text
        
        headers = response.headers
        
        # Run all detection methods
        self._detect_from_headers(headers)
        self._detect_from_html(html_content)
        self._detect_from_scripts(html_content)
        self._detect_from_meta_tags(html_content)
        self._detect_from_cookies(response.cookies)
        self._detect_cms(html_content, headers)
        self._detect_js_frameworks(html_content)
        self._detect_analytics(html_content)
        self._detect_security_headers(headers)
        self._detect_cdn(headers, html_content)
        
        # Convert sets to sorted lists
        result = {
            category: sorted(list(techs)) 
            for category, techs in self.detected.items() 
            if techs
        }
        
        self.logger.info(i18n.get('technologies.completed', count=sum(len(v) for v in result.values())))
        
        return result
    
    def _detect_from_headers(self, headers: dict):
        """Detect technologies from HTTP headers"""
        for header_name, header_value in headers.items():
            header_lower = header_value.lower()
            
            # Detect servers
            if header_name.lower() in ['server', 'x-powered-by']:
                for tech, patterns in self.tech_signatures.get('servers', {}).items():
                    for pattern in patterns:
                        if pattern.lower() in header_lower:
                            self.detected['servers'].add(tech)
                            self._update_confidence(tech, 'high')
            
            # Detect languages
            for lang, patterns in self.tech_signatures.get('languages', {}).items():
                for pattern in patterns:
                    if pattern.lower() in header_lower:
                        self.detected['languages'].add(lang)
                        self._update_confidence(lang, 'high')
    
    def _detect_from_html(self, html_content: str):
        """Detect technologies from HTML content patterns"""
        html_lower = html_content.lower()
        
        for category, tech_dict in self.tech_signatures.items():
            if category not in ['servers', 'languages']:  # Already handled by headers
                for tech, patterns in tech_dict.items():
                    for pattern in patterns:
                        if pattern.lower() in html_lower:
                            self.detected[category].add(tech)
                            self._update_confidence(tech, 'medium')
    
    def _detect_from_scripts(self, html_content: str):
        """Detect technologies from script tags"""
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            scripts = soup.find_all('script')
            
            for script in scripts:
                # Check src attribute
                src = script.get('src', '')
                if src:
                    self._analyze_script_url(src)
                
                # Check inline script content
                script_content = script.string if script.string else ''
                if script_content:
                    self._analyze_script_content(script_content)
                    
        except Exception as e:
            self.logger.warning(f"Error detecting technologies from scripts: {e}")
    
    def _analyze_script_url(self, src: str):
        """Analyze script URL for technology detection"""
        src_lower = src.lower()
        
        # Detect JS frameworks
        for framework, patterns in self.js_signatures.items():
            for pattern in patterns:
                if pattern.lower() in src_lower:
                    self.detected['js_frameworks'].add(framework)
                    self._update_confidence(framework, 'high')
        
        # Detect frontend frameworks
        for framework, patterns in self.tech_signatures.get('frontend', {}).items():
            for pattern in patterns:
                if pattern.lower() in src_lower:
                    self.detected['frontend'].add(framework)
                    self._update_confidence(framework, 'high')
    
    def _analyze_script_content(self, content: str):
        """Analyze inline script content"""
        content_lower = content.lower()
        
        # Look for common framework patterns
        patterns = {
            'React': ['react', 'reactdom', '__react'],
            'Vue.js': ['vue', 'createapp', 'vue.createapp'],
            'Angular': ['angular', 'ng-', '@angular'],
            'jQuery': ['jquery', '$.', 'jquery('],
            'Bootstrap': ['bootstrap'],
            'Backbone.js': ['backbone'],
            'Ember.js': ['ember']
        }
        
        for tech, tech_patterns in patterns.items():
            for pattern in tech_patterns:
                if pattern in content_lower:
                    self.detected['js_frameworks'].add(tech)
                    self._update_confidence(tech, 'medium')
    
    def _detect_from_meta_tags(self, html_content: str):
        """Detect technologies from meta tags"""
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            meta_tags = soup.find_all('meta')
            
            for meta in meta_tags:
                # Generator meta tag (CMS detection)
                if meta.get('name') == 'generator':
                    content = meta.get('content', '').lower()
                    for cms, patterns in self.cms_signatures.items():
                        for pattern in patterns:
                            if pattern.lower() in content:
                                self.detected['cms'].add(cms)
                                self._update_confidence(cms, 'high')
                
                # Other meta tags
                for attr in ['content', 'property', 'name']:
                    value = meta.get(attr, '').lower()
                    if 'wordpress' in value:
                        self.detected['cms'].add('WordPress')
                    elif 'drupal' in value:
                        self.detected['cms'].add('Drupal')
                    elif 'joomla' in value:
                        self.detected['cms'].add('Joomla')
                        
        except Exception as e:
            self.logger.warning(f"Error detecting from meta tags: {e}")
    
    def _detect_from_cookies(self, cookies):
        """Detect technologies from cookies"""
        for cookie in cookies:
            cookie_name = cookie.name.lower()
            
            if 'phpsessid' in cookie_name:
                self.detected['languages'].add('PHP')
            elif 'asp.net' in cookie_name or 'aspx' in cookie_name:
                self.detected['languages'].add('ASP.NET')
            elif 'jsessionid' in cookie_name:
                self.detected['languages'].add('Java')
            elif 'cfid' in cookie_name or 'cftoken' in cookie_name:
                self.detected['languages'].add('ColdFusion')
    
    def _detect_cms(self, html_content: str, headers: dict):
        """Enhanced CMS detection"""
        html_lower = html_content.lower()
        
        for cms, patterns in self.cms_signatures.items():
            match_count = 0
            for pattern in patterns:
                if pattern.lower() in html_lower:
                    match_count += 1
            
            if match_count > 0:
                self.detected['cms'].add(cms)
                confidence = 'high' if match_count >= 2 else 'medium'
                self._update_confidence(cms, confidence)
    
    def _detect_js_frameworks(self, html_content: str):
        """Detect JavaScript frameworks"""
        html_lower = html_content.lower()
        
        for framework, patterns in self.js_signatures.items():
            for pattern in patterns:
                if pattern.lower() in html_lower:
                    self.detected['js_frameworks'].add(framework)
                    self._update_confidence(framework, 'medium')
    
    def _detect_analytics(self, html_content: str):
        """Detect analytics and tracking tools"""
        html_lower = html_content.lower()
        
        for tool, patterns in self.analytics_signatures.items():
            for pattern in patterns:
                if pattern.lower() in html_lower:
                    self.detected['analytics'].add(tool)
                    self._update_confidence(tool, 'high')
    
    def _detect_security_headers(self, headers: dict):
        """Detect security headers and WAF"""
        security_headers = {
            'X-Frame-Options': 'X-Frame-Options',
            'X-Content-Type-Options': 'X-Content-Type-Options',
            'X-XSS-Protection': 'X-XSS-Protection',
            'Strict-Transport-Security': 'HSTS',
            'Content-Security-Policy': 'CSP',
            'X-Powered-By': None  # Check for absence
        }
        
        detected_security = []
        
        for header, name in security_headers.items():
            if name and header in headers:
                detected_security.append(name)
            elif header == 'X-Powered-By' and header not in headers:
                detected_security.append('X-Powered-By Hidden')
        
        if detected_security:
            self.detected['security_headers'] = set(detected_security)
        
        # WAF Detection
        waf_indicators = {
            'cloudflare': ['cf-ray', 'cloudflare'],
            'akamai': ['akamai'],
            'imperva': ['incap_ses', 'visid_incap'],
            'aws waf': ['x-amzn-requestid', 'x-amz-cf-id'],
            'barracuda': ['barra_counter_session'],
            'f5 big-ip': ['bigipserver', 'f5'],
            'sucuri': ['sucuri', 'x-sucuri']
        }
        
        for waf, indicators in waf_indicators.items():
            for indicator in indicators:
                for header_name, header_value in headers.items():
                    if indicator.lower() in header_name.lower() or indicator.lower() in str(header_value).lower():
                        self.detected['waf'].add(waf.upper())
                        self._update_confidence(waf, 'high')
    
    def _detect_cdn(self, headers: dict, html_content: str):
        """Detect CDN usage"""
        cdn_patterns = {
            'Cloudflare': ['cloudflare', 'cf-ray'],
            'Akamai': ['akamai'],
            'Fastly': ['fastly'],
            'CloudFront': ['cloudfront', 'x-amz-cf'],
            'MaxCDN': ['maxcdn'],
            'KeyCDN': ['keycdn'],
            'Incapsula': ['incap_ses', 'visid_incap'],
            'Sucuri': ['sucuri'],
            'jsDelivr': ['jsdelivr'],
            'unpkg': ['unpkg.com'],
            'cdnjs': ['cdnjs.cloudflare.com']
        }
        
        for cdn, patterns in cdn_patterns.items():
            for pattern in patterns:
                # Check headers
                for header_name, header_value in headers.items():
                    if pattern.lower() in header_name.lower() or pattern.lower() in str(header_value).lower():
                        self.detected['cdn'].add(cdn)
                        self._update_confidence(cdn, 'high')
                        break
                
                # Check HTML content
                if pattern.lower() in html_content.lower():
                    self.detected['cdn'].add(cdn)
                    self._update_confidence(cdn, 'medium')
    
    def _update_confidence(self, tech: str, level: str):
        """Update confidence score for detected technology"""
        confidence_values = {
            'low': 1,
            'medium': 2,
            'high': 3
        }
        
        current = self.confidence_scores.get(tech, 0)
        new_value = confidence_values.get(level, 0)
        
        self.confidence_scores[tech] = max(current, new_value)
    
    def get_confidence_level(self, tech: str) -> str:
        """Get confidence level for a technology"""
        score = self.confidence_scores.get(tech, 0)
        
        if score >= 3:
            return 'high'
        elif score >= 2:
            return 'medium'
        else:
            return 'low'
    
    def get_detailed_report(self) -> Dict:
        """Get detailed report with confidence levels"""
        report = {}
        
        for category, techs in self.detected.items():
            report[category] = []
            for tech in sorted(techs):
                report[category].append({
                    'name': tech,
                    'confidence': self.get_confidence_level(tech)
                })
        
        return report
