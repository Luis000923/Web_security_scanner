"""
Core scanner functionality
"""

import requests
import time
import hashlib
from urllib3.exceptions import InsecureRequestWarning
from typing import Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor
from threading import Lock, Semaphore

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


class ResponseCache:
    """Thread-safe response cache with TTL support"""
    
    def __init__(self, max_size: int = 1000, ttl: int = 3600):
        self.cache = {}
        self.max_size = max_size
        self.ttl = ttl
        self.lock = Lock()
        self.access_times = {}
    
    def _generate_key(self, url: str, method: str, data: dict) -> str:
        """Generate cache key"""
        key_data = f"{url}-{method}-{str(sorted(data.items()) if data else '')}"
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def get(self, url: str, method: str, data: dict = None) -> Optional[Dict]:
        """Get cached response"""
        with self.lock:
            key = self._generate_key(url, method, data or {})
            
            if key in self.cache:
                # Check TTL
                if time.time() - self.access_times[key] < self.ttl:
                    return self.cache[key]
                else:
                    # Expired, remove from cache
                    del self.cache[key]
                    del self.access_times[key]
            
            return None
    
    def put(self, url: str, method: str, data: dict, response: requests.Response):
        """Store response in cache"""
        with self.lock:
            # Clean old entries if cache is full
            if len(self.cache) >= self.max_size:
                self._evict_old_entries()
            
            key = self._generate_key(url, method, data or {})
            
            if response and hasattr(response, 'status_code'):
                self.cache[key] = {
                    'status_code': response.status_code,
                    'text': response.text,
                    'headers': dict(response.headers),
                    'url': response.url,
                    'elapsed': response.elapsed.total_seconds(),
                    'cookies': response.cookies.get_dict()
                }
                self.access_times[key] = time.time()
    
    def _evict_old_entries(self):
        """Remove 25% oldest entries"""
        if not self.access_times:
            return
        
        sorted_keys = sorted(self.access_times.items(), key=lambda x: x[1])
        to_remove = int(len(sorted_keys) * 0.25)
        
        for key, _ in sorted_keys[:to_remove]:
            if key in self.cache:
                del self.cache[key]
            del self.access_times[key]
    
    def clear(self):
        """Clear all cache"""
        with self.lock:
            self.cache.clear()
            self.access_times.clear()


class RateLimiter:
    """Rate limiter for HTTP requests"""
    
    def __init__(self, requests_per_second: int = 10):
        self.requests_per_second = requests_per_second
        self.min_interval = 1.0 / requests_per_second if requests_per_second > 0 else 0
        self.last_request_time = 0
        self.lock = Lock()
    
    def wait(self):
        """Wait if necessary to respect rate limit"""
        with self.lock:
            if self.requests_per_second <= 0:
                return
            
            current_time = time.time()
            time_since_last = current_time - self.last_request_time
            
            if time_since_last < self.min_interval:
                sleep_time = self.min_interval - time_since_last
                time.sleep(sleep_time)
            
            self.last_request_time = time.time()


class ScannerCore:
    """Core scanner with advanced request handling"""
    
    def __init__(self, config: 'Config', logger: 'ScanLogger'):
        self.config = config
        self.logger = logger
        
        # Setup session
        self.session = requests.Session()
        self.session.headers = {
            'User-Agent': config.get('scanner.user_agent'),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3',
            'Connection': 'keep-alive'
        }
        
        # Setup cache if enabled
        self.cache = None
        if config.get('cache.enabled'):
            self.cache = ResponseCache(
                max_size=config.get('cache.max_size'),
                ttl=config.get('cache.ttl')
            )
        
        # Setup rate limiter
        self.rate_limiter = RateLimiter(
            requests_per_second=config.get('scanner.rate_limit')
        )
        
        # Statistics
        self.stats = {
            'total_requests': 0,
            'cached_responses': 0,
            'failed_requests': 0,
            'total_time': 0
        }
        self.stats_lock = Lock()
    
    def make_request(
        self,
        url: str,
        method: str = 'GET',
        data: dict = None,
        headers: dict = None,
        allow_redirects: bool = True,
        timeout: int = None
    ) -> Optional[requests.Response]:
        """
        Make HTTP request with caching, rate limiting, and retry logic
        
        Args:
            url: Target URL
            method: HTTP method (GET, POST, etc.)
            data: Request data
            headers: Additional headers
            allow_redirects: Follow redirects
            timeout: Request timeout
            
        Returns:
            Response object or None if failed
        """
        # Check cache first
        if self.cache and method.upper() == 'GET':
            cached = self.cache.get(url, method, data or {})
            if cached:
                with self.stats_lock:
                    self.stats['cached_responses'] += 1
                
                self.logger.debug(f"Cache hit: {url}")
                return self._create_mock_response(cached)
        
        # Rate limiting
        self.rate_limiter.wait()
        
        # Prepare request parameters
        timeout = timeout or self.config.get('scanner.timeout')
        verify_ssl = self.config.get('scanner.verify_ssl')
        max_retries = self.config.get('scanner.max_retries')
        retry_delay = self.config.get('scanner.retry_delay')
        
        # Merge headers
        req_headers = self.session.headers.copy()
        if headers:
            req_headers.update(headers)
        
        # Retry logic
        for attempt in range(max_retries):
            try:
                start_time = time.time()
                
                # Make request
                if method.upper() == 'POST':
                    response = self.session.post(
                        url,
                        data=data,
                        headers=req_headers,
                        verify=verify_ssl,
                        timeout=timeout,
                        allow_redirects=allow_redirects
                    )
                else:
                    response = self.session.get(
                        url,
                        params=data,
                        headers=req_headers,
                        verify=verify_ssl,
                        timeout=timeout,
                        allow_redirects=allow_redirects
                    )
                
                elapsed = time.time() - start_time
                
                # Update statistics
                with self.stats_lock:
                    self.stats['total_requests'] += 1
                    self.stats['total_time'] += elapsed
                
                # Log request
                self.logger.request(method, url, response.status_code)
                
                # Cache successful responses
                if self.cache and method.upper() == 'GET' and response.status_code < 500:
                    self.cache.put(url, method, data or {}, response)
                
                return response
                
            except requests.exceptions.Timeout:
                self.logger.warning(f"Timeout on attempt {attempt + 1}/{max_retries}: {url}")
                
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                else:
                    with self.stats_lock:
                        self.stats['failed_requests'] += 1
                    return None
                    
            except requests.exceptions.RequestException as e:
                self.logger.warning(f"Request error on attempt {attempt + 1}/{max_retries}: {url} - {str(e)}")
                
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                else:
                    with self.stats_lock:
                        self.stats['failed_requests'] += 1
                    return None
        
        return None
    
    def _create_mock_response(self, cached_data: dict):
        """Create mock response object from cached data"""
        class MockResponse:
            def __init__(self, data):
                self.status_code = data['status_code']
                self.text = data['text']
                self.headers = data['headers']
                self.url = data['url']
                self.elapsed = type('obj', (object,), {'total_seconds': lambda: data['elapsed']})()
                self.cookies = data.get('cookies', {})
        
        return MockResponse(cached_data)
    
    def get_stats(self) -> dict:
        """Get scanner statistics"""
        with self.stats_lock:
            stats = self.stats.copy()
            if stats['total_requests'] > 0:
                stats['avg_response_time'] = stats['total_time'] / stats['total_requests']
                stats['cache_hit_rate'] = stats['cached_responses'] / (stats['total_requests'] + stats['cached_responses'])
            else:
                stats['avg_response_time'] = 0
                stats['cache_hit_rate'] = 0
            
            return stats
    
    def reset_stats(self):
        """Reset statistics"""
        with self.stats_lock:
            self.stats = {
                'total_requests': 0,
                'cached_responses': 0,
                'failed_requests': 0,
                'total_time': 0
            }
    
    def set_authentication(self, auth_type: str, credentials: dict):
        """
        Set authentication for requests
        
        Args:
            auth_type: 'basic', 'bearer', 'session', 'oauth'
            credentials: Authentication credentials
        """
        if auth_type == 'basic':
            from requests.auth import HTTPBasicAuth
            username = credentials.get('username')
            password = credentials.get('password')
            self.session.auth = HTTPBasicAuth(username, password)
            
        elif auth_type == 'bearer':
            token = credentials.get('token')
            self.session.headers['Authorization'] = f'Bearer {token}'
            
        elif auth_type == 'session':
            cookies = credentials.get('cookies', {})
            self.session.cookies.update(cookies)
            
        elif auth_type == 'oauth':
            token = credentials.get('access_token')
            self.session.headers['Authorization'] = f'Bearer {token}'
        
        self.logger.info(f"Authentication configured: {auth_type}")
