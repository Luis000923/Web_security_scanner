import aiohttp
import asyncio
import time
import hashlib
import logging
from typing import Optional, Dict, Any, Union
from dataclasses import dataclass, field
from threading import Lock

@dataclass
class ScanConfig:
    max_concurrency: int = 50
    timeout: int = 10
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    proxy: Optional[str] = None
    rate_limit: float = 0.0  # seconds between requests
    headers: Dict[str, str] = field(default_factory=dict)

class AsyncResponseCache:
    """Thread-safe and Async-friendly response cache."""
    
    def __init__(self, max_size: int = 1000, ttl: int = 3600):
        self.cache = {}
        self.max_size = max_size
        self.ttl = ttl
        self.lock = Lock() # Still useful if accessed from mixed contexts
        self.access_times = {}
    
    def _generate_key(self, url: str, method: str, data: Any) -> str:
        key_data = f"{url}-{method}-{str(data)}"
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def get(self, url: str, method: str, data: Any = None) -> Optional[Dict]:
        with self.lock:
            key = self._generate_key(url, method, data)
            if key in self.cache:
                if time.time() - self.access_times.get(key, 0) < self.ttl:
                    return self.cache[key]
                else:
                    self._remove(key)
            return None
    
    def put(self, url: str, method: str, data: Any, response_data: Dict):
        with self.lock:
            if len(self.cache) >= self.max_size:
                self._evict_old_entries()
            
            key = self._generate_key(url, method, data)
            self.cache[key] = response_data
            self.access_times[key] = time.time()

    def _remove(self, key):
        if key in self.cache:
            del self.cache[key]
        if key in self.access_times:
            del self.access_times[key]

    def _evict_old_entries(self):
        if not self.access_times:
            return
        sorted_keys = sorted(self.access_times.items(), key=lambda x: x[1])
        to_remove = int(len(sorted_keys) * 0.25)
        for key, _ in sorted_keys[:to_remove]:
            self._remove(key)

class AsyncScannerCore:
    """
    Core scanner functionality using asyncio and aiohttp.
    Handles connection pooling, rate limiting, and caching.
    """
    def __init__(self, config: ScanConfig):
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None
        self.cache = AsyncResponseCache()
        self._semaphore = asyncio.Semaphore(config.max_concurrency)
        self._last_request_time = 0
        self._logger = logging.getLogger(__name__)

    async def start(self):
        """Initialize the aiohttp session."""
        if not self.session:
            connector = aiohttp.TCPConnector(limit=self.config.max_concurrency, ssl=False)
            headers = {"User-Agent": self.config.user_agent}
            headers.update(self.config.headers)
            self.session = aiohttp.ClientSession(connector=connector, headers=headers)

    async def close(self):
        """Close the aiohttp session."""
        if self.session:
            await self.session.close()
            self.session = None

    async def request(self, method: str, url: str, **kwargs) -> Dict[str, Any]:
        """
        Execute an HTTP request with caching and rate limiting.
        Returns a dictionary with status, text, headers, etc.
        """
        if not self.session:
            await self.start()

        # Check cache
        data = kwargs.get('data') or kwargs.get('json')
        cached = self.cache.get(url, method, data)
        if cached:
            return cached

        # Rate limiting
        async with self._semaphore:
            if self.config.rate_limit > 0:
                now = time.time()
                elapsed = now - self._last_request_time
                if elapsed < self.config.rate_limit:
                    await asyncio.sleep(self.config.rate_limit - elapsed)
                self._last_request_time = time.time()

            try:
                timeout = aiohttp.ClientTimeout(total=self.config.timeout)
                async with self.session.request(method, url, timeout=timeout, proxy=self.config.proxy, **kwargs) as response:
                    # Read content immediately to release connection
                    text = await response.text(errors='ignore')
                    result = {
                        'status_code': response.status,
                        'text': text,
                        'headers': dict(response.headers),
                        'url': str(response.url),
                        'elapsed': 0 # TODO: Calculate elapsed
                    }
                    
                    # Cache successful GET requests
                    if method.upper() == 'GET' and response.status == 200:
                        self.cache.put(url, method, data, result)
                    
                    return result
            except Exception as e:
                self._logger.debug(f"Request failed: {url} - {e}")
                return {
                    'status_code': 0,
                    'text': '',
                    'headers': {},
                    'url': url,
                    'error': str(e)
                }
