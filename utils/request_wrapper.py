import requests
import time
import random
from fake_useragent import UserAgent

class RequestWrapper:
    def __init__(self, use_proxy=False, delay=0, max_retries=3):
        self.use_proxy = use_proxy
        self.delay = delay
        self.max_retries = max_retries
        self.ua = UserAgent()
        self.session = requests.Session()
        
        if use_proxy:
            from .proxy_manager import ProxyManager
            self.proxy_manager = ProxyManager()
            
    def make_request(self, url, method='GET', **kwargs):
        """Make HTTP request with advanced features"""
        for attempt in range(self.max_retries):
            try:
                # Apply delay
                if self.delay > 0:
                    time.sleep(random.uniform(0, self.delay))
                    
                # Prepare headers
                headers = kwargs.get('headers', {})
                if 'User-Agent' not in headers:
                    headers['User-Agent'] = self.ua.random
                    
                kwargs['headers'] = headers
                
                # Add proxy if enabled
                if self.use_proxy:
                    proxy = self.proxy_manager.get_random_proxy()
                    if proxy:
                        kwargs['proxies'] = proxy
                        
                # Make request
                if method.upper() == 'GET':
                    response = self.session.get(url, **kwargs)
                elif method.upper() == 'POST':
                    response = self.session.post(url, **kwargs)
                elif method.upper() == 'HEAD':
                    response = self.session.head(url, **kwargs)
                elif method.upper() == 'PUT':
                    response = self.session.put(url, **kwargs)
                elif method.upper() == 'DELETE':
                    response = self.session.delete(url, **kwargs)
                else:
                    response = self.session.request(method, url, **kwargs)
                    
                return response
                
            except Exception as e:
                if attempt == self.max_retries - 1:
                    raise e
                    
                # Rotate proxy on failure
                if self.use_proxy:
                    self.proxy_manager.rotate_proxy()
                    
                time.sleep(2 ** attempt)  # Exponential backoff
                
        return None
    
    def get(self, url, **kwargs):
        """GET request shortcut"""
        return self.make_request(url, 'GET', **kwargs)
    
    def post(self, url, **kwargs):
        """POST request shortcut"""
        return self.make_request(url, 'POST', **kwargs)
    
    def head(self, url, **kwargs):
        """HEAD request shortcut"""
        return self.make_request(url, 'HEAD', **kwargs)