"""
Advanced HTTP request wrapper with security features
"""

import requests
import time
import random
from urllib.parse import urlparse, urljoin
from colorama import Fore, Style

class RequestWrapper:
    def __init__(self, timeout=30, verify_ssl=False, max_retries=3):
        self.session = requests.Session()
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.max_retries = max_retries
        self.base_url = None
        
        # Set default headers
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
        self.session.headers.update(self.headers)
        
        # Disable SSL warnings if verify_ssl is False
        if not verify_ssl:
            requests.packages.urllib3.disable_warnings()
    
    def set_base_url(self, url):
        """Set base URL for relative requests"""
        self.base_url = url
    
    def get(self, url, params=None, **kwargs):
        """Send GET request"""
        return self._request('GET', url, params=params, **kwargs)
    
    def post(self, url, data=None, json=None, **kwargs):
        """Send POST request"""
        return self._request('POST', url, data=data, json=json, **kwargs)
    
    def put(self, url, data=None, **kwargs):
        """Send PUT request"""
        return self._request('PUT', url, data=data, **kwargs)
    
    def delete(self, url, **kwargs):
        """Send DELETE request"""
        return self._request('DELETE', url, **kwargs)
    
    def head(self, url, **kwargs):
        """Send HEAD request"""
        return self._request('HEAD', url, **kwargs)
    
    def options(self, url, **kwargs):
        """Send OPTIONS request"""
        return self._request('OPTIONS', url, **kwargs)
    
    def _request(self, method, url, **kwargs):
        """Internal request method with retry logic"""
        # Handle relative URLs
        if self.base_url and not urlparse(url).scheme:
            url = urljoin(self.base_url, url)
        
        # Set default kwargs
        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('verify', self.verify_ssl)
        
        # Add random delay to avoid rate limiting
        time.sleep(random.uniform(0.5, 2.0))
        
        retries = 0
        while retries <= self.max_retries:
            try:
                response = self.session.request(method, url, **kwargs)
                
                # Print request info in debug mode
                self._log_request(method, url, response)
                
                return response
                
            except requests.exceptions.RequestException as e:
                retries += 1
                print(f"{Fore.YELLOW}[!] Request failed ({retries}/{self.max_retries}): {e}")
                
                if retries > self.max_retries:
                    raise
                
                # Exponential backoff
                time.sleep(2 ** retries)
    
    def _log_request(self, method, url, response):
        """Log request details"""
        status_color = Fore.GREEN if response.status_code < 400 else Fore.RED
        
        print(f"{Fore.CYAN}[>] {method} {url}")
        print(f"{status_color}[<] Status: {response.status_code} | Size: {len(response.content)} bytes")
    
    def add_header(self, key, value):
        """Add custom header"""
        self.session.headers[key] = value
    
    def remove_header(self, key):
        """Remove header"""
        if key in self.session.headers:
            del self.session.headers[key]
    
    def set_user_agent(self, user_agent):
        """Set custom User-Agent"""
        self.session.headers['User-Agent'] = user_agent
    
    def random_user_agent(self):
        """Set random User-Agent"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1'
        ]
        
        self.session.headers['User-Agent'] = random.choice(user_agents)
    
    def raw_request(self, url, raw_http):
        """Send raw HTTP request"""
        import socket
        
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        
        # Create socket connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        if parsed.scheme == 'https':
            import ssl
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=host)
        
        sock.settimeout(self.timeout)
        sock.connect((host, port))
        
        # Send request
        sock.sendall(raw_http.encode())
        
        # Receive response
        response_data = b''
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response_data += chunk
            except socket.timeout:
                break
        
        sock.close()
        
        # Parse response
        from http.client import HTTPResponse
        from io import BytesIO
        
        class FakeSocket:
            def __init__(self, response_bytes):
                self._file = BytesIO(response_bytes)
            
            def makefile(self, *args, **kwargs):
                return self._file
        
        response = HTTPResponse(FakeSocket(response_data))
        response.begin()
        
        # Convert to requests-like response
        class CustomResponse:
            def __init__(self, http_response, content):
                self.status_code = http_response.status
                self.headers = dict(http_response.headers)
                self.content = content
                self.text = content.decode('utf-8', errors='ignore')
                self.url = url
        
        return CustomResponse(response, response_data)