"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                 𝗔𝗗𝗩𝗔𝗡𝗖𝗘𝗗 𝗛𝗧𝗧𝗣 𝗥𝗘𝗤𝗨𝗘𝗦𝗧 𝗪𝗥𝗔𝗣𝗣𝗘𝗥                    ║
║      Intelligent HTTP Client with Security, Stealth & Anti-Detection        ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import requests
import time
import random
import json
import hashlib
import socket
import ssl
import urllib3
import threading
import asyncio
import aiohttp
from urllib.parse import urlparse, urljoin, quote, unquote
from http.client import HTTPResponse
from io import BytesIO
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, deque
import warnings
import os
import base64
import gzip
import brotli
from colorama import Fore, Back, Style, init

# Initialize colorama
init(autoreset=True)

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class RequestColors:
    """Rich color palette for request wrapper"""
    
    # Black Variations
    BLACK = '\033[30m'
    BLACK_BOLD = '\033[1;30m'
    BLACK_ITALIC = '\033[3;30m'
    BLACK_UNDERLINE = '\033[4;30m'
    BLACK_BLINK = '\033[5;30m'
    BLACK_REVERSE = '\033[7;30m'
    BLACK_STRIKETHROUGH = '\033[9;30m'
    
    # Gray Scale
    DARK_GRAY = '\033[90m'
    DARK_GRAY_BOLD = '\033[1;90m'
    DIM_GRAY = '\033[38;5;8m'
    CHARCOAL = '\033[38;5;236m'
    GUNMETAL = '\033[38;5;238m'
    SLATE = '\033[38;5;240m'
    
    # Rich Blacks
    BLACK_GRADIENT_1 = '\033[38;5;232m'
    BLACK_GRADIENT_2 = '\033[38;5;233m'
    BLACK_GRADIENT_3 = '\033[38;5;234m'
    
    # Backgrounds
    ON_BLACK = '\033[40m'
    ON_DARK_GRAY = '\033[100m'
    ON_CHARCOAL = '\033[48;5;236m'
    
    # Status Colors
    ON_GREEN = '\033[42m'
    ON_RED = '\033[41m'
    ON_YELLOW = '\033[43m'
    ON_BLUE = '\033[44m'
    ON_MAGENTA = '\033[45m'
    ON_CYAN = '\033[46m'
    
    RESET = '\033[0m'

class RequestMethod:
    """HTTP Methods"""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    PATCH = "PATCH"
    TRACE = "TRACE"
    CONNECT = "CONNECT"

class SecurityLevel:
    """Security levels for request configuration"""
    LOW = "low"        # Basic security
    MEDIUM = "medium"  # Moderate security
    HIGH = "high"      # High security
    STEALTH = "stealth"  # Maximum stealth
    TOR = "tor"        # Tor network level

@dataclass
class RequestStats:
    """Request statistics tracker"""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    total_bytes_sent: int = 0
    total_bytes_received: int = 0
    total_response_time: float = 0
    requests_by_status: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    requests_by_domain: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    last_request_time: Optional[datetime] = None
    start_time: datetime = field(default_factory=datetime.now)
    
    def update(self, success: bool, bytes_sent: int, bytes_received: int, 
               response_time: float, status_code: int, domain: str):
        """Update statistics"""
        self.total_requests += 1
        if success:
            self.successful_requests += 1
        else:
            self.failed_requests += 1
        
        self.total_bytes_sent += bytes_sent
        self.total_bytes_received += bytes_received
        self.total_response_time += response_time
        self.requests_by_status[status_code] += 1
        self.requests_by_domain[domain] += 1
        self.last_request_time = datetime.now()
    
    def get_average_response_time(self) -> float:
        """Get average response time"""
        if self.total_requests > 0:
            return self.total_response_time / self.total_requests
        return 0.0
    
    def get_success_rate(self) -> float:
        """Get success rate percentage"""
        if self.total_requests > 0:
            return (self.successful_requests / self.total_requests) * 100
        return 0.0

@dataclass
class RequestConfig:
    """Request configuration"""
    timeout: int = 30
    verify_ssl: bool = False
    max_retries: int = 3
    retry_delay: float = 1.0
    follow_redirects: bool = True
    max_redirects: int = 10
    allow_http: bool = True
    security_level: str = SecurityLevel.MEDIUM
    proxy_url: Optional[str] = None
    proxy_auth: Optional[Tuple[str, str]] = None
    user_agent_rotation: bool = True
    header_rotation: bool = True
    delay_between_requests: Tuple[float, float] = (0.5, 2.0)
    cache_responses: bool = False
    cache_ttl: int = 300  # 5 minutes
    enable_fingerprinting: bool = True
    anti_waf: bool = True
    anti_fingerprinting: bool = True
    use_tor: bool = False
    tor_port: int = 9050

class UserAgentManager:
    """Intelligent User-Agent management"""
    
    def __init__(self):
        self.user_agents = self._load_user_agents()
        self.current_index = 0
        self.usage_count = defaultdict(int)
        self.blacklisted_agents = set()
        
    def _load_user_agents(self) -> List[str]:
        """Load comprehensive user agents database"""
        return [
            # Chrome Windows
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
            
            # Firefox Windows
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:119.0) Gecko/20100101 Firefox/119.0',
            
            # Chrome macOS
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            
            # Safari macOS
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
            
            # Linux
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0',
            
            # Mobile
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.210 Mobile Safari/537.36',
            'Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.210 Mobile Safari/537.36',
            
            # Less common but valid
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; Trident/7.0; rv:11.0) like Gecko',
            'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:54.0) Gecko/20100101 Firefox/54.0',
        ]
    
    def get_random(self) -> str:
        """Get random user agent"""
        available = [ua for ua in self.user_agents if ua not in self.blacklisted_agents]
        if not available:
            available = self.user_agents
        
        ua = random.choice(available)
        self.usage_count[ua] += 1
        
        # Rotate if used too many times
        if self.usage_count[ua] > 10:
            self.blacklisted_agents.add(ua)
        
        return ua
    
    def get_next(self) -> str:
        """Get next user agent in rotation"""
        ua = self.user_agents[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.user_agents)
        self.usage_count[ua] += 1
        return ua
    
    def blacklist(self, user_agent: str):
        """Blacklist a user agent"""
        self.blacklisted_agents.add(user_agent)
    
    def whitelist(self, user_agent: str):
        """Remove user agent from blacklist"""
        if user_agent in self.blacklisted_agents:
            self.blacklisted_agents.remove(user_agent)

class HeaderManager:
    """Intelligent header management"""
    
    def __init__(self):
        self.base_headers = self._get_base_headers()
        self.header_variations = self._get_header_variations()
        self.current_headers = self.base_headers.copy()
    
    def _get_base_headers(self) -> Dict[str, str]:
        """Get base headers"""
        return {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0',
        }
    
    def _get_header_variations(self) -> Dict[str, List[str]]:
        """Get header value variations"""
        return {
            'Accept': [
                'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            ],
            'Accept-Language': [
                'en-US,en;q=0.9',
                'en-US,en;q=0.8',
                'en-GB,en;q=0.9,en-US;q=0.8',
                'en;q=0.8',
            ],
            'Accept-Encoding': [
                'gzip, deflate',
                'gzip, deflate, br',
                'gzip',
                'deflate',
            ],
        }
    
    def randomize_headers(self) -> Dict[str, str]:
        """Randomize headers to avoid fingerprinting"""
        headers = self.base_headers.copy()
        
        # Randomize variable headers
        for header, variations in self.header_variations.items():
            if random.random() > 0.5:  # 50% chance to change each header
                headers[header] = random.choice(variations)
        
        # Add some random headers occasionally
        if random.random() > 0.7:
            headers['DNT'] = '1' if random.random() > 0.5 else '0'
        
        if random.random() > 0.8:
            headers['TE'] = 'Trailers'
        
        self.current_headers = headers
        return headers
    
    def get_security_headers(self, level: str = SecurityLevel.MEDIUM) -> Dict[str, str]:
        """Get headers for specific security level"""
        headers = self.current_headers.copy()
        
        if level == SecurityLevel.STEALTH:
            # Add stealth headers
            headers.update({
                'X-Requested-With': 'XMLHttpRequest',
                'X-Forwarded-For': self._generate_random_ip(),
                'X-Forwarded-Host': 'localhost',
                'X-Forwarded-Proto': 'https',
                'X-Real-IP': self._generate_random_ip(),
            })
        elif level == SecurityLevel.TOR:
            # Tor-specific headers
            headers.update({
                'X-Tor': 'true',
                'X-Forwarded-For': '127.0.0.1',
            })
        
        return headers
    
    def _generate_random_ip(self) -> str:
        """Generate random IP address"""
        return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"

class ResponseAnalyzer:
    """Advanced response analysis"""
    
    @staticmethod
    def analyze(response: requests.Response) -> Dict[str, Any]:
        """Analyze response for security insights"""
        analysis = {
            'security': {},
            'performance': {},
            'server_info': {},
            'vulnerabilities': [],
        }
        
        # Security headers check
        security_headers = ['X-Frame-Options', 'X-Content-Type-Options', 
                           'X-XSS-Protection', 'Content-Security-Policy',
                           'Strict-Transport-Security']
        
        analysis['security']['headers'] = {
            header: response.headers.get(header, 'MISSING')
            for header in security_headers
        }
        
        # Server information
        analysis['server_info'] = {
            'server': response.headers.get('Server', 'Unknown'),
            'powered_by': response.headers.get('X-Powered-By', 'Unknown'),
            'content_type': response.headers.get('Content-Type', 'Unknown'),
            'content_length': response.headers.get('Content-Length', 'Unknown'),
        }
        
        # Performance metrics
        analysis['performance'] = {
            'response_time': response.elapsed.total_seconds() * 1000,  # ms
            'size_bytes': len(response.content),
            'size_human': ResponseAnalyzer._humanize_bytes(len(response.content)),
        }
        
        # Vulnerability detection
        analysis['vulnerabilities'] = ResponseAnalyzer._detect_vulnerabilities(response)
        
        return analysis
    
    @staticmethod
    def _humanize_bytes(size: int) -> str:
        """Convert bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} TB"
    
    @staticmethod
    def _detect_vulnerabilities(response: requests.Response) -> List[Dict[str, str]]:
        """Detect potential vulnerabilities from response"""
        vulnerabilities = []
        
        # Check for common vulnerabilities
        if 'Server' in response.headers:
            server = response.headers['Server']
            if 'Apache/2.4.49' in server or 'Apache/2.4.50' in server:
                vulnerabilities.append({
                    'type': 'CVE-2021-41773',
                    'severity': 'CRITICAL',
                    'description': 'Apache HTTP Server Path Traversal and RCE'
                })
        
        # Check for debug information
        if 'debug' in response.text.lower() or 'console.log' in response.text:
            vulnerabilities.append({
                'type': 'INFO_LEAK',
                'severity': 'LOW',
                'description': 'Debug information exposed in response'
            })
        
        # Check for error messages
        error_keywords = ['error', 'exception', 'stack trace', 'mysql_fetch_array']
        for keyword in error_keywords:
            if keyword in response.text.lower():
                vulnerabilities.append({
                    'type': 'ERROR_EXPOSURE',
                    'severity': 'MEDIUM',
                    'description': f'Error message containing "{keyword}" exposed'
                })
                break
        
        return vulnerabilities

class AdvancedRequestWrapper:
    """Advanced HTTP request wrapper with security features"""
    
    def __init__(self, config: Optional[RequestConfig] = None):
        self.config = config or RequestConfig()
        self.session = requests.Session()
        self.base_url = None
        self.user_agent_manager = UserAgentManager()
        self.header_manager = HeaderManager()
        self.response_cache = {}
        self.request_stats = RequestStats()
        self.request_history = deque(maxlen=1000)
        self.rate_limiter = defaultdict(lambda: {'count': 0, 'reset_time': 0})
        self.fingerprint = self._generate_fingerprint()
        
        # Setup session
        self._setup_session()
        
        # Print banner
        self._print_banner()
    
    def _print_banner(self):
        """Print initialization banner"""
        banner = f"""
{RequestColors.ON_CHARCOAL}{RequestColors.BLACK_BOLD}{'═' * 80}{RequestColors.RESET}
{RequestColors.ON_CHARCOAL}{RequestColors.BLACK_UNDERLINE}{'ADVANCED HTTP REQUEST WRAPPER':^80}{RequestColors.RESET}
{RequestColors.ON_CHARCOAL}{RequestColors.BLACK_ITALIC}{'Security • Stealth • Intelligence • Performance':^80}{RequestColors.RESET}
{RequestColors.ON_CHARCOAL}{RequestColors.BLACK_BOLD}{'═' * 80}{RequestColors.RESET}
{RequestColors.DARK_GRAY_BOLD}[*] Initialized with security level: {self.config.security_level.upper()}{RequestColors.RESET}
        """
        print(banner)
    
    def _setup_session(self):
        """Setup HTTP session with security configuration"""
        # Configure session
        self.session.verify = self.config.verify_ssl
        self.session.max_redirects = self.config.max_redirects if self.config.follow_redirects else 0
        
        # Setup adapters for better performance
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=100,
            pool_maxsize=100,
            max_retries=3
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        
        # Set default headers
        self._update_headers()
        
        # Configure proxy if provided
        if self.config.proxy_url:
            self._setup_proxy()
        
        # Configure Tor if enabled
        if self.config.use_tor:
            self._setup_tor()
    
    def _update_headers(self):
        """Update session headers"""
        if self.config.user_agent_rotation:
            user_agent = self.user_agent_manager.get_random()
        else:
            user_agent = self.user_agent_manager.user_agents[0]
        
        headers = self.header_manager.randomize_headers() if self.config.header_rotation else self.header_manager.base_headers
        headers['User-Agent'] = user_agent
        
        # Add security headers based on level
        security_headers = self.header_manager.get_security_headers(self.config.security_level)
        headers.update(security_headers)
        
        self.session.headers.update(headers)
    
    def _setup_proxy(self):
        """Setup proxy configuration"""
        if self.config.proxy_url:
            proxies = {
                'http': self.config.proxy_url,
                'https': self.config.proxy_url,
            }
            
            if self.config.proxy_auth:
                self.session.proxies = proxies
                # Add proxy auth to session
                if 'http' in self.config.proxy_url:
                    from requests.auth import HTTPProxyAuth
                    auth = HTTPProxyAuth(*self.config.proxy_auth)
                    self.session.auth = auth
            else:
                self.session.proxies = proxies
    
    def _setup_tor(self):
        """Setup Tor proxy"""
        tor_proxy = f'socks5h://127.0.0.1:{self.config.tor_port}'
        self.session.proxies = {
            'http': tor_proxy,
            'https': tor_proxy,
        }
        print(f"{RequestColors.DARK_GRAY_BOLD}[*] Tor proxy enabled on port {self.config.tor_port}{RequestColors.RESET}")
    
    def _generate_fingerprint(self) -> Dict[str, Any]:
        """Generate client fingerprint for tracking"""
        return {
            'user_agent': self.session.headers.get('User-Agent', ''),
            'accept_language': self.session.headers.get('Accept-Language', ''),
            'accept_encoding': self.session.headers.get('Accept-Encoding', ''),
            'connection': self.session.headers.get('Connection', ''),
            'timestamp': datetime.now().isoformat(),
            'session_id': hashlib.md5(str(time.time()).encode()).hexdigest()[:16],
        }
    
    def _check_rate_limit(self, domain: str) -> bool:
        """Check if request is rate limited for domain"""
        now = time.time()
        domain_data = self.rate_limiter[domain]
        
        if now > domain_data['reset_time']:
            domain_data['count'] = 0
            domain_data['reset_time'] = now + 60  # Reset every minute
        
        if domain_data['count'] >= 60:  # 60 requests per minute max
            return False
        
        domain_data['count'] += 1
        return True
    
    def _add_delay(self):
        """Add random delay between requests"""
        min_delay, max_delay = self.config.delay_between_requests
        delay = random.uniform(min_delay, max_delay)
        time.sleep(delay)
    
    def _log_request(self, method: str, url: str, response: Optional[requests.Response] = None, 
                    error: Optional[str] = None, start_time: Optional[float] = None):
        """Log request details with advanced formatting"""
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        if response:
            status_code = response.status_code
            size = len(response.content)
            response_time = (time.time() - start_time) * 1000 if start_time else 0
            
            # Color based on status code
            if 200 <= status_code < 300:
                status_color = RequestColors.BLACK_ON_GREEN
            elif 300 <= status_code < 400:
                status_color = RequestColors.BLACK_ON_YELLOW
            elif 400 <= status_code < 500:
                status_color = RequestColors.BLACK_ON_MAGENTA
            else:
                status_color = RequestColors.BLACK_ON_RED
            
            # Format output
            print(f"{RequestColors.DARK_GRAY}[{datetime.now().strftime('%H:%M:%S')}] "
                  f"{RequestColors.BLACK_BOLD}{method:7}{RequestColors.RESET} "
                  f"{RequestColors.CHARCOAL}{url[:50]:50}...{RequestColors.RESET} "
                  f"{status_color} {status_code:3} {RequestColors.RESET} "
                  f"{RequestColors.DIM_GRAY}{size:8,} bytes{RequestColors.RESET} "
                  f"{RequestColors.SLATE}{response_time:6.0f}ms{RequestColors.RESET}")
        else:
            error_color = RequestColors.BLACK_ON_RED
            print(f"{RequestColors.DARK_GRAY}[{datetime.now().strftime('%H:%M:%S')}] "
                  f"{RequestColors.BLACK_BOLD}{method:7}{RequestColors.RESET} "
                  f"{RequestColors.CHARCOAL}{url[:50]:50}...{RequestColors.RESET} "
                  f"{error_color} ERROR {RequestColors.RESET} "
                  f"{RequestColors.DIM_GRAY}{error}{RequestColors.RESET}")
    
    def _handle_retry(self, method: str, url: str, attempt: int, max_retries: int, 
                     error: Optional[str] = None):
        """Handle retry logic with exponential backoff"""
        if attempt >= max_retries:
            print(f"{RequestColors.BLACK_ON_RED}[✗] Max retries ({max_retries}) exceeded for {url}{RequestColors.RESET}")
            return False
        
        wait_time = self.config.retry_delay * (2 ** attempt)
        print(f"{RequestColors.BLACK_ON_YELLOW}[↻] Retry {attempt + 1}/{max_retries} for {url} "
              f"(waiting {wait_time:.1f}s){RequestColors.RESET}")
        
        time.sleep(wait_time)
        return True
    
    def set_base_url(self, url: str):
        """Set base URL for relative requests"""
        self.base_url = url
        print(f"{RequestColors.DARK_GRAY_BOLD}[*] Base URL set to: {url}{RequestColors.RESET}")
    
    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Send GET request"""
        return self.request('GET', url, **kwargs)
    
    def post(self, url: str, data: Optional[Any] = None, json: Optional[Any] = None, **kwargs) -> Optional[requests.Response]:
        """Send POST request"""
        return self.request('POST', url, data=data, json=json, **kwargs)
    
    def put(self, url: str, data: Optional[Any] = None, **kwargs) -> Optional[requests.Response]:
        """Send PUT request"""
        return self.request('PUT', url, data=data, **kwargs)
    
    def delete(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Send DELETE request"""
        return self.request('DELETE', url, **kwargs)
    
    def head(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Send HEAD request"""
        return self.request('HEAD', url, **kwargs)
    
    def options(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Send OPTIONS request"""
        return self.request('OPTIONS', url, **kwargs)
    
    def patch(self, url: str, data: Optional[Any] = None, **kwargs) -> Optional[requests.Response]:
        """Send PATCH request"""
        return self.request('PATCH', url, data=data, **kwargs)
    
    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """Main request method with advanced features"""
        # Handle relative URLs
        if self.base_url and not urlparse(url).scheme:
            url = urljoin(self.base_url, url)
        
        # Check cache
        cache_key = self._generate_cache_key(method, url, kwargs)
        if self.config.cache_responses and cache_key in self.response_cache:
            cached_data = self.response_cache[cache_key]
            if time.time() - cached_data['timestamp'] < self.config.cache_ttl:
                print(f"{RequestColors.DARK_GRAY}[*] Cache hit for {url}{RequestColors.RESET}")
                return cached_data['response']
        
        # Check rate limit
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        if not self._check_rate_limit(domain):
            print(f"{RequestColors.BLACK_ON_YELLOW}[!] Rate limited for {domain}{RequestColors.RESET}")
            return None
        
        # Add delay
        self._add_delay()
        
        # Prepare request
        kwargs.setdefault('timeout', self.config.timeout)
        kwargs.setdefault('verify', self.config.verify_ssl)
        kwargs.setdefault('allow_redirects', self.config.follow_redirects)
        
        # Rotate headers and user agent
        if self.config.user_agent_rotation or self.config.header_rotation:
            self._update_headers()
        
        # Add anti-WAF techniques if enabled
        if self.config.anti_waf:
            kwargs = self._apply_anti_waf_techniques(url, kwargs)
        
        # Execute request with retries
        max_retries = kwargs.pop('max_retries', self.config.max_retries)
        attempt = 0
        
        while attempt <= max_retries:
            start_time = time.time()
            attempt += 1
            
            try:
                response = self.session.request(method, url, **kwargs)
                
                # Update stats
                bytes_sent = len(str(kwargs.get('data', '') or kwargs.get('json', '')))
                bytes_received = len(response.content)
                response_time = (time.time() - start_time) * 1000
                
                self.request_stats.update(
                    success=True,
                    bytes_sent=bytes_sent,
                    bytes_received=bytes_received,
                    response_time=response_time,
                    status_code=response.status_code,
                    domain=domain
                )
                
                # Log request
                self._log_request(method, url, response, start_time=start_time)
                
                # Cache response if enabled
                if self.config.cache_responses:
                    self.response_cache[cache_key] = {
                        'response': response,
                        'timestamp': time.time(),
                        'domain': domain
                    }
                
                # Add to history
                self.request_history.append({
                    'method': method,
                    'url': url,
                    'status': response.status_code,
                    'timestamp': datetime.now().isoformat(),
                    'response_time': response_time,
                })
                
                return response
                
            except requests.exceptions.RequestException as e:
                # Update stats
                self.request_stats.update(
                    success=False,
                    bytes_sent=0,
                    bytes_received=0,
                    response_time=0,
                    status_code=0,
                    domain=domain
                )
                
                # Log error
                self._log_request(method, url, error=str(e))
                
                # Handle retry
                if not self._handle_retry(method, url, attempt, max_retries, str(e)):
                    return None
        
        return None
    
    def _generate_cache_key(self, method: str, url: str, kwargs: Dict) -> str:
        """Generate cache key for request"""
        key_data = {
            'method': method,
            'url': url,
            'params': kwargs.get('params'),
            'data': kwargs.get('data'),
            'json': kwargs.get('json'),
            'headers': dict(self.session.headers),
        }
        return hashlib.md5(json.dumps(key_data, sort_keys=True).encode()).hexdigest()
    
    def _apply_anti_waf_techniques(self, url: str, kwargs: Dict) -> Dict:
        """Apply anti-WAF techniques to bypass security"""
        # URL encoding variations
        if 'params' in kwargs:
            params = kwargs['params']
            if isinstance(params, dict):
                # Apply different encoding techniques
                encoded_params = {}
                for key, value in params.items():
                    # Randomly choose encoding technique
                    technique = random.choice(['normal', 'double', 'unicode', 'uppercase'])
                    
                    if technique == 'double':
                        encoded_key = quote(quote(key))
                        encoded_value = quote(quote(str(value)))
                    elif technique == 'unicode':
                        encoded_key = ''.join([f'%u{ord(c):04x}' for c in key])
                        encoded_value = ''.join([f'%u{ord(c):04x}' for c in str(value)])
                    elif technique == 'uppercase':
                        encoded_key = key.upper()
                        encoded_value = str(value).upper()
                    else:
                        encoded_key = quote(key)
                        encoded_value = quote(str(value))
                    
                    encoded_params[encoded_key] = encoded_value
                
                kwargs['params'] = encoded_params
        
        # Add random headers to confuse WAF
        if random.random() > 0.7:
            kwargs['headers'] = kwargs.get('headers', {})
            kwargs['headers']['X-Originating-IP'] = self.header_manager._generate_random_ip()
            kwargs['headers']['X-Remote-IP'] = self.header_manager._generate_random_ip()
            kwargs['headers']['X-Remote-Addr'] = self.header_manager._generate_random_ip()
        
        # Add random parameter ordering
        if 'params' in kwargs and isinstance(kwargs['params'], dict):
            items = list(kwargs['params'].items())
            random.shuffle(items)
            kwargs['params'] = dict(items)
        
        return kwargs
    
    def analyze_response(self, response: requests.Response) -> Dict[str, Any]:
        """Analyze response for security insights"""
        return ResponseAnalyzer.analyze(response)
    
    def fingerprint_target(self, url: str) -> Dict[str, Any]:
        """Fingerprint target server"""
        try:
            # Get server information
            response = self.head(url, allow_redirects=True)
            
            if not response:
                return {'error': 'No response from server'}
            
            fingerprint = {
                'server': response.headers.get('Server', 'Unknown'),
                'technologies': [],
                'security_headers': {},
                'ports': [],
            }
            
            # Check common ports
            common_ports = [80, 443, 8080, 8443, 3000, 8000]
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname
            
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((hostname, port))
                    if result == 0:
                        fingerprint['ports'].append(port)
                    sock.close()
                except:
                    pass
            
            # Analyze headers for technologies
            headers = dict(response.headers)
            tech_indicators = {
                'nginx': ['nginx'],
                'apache': ['apache', 'httpd'],
                'iis': ['iis', 'microsoft'],
                'cloudflare': ['cloudflare'],
                'wordpress': ['wordpress', 'wp-'],
                'drupal': ['drupal'],
                'joomla': ['joomla'],
            }
            
            for tech, indicators in tech_indicators.items():
                for indicator in indicators:
                    if any(indicator in str(value).lower() for value in headers.values()):
                        if tech not in fingerprint['technologies']:
                            fingerprint['technologies'].append(tech)
            
            # Check security headers
            security_headers = ['X-Frame-Options', 'X-Content-Type-Options', 
                              'X-XSS-Protection', 'Content-Security-Policy',
                              'Strict-Transport-Security']
            
            for header in security_headers:
                fingerprint['security_headers'][header] = headers.get(header, 'MISSING')
            
            return fingerprint
            
        except Exception as e:
            return {'error': str(e)}
    
    def brute_force_endpoints(self, base_url: str, wordlist: List[str], 
                             methods: List[str] = None) -> List[Dict[str, Any]]:
        """Brute force endpoints using wordlist"""
        if methods is None:
            methods = ['GET', 'POST']
        
        results = []
        
        for endpoint in wordlist:
            url = urljoin(base_url, endpoint)
            
            for method in methods:
                try:
                    if method == 'GET':
                        response = self.get(url)
                    elif method == 'POST':
                        response = self.post(url, data={'test': 'data'})
                    else:
                        continue
                    
                    if response:
                        results.append({
                            'url': url,
                            'method': method,
                            'status': response.status_code,
                            'size': len(response.content),
                            'redirect': response.url if response.url != url else None,
                        })
                        
                        # Log finding
                        if response.status_code < 400:
                            print(f"{RequestColors.BLACK_ON_GREEN}[+] Found: {method} {url} - {response.status_code}{RequestColors.RESET}")
                        elif response.status_code == 403:
                            print(f"{RequestColors.BLACK_ON_YELLOW}[!] Forbidden: {method} {url}{RequestColors.RESET}")
                        elif response.status_code == 404:
                            print(f"{RequestColors.DARK_GRAY}[-] Not Found: {method} {url}{RequestColors.RESET}")
                        
                except Exception as e:
                    print(f"{RequestColors.BLACK_ON_RED}[-] Error: {method} {url} - {e}{RequestColors.RESET}")
        
        return results
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get request statistics"""
        return {
            'total_requests': self.request_stats.total_requests,
            'successful_requests': self.request_stats.successful_requests,
            'failed_requests': self.request_stats.failed_requests,
            'success_rate': self.request_stats.get_success_rate(),
            'average_response_time': self.request_stats.get_average_response_time(),
            'total_bytes_sent': self.request_stats.total_bytes_sent,
            'total_bytes_received': self.request_stats.total_bytes_received,
            'requests_by_status': dict(self.request_stats.requests_by_status),
            'top_domains': dict(sorted(
                self.request_stats.requests_by_domain.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]),
            'uptime': str(datetime.now() - self.request_stats.start_time),
        }
    
    def print_statistics(self):
        """Print request statistics dashboard"""
        stats = self.get_statistics()
        
        print(f"\n{RequestColors.ON_CHARCOAL}{RequestColors.BLACK_BOLD}{' REQUEST STATISTICS ':{'═'}^80}{RequestColors.RESET}")
        
        # Overview
        print(f"\n{RequestColors.BLACK_UNDERLINE}Overview:{RequestColors.RESET}")
        print(f"{RequestColors.DARK_GRAY}{'-' * 40}{RequestColors.RESET}")
        print(f"{RequestColors.BLACK_BOLD}Total Requests:{RequestColors.RESET} {stats['total_requests']:,}")
        print(f"{RequestColors.BLACK_BOLD}Successful:{RequestColors.RESET} {stats['successful_requests']:,} "
              f"{RequestColors.BLACK_BOLD}Failed:{RequestColors.RESET} {stats['failed_requests']:,}")
        print(f"{RequestColors.BLACK_BOLD}Success Rate:{RequestColors.RESET} {stats['success_rate']:.1f}%")
        print(f"{RequestColors.BLACK_BOLD}Avg Response Time:{RequestColors.RESET} {stats['average_response_time']:.1f}ms")
        
        # Data transferred
        print(f"\n{RequestColors.BLACK_UNDERLINE}Data Transferred:{RequestColors.RESET}")
        print(f"{RequestColors.DARK_GRAY}{'-' * 40}{RequestColors.RESET}")
        sent_human = ResponseAnalyzer._humanize_bytes(stats['total_bytes_sent'])
        received_human = ResponseAnalyzer._humanize_bytes(stats['total_bytes_received'])
        print(f"{RequestColors.BLACK_BOLD}Sent:{RequestColors.RESET} {sent_human}")
        print(f"{RequestColors.BLACK_BOLD}Received:{RequestColors.RESET} {received_human}")
        
        # Status codes
        print(f"\n{RequestColors.BLACK_UNDERLINE}Status Codes:{RequestColors.RESET}")
        print(f"{RequestColors.DARK_GRAY}{'-' * 40}{RequestColors.RESET}")
        for code, count in sorted(stats['requests_by_status'].items()):
            print(f"  {code}: {count:,}")
        
        # Top domains
        print(f"\n{RequestColors.BLACK_UNDERLINE}Top Domains:{RequestColors.RESET}")
        print(f"{RequestColors.DARK_GRAY}{'-' * 40}{RequestColors.RESET}")
        for domain, count in stats['top_domains'].items():
            print(f"  {domain}: {count:,}")
        
        # Uptime
        print(f"\n{RequestColors.BLACK_BOLD}Uptime:{RequestColors.RESET} {stats['uptime']}")
        print(f"{RequestColors.ON_CHARCOAL}{RequestColors.BLACK_BOLD}{'═' * 80}{RequestColors.RESET}")

# Export main classes
__all__ = [
    'AdvancedRequestWrapper',
    'RequestConfig',
    'SecurityLevel',
    'RequestMethod',
    'UserAgentManager',
    'HeaderManager',
    'ResponseAnalyzer',
    'RequestColors'
]

# Example usage
if __name__ == "__main__":
    print(f"{RequestColors.ON_CHARCOAL}{RequestColors.BLACK_BOLD}{' TESTING ADVANCED REQUEST WRAPPER ':{'═'}^80}{RequestColors.RESET}")
    
    # Create configuration
    config = RequestConfig(
        timeout=15,
        verify_ssl=False,
        max_retries=2,
        security_level=SecurityLevel.STEALTH,
        user_agent_rotation=True,
        header_rotation=True,
        anti_waf=True,
        use_tor=False,
    )
    
    # Initialize wrapper
    wrapper = AdvancedRequestWrapper(config)
    
    # Test requests
    test_urls = [
        'https://httpbin.org/get',
        'https://httpbin.org/status/200',
        'https://httpbin.org/status/404',
        'https://httpbin.org/status/500',
    ]
    
    for url in test_urls:
        print(f"\n{RequestColors.DARK_GRAY_BOLD}[*] Testing: {url}{RequestColors.RESET}")
        response = wrapper.get(url)
        
        if response:
            # Analyze response
            analysis = wrapper.analyze_response(response)
            
            print(f"{RequestColors.BLACK_BOLD}Security Headers:{RequestColors.RESET}")
            for header, value in analysis['security']['headers'].items():
                status = f"{RequestColors.BLACK_ON_GREEN}✓{RequestColors.RESET}" if value != 'MISSING' else f"{RequestColors.BLACK_ON_RED}✗{RequestColors.RESET}"
                print(f"  {status} {header}: {value}")
    
    # Print statistics
    wrapper.print_statistics()
    
    # Test fingerprinting
    print(f"\n{RequestColors.DARK_GRAY_BOLD}[*] Fingerprinting target...{RequestColors.RESET}")
    fingerprint = wrapper.fingerprint_target('https://httpbin.org')
    print(f"{RequestColors.BLACK_BOLD}Server:{RequestColors.RESET} {fingerprint.get('server', 'Unknown')}")
    print(f"{RequestColors.BLACK_BOLD}Technologies:{RequestColors.RESET} {', '.join(fingerprint.get('technologies', []))}")
    
    print(f"\n{RequestColors.BLACK_ON_CHARCOAL}{' TEST COMPLETE ':{'═'}^80}{RequestColors.RESET}")