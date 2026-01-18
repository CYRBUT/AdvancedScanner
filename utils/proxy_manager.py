"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                      𝗔𝗗𝗩𝗔𝗡𝗖𝗘𝗗 𝗣𝗥𝗢𝗫𝗬 𝗠𝗔𝗡𝗔𝗚𝗘𝗠𝗘𝗡𝗧 𝗦𝗬𝗦𝗧𝗘𝗠                      ║
║             Intelligent Proxy Rotation, Validation & Anonymity               ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import random
import requests
import time
import threading
import socket
import ipaddress
import hashlib
import json
import queue
import socks
import asyncio
import aiohttp
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Set, Any, Union
from dataclasses import dataclass, field
from enum import Enum, auto
from colorama import Fore, Back, Style, init
from collections import defaultdict, deque
import dns.resolver
import tldextract

# Initialize colorama
init(autoreset=True)

class ProxyColors:
    """Rich black and gray text colors for proxy management"""
    
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

class ProxyType(Enum):
    """Types of proxies supported"""
    HTTP = auto()
    HTTPS = auto()
    SOCKS4 = auto()
    SOCKS5 = auto()
    TOR = auto()
    SHADOWSOCKS = auto()
    VPN = auto()
    RESIDENTIAL = auto()
    DATACENTER = auto()
    MOBILE = auto()
    ELITE = auto()
    ANONYMOUS = auto()
    TRANSPARENT = auto()

class ProxySource(Enum):
    """Sources of proxy acquisition"""
    FILE = auto()
    API = auto()
    WEB_SCRAPING = auto()
    PAID_SERVICE = auto()
    PUBLIC_LIST = auto()
    CUSTOM = auto()
    DATABASE = auto()

class ProxyAnonymity(Enum):
    """Levels of proxy anonymity"""
    TRANSPARENT = 0     # Reveals real IP
    ANONYMOUS = 1       # Hides real IP but reveals proxy usage
    ELITE = 2           # Completely anonymous

@dataclass
class ProxyStats:
    """Statistics for proxy performance tracking"""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    total_response_time: float = 0
    last_used: datetime = field(default_factory=datetime.now)
    last_success: Optional[datetime] = None
    last_failure: Optional[datetime] = None
    consecutive_failures: int = 0
    avg_response_time: float = 0
    success_rate: float = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    
    def update_success(self, response_time: float, bytes_sent: int = 0, bytes_received: int = 0):
        """Update stats on successful request"""
        self.total_requests += 1
        self.successful_requests += 1
        self.total_response_time += response_time
        self.last_used = datetime.now()
        self.last_success = datetime.now()
        self.consecutive_failures = 0
        self.bytes_sent += bytes_sent
        self.bytes_received += bytes_received
        self.avg_response_time = self.total_response_time / self.successful_requests
        self.success_rate = (self.successful_requests / self.total_requests) * 100
    
    def update_failure(self, bytes_sent: int = 0):
        """Update stats on failed request"""
        self.total_requests += 1
        self.failed_requests += 1
        self.last_used = datetime.now()
        self.last_failure = datetime.now()
        self.consecutive_failures += 1
        self.bytes_sent += bytes_sent
        self.success_rate = (self.successful_requests / self.total_requests) * 100 if self.total_requests > 0 else 0

@dataclass
class Proxy:
    """Proxy data structure with comprehensive information"""
    url: str
    ip: Optional[str] = None
    port: int = 8080
    username: Optional[str] = None
    password: Optional[str] = None
    proxy_type: ProxyType = ProxyType.HTTP
    anonymity: ProxyAnonymity = ProxyAnonymity.ANONYMOUS
    source: ProxySource = ProxySource.FILE
    country: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None
    asn: Optional[str] = None
    is_active: bool = True
    is_verified: bool = False
    verification_date: Optional[datetime] = None
    speed_rating: float = 0.0  # 0-10
    reliability_rating: float = 0.0  # 0-10
    security_score: int = 0  # 0-100
    last_checked: Optional[datetime] = None
    timeout: int = 30
    stats: ProxyStats = field(default_factory=ProxyStats)
    tags: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Parse URL if needed"""
        if not self.ip and '://' in self.url:
            # Extract IP from URL
            parts = self.url.split('://')[1].split(':')
            self.ip = parts[0]
            if len(parts) > 1:
                try:
                    self.port = int(parts[1].split('/')[0])
                except:
                    pass
    
    @property
    def formatted_url(self) -> str:
        """Get formatted proxy URL with auth if needed"""
        if self.username and self.password:
            if self.proxy_type in [ProxyType.HTTP, ProxyType.HTTPS]:
                return f"http://{self.username}:{self.password}@{self.ip}:{self.port}"
            elif self.proxy_type == ProxyType.SOCKS5:
                return f"socks5://{self.username}:{self.password}@{self.ip}:{self.port}"
        return f"{self.proxy_type.name.lower()}://{self.ip}:{self.port}"
    
    @property
    def requests_dict(self) -> Dict[str, str]:
        """Get proxy dict for requests library"""
        if self.proxy_type in [ProxyType.HTTP, ProxyType.HTTPS]:
            scheme = 'http' if self.proxy_type == ProxyType.HTTP else 'https'
            return {
                'http': f"{scheme}://{self.ip}:{self.port}",
                'https': f"{scheme}://{self.ip}:{self.port}"
            }
        elif self.proxy_type == ProxyType.SOCKS4:
            return {
                'http': f"socks4://{self.ip}:{self.port}",
                'https': f"socks4://{self.ip}:{self.port}"
            }
        elif self.proxy_type == ProxyType.SOCKS5:
            return {
                'http': f"socks5://{self.ip}:{self.port}",
                'https': f"socks5://{self.ip}:{self.port}"
            }
        return {}
    
    @property
    def quality_score(self) -> float:
        """Calculate overall proxy quality score"""
        return (
            self.stats.success_rate * 0.4 +
            (10 - self.stats.avg_response_time / 1000) * 0.3 +
            self.reliability_rating * 0.2 +
            self.speed_rating * 0.1
        )

class ProxyPool:
    """Intelligent proxy pool with load balancing and failover"""
    
    def __init__(self, max_size: int = 1000):
        self.proxies: Dict[str, Proxy] = {}
        self.active_proxies: List[str] = []
        self.inactive_proxies: List[str] = []
        self.current_index: int = 0
        self.rotation_strategy: str = "round_robin"  # round_robin, random, weighted, quality
        self.max_size = max_size
        self.blacklist: Set[str] = set()
        self.whitelist: Set[str] = set()
        self.rotation_lock = threading.Lock()
        self.stats_lock = threading.Lock()
        
        # Performance tracking
        self.total_requests = 0
        self.total_failures = 0
        self.start_time = datetime.now()
        
        # Initialize proxy sources
        self.proxy_sources = {
            'file': 'proxies.txt',
            'api': [],
            'web': [
                'https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all',
                'https://www.proxy-list.download/api/v1/get?type=http',
                'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt'
            ]
        }
    
    def add_proxy(self, proxy: Proxy) -> bool:
        """Add a proxy to the pool"""
        if len(self.proxies) >= self.max_size:
            # Remove lowest quality proxy
            worst_key = min(self.proxies.keys(), 
                           key=lambda k: self.proxies[k].quality_score)
            del self.proxies[worst_key]
        
        proxy_key = f"{proxy.ip}:{proxy.port}"
        
        if proxy_key in self.proxies:
            return False
        
        self.proxies[proxy_key] = proxy
        
        if proxy.is_active:
            self.active_proxies.append(proxy_key)
        else:
            self.inactive_proxies.append(proxy_key)
        
        return True
    
    def remove_proxy(self, proxy_key: str) -> bool:
        """Remove a proxy from the pool"""
        if proxy_key in self.proxies:
            del self.proxies[proxy_key]
            
            if proxy_key in self.active_proxies:
                self.active_proxies.remove(proxy_key)
            if proxy_key in self.inactive_proxies:
                self.inactive_proxies.remove(proxy_key)
            
            return True
        return False
    
    def get_next_proxy(self, strategy: Optional[str] = None) -> Optional[Proxy]:
        """Get next proxy based on rotation strategy"""
        if not self.active_proxies:
            return None
        
        strategy = strategy or self.rotation_strategy
        
        with self.rotation_lock:
            if strategy == "round_robin":
                proxy_key = self.active_proxies[self.current_index]
                self.current_index = (self.current_index + 1) % len(self.active_proxies)
            
            elif strategy == "random":
                proxy_key = random.choice(self.active_proxies)
            
            elif strategy == "weighted":
                # Weight by quality score
                weights = [self.proxies[k].quality_score for k in self.active_proxies]
                proxy_key = random.choices(self.active_proxies, weights=weights, k=1)[0]
            
            elif strategy == "quality":
                # Always pick highest quality
                proxy_key = max(self.active_proxies, 
                               key=lambda k: self.proxies[k].quality_score)
            
            else:
                proxy_key = self.active_proxies[self.current_index]
            
            return self.proxies[proxy_key] if proxy_key in self.proxies else None
    
    def rotate(self):
        """Rotate to next proxy"""
        with self.rotation_lock:
            self.current_index = (self.current_index + 1) % len(self.active_proxies)
    
    def update_proxy_status(self, proxy_key: str, success: bool, response_time: float = 0):
        """Update proxy status based on request outcome"""
        if proxy_key not in self.proxies:
            return
        
        with self.stats_lock:
            proxy = self.proxies[proxy_key]
            
            if success:
                proxy.stats.update_success(response_time)
                proxy.is_active = True
                
                # Move to active if not already
                if proxy_key in self.inactive_proxies:
                    self.inactive_proxies.remove(proxy_key)
                    self.active_proxies.append(proxy_key)
            else:
                proxy.stats.update_failure()
                
                # If too many consecutive failures, mark as inactive
                if proxy.stats.consecutive_failures >= 3:
                    proxy.is_active = False
                    if proxy_key in self.active_proxies:
                        self.active_proxies.remove(proxy_key)
                        self.inactive_proxies.append(proxy_key)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get pool statistics"""
        active_count = len(self.active_proxies)
        inactive_count = len(self.inactive_proxies)
        total_count = len(self.proxies)
        
        avg_success_rate = sum(p.stats.success_rate for p in self.proxies.values()) / total_count if total_count > 0 else 0
        avg_response_time = sum(p.stats.avg_response_time for p in self.proxies.values()) / total_count if total_count > 0 else 0
        
        return {
            'total_proxies': total_count,
            'active_proxies': active_count,
            'inactive_proxies': inactive_count,
            'success_rate': avg_success_rate,
            'avg_response_time': avg_response_time,
            'uptime': str(datetime.now() - self.start_time)
        }

class AdvancedProxyManager:
    """Main proxy management class with advanced features"""
    
    def __init__(self, config_file: str = "proxy_config.json"):
        self.pool = ProxyPool(max_size=5000)
        self.config_file = config_file
        self.config = self._load_config()
        self.current_proxy: Optional[Proxy] = None
        self.session_proxies: Dict[str, Proxy] = {}
        self.geo_cache: Dict[str, Dict] = {}
        self.health_check_interval = 300  # 5 minutes
        self.health_check_thread = None
        self.is_running = False
        
        # Load proxies on initialization
        self.load_all_proxies()
        
        # Start health check thread
        self.start_health_check()
        
        self._print_banner()
    
    def _print_banner(self):
        """Print initialization banner"""
        banner = f"""
{ProxyColors.ON_CHARCOAL}{ProxyColors.BLACK_BOLD}{'═' * 80}{ProxyColors.RESET}
{ProxyColors.ON_CHARCOAL}{ProxyColors.BLACK_UNDERLINE}{'ADVANCED PROXY MANAGEMENT SYSTEM':^80}{ProxyColors.RESET}
{ProxyColors.ON_CHARCOAL}{ProxyColors.BLACK_ITALIC}{'Intelligent Rotation • Geo-Distribution • Performance Optimization':^80}{ProxyColors.RESET}
{ProxyColors.ON_CHARCOAL}{ProxyColors.BLACK_BOLD}{'═' * 80}{ProxyColors.RESET}
        """
        print(banner)
        print(f"{ProxyColors.DARK_GRAY_BOLD}[*] Initializing Proxy Manager...{ProxyColors.RESET}")
    
    def _load_config(self) -> Dict:
        """Load configuration from file"""
        default_config = {
            'proxy_sources': {
                'files': ['proxies.txt', 'proxies.json'],
                'apis': [],
                'web_sources': [
                    'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt',
                    'https://www.proxy-list.download/api/v1/get?type=http',
                    'https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all'
                ]
            },
            'rotation_strategy': 'weighted',
            'health_check_interval': 300,
            'max_proxies': 5000,
            'timeout': 30,
            'verify_ssl': False,
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        try:
            with open(self.config_file, 'r') as f:
                user_config = json.load(f)
                default_config.update(user_config)
        except:
            print(f"{ProxyColors.BLACK_ON_YELLOW}[!] Config file not found, using defaults{ProxyColors.RESET}")
        
        return default_config
    
    def load_all_proxies(self):
        """Load proxies from all configured sources"""
        print(f"{ProxyColors.DARK_GRAY_BOLD}[*] Loading proxies from all sources...{ProxyColors.RESET}")
        
        total_loaded = 0
        
        # Load from files
        for file_path in self.config['proxy_sources']['files']:
            loaded = self.load_proxies_from_file(file_path)
            total_loaded += loaded
            print(f"{ProxyColors.DARK_GRAY}[+] Loaded {loaded} proxies from {file_path}{ProxyColors.RESET}")
        
        # Load from web sources
        for url in self.config['proxy_sources']['web_sources']:
            loaded = self.load_proxies_from_web(url)
            total_loaded += loaded
            print(f"{ProxyColors.DARK_GRAY}[+] Loaded {loaded} proxies from {url}{ProxyColors.RESET}")
        
        # Load from APIs
        for api_config in self.config['proxy_sources']['apis']:
            loaded = self.load_proxies_from_api(api_config)
            total_loaded += loaded
            print(f"{ProxyColors.DARK_GRAY}[+] Loaded {loaded} proxies from API{ProxyColors.RESET}")
        
        print(f"{ProxyColors.BLACK_ON_GREEN}[✓] Total proxies loaded: {total_loaded}{ProxyColors.RESET}")
        
        # Validate loaded proxies
        if total_loaded > 0:
            self.validate_proxies_quick()
    
    def load_proxies_from_file(self, file_path: str) -> int:
        """Load proxies from a file"""
        loaded_count = 0
        
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        proxy = self._parse_proxy_line(line)
                        if proxy:
                            if self.pool.add_proxy(proxy):
                                loaded_count += 1
        except FileNotFoundError:
            print(f"{ProxyColors.BLACK_ON_YELLOW}[!] File not found: {file_path}{ProxyColors.RESET}")
        
        return loaded_count
    
    def load_proxies_from_web(self, url: str) -> int:
        """Load proxies from a web source"""
        loaded_count = 0
        
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                lines = response.text.split('\n')
                for line in lines:
                    line = line.strip()
                    if line:
                        proxy = self._parse_proxy_line(line)
                        if proxy:
                            proxy.source = ProxySource.WEB_SCRAPING
                            if self.pool.add_proxy(proxy):
                                loaded_count += 1
        except Exception as e:
            print(f"{ProxyColors.BLACK_ON_RED}[-] Error loading from {url}: {e}{ProxyColors.RESET}")
        
        return loaded_count
    
    def _parse_proxy_line(self, line: str) -> Optional[Proxy]:
        """Parse a line of text into a Proxy object"""
        try:
            # Handle different formats
            if '://' in line:
                # Full URL format
                parts = line.split('://')
                protocol = parts[0].lower()
                rest = parts[1]
                
                # Extract auth if present
                if '@' in rest:
                    auth, hostport = rest.split('@')
                    if ':' in auth:
                        username, password = auth.split(':')
                    else:
                        username, password = auth, None
                else:
                    username = password = None
                    hostport = rest
                
                # Extract host and port
                if ':' in hostport:
                    host, port = hostport.split(':')[:2]
                    port = int(port.split('/')[0]) if '/' in port else int(port)
                else:
                    host = hostport
                    port = 8080 if protocol == 'http' else 1080
                
                # Map protocol to ProxyType
                type_map = {
                    'http': ProxyType.HTTP,
                    'https': ProxyType.HTTPS,
                    'socks4': ProxyType.SOCKS4,
                    'socks5': ProxyType.SOCKS5,
                    'socks': ProxyType.SOCKS5
                }
                
                proxy_type = type_map.get(protocol, ProxyType.HTTP)
                
            elif ':' in line:
                # IP:PORT format
                parts = line.split(':')
                host = parts[0]
                port = int(parts[1]) if len(parts) > 1 else 8080
                username = password = None
                proxy_type = ProxyType.HTTP
            
            else:
                return None
            
            # Create Proxy object
            proxy = Proxy(
                url=f"{proxy_type.name.lower()}://{host}:{port}",
                ip=host,
                port=port,
                username=username,
                password=password,
                proxy_type=proxy_type,
                source=ProxySource.FILE,
                timeout=self.config.get('timeout', 30)
            )
            
            return proxy
            
        except Exception as e:
            print(f"{ProxyColors.BLACK_ON_YELLOW}[!] Failed to parse proxy line: {line} - {e}{ProxyColors.RESET}")
            return None
    
    def get_random_proxy(self) -> Optional[Proxy]:
        """Get a random proxy"""
        self.current_proxy = self.pool.get_next_proxy('random')
        return self.current_proxy
    
    def get_proxy_by_country(self, country_code: str) -> Optional[Proxy]:
        """Get a proxy from specific country"""
        country_proxies = [
            key for key, proxy in self.pool.proxies.items()
            if proxy.country and proxy.country.lower() == country_code.lower() and proxy.is_active
        ]
        
        if country_proxies:
            proxy_key = random.choice(country_proxies)
            self.current_proxy = self.pool.proxies[proxy_key]
            return self.current_proxy
        
        return None
    
    def get_proxy_dict(self) -> Optional[Dict[str, str]]:
        """Get proxy configuration for requests library"""
        if self.current_proxy:
            return self.current_proxy.requests_dict
        return None
    
    def rotate_proxy(self, strategy: Optional[str] = None):
        """Rotate to next proxy"""
        old_proxy = self.current_proxy
        self.current_proxy = self.pool.get_next_proxy(strategy)
        
        if old_proxy and self.current_proxy:
            old_key = f"{old_proxy.ip}:{old_proxy.port}"
            new_key = f"{self.current_proxy.ip}:{self.current_proxy.port}"
            
            print(f"{ProxyColors.BLACK_ON_BLUE}[↻] Proxy Rotation:{ProxyColors.RESET}")
            print(f"{ProxyColors.DARK_GRAY}  From: {old_key} (SR: {old_proxy.stats.success_rate:.1f}%){ProxyColors.RESET}")
            print(f"{ProxyColors.BLACK_BOLD}    To: {new_key} (SR: {self.current_proxy.stats.success_rate:.1f}%){ProxyColors.RESET}")
        
        return self.current_proxy
    
    def test_proxy(self, proxy: Proxy, test_url: str = "http://httpbin.org/ip") -> Tuple[bool, float, Dict]:
        """Test if proxy is working and gather metrics"""
        start_time = time.time()
        
        try:
            proxies = proxy.requests_dict
            headers = {'User-Agent': self.config['user_agent']}
            
            response = requests.get(
                test_url,
                proxies=proxies,
                headers=headers,
                timeout=proxy.timeout,
                verify=self.config['verify_ssl']
            )
            
            response_time = (time.time() - start_time) * 1000  # Convert to ms
            
            if response.status_code == 200:
                # Get actual IP from response
                try:
                    data = response.json()
                    actual_ip = data.get('origin', '').split(',')[0]
                    
                    # Check if proxy is leaking real IP
                    is_leaking = actual_ip != proxy.ip
                    
                    return True, response_time, {
                        'ip': actual_ip,
                        'is_leaking': is_leaking,
                        'status_code': response.status_code,
                        'headers': dict(response.headers)
                    }
                except:
                    return True, response_time, {'status_code': response.status_code}
            else:
                return False, response_time, {'status_code': response.status_code}
                
        except requests.exceptions.Timeout:
            return False, proxy.timeout * 1000, {'error': 'timeout'}
        except requests.exceptions.ProxyError:
            return False, 0, {'error': 'proxy_error'}
        except Exception as e:
            return False, 0, {'error': str(e)}
    
    def validate_proxies_quick(self, max_checks: int = 50):
        """Quick validation of proxies"""
        print(f"{ProxyColors.DARK_GRAY_BOLD}[*] Quick validating proxies...{ProxyColors.RESET}")
        
        proxy_keys = list(self.pool.proxies.keys())[:max_checks]
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(self._validate_single_proxy, key): key 
                for key in proxy_keys
            }
            
            for future in as_completed(futures):
                proxy_key = futures[future]
                try:
                    success = future.result()
                    if success:
                        print(f"{ProxyColors.BLACK_ON_GREEN}[✓] {proxy_key}{ProxyColors.RESET}", end=' ')
                    else:
                        print(f"{ProxyColors.BLACK_ON_RED}[✗] {proxy_key}{ProxyColors.RESET}", end=' ')
                except:
                    print(f"{ProxyColors.BLACK_ON_YELLOW}[!] {proxy_key}{ProxyColors.RESET}", end=' ')
        
        print(f"\n{ProxyColors.BLACK_BOLD}[+] Quick validation complete{ProxyColors.RESET}")
    
    def _validate_single_proxy(self, proxy_key: str) -> bool:
        """Validate a single proxy"""
        if proxy_key not in self.pool.proxies:
            return False
        
        proxy = self.pool.proxies[proxy_key]
        success, response_time, _ = self.test_proxy(proxy)
        
        self.pool.update_proxy_status(proxy_key, success, response_time)
        
        return success
    
    def start_health_check(self):
        """Start background health check thread"""
        if not self.is_running:
            self.is_running = True
            self.health_check_thread = threading.Thread(
                target=self._health_check_worker,
                daemon=True
            )
            self.health_check_thread.start()
            print(f"{ProxyColors.BLACK_ON_GREEN}[✓] Health check thread started{ProxyColors.RESET}")
    
    def _health_check_worker(self):
        """Background worker for health checks"""
        while self.is_running:
            try:
                self._perform_health_check()
                time.sleep(self.health_check_interval)
            except Exception as e:
                print(f"{ProxyColors.BLACK_ON_RED}[-] Health check error: {e}{ProxyColors.RESET}")
                time.sleep(60)
    
    def _perform_health_check(self):
        """Perform health check on all proxies"""
        print(f"{ProxyColors.DARK_GRAY_BOLD}[*] Performing health check...{ProxyColors.RESET}")
        
        # Check inactive proxies
        for proxy_key in self.pool.inactive_proxies[:100]:  # Check 100 at a time
            if not self.is_running:
                break
            
            proxy = self.pool.proxies[proxy_key]
            success, response_time, _ = self.test_proxy(proxy)
            
            if success:
                print(f"{ProxyColors.BLACK_ON_GREEN}[+] Reactivated: {proxy_key}{ProxyColors.RESET}")
                proxy.is_active = True
                self.pool.update_proxy_status(proxy_key, True, response_time)
            else:
                # Remove if too many failures
                if proxy.stats.consecutive_failures >= 10:
                    self.pool.remove_proxy(proxy_key)
                    print(f"{ProxyColors.BLACK_ON_RED}[-] Removed dead proxy: {proxy_key}{ProxyColors.RESET}")
    
    def get_geolocation(self, ip: str) -> Dict:
        """Get geolocation information for an IP"""
        if ip in self.geo_cache:
            return self.geo_cache[ip]
        
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                self.geo_cache[ip] = data
                return data
        except:
            pass
        
        return {'country': 'Unknown', 'city': 'Unknown', 'isp': 'Unknown'}
    
    def enrich_proxy_info(self, proxy: Proxy):
        """Enrich proxy information with geolocation and other data"""
        if not proxy.ip:
            return
        
        geo = self.get_geolocation(proxy.ip)
        proxy.country = geo.get('country', 'Unknown')
        proxy.city = geo.get('city', 'Unknown')
        proxy.isp = geo.get('isp', 'Unknown')
        proxy.asn = geo.get('as', 'Unknown')
        
        # Determine anonymity level
        test_result = self.test_proxy(proxy, "http://httpbin.org/headers")
        if test_result[0]:
            headers = test_result[2].get('headers', {})
            if 'via' in headers or 'x-forwarded-for' in headers:
                proxy.anonymity = ProxyAnonymity.ANONYMOUS
            else:
                proxy.anonymity = ProxyAnonymity.ELITE
    
    def create_session_proxy(self, session_id: str, strategy: str = "quality") -> Optional[Proxy]:
        """Create a dedicated proxy for a session"""
        proxy = self.pool.get_next_proxy(strategy)
        if proxy:
            self.session_proxies[session_id] = proxy
        return proxy
    
    def get_session_proxy(self, session_id: str) -> Optional[Proxy]:
        """Get proxy for a specific session"""
        return self.session_proxies.get(session_id)
    
    def release_session_proxy(self, session_id: str):
        """Release proxy from session"""
        if session_id in self.session_proxies:
            del self.session_proxies[session_id]
    
    def print_dashboard(self):
        """Print proxy dashboard with statistics"""
        stats = self.pool.get_stats()
        
        print(f"\n{ProxyColors.ON_CHARCOAL}{ProxyColors.BLACK_BOLD}{' PROXY DASHBOARD ':{'═'}^80}{ProxyColors.RESET}")
        
        # Active proxies table
        print(f"\n{ProxyColors.BLACK_UNDERLINE}Active Proxies ({stats['active_proxies']}):{ProxyColors.RESET}")
        print(f"{ProxyColors.DARK_GRAY}{'-' * 80}{ProxyColors.RESET}")
        
        # Show top 10 active proxies
        active_keys = self.pool.active_proxies[:10]
        for i, key in enumerate(active_keys, 1):
            proxy = self.pool.proxies[key]
            print(f"{ProxyColors.BLACK_BOLD}{i:2}. {key:<20} {ProxyColors.RESET}"
                  f"{ProxyColors.DARK_GRAY}SR: {proxy.stats.success_rate:5.1f}% | "
                  f"RT: {proxy.stats.avg_response_time:6.1f}ms | "
                  f"Q: {proxy.quality_score:4.1f} | "
                  f"{proxy.country or 'N/A'}{ProxyColors.RESET}")
        
        # Statistics
        print(f"\n{ProxyColors.BLACK_UNDERLINE}Statistics:{ProxyColors.RESET}")
        print(f"{ProxyColors.DARK_GRAY}{'-' * 40}{ProxyColors.RESET}")
        print(f"{ProxyColors.BLACK_BOLD}Total Proxies:{ProxyColors.RESET} {stats['total_proxies']}")
        print(f"{ProxyColors.BLACK_BOLD}Active:{ProxyColors.RESET} {stats['active_proxies']} "
              f"{ProxyColors.BLACK_BOLD}Inactive:{ProxyColors.RESET} {stats['inactive_proxies']}")
        print(f"{ProxyColors.BLACK_BOLD}Avg Success Rate:{ProxyColors.RESET} {stats['success_rate']:.1f}%")
        print(f"{ProxyColors.BLACK_BOLD}Avg Response Time:{ProxyColors.RESET} {stats['avg_response_time']:.1f}ms")
        print(f"{ProxyColors.BLACK_BOLD}Uptime:{ProxyColors.RESET} {stats['uptime']}")
        
        # Current proxy
        if self.current_proxy:
            print(f"\n{ProxyColors.BLACK_UNDERLINE}Current Proxy:{ProxyColors.RESET}")
            print(f"{ProxyColors.DARK_GRAY}{'-' * 40}{ProxyColors.RESET}")
            print(f"{ProxyColors.BLACK_BOLD}URL:{ProxyColors.RESET} {self.current_proxy.formatted_url}")
            print(f"{ProxyColors.BLACK_BOLD}Type:{ProxyColors.RESET} {self.current_proxy.proxy_type.name}")
            print(f"{ProxyColors.BLACK_BOLD}Anonymity:{ProxyColors.RESET} {self.current_proxy.anonymity.name}")
            print(f"{ProxyColors.BLACK_BOLD}Country:{ProxyColors.RESET} {self.current_proxy.country or 'Unknown'}")
            print(f"{ProxyColors.BLACK_BOLD}Success Rate:{ProxyColors.RESET} {self.current_proxy.stats.success_rate:.1f}%")
            print(f"{ProxyColors.BLACK_BOLD}Quality Score:{ProxyColors.RESET} {self.current_proxy.quality_score:.1f}/10")
        
        print(f"{ProxyColors.ON_CHARCOAL}{ProxyColors.BLACK_BOLD}{'═' * 80}{ProxyColors.RESET}")

# Export main classes
__all__ = [
    'AdvancedProxyManager',
    'Proxy',
    'ProxyPool',
    'ProxyType',
    'ProxyAnonymity',
    'ProxySource',
    'ProxyColors'
]

# Example usage
if __name__ == "__main__":
    # Initialize proxy manager
    manager = AdvancedProxyManager()
    
    # Print dashboard
    manager.print_dashboard()
    
    # Test proxy rotation
    print(f"\n{ProxyColors.BLACK_BOLD}[*] Testing proxy rotation:{ProxyColors.RESET}")
    for i in range(5):
        proxy = manager.rotate_proxy()
        if proxy:
            success, response_time, info = manager.test_proxy(proxy)
            status = f"{ProxyColors.BLACK_ON_GREEN}SUCCESS{ProxyColors.RESET}" if success else f"{ProxyColors.BLACK_ON_RED}FAILED{ProxyColors.RESET}"
            print(f"  {i+1}. {proxy.ip}:{proxy.port} - {status} ({response_time:.0f}ms)")
    
    # Get proxy for specific country
    print(f"\n{ProxyColors.BLACK_BOLD}[*] Getting proxy for US:{ProxyColors.RESET}")
    us_proxy = manager.get_proxy_by_country("US")
    if us_proxy:
        print(f"  Found: {us_proxy.ip}:{us_proxy.port} - {us_proxy.country}")
    
    # Final dashboard
    manager.print_dashboard()