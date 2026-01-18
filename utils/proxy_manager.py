"""
Proxy management for requests
"""

import random
import requests
from colorama import Fore

class ProxyManager:
    def __init__(self):
        self.proxies = []
        self.current_proxy = None
        self.proxy_enabled = False
        
        # Load proxy list
        self.load_proxies()
    
    def load_proxies(self):
        """Load proxies from file or use defaults"""
        try:
            # Try to load from file
            with open('proxies.txt', 'r') as f:
                self.proxies = [line.strip() for line in f if line.strip()]
        except:
            # Default proxies (for educational purposes only)
            self.proxies = [
                # These are example proxies, replace with actual proxies
                # 'http://proxy1.example.com:8080',
                # 'socks5://proxy2.example.com:1080'
            ]
        
        if self.proxies:
            print(f"{Fore.GREEN}[+] Loaded {len(self.proxies)} proxies")
            self.proxy_enabled = True
        else:
            print(f"{Fore.YELLOW}[!] No proxies loaded, using direct connection")
    
    def get_random_proxy(self):
        """Get random proxy from list"""
        if not self.proxies:
            return None
        
        proxy = random.choice(self.proxies)
        self.current_proxy = proxy
        return proxy
    
    def get_proxy_dict(self):
        """Get proxy configuration for requests"""
        if not self.proxy_enabled or not self.current_proxy:
            return None
        
        proxy_dict = {
            'http': self.current_proxy,
            'https': self.current_proxy
        }
        
        return proxy_dict
    
    def rotate_proxy(self):
        """Rotate to next proxy"""
        if self.proxies:
            self.current_proxy = self.get_random_proxy()
            print(f"{Fore.CYAN}[*] Rotated to proxy: {self.current_proxy}")
    
    def test_proxy(self, proxy_url, test_url="http://httpbin.org/ip"):
        """Test if proxy is working"""
        try:
            proxies = {
                'http': proxy_url,
                'https': proxy_url
            }
            
            response = requests.get(test_url, proxies=proxies, timeout=10)
            
            if response.status_code == 200:
                print(f"{Fore.GREEN}[+] Proxy working: {proxy_url}")
                return True
            else:
                print(f"{Fore.RED}[-] Proxy failed: {proxy_url}")
                return False
                
        except Exception as e:
            print(f"{Fore.RED}[-] Proxy error: {e}")
            return False
    
    def validate_proxies(self):
        """Validate all proxies in list"""
        valid_proxies = []
        
        for proxy in self.proxies:
            if self.test_proxy(proxy):
                valid_proxies.append(proxy)
        
        self.proxies = valid_proxies
        print(f"{Fore.GREEN}[+] Validated {len(self.proxies)} working proxies")