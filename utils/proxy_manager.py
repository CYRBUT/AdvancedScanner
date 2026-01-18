import random
import requests
from datetime import datetime

class ProxyManager:
    def __init__(self):
        self.proxies = []
        self.active_proxy = None
        self.load_proxies()
        
    def load_proxies(self):
        """Load proxy list from multiple sources"""
        # Free proxy sources (for demonstration)
        proxy_sources = [
            'https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt',
            'https://raw.githubusercontent.com/shiftytr/proxy-list/master/proxy.txt',
            'https://api.proxyscrape.com/v2/?request=getproxies&protocol=http'
        ]
        
        for source in proxy_sources:
            try:
                response = requests.get(source, timeout=10)
                proxies = response.text.strip().split('\n')
                self.proxies.extend([p.strip() for p in proxies if p.strip()])
            except:
                continue
                
        # Remove duplicates
        self.proxies = list(set(self.proxies))
        
    def get_random_proxy(self):
        """Get random working proxy"""
        if not self.proxies:
            return None
            
        for _ in range(min(10, len(self.proxies))):
            proxy = random.choice(self.proxies)
            
            # Test proxy
            if self._test_proxy(proxy):
                self.active_proxy = proxy
                return {
                    'http': f'http://{proxy}',
                    'https': f'http://{proxy}'
                }
                
        return None
    
    def _test_proxy(self, proxy):
        """Test if proxy is working"""
        try:
            test_url = 'http://httpbin.org/ip'
            response = requests.get(
                test_url,
                proxies={'http': f'http://{proxy}', 'https': f'http://{proxy}'},
                timeout=5
            )
            return response.status_code == 200
        except:
            return False
    
    def rotate_proxy(self):
        """Rotate to next proxy"""
        return self.get_random_proxy()
    
    def get_proxy_list(self):
        """Get all proxies"""
        return self.proxies
    
    def add_proxy(self, proxy):
        """Add custom proxy"""
        if proxy not in self.proxies:
            self.proxies.append(proxy)
            
    def remove_proxy(self, proxy):
        """Remove proxy from list"""
        if proxy in self.proxies:
            self.proxies.remove(proxy)