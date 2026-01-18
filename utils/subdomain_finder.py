import dns.resolver
import requests
from concurrent.futures import ThreadPoolExecutor

class SubdomainFinder:
    def __init__(self, domain, wordlist=None):
        self.domain = domain
        self.wordlist = wordlist or self._default_wordlist()
        self.found = []
        
    def _default_wordlist(self):
        """Default subdomain wordlist"""
        return [
            'www', 'mail', 'ftp', 'admin', 'blog', 'api',
            'test', 'dev', 'stage', 'prod', 'secure'
        ]
    
    def find(self, threads=50):
        """Find subdomains"""
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            
            for word in self.wordlist:
                subdomain = f"{word}.{self.domain}"
                futures.append(executor.submit(self._check_subdomain, subdomain))
                
            for future in futures:
                try:
                    result = future.result(timeout=2)
                    if result:
                        self.found.append(result)
                except:
                    continue
                    
        return self.found
    
    def _check_subdomain(self, subdomain):
        """Check if subdomain exists"""
        try:
            answers = dns.resolver.resolve(subdomain, 'A')
            if answers:
                return {
                    'subdomain': subdomain,
                    'ips': [str(answer) for answer in answers]
                }
        except:
            pass
        return None
    
    def check_http(self):
        """Check which subdomains have HTTP services"""
        http_subdomains = []
        
        for subdomain in self.found:
            subdomain_str = subdomain['subdomain']
            
            for scheme in ['http://', 'https://']:
                try:
                    url = f"{scheme}{subdomain_str}"
                    response = requests.get(url, timeout=5, verify=False)
                    
                    if response.status_code < 400:
                        http_subdomains.append({
                            'url': url,
                            'status': response.status_code,
                            'title': self._extract_title(response.text),
                            'original': subdomain
                        })
                        break
                except:
                    continue
                    
        return http_subdomains
    
    def _extract_title(self, html):
        """Extract title from HTML"""
        from bs4 import BeautifulSoup
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            title = soup.title.string
            return title.strip() if title else "No Title"
        except:
            return "No Title"