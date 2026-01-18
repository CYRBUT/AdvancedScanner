import dns.resolver
import socket
import ssl
import concurrent.futures
from urllib.parse import urlparse
import requests

class SubdomainScanner:
    def __init__(self, target, brute_force=True):
        self.target = urlparse(target).netloc
        self.brute_force = brute_force
        self.subdomains = []
        self.wordlist = self._load_wordlist()
        
    def _load_wordlist(self):
        """Load subdomain wordlist"""
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'blog', 'api',
            'test', 'dev', 'stage', 'prod', 'secure', 'portal',
            'cpanel', 'webmail', 'ns1', 'ns2', 'ns3', 'ns4',
            'mx', 'mx1', 'mx2', 'smtp', 'pop', 'imap', 'webdisk',
            'autodiscover', 'autoconfig', 'git', 'svn', 'vpn',
            'remote', 'ssh', 'dashboard', 'panel', 'console',
            'app', 'apps', 'mobile', 'm', 'static', 'cdn',
            'media', 'images', 'img', 'video', 'videos',
            'download', 'uploads', 'files', 'docs', 'wiki',
            'status', 'monitor', 'monitoring', 'stats', 'analytics',
            'search', 'shop', 'store', 'cart', 'checkout',
            'payment', 'payments', 'billing', 'invoice', 'account',
            'accounts', 'support', 'help', 'faq', 'kb', 'knowledgebase',
            'forum', 'forums', 'community', 'chat', 'livechat',
            'blog', 'news', 'events', 'calendar', 'contact',
            'about', 'team', 'careers', 'jobs', 'services',
            'partners', 'affiliate', 'affiliates', 'client',
            'clients', 'customer', 'customers', 'user', 'users',
            'member', 'members', 'profile', 'profiles', 'settings',
            'config', 'configuration', 'manage', 'management',
            'admin', 'administrator', 'root', 'superuser',
            'sysadmin', 'system', 'server', 'servers', 'host',
            'hosting', 'cloud', 'aws', 'azure', 'gcp',
            'office', 'exchange', 'outlook', 'owa', 'lync',
            'skype', 'teams', 'sharepoint', 'onedrive', 'portal',
            'intranet', 'extranet', 'partner', 'vendor', 'supplier',
            'demo', 'sample', 'test', 'testing', 'qa', 'staging',
            'preprod', 'production', 'live', 'prod', 'beta',
            'alpha', 'gamma', 'delta', 'epsilon', 'zeta'
        ]
        
        return common_subdomains
    
    def scan(self):
        """Scan for subdomains"""
        print(f"[Subdomain] Scanning {self.target}...")
        
        # DNS enumeration
        self._dns_enumeration()
        
        # Brute force if enabled
        if self.brute_force:
            self._brute_force_subdomains()
            
        # Check each found subdomain
        verified = self._verify_subdomains()
        
        return {
            "target": self.target,
            "subdomains_found": len(self.subdomains),
            "verified_subdomains": verified,
            "total_verified": len(verified),
            "risk_level": "INFO"
        }
    
    def _dns_enumeration(self):
        """Enumerate subdomains via DNS"""
        try:
            # Check common records
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(self.target, record_type)
                    for answer in answers:
                        self.subdomains.append({
                            'subdomain': str(answer),
                            'type': record_type,
                            'source': 'dns_enum'
                        })
                except:
                    continue
                    
        except Exception as e:
            print(f"[Subdomain] DNS enumeration error: {e}")
    
    def _brute_force_subdomains(self):
        """Brute force subdomains"""
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = []
            
            for word in self.wordlist:
                subdomain = f"{word}.{self.target}"
                futures.append(executor.submit(self._check_subdomain, subdomain))
                
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result(timeout=2)
                    if result:
                        self.subdomains.append(result)
                except:
                    continue
    
    def _check_subdomain(self, subdomain):
        """Check if subdomain exists"""
        try:
            # Try A record
            answers = dns.resolver.resolve(subdomain, 'A', lifetime=2)
            if answers:
                return {
                    'subdomain': subdomain,
                    'type': 'A',
                    'source': 'brute_force',
                    'ips': [str(answer) for answer in answers]
                }
        except:
            pass
            
        try:
            # Try CNAME
            answers = dns.resolver.resolve(subdomain, 'CNAME', lifetime=2)
            if answers:
                return {
                    'subdomain': subdomain,
                    'type': 'CNAME',
                    'source': 'brute_force',
                    'cname': str(answers[0].target)
                }
        except:
            pass
            
        return None
    
    def _verify_subdomains(self):
        """Verify subdomains are accessible via HTTP/HTTPS"""
        verified = []
        
        for subdomain in self.subdomains:
            subdomain_str = subdomain.get('subdomain', '')
            
            if not subdomain_str:
                continue
                
            # Try HTTP
            for scheme in ['http://', 'https://']:
                try:
                    url = f"{scheme}{subdomain_str}"
                    response = requests.get(url, timeout=5, verify=False)
                    
                    if response.status_code < 400:
                        verified.append({
                            'url': url,
                            'status': response.status_code,
                            'title': self._extract_title(response.text),
                            'server': response.headers.get('Server', 'Unknown'),
                            'source': subdomain.get('source')
                        })
                        break
                        
                except Exception:
                    continue
                    
        return verified
    
    def _extract_title(self, html):
        """Extract title from HTML"""
        from bs4 import BeautifulSoup
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            title = soup.title.string
            return title.strip() if title else "No Title"
        except:
            return "No Title"