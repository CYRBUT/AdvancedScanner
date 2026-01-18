import time
import dns.resolver
import threading
import queue
from colorama import Fore, Style

class SubdomainScanner:
    def __init__(self):
        self.name = "Subdomain Scanner"
        self.version = "2.2"
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 
            'ns2', 'cpanel', 'whm', 'autodiscover', 'webdisk', 'admin', 'blog',
            'dev', 'development', 'test', 'staging', 'secure', 'portal', 'api',
            'vpn', 'm', 'mobile', 'static', 'img', 'images', 'cdn', 'assets',
            'shop', 'store', 'payment', 'billing', 'support', 'help', 'status',
            'docs', 'wiki', 'forum', 'community', 'news', 'media', 'download',
            'email', 'web', 'site', 'app', 'apps', 'beta', 'demo', 'old',
            'new', 'backup', 'backups', 'db', 'database', 'sql', 'mysql',
            'oracle', 'postgres', 'mongodb', 'redis', 'elasticsearch', 'git',
            'svn', 'ssh', 'sftp', 'ftp', 'file', 'files', 'share', 'shared',
            'cloud', 'storage', 'cdn', 'proxy', 'firewall', 'router', 'switch',
            'gateway', 'mx', 'mx1', 'mx2', 'ns', 'dns', 'ldap', 'radius', 'ntp',
            'time', 'log', 'logs', 'monitor', 'monitoring', 'stats', 'statistics',
            'analytics', 'tracking', 'spam', 'virus', 'antivirus', 'security',
            'firewall', 'fw', 'ids', 'ips', 'waf', 'ssl', 'cert', 'certificate',
            'ca', 'root', 'auth', 'authentication', 'login', 'logout', 'signin',
            'signup', 'register', 'registration', 'account', 'accounts', 'user',
            'users', 'profile', 'profiles', 'member', 'members', 'customer',
            'customers', 'client', 'clients', 'partner', 'partners', 'vendor',
            'vendors', 'supplier', 'suppliers', 'service', 'services', 'api',
            'api1', 'api2', 'api3', 'internal', 'private', 'secret', 'hidden',
            'staging', 'test', 'testing', 'qa', 'quality', 'preprod', 'production',
            'prod', 'live', 'uat', 'demo', 'demonstration', 'example', 'sample',
            'temp', 'temporary', 'backup', 'archive', 'archives', 'old', 'new'
        ]
        
        self.max_threads = 20
        self.results = queue.Queue()
    
    def scan(self, target, options=None):
        """Scan for subdomains"""
        from urllib.parse import urlparse
        
        results = {
            'subdomains_found': [],
            'dns_records': {},
            'timestamp': time.time()
        }
        
        try:
            # Extract domain from target
            parsed = urlparse(target)
            domain = parsed.netloc or parsed.path
            
            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]
            
            print(f"{Fore.YELLOW}[*] Scanning subdomains for: {domain}")
            
            # Use threading for faster scanning
            threads = []
            for subdomain in self.common_subdomains[:100]:  # Test first 100
                full_domain = f"{subdomain}.{domain}"
                
                thread = threading.Thread(
                    target=self.check_subdomain,
                    args=(full_domain,)
                )
                threads.append(thread)
                thread.start()
                
                # Control number of concurrent threads
                if len(threads) >= self.max_threads:
                    for t in threads:
                        t.join()
                    threads = []
            
            # Wait for remaining threads
            for thread in threads:
                thread.join()
            
            # Collect results
            while not self.results.empty():
                subdomain_info = self.results.get()
                results['subdomains_found'].append(subdomain_info)
                
                print(f"{Fore.GREEN}[+] Found: {subdomain_info['subdomain']} -> {subdomain_info['ip']}")
            
            # Also check for wildcard DNS
            self.check_wildcard_dns(domain, results)
            
            return results
            
        except Exception as e:
            print(f"{Fore.RED}[-] Subdomain scan error: {e}")
            return results
    
    def check_subdomain(self, domain):
        """Check if subdomain exists"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            
            answers = resolver.resolve(domain, 'A')
            
            for answer in answers:
                self.results.put({
                    'subdomain': domain,
                    'ip': str(answer),
                    'record_type': 'A'
                })
                
        except dns.resolver.NXDOMAIN:
            pass
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.Timeout:
            pass
        except Exception:
            pass
    
    def check_wildcard_dns(self, domain, results):
        """Check for wildcard DNS configuration"""
        try:
            import random
            random_string = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=10))
            test_domain = f"{random_string}.{domain}"
            
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            
            answers = resolver.resolve(test_domain, 'A')
            
            if answers:
                results['wildcard_dns'] = True
                print(f"{Fore.YELLOW}[!] Wildcard DNS detected on {domain}")
                
        except:
            results['wildcard_dns'] = False