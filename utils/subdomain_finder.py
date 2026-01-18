"""
Subdomain discovery utilities
"""

import dns.resolver
import requests
import threading
import queue
from colorama import Fore, Style

class SubdomainFinder:
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2
        self.resolver.lifetime = 2
        
        # Common subdomain wordlist
        self.wordlist = [
            'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'admin', 'blog', 'dev', 'test', 'staging', 'api', 'vpn', 'm',
            'mobile', 'static', 'cdn', 'shop', 'store', 'support', 'help'
        ]
        
        # Additional sources for subdomain discovery
        self.sources = [
            'crt.sh',  # Certificate Transparency
            'securitytrails.com',
            'virustotal.com',
            'dnsdumpster.com'
        ]
    
    def find_from_ct(self, domain):
        """Find subdomains from Certificate Transparency logs"""
        subdomains = set()
        
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                for entry in data:
                    name_value = entry.get('name_value', '')
                    
                    if name_value:
                        # Split by newlines and add to set
                        names = name_value.split('\n')
                        for name in names:
                            name = name.strip().lower()
                            if domain in name:
                                subdomains.add(name)
            
            print(f"{Fore.GREEN}[+] Found {len(subdomains)} subdomains from CT logs")
            
        except Exception as e:
            print(f"{Fore.RED}[-] CT log query failed: {e}")
        
        return list(subdomains)
    
    def brute_force(self, domain, wordlist=None):
        """Brute force subdomains using DNS resolution"""
        found = []
        
        if wordlist is None:
            wordlist = self.wordlist
        
        print(f"{Fore.YELLOW}[*] Brute-forcing subdomains for {domain}...")
        
        def check_subdomain(subdomain):
            try:
                full_domain = f"{subdomain}.{domain}"
                answers = self.resolver.resolve(full_domain, 'A')
                
                for answer in answers:
                    found.append({
                        'subdomain': full_domain,
                        'ip': str(answer),
                        'type': 'A'
                    })
                    
            except dns.resolver.NXDOMAIN:
                pass
            except Exception:
                pass
        
        # Use threading for faster scanning
        threads = []
        for sub in wordlist:
            thread = threading.Thread(target=check_subdomain, args=(sub,))
            threads.append(thread)
            thread.start()
            
            if len(threads) >= 10:
                for t in threads:
                    t.join()
                threads = []
        
        for thread in threads:
            thread.join()
        
        return found
    
    def find_all(self, domain, use_ct=True, brute=True, custom_wordlist=None):
        """Find all subdomains using multiple methods"""
        all_subdomains = set()
        
        # Certificate Transparency
        if use_ct:
            ct_subs = self.find_from_ct(domain)
            all_subdomains.update(ct_subs)
        
        # Brute force
        if brute:
            wordlist = custom_wordlist or self.wordlist
            brute_subs = self.brute_force(domain, wordlist)
            
            for sub in brute_subs:
                all_subdomains.add(sub['subdomain'])
        
        # Additional checks
        additional = self.check_common_services(domain)
        all_subdomains.update(additional)
        
        return sorted(list(all_subdomains))
    
    def check_common_services(self, domain):
        """Check for common service subdomains"""
        services = [
            ('_acme-challenge', 'TXT'),
            ('_dmarc', 'TXT'),
            ('_domainkey', 'TXT'),
            ('autodiscover', 'A'),
            ('autoconfig', 'A'),
            ('sip', 'A'),
            ('lyncdiscover', 'A'),
            ('enterpriseenrollment', 'A'),
            ('enterpriseregistration', 'A')
        ]
        
        found = []
        
        for subdomain, record_type in services:
            try:
                full_domain = f"{subdomain}.{domain}"
                answers = self.resolver.resolve(full_domain, record_type)
                
                for answer in answers:
                    found.append(full_domain)
                    print(f"{Fore.GREEN}[+] Found service: {full_domain} ({record_type})")
                    
            except:
                continue
        
        return found