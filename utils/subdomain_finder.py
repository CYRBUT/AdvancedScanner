"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                𝗔𝗗𝗩𝗔𝗡𝗖𝗘𝗗 𝗦𝗨𝗕𝗗𝗢𝗠𝗔𝗜𝗡 𝗗𝗜𝗦𝗖𝗢𝗩𝗘𝗥𝗬 𝗦𝗬𝗦𝗧𝗘𝗠                ║
║         Comprehensive Subdomain Enumeration & Intelligence Gathering         ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import dns.resolver
import requests
import socket
import threading
import queue
import asyncio
import aiohttp
import json
import time
import re
import hashlib
import random
import string
import ssl
import whois
import urllib.parse
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set, Tuple, Any, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, deque
from colorama import Fore, Back, Style, init
import tldextract
import dns.reversename
import dns.rdatatype
import censys.certificates
import censys.ipv4
import censys
import shodan
import virustotal_python
from bs4 import BeautifulSoup
import csv
import xml.etree.ElementTree as ET

# Initialize colorama
init(autoreset=True)

class SubdomainColors:
    """Rich color palette for subdomain discovery"""
    
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
    STEEL = '\033[38;5;245m'
    
    # Rich Blacks
    BLACK_GRADIENT_1 = '\033[38;5;232m'
    BLACK_GRADIENT_2 = '\033[38;5;233m'
    BLACK_GRADIENT_3 = '\033[38;5;234m'
    
    # Backgrounds
    ON_BLACK = '\033[40m'
    ON_DARK_GRAY = '\033[100m'
    ON_CHARCOAL = '\033[48;5;236m'
    ON_STEEL = '\033[48;5;245m'
    
    # Status Colors
    ON_GREEN = '\033[42m'
    ON_RED = '\033[41m'
    ON_YELLOW = '\033[43m'
    ON_BLUE = '\033[44m'
    ON_MAGENTA = '\033[45m'
    ON_CYAN = '\033[46m'
    
    RESET = '\033[0m'

class DiscoveryMethod(Enum):
    """Methods for subdomain discovery"""
    BRUTE_FORCE = "brute_force"
    DICTIONARY = "dictionary"
    CERTIFICATE_TRANSPARENCY = "certificate_transparency"
    DNS_CRAWLING = "dns_crawling"
    REVERSE_DNS = "reverse_dns"
    SEARCH_ENGINES = "search_engines"
    WEB_ARCHIVES = "web_archives"
    API_INTEGRATION = "api_integration"
    DNS_ZONE_TRANSFER = "dns_zone_transfer"
    SUBDOMAIN_TAKEOVER = "subdomain_takeover"
    PASSIVE_DNS = "passive_dns"
    THREAT_INTELLIGENCE = "threat_intelligence"
    SSL_CERTIFICATES = "ssl_certificates"
    DNS_HISTORY = "dns_history"

class SubdomainStatus(Enum):
    """Status of discovered subdomains"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    UNKNOWN = "unknown"
    CNAME = "cname"
    WILDCARD = "wildcard"
    TAKEOVER_VULNERABLE = "takeover_vulnerable"

@dataclass
class SubdomainInfo:
    """Detailed information about a subdomain"""
    subdomain: str
    domain: str
    ip_addresses: List[str] = field(default_factory=list)
    cname: Optional[str] = None
    status: SubdomainStatus = SubdomainStatus.UNKNOWN
    discovery_method: List[DiscoveryMethod] = field(default_factory=list)
    discovery_date: datetime = field(default_factory=datetime.now)
    response_time: float = 0.0
    http_status: Optional[int] = None
    title: Optional[str] = None
    technologies: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    ssl_cert: Optional[Dict] = None
    whois_info: Optional[Dict] = None
    screenshot_path: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def full_domain(self) -> str:
        """Get full domain name"""
        return f"{self.subdomain}.{self.domain}" if self.subdomain != "@" else self.domain
    
    @property
    def is_wildcard(self) -> bool:
        """Check if subdomain is a wildcard"""
        return self.status == SubdomainStatus.WILDCARD
    
    @property
    def is_takeover_vulnerable(self) -> bool:
        """Check if subdomain is vulnerable to takeover"""
        return self.status == SubdomainStatus.TAKEOVER_VULNERABLE

class WordlistManager:
    """Manager for subdomain wordlists"""
    
    def __init__(self):
        self.wordlists = {
            'common': self._generate_common_wordlist(),
            'extended': self._generate_extended_wordlist(),
            'mega': self._generate_mega_wordlist(),
            'api': self._generate_api_wordlist(),
            'cloud': self._generate_cloud_wordlist(),
            'devops': self._generate_devops_wordlist(),
        }
        
    def _generate_common_wordlist(self) -> List[str]:
        """Generate common subdomain wordlist"""
        return [
            # Basic
            'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'pop3', 'imap',
            'ns1', 'ns2', 'ns3', 'ns4', 'dns1', 'dns2', 'mx', 'mx1', 'mx2',
            
            # Admin
            'admin', 'administrator', 'login', 'portal', 'dashboard', 'control',
            'cp', 'controlpanel', 'adminpanel', 'manager', 'webadmin',
            
            # Development
            'dev', 'development', 'test', 'testing', 'staging', 'stage', 'qa',
            'preprod', 'preproduction', 'sandbox', 'demo', 'lab', 'beta',
            
            # Services
            'api', 'api1', 'api2', 'rest', 'graphql', 'soap', 'ws', 'wss',
            'vpn', 'ssh', 'sftp', 'telnet', 'rdp', 'remote', 'proxy',
            
            # Cloud
            'aws', 'azure', 'gcp', 'cloud', 'cdn', 'storage', 'bucket',
            's3', 'blob', 'compute', 'lambda', 'functions', 'serverless',
            
            # Monitoring
            'monitor', 'monitoring', 'grafana', 'prometheus', 'zabbix',
            'nagios', 'status', 'health', 'metrics', 'stats', 'analytics',
            
            # Misc
            'blog', 'news', 'forum', 'community', 'support', 'help', 'kb',
            'wiki', 'docs', 'documentation', 'guide', 'tutorial', 'learn',
            
            # Geographic
            'us', 'uk', 'eu', 'de', 'fr', 'jp', 'cn', 'in', 'au', 'br',
            'nyc', 'lon', 'par', 'tok', 'sg', 'syd',
        ]
    
    def _generate_extended_wordlist(self) -> List[str]:
        """Generate extended subdomain wordlist"""
        extended = self._generate_common_wordlist()
        
        # Add variations
        prefixes = ['', 'prod-', 'dev-', 'test-', 'staging-', 'uat-']
        suffixes = ['', '-prod', '-dev', '-test', '-stage', '-uat']
        
        variations = []
        for word in extended:
            for prefix in prefixes:
                for suffix in suffixes:
                    variations.append(f"{prefix}{word}{suffix}")
        
        # Add numeric variations
        for i in range(10):
            variations.append(f"server{i}")
            variations.append(f"node{i}")
            variations.append(f"app{i}")
            variations.append(f"web{i}")
        
        return list(set(variations))
    
    def _generate_mega_wordlist(self) -> List[str]:
        """Generate mega wordlist with permutations"""
        base = self._generate_extended_wordlist()
        
        # Add common patterns
        patterns = [
            '{word}-{env}',
            '{env}-{word}',
            '{word}{num}',
            '{word}-{num}',
            '{word}.{env}',
        ]
        
        expanded = []
        for word in base:
            for pattern in patterns:
                if '{env}' in pattern:
                    for env in ['prod', 'dev', 'test', 'stage', 'uat']:
                        expanded.append(pattern.format(word=word, env=env))
                elif '{num}' in pattern:
                    for num in range(1, 10):
                        expanded.append(pattern.format(word=word, num=num))
                else:
                    expanded.append(pattern.format(word=word))
        
        return list(set(base + expanded))
    
    def _generate_api_wordlist(self) -> List[str]:
        """Generate wordlist for API discovery"""
        return [
            'api', 'api1', 'api2', 'api3', 'api-gateway', 'apigateway',
            'rest', 'restapi', 'graphql', 'grpc', 'soap', 'jsonapi',
            'v1', 'v2', 'v3', 'version1', 'version2', 'version3',
            'internal-api', 'external-api', 'public-api', 'private-api',
            'mobile-api', 'web-api', 'admin-api', 'partner-api',
            'auth', 'authentication', 'oauth', 'oauth2', 'jwt',
            'payment', 'billing', 'invoice', 'subscription',
            'notification', 'email', 'sms', 'push',
            'storage', 'upload', 'download', 'file',
            'search', 'query', 'filter', 'sort',
            'analytics', 'metrics', 'stats', 'report',
        ]
    
    def _generate_cloud_wordlist(self) -> List[str]:
        """Generate wordlist for cloud services"""
        return [
            # AWS
            's3', 'ec2', 'lambda', 'rds', 'dynamodb', 'sns', 'sqs',
            'cloudfront', 'route53', 'elasticbeanstalk', 'lightsail',
            'aws', 'amazon', 'cloudwatch', 'cloudtrail',
            
            # Azure
            'azure', 'blob', 'table', 'queue', 'function', 'appservice',
            'vm', 'virtualmachine', 'sql', 'cosmosdb',
            
            # GCP
            'gcp', 'google', 'cloudstorage', 'bigquery', 'cloudfunctions',
            'compute', 'appengine', 'cloudrun',
            
            # CDN
            'cdn', 'edge', 'cache', 'akamai', 'cloudflare', 'fastly',
            
            # Container
            'k8s', 'kubernetes', 'docker', 'container', 'pod', 'service',
            'ingress', 'helm', 'istio', 'linkerd',
        ]
    
    def _generate_devops_wordlist(self) -> List[str]:
        """Generate wordlist for DevOps infrastructure"""
        return [
            # CI/CD
            'jenkins', 'gitlab', 'github', 'bitbucket', 'circleci',
            'travis', 'bamboo', 'teamcity', 'azure-devops',
            
            # Monitoring
            'prometheus', 'grafana', 'elk', 'kibana', 'logstash',
            'splunk', 'datadog', 'newrelic', 'appdynamics',
            
            # Infrastructure
            'ansible', 'terraform', 'puppet', 'chef', 'salt',
            'vault', 'consul', 'nomad', 'packer',
            
            # Container Registry
            'registry', 'docker-registry', 'harbor', 'nexus',
            'artifactory', 'quay', 'ecr', 'gcr',
        ]
    
    def get_wordlist(self, name: str = 'common') -> List[str]:
        """Get wordlist by name"""
        return self.wordlists.get(name, self.wordlists['common'])
    
    def load_wordlist_from_file(self, filepath: str) -> List[str]:
        """Load wordlist from file"""
        try:
            with open(filepath, 'r') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except:
            return []
    
    def generate_pattern_based(self, domain: str) -> List[str]:
        """Generate subdomains based on patterns"""
        patterns = []
        
        # Extract components from domain
        parts = domain.split('.')
        if len(parts) >= 2:
            company_name = parts[-2]  # e.g., "google" from "google.com"
            
            patterns.extend([
                f"mail-{company_name}",
                f"{company_name}-mail",
                f"web-{company_name}",
                f"{company_name}-web",
                f"portal-{company_name}",
                f"{company_name}-portal",
            ])
        
        return patterns

class SubdomainScanner:
    """Advanced subdomain scanner with multiple discovery methods"""
    
    def __init__(self, domain: str, config: Optional[Dict] = None):
        self.domain = domain
        self.config = config or self._default_config()
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = self.config['dns_timeout']
        self.resolver.lifetime = self.config['dns_lifetime']
        self.wordlist_manager = WordlistManager()
        self.discovered_subdomains: Dict[str, SubdomainInfo] = {}
        self.stats = {
            'total_found': 0,
            'active': 0,
            'inactive': 0,
            'vulnerable': 0,
            'start_time': datetime.now(),
            'methods_used': set(),
        }
        
        # API clients (if configured)
        self.censys_client = None
        self.shodan_client = None
        self.virustotal_client = None
        
        self._initialize_api_clients()
        self._print_banner()
    
    def _print_banner(self):
        """Print initialization banner"""
        banner = f"""
{SubdomainColors.ON_CHARCOAL}{SubdomainColors.BLACK_BOLD}{'═' * 80}{SubdomainColors.RESET}
{SubdomainColors.ON_CHARCOAL}{SubdomainColors.BLACK_UNDERLINE}{'ADVANCED SUBDOMAIN DISCOVERY SYSTEM':^80}{SubdomainColors.RESET}
{SubdomainColors.ON_CHARCOAL}{SubdomainColors.BLACK_ITALIC}{'Target':^80}{SubdomainColors.RESET}
{SubdomainColors.ON_CHARCOAL}{SubdomainColors.BLACK_BOLD}{self.domain.center(80)}{SubdomainColors.RESET}
{SubdomainColors.ON_CHARCOAL}{SubdomainColors.BLACK_BOLD}{'═' * 80}{SubdomainColors.RESET}
        """
        print(banner)
        print(f"{SubdomainColors.DARK_GRAY_BOLD}[*] Initializing subdomain scanner for {self.domain}...{SubdomainColors.RESET}")
    
    def _default_config(self) -> Dict:
        """Get default configuration"""
        return {
            'dns_timeout': 2,
            'dns_lifetime': 2,
            'max_threads': 50,
            'rate_limit': 100,  # requests per minute
            'check_wildcard': True,
            'check_takeover': True,
            'enable_passive': True,
            'enable_active': True,
            'enable_bruteforce': True,
            'wordlist': 'common',
            'custom_wordlist': None,
            'output_format': 'json',
            'save_results': True,
            'resolvers': [
                '8.8.8.8',  # Google DNS
                '1.1.1.1',  # Cloudflare DNS
                '9.9.9.9',  # Quad9
                '208.67.222.222',  # OpenDNS
            ],
        }
    
    def _initialize_api_clients(self):
        """Initialize API clients if credentials are available"""
        # Censys
        if self.config.get('censys_api_id') and self.config.get('censys_api_secret'):
            try:
                self.censys_client = censys.certificates.CensysCertificates(
                    api_id=self.config['censys_api_id'],
                    api_secret=self.config['censys_api_secret']
                )
                print(f"{SubdomainColors.BLACK_ON_GREEN}[✓] Censys API initialized{SubdomainColors.RESET}")
            except:
                print(f"{SubdomainColors.BLACK_ON_YELLOW}[!] Failed to initialize Censys API{SubdomainColors.RESET}")
        
        # Shodan
        if self.config.get('shodan_api_key'):
            try:
                self.shodan_client = shodan.Shodan(self.config['shodan_api_key'])
                print(f"{SubdomainColors.BLACK_ON_GREEN}[✓] Shodan API initialized{SubdomainColors.RESET}")
            except:
                print(f"{SubdomainColors.BLACK_ON_YELLOW}[!] Failed to initialize Shodan API{SubdomainColors.RESET}")
        
        # VirusTotal
        if self.config.get('virustotal_api_key'):
            try:
                self.virustotal_client = virustotal_python.Virustotal(self.config['virustotal_api_key'])
                print(f"{SubdomainColors.BLACK_ON_GREEN}[✓] VirusTotal API initialized{SubdomainColors.RESET}")
            except:
                print(f"{SubdomainColors.BLACK_ON_YELLOW}[!] Failed to initialize VirusTotal API{SubdomainColors.RESET}")
    
    def discover_all(self) -> Dict[str, SubdomainInfo]:
        """Discover subdomains using all available methods"""
        print(f"{SubdomainColors.DARK_GRAY_BOLD}[*] Starting comprehensive subdomain discovery...{SubdomainColors.RESET}")
        
        # Check wildcard DNS first
        if self.config['check_wildcard']:
            self._check_wildcard_dns()
        
        # Passive discovery methods
        if self.config['enable_passive']:
            print(f"{SubdomainColors.DARK_GRAY_BOLD}[*] Running passive discovery methods...{SubdomainColors.RESET}")
            
            # Certificate Transparency
            ct_subs = self.discover_from_certificate_transparency()
            self._add_subdomains(ct_subs, DiscoveryMethod.CERTIFICATE_TRANSPARENCY)
            
            # Search engines
            search_subs = self.discover_from_search_engines()
            self._add_subdomains(search_subs, DiscoveryMethod.SEARCH_ENGINES)
            
            # Web archives
            archive_subs = self.discover_from_web_archives()
            self._add_subdomains(archive_subs, DiscoveryMethod.WEB_ARCHIVES)
            
            # Passive DNS
            passive_subs = self.discover_from_passive_dns()
            self._add_subdomains(passive_subs, DiscoveryMethod.PASSIVE_DNS)
        
        # Active discovery methods
        if self.config['enable_active']:
            print(f"{SubdomainColors.DARK_GRAY_BOLD}[*] Running active discovery methods...{SubdomainColors.RESET}")
            
            # DNS zone transfer attempt
            zone_subs = self.attempt_dns_zone_transfer()
            self._add_subdomains(zone_subs, DiscoveryMethod.DNS_ZONE_TRANSFER)
            
            # Reverse DNS lookup
            reverse_subs = self.discover_from_reverse_dns()
            self._add_subdomains(reverse_subs, DiscoveryMethod.REVERSE_DNS)
            
            # SSL certificate scanning
            ssl_subs = self.discover_from_ssl_certificates()
            self._add_subdomains(ssl_subs, DiscoveryMethod.SSL_CERTIFICATES)
        
        # Brute force
        if self.config['enable_bruteforce']:
            print(f"{SubdomainColors.DARK_GRAY_BOLD}[*] Running brute force enumeration...{SubdomainColors.RESET}")
            
            # Dictionary attack
            dict_subs = self.brute_force_dictionary()
            self._add_subdomains(dict_subs, DiscoveryMethod.DICTIONARY)
            
            # Permutation attack
            perm_subs = self.brute_force_permutations()
            self._add_subdomains(perm_subs, DiscoveryMethod.BRUTE_FORCE)
        
        # Check for subdomain takeover vulnerabilities
        if self.config['check_takeover']:
            print(f"{SubdomainColors.DARK_GRAY_BOLD}[*] Checking for subdomain takeover vulnerabilities...{SubdomainColors.RESET}")
            self._check_subdomain_takeover()
        
        # Enrich subdomain information
        print(f"{SubdomainColors.DARK_GRAY_BOLD}[*] Enriching subdomain information...{SubdomainColors.RESET}")
        self._enrich_subdomain_info()
        
        return self.discovered_subdomains
    
    def _add_subdomains(self, subdomains: List[str], method: DiscoveryMethod):
        """Add discovered subdomains to collection"""
        for subdomain in subdomains:
            full_domain = f"{subdomain}.{self.domain}" if subdomain != "@" else self.domain
            
            if full_domain not in self.discovered_subdomains:
                self.discovered_subdomains[full_domain] = SubdomainInfo(
                    subdomain=subdomain,
                    domain=self.domain,
                    discovery_method=[method]
                )
                self.stats['total_found'] += 1
                print(f"{SubdomainColors.BLACK_ON_GREEN}[+] {full_domain}{SubdomainColors.RESET}")
            else:
                # Add method to existing subdomain
                if method not in self.discovered_subdomains[full_domain].discovery_method:
                    self.discovered_subdomains[full_domain].discovery_method.append(method)
        
        self.stats['methods_used'].add(method)
    
    def _check_wildcard_dns(self):
        """Check for wildcard DNS configuration"""
        try:
            test_subdomain = f"{''.join(random.choices(string.ascii_lowercase, k=16))}.{self.domain}"
            answers = self.resolver.resolve(test_subdomain, 'A')
            
            print(f"{SubdomainColors.BLACK_ON_YELLOW}[!] Wildcard DNS detected for {self.domain}{SubdomainColors.RESET}")
            print(f"{SubdomainColors.DARK_GRAY}   Random test: {test_subdomain} resolves to {[str(a) for a in answers]}{SubdomainColors.RESET}")
            
            # Mark all future discoveries as potentially wildcard
            self.config['has_wildcard'] = True
        except:
            self.config['has_wildcard'] = False
    
    def discover_from_certificate_transparency(self) -> List[str]:
        """Discover subdomains from Certificate Transparency logs"""
        subdomains = set()
        
        print(f"{SubdomainColors.DARK_GRAY}[*] Querying Certificate Transparency logs...{SubdomainColors.RESET}")
        
        # crt.sh
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    if name_value:
                        names = name_value.split('\n')
                        for name in names:
                            name = name.strip().lower()
                            # Clean and validate
                            if name.endswith(self.domain):
                                # Remove wildcard prefix
                                if name.startswith('*.'):
                                    name = name[2:]
                                subdomains.add(name.replace(f'.{self.domain}', ''))
            
            print(f"{SubdomainColors.DARK_GRAY}[+] Found {len(subdomains)} subdomains from crt.sh{SubdomainColors.RESET}")
        except Exception as e:
            print(f"{SubdomainColors.BLACK_ON_RED}[-] crt.sh query failed: {e}{SubdomainColors.RESET}")
        
        # Censys certificates (if available)
        if self.censys_client:
            try:
                query = f"parsed.names: {self.domain}"
                certificates = self.censys_client.search(query, fields=['parsed.names'], max_records=1000)
                
                for cert in certificates:
                    names = cert.get('parsed.names', [])
                    for name in names:
                        if name.endswith(self.domain):
                            if name.startswith('*.'):
                                name = name[2:]
                            subdomains.add(name.replace(f'.{self.domain}', ''))
                
                print(f"{SubdomainColors.DARK_GRAY}[+] Found {len(subdomains)} subdomains from Censys{SubdomainColors.RESET}")
            except Exception as e:
                print(f"{SubdomainColors.BLACK_ON_YELLOW}[!] Censys query failed: {e}{SubdomainColors.RESET}")
        
        return list(subdomains)
    
    def discover_from_search_engines(self) -> List[str]:
        """Discover subdomains from search engines"""
        subdomains = set()
        
        print(f"{SubdomainColors.DARK_GRAY}[*] Querying search engines...{SubdomainColors.RESET}")
        
        search_queries = [
            f"site:*.{self.domain}",
            f"inurl:{self.domain}",
            f"*.{self.domain}",
        ]
        
        for query in search_queries:
            try:
                # Google (via custom search or scraping)
                url = f"https://www.google.com/search?q={query}"
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
                response = requests.get(url, headers=headers, timeout=10)
                
                if response.status_code == 200:
                    # Extract subdomains from search results
                    pattern = r'https?://([a-zA-Z0-9.-]+)\.' + re.escape(self.domain)
                    found = re.findall(pattern, response.text)
                    subdomains.update(found)
                
                # Delay to avoid rate limiting
                time.sleep(2)
            except:
                pass
        
        return list(subdomains)
    
    def discover_from_web_archives(self) -> List[str]:
        """Discover subdomains from web archives"""
        subdomains = set()
        
        print(f"{SubdomainColors.DARK_GRAY}[*] Querying web archives...{SubdomainColors.RESET}")
        
        # Wayback Machine
        try:
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}&output=json&collapse=urlkey"
            response = requests.get(url, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data[1:]:  # Skip header
                    url = entry[2]
                    pattern = r'https?://([a-zA-Z0-9.-]+)\.' + re.escape(self.domain)
                    matches = re.findall(pattern, url)
                    subdomains.update(matches)
            
            print(f"{SubdomainColors.DARK_GRAY}[+] Found {len(subdomains)} subdomains from Wayback Machine{SubdomainColors.RESET}")
        except Exception as e:
            print(f"{SubdomainColors.BLACK_ON_YELLOW}[!] Wayback Machine query failed: {e}{SubdomainColors.RESET}")
        
        return list(subdomains)
    
    def discover_from_passive_dns(self) -> List[str]:
        """Discover subdomains from passive DNS databases"""
        subdomains = set()
        
        print(f"{SubdomainColors.DARK_GRAY}[*] Querying passive DNS databases...{SubdomainColors.RESET}")
        
        # SecurityTrails (if API available)
        if self.config.get('securitytrails_api_key'):
            try:
                url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
                headers = {
                    'APIKEY': self.config['securitytrails_api_key'],
                    'Accept': 'application/json'
                }
                response = requests.get(url, headers=headers, timeout=15)
                
                if response.status_code == 200:
                    data = response.json()
                    subdomains.update(data.get('subdomains', []))
                
                print(f"{SubdomainColors.DARK_GRAY}[+] Found {len(subdomains)} subdomains from SecurityTrails{SubdomainColors.RESET}")
            except Exception as e:
                print(f"{SubdomainColors.BLACK_ON_YELLOW}[!] SecurityTrails query failed: {e}{SubdomainColors.RESET}")
        
        # VirusTotal (if API available)
        if self.virustotal_client:
            try:
                # This requires proper VirusTotal API implementation
                pass
            except:
                pass
        
        return list(subdomains)
    
    def attempt_dns_zone_transfer(self) -> List[str]:
        """Attempt DNS zone transfer"""
        subdomains = set()
        
        print(f"{SubdomainColors.DARK_GRAY}[*] Attempting DNS zone transfer...{SubdomainColors.RESET}")
        
        # Get nameservers for domain
        try:
            answers = self.resolver.resolve(self.domain, 'NS')
            nameservers = [str(ns).rstrip('.') for ns in answers]
            
            for ns in nameservers:
                try:
                    # Try zone transfer
                    transfer_resolver = dns.resolver.Resolver()
                    transfer_resolver.nameservers = [socket.gethostbyname(ns)]
                    
                    zone = transfer_resolver.query(self.domain, 'AXFR')
                    
                    for record in zone:
                        if isinstance(record, dns.rdtypes.IN.A):
                            subdomain = record.name.to_text().rstrip('.')
                            if subdomain.endswith(self.domain):
                                subdomains.add(subdomain.replace(f'.{self.domain}', ''))
                    
                    print(f"{SubdomainColors.BLACK_ON_GREEN}[!] Zone transfer successful from {ns}{SubdomainColors.RESET}")
                    break
                except:
                    continue
        
        except Exception as e:
            print(f"{SubdomainColors.DARK_GRAY}[-] Zone transfer failed (expected): {e}{SubdomainColors.RESET}")
        
        return list(subdomains)
    
    def discover_from_reverse_dns(self) -> List[str]:
        """Discover subdomains from reverse DNS lookups"""
        subdomains = set()
        
        print(f"{SubdomainColors.DARK_GRAY}[*] Performing reverse DNS lookups...{SubdomainColors.RESET}")
        
        # First get IPs for main domain
        try:
            answers = self.resolver.resolve(self.domain, 'A')
            ips = [str(a) for a in answers]
            
            for ip in ips:
                try:
                    # Perform reverse lookup
                    reverse_name = dns.reversename.from_address(ip)
                    ptr_records = self.resolver.resolve(reverse_name, 'PTR')
                    
                    for ptr in ptr_records:
                        ptr_name = str(ptr).rstrip('.')
                        if self.domain in ptr_name:
                            subdomain = ptr_name.replace(f'.{self.domain}', '')
                            subdomains.add(subdomain)
                except:
                    continue
        except:
            pass
        
        return list(subdomains)
    
    def discover_from_ssl_certificates(self) -> List[str]:
        """Discover subdomains from SSL certificates"""
        subdomains = set()
        
        print(f"{SubdomainColors.DARK_GRAY}[*] Scanning SSL certificates...{SubdomainColors.RESET}")
        
        # Scan common SSL ports
        ports = [443, 8443, 9443]
        
        for port in ports:
            try:
                context = ssl.create_default_context()
                with socket.create_connection((self.domain, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                        cert = ssock.getpeercert()
                        
                        # Extract subjectAltNames
                        for field in cert.get('subjectAltName', []):
                            if field[0] == 'DNS' and self.domain in field[1]:
                                name = field[1]
                                if name.startswith('*.'):
                                    name = name[2:]
                                subdomains.add(name.replace(f'.{self.domain}', ''))
            except:
                continue
        
        return list(subdomains)
    
    def brute_force_dictionary(self) -> List[str]:
        """Brute force subdomains using dictionary attack"""
        found = []
        
        # Get wordlist
        if self.config['custom_wordlist']:
            wordlist = self.wordlist_manager.load_wordlist_from_file(self.config['custom_wordlist'])
        else:
            wordlist = self.wordlist_manager.get_wordlist(self.config['wordlist'])
        
        print(f"{SubdomainColors.DARK_GRAY}[*] Starting dictionary attack with {len(wordlist)} words...{SubdomainColors.RESET}")
        
        # Use threading for faster scanning
        with ThreadPoolExecutor(max_workers=self.config['max_threads']) as executor:
            future_to_sub = {
                executor.submit(self._resolve_subdomain, sub): sub 
                for sub in wordlist
            }
            
            completed = 0
            for future in as_completed(future_to_sub):
                subdomain = future_to_sub[future]
                completed += 1
                
                if completed % 100 == 0:
                    print(f"{SubdomainColors.DARK_GRAY}[*] Progress: {completed}/{len(wordlist)} ({completed/len(wordlist)*100:.1f}%){SubdomainColors.RESET}")
                
                try:
                    result = future.result()
                    if result:
                        found.append(subdomain)
                except:
                    pass
        
        return found
    
    def brute_force_permutations(self) -> List[str]:
        """Brute force subdomains using permutations"""
        found = []
        
        print(f"{SubdomainColors.DARK_GRAY}[*] Starting permutation attack...{SubdomainColors.RESET}")
        
        # Generate permutations
        permutations = self.wordlist_manager.generate_pattern_based(self.domain)
        
        # Also try common patterns
        patterns = [
            '{word}-{num}',
            '{num}-{word}',
            '{word}{num}',
        ]
        
        base_words = ['dev', 'test', 'stage', 'prod', 'uat', 'api', 'web']
        for pattern in patterns:
            for word in base_words:
                for num in range(1, 10):
                    permutations.append(pattern.format(word=word, num=num))
        
        # Resolve permutations
        with ThreadPoolExecutor(max_workers=self.config['max_threads']) as executor:
            future_to_sub = {
                executor.submit(self._resolve_subdomain, sub): sub 
                for sub in permutations
            }
            
            for future in as_completed(future_to_sub):
                subdomain = future_to_sub[future]
                try:
                    result = future.result()
                    if result:
                        found.append(subdomain)
                except:
                    pass
        
        return found
    
    def _resolve_subdomain(self, subdomain: str) -> Optional[Dict]:
        """Resolve a single subdomain"""
        full_domain = f"{subdomain}.{self.domain}"
        
        try:
            start_time = time.time()
            answers = self.resolver.resolve(full_domain, 'A')
            response_time = (time.time() - start_time) * 1000  # ms
            
            ips = [str(a) for a in answers]
            
            # Check for CNAME
            cname = None
            try:
                cname_answers = self.resolver.resolve(full_domain, 'CNAME')
                if cname_answers:
                    cname = str(cname_answers[0].target).rstrip('.')
            except:
                pass
            
            return {
                'subdomain': subdomain,
                'ips': ips,
                'cname': cname,
                'response_time': response_time,
            }
            
        except dns.resolver.NXDOMAIN:
            return None
        except dns.resolver.NoAnswer:
            return None
        except Exception:
            return None
    
    def _check_subdomain_takeover(self):
        """Check for subdomain takeover vulnerabilities"""
        vulnerable_services = [
            # Service: [CNAME patterns, status check]
            ('github.io', ['github.io'], self._check_github_takeover),
            ('herokuapp.com', ['herokuapp.com'], self._check_heroku_takeover),
            ('azurewebsites.net', ['azurewebsites.net'], self._check_azure_takeover),
            ('aws.amazon.com', ['s3.amazonaws.com', 'cloudfront.net'], self._check_aws_takeover),
            ('shopify.com', ['myshopify.com'], self._check_shopify_takeover),
        ]
        
        for subdomain_info in self.discovered_subdomains.values():
            if subdomain_info.cname:
                for service, patterns, check_func in vulnerable_services:
                    for pattern in patterns:
                        if pattern in subdomain_info.cname:
                            if check_func(subdomain_info):
                                subdomain_info.status = SubdomainStatus.TAKEOVER_VULNERABLE
                                self.stats['vulnerable'] += 1
                                print(f"{SubdomainColors.BLACK_ON_RED}[!] Takeover vulnerable: {subdomain_info.full_domain} -> {service}{SubdomainColors.RESET}")
                            break
    
    def _check_github_takeover(self, subdomain_info: SubdomainInfo) -> bool:
        """Check GitHub Pages takeover vulnerability"""
        try:
            response = requests.get(f"http://{subdomain_info.full_domain}", timeout=5)
            if response.status_code == 404 and 'github.com' in response.text:
                return True
        except:
            pass
        return False
    
    def _check_heroku_takeover(self, subdomain_info: SubdomainInfo) -> bool:
        """Check Heroku takeover vulnerability"""
        try:
            response = requests.get(f"http://{subdomain_info.full_domain}", timeout=5)
            if response.status_code == 404 and 'herokucdn.com' in response.text:
                return True
        except:
            pass
        return False
    
    def _check_azure_takeover(self, subdomain_info: SubdomainInfo) -> bool:
        """Check Azure takeover vulnerability"""
        try:
            response = requests.get(f"http://{subdomain_info.full_domain}", timeout=5)
            if response.status_code == 404 and 'azurewebsites.net' in response.text:
                return True
        except:
            pass
        return False
    
    def _check_aws_takeover(self, subdomain_info: SubdomainInfo) -> bool:
        """Check AWS takeover vulnerability"""
        try:
            response = requests.get(f"http://{subdomain_info.full_domain}", timeout=5)
            if response.status_code == 404 and 'NoSuchBucket' in response.text:
                return True
        except:
            pass
        return False
    
    def _check_shopify_takeover(self, subdomain_info: SubdomainInfo) -> bool:
        """Check Shopify takeover vulnerability"""
        try:
            response = requests.get(f"http://{subdomain_info.full_domain}", timeout=5)
            if response.status_code == 404 and 'shopify.com' in response.text:
                return True
        except:
            pass
        return False
    
    def _enrich_subdomain_info(self):
        """Enrich subdomain information with additional data"""
        print(f"{SubdomainColors.DARK_GRAY}[*] Enriching subdomain information...{SubdomainColors.RESET}")
        
        for subdomain_info in self.discovered_subdomains.values():
            try:
                # Resolve IP addresses
                if not subdomain_info.ip_addresses:
                    try:
                        answers = self.resolver.resolve(subdomain_info.full_domain, 'A')
                        subdomain_info.ip_addresses = [str(a) for a in answers]
                        subdomain_info.status = SubdomainStatus.ACTIVE
                        self.stats['active'] += 1
                    except:
                        subdomain_info.status = SubdomainStatus.INACTIVE
                        self.stats['inactive'] += 1
                
                # Check HTTP service
                if subdomain_info.ip_addresses:
                    self._enrich_http_info(subdomain_info)
                    
                    # Port scan (limited)
                    self._scan_ports(subdomain_info)
            except Exception as e:
                print(f"{SubdomainColors.BLACK_ON_YELLOW}[!] Failed to enrich {subdomain_info.full_domain}: {e}{SubdomainColors.RESET}")
    
    def _enrich_http_info(self, subdomain_info: SubdomainInfo):
        """Enrich HTTP information for subdomain"""
        try:
            # Try HTTP
            response = requests.get(
                f"http://{subdomain_info.full_domain}",
                timeout=5,
                allow_redirects=True
            )
            
            subdomain_info.http_status = response.status_code
            subdomain_info.response_time = response.elapsed.total_seconds() * 1000
            
            # Extract title
            soup = BeautifulSoup(response.text, 'html.parser')
            title = soup.title.string if soup.title else None
            if title:
                subdomain_info.title = title.strip()
            
            # Detect technologies
            subdomain_info.technologies = self._detect_technologies(response)
            
        except:
            # Try HTTPS
            try:
                response = requests.get(
                    f"https://{subdomain_info.full_domain}",
                    timeout=5,
                    allow_redirects=True,
                    verify=False
                )
                
                subdomain_info.http_status = response.status_code
                subdomain_info.response_time = response.elapsed.total_seconds() * 1000
                
                # Extract title
                soup = BeautifulSoup(response.text, 'html.parser')
                title = soup.title.string if soup.title else None
                if title:
                    subdomain_info.title = title.strip()
                
                # Detect technologies
                subdomain_info.technologies = self._detect_technologies(response)
                
            except:
                pass
    
    def _detect_technologies(self, response: requests.Response) -> List[str]:
        """Detect web technologies from response"""
        technologies = []
        
        headers = response.headers
        
        # Server detection
        server = headers.get('Server', '').lower()
        if 'nginx' in server:
            technologies.append('nginx')
        elif 'apache' in server:
            technologies.append('apache')
        elif 'iis' in server:
            technologies.append('iis')
        elif 'cloudflare' in server:
            technologies.append('cloudflare')
        
        # Framework detection via headers
        powered_by = headers.get('X-Powered-By', '').lower()
        if 'php' in powered_by:
            technologies.append('php')
        elif 'asp.net' in powered_by:
            technologies.append('asp.net')
        
        # Framework detection via cookies
        cookies = headers.get('Set-Cookie', '').lower()
        if 'wordpress' in cookies:
            technologies.append('wordpress')
        elif 'drupal' in cookies:
            technologies.append('drupal')
        elif 'joomla' in cookies:
            technologies.append('joomla')
        
        # Framework detection via body
        body = response.text.lower()
        if 'wp-content' in body:
            technologies.append('wordpress')
        if 'drupal' in body:
            technologies.append('drupal')
        if 'joomla' in body:
            technologies.append('joomla')
        if 'react' in body:
            technologies.append('react')
        if 'vue' in body:
            technologies.append('vue')
        if 'angular' in body:
            technologies.append('angular')
        
        return list(set(technologies))
    
    def _scan_ports(self, subdomain_info: SubdomainInfo):
        """Scan common ports for subdomain"""
        common_ports = [80, 443, 8080, 8443, 3000, 8000, 9000]
        
        for ip in subdomain_info.ip_addresses[:3]:  # Limit to first 3 IPs
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        if port not in subdomain_info.ports:
                            subdomain_info.ports.append(port)
                    sock.close()
                except:
                    pass
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get scanning statistics"""
        duration = datetime.now() - self.stats['start_time']
        
        return {
            'domain': self.domain,
            'total_subdomains': self.stats['total_found'],
            'active_subdomains': self.stats['active'],
            'inactive_subdomains': self.stats['inactive'],
            'vulnerable_subdomains': self.stats['vulnerable'],
            'methods_used': list(self.stats['methods_used']),
            'scan_duration': str(duration),
            'scan_start_time': self.stats['start_time'].isoformat(),
            'scan_end_time': datetime.now().isoformat(),
        }
    
    def print_statistics(self):
        """Print scanning statistics"""
        stats = self.get_statistics()
        
        print(f"\n{SubdomainColors.ON_CHARCOAL}{SubdomainColors.BLACK_BOLD}{' SCAN STATISTICS ':{'═'}^80}{SubdomainColors.RESET}")
        
        # Overview
        print(f"\n{SubdomainColors.BLACK_UNDERLINE}Overview:{SubdomainColors.RESET}")
        print(f"{SubdomainColors.DARK_GRAY}{'-' * 40}{SubdomainColors.RESET}")
        print(f"{SubdomainColors.BLACK_BOLD}Domain:{SubdomainColors.RESET} {stats['domain']}")
        print(f"{SubdomainColors.BLACK_BOLD}Total Subdomains:{SubdomainColors.RESET} {stats['total_subdomains']:,}")
        print(f"{SubdomainColors.BLACK_BOLD}Active:{SubdomainColors.RESET} {stats['active_subdomains']:,} "
              f"{SubdomainColors.BLACK_BOLD}Inactive:{SubdomainColors.RESET} {stats['inactive_subdomains']:,}")
        print(f"{SubdomainColors.BLACK_BOLD}Vulnerable:{SubdomainColors.RESET} {stats['vulnerable_subdomains']:,}")
        
        # Methods used
        print(f"\n{SubdomainColors.BLACK_UNDERLINE}Methods Used:{SubdomainColors.RESET}")
        print(f"{SubdomainColors.DARK_GRAY}{'-' * 40}{SubdomainColors.RESET}")
        for method in stats['methods_used']:
            print(f"  • {method.value.replace('_', ' ').title()}")
        
        # Timing
        print(f"\n{SubdomainColors.BLACK_BOLD}Duration:{SubdomainColors.RESET} {stats['scan_duration']}")
        print(f"{SubdomainColors.BLACK_BOLD}Start Time:{SubdomainColors.RESET} {stats['scan_start_time']}")
        print(f"{SubdomainColors.BLACK_BOLD}End Time:{SubdomainColors.RESET} {stats['scan_end_time']}")
        
        print(f"{SubdomainColors.ON_CHARCOAL}{SubdomainColors.BLACK_BOLD}{'═' * 80}{SubdomainColors.RESET}")
    
    def export_results(self, format: str = 'json', filename: Optional[str] = None):
        """Export results to file"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"subdomains_{self.domain}_{timestamp}"
        
        results = {
            'domain': self.domain,
            'scan_date': datetime.now().isoformat(),
            'statistics': self.get_statistics(),
            'subdomains': {
                sub: {
                    'subdomain': info.subdomain,
                    'full_domain': info.full_domain,
                    'ip_addresses': info.ip_addresses,
                    'cname': info.cname,
                    'status': info.status.value,
                    'discovery_method': [m.value for m in info.discovery_method],
                    'http_status': info.http_status,
                    'title': info.title,
                    'technologies': info.technologies,
                    'ports': info.ports,
                    'is_takeover_vulnerable': info.is_takeover_vulnerable,
                }
                for sub, info in self.discovered_subdomains.items()
            }
        }
        
        if format.lower() == 'json':
            with open(f"{filename}.json", 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"{SubdomainColors.BLACK_ON_GREEN}[✓] Results exported to {filename}.json{SubdomainColors.RESET}")
        
        elif format.lower() == 'csv':
            with open(f"{filename}.csv", 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Subdomain', 'Full Domain', 'IPs', 'Status', 'HTTP Status', 'Title', 'Technologies'])
                
                for info in self.discovered_subdomains.values():
                    writer.writerow([
                        info.subdomain,
                        info.full_domain,
                        ', '.join(info.ip_addresses),
                        info.status.value,
                        info.http_status or '',
                        info.title or '',
                        ', '.join(info.technologies)
                    ])
            print(f"{SubdomainColors.BLACK_ON_GREEN}[✓] Results exported to {filename}.csv{SubdomainColors.RESET}")
        
        elif format.lower() == 'txt':
            with open(f"{filename}.txt", 'w') as f:
                f.write(f"Subdomains for {self.domain}\n")
                f.write(f"Scan date: {datetime.now()}\n")
                f.write("=" * 50 + "\n\n")
                
                for info in self.discovered_subdomains.values():
                    f.write(f"{info.full_domain}\n")
                    if info.ip_addresses:
                        f.write(f"  IPs: {', '.join(info.ip_addresses)}\n")
                    if info.cname:
                        f.write(f"  CNAME: {info.cname}\n")
                    if info.http_status:
                        f.write(f"  HTTP Status: {info.http_status}\n")
                    if info.title:
                        f.write(f"  Title: {info.title}\n")
                    if info.technologies:
                        f.write(f"  Technologies: {', '.join(info.technologies)}\n")
                    f.write("\n")
            print(f"{SubdomainColors.BLACK_ON_GREEN}[✓] Results exported to {filename}.txt{SubdomainColors.RESET}")

# Export main classes
__all__ = [
    'SubdomainScanner',
    'WordlistManager',
    'SubdomainInfo',
    'SubdomainStatus',
    'DiscoveryMethod',
    'SubdomainColors',
]

# Example usage
if __name__ == "__main__":
    print(f"{SubdomainColors.ON_CHARCOAL}{SubdomainColors.BLACK_BOLD}{' TESTING SUBDOMAIN DISCOVERY ':{'═'}^80}{SubdomainColors.RESET}")
    
    # Configuration
    config = {
        'dns_timeout': 3,
        'dns_lifetime': 3,
        'max_threads': 30,
        'check_wildcard': True,
        'check_takeover': True,
        'enable_passive': True,
        'enable_active': True,
        'enable_bruteforce': True,
        'wordlist': 'common',
        'output_format': 'json',
        'save_results': True,
    }
    
    # Initialize scanner
    scanner = SubdomainScanner("example.com", config)
    
    # Run discovery
    print(f"\n{SubdomainColors.DARK_GRAY_BOLD}[*] Starting subdomain discovery...{SubdomainColors.RESET}")
    subdomains = scanner.discover_all()
    
    # Print results
    print(f"\n{SubdomainColors.BLACK_BOLD}{'DISCOVERED SUBDOMAINS:'}{SubdomainColors.RESET}")
    print(f"{SubdomainColors.DARK_GRAY}{'-' * 80}{SubdomainColors.RESET}")
    
    for subdomain, info in list(subdomains.items())[:20]:  # Show first 20
        status_color = SubdomainColors.BLACK_ON_GREEN if info.status == SubdomainStatus.ACTIVE else SubdomainColors.DARK_GRAY
        print(f"{status_color}{info.full_domain:40}{SubdomainColors.RESET} "
              f"{SubdomainColors.STEEL}IPs: {len(info.ip_addresses):2} | "
              f"Status: {info.http_status or 'N/A':3} | "
              f"Tech: {', '.join(info.technologies[:2])}{SubdomainColors.RESET}")
    
    # Print statistics
    scanner.print_statistics()
    
    # Export results
    scanner.export_results(format='json')
    
    print(f"\n{SubdomainColors.BLACK_ON_CHARCOAL}{' DISCOVERY COMPLETE ':{'═'}^80}{SubdomainColors.RESET}")