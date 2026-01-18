import time
import dns.resolver
import dns.exception
import threading
import queue
import random
import socket
import sys
import json
from urllib.parse import urlparse, urlunparse
from colorama import Fore, Style, Back, init
from datetime import datetime
import concurrent.futures
from collections import defaultdict

# Initialize colorama
init(autoreset=True)

class SubdomainScanner:
    def __init__(self):
        self.name = "🌐 ADVANCED SUBDOMAIN ENUMERATION & DISCOVERY SCANNER"
        self.version = "3.5"
        self.author = "Security Research Team"
        
        # Enhanced color scheme
        self.colors = {
            'banner': Fore.MAGENTA + Style.BRIGHT,
            'header': Fore.WHITE + Style.BRIGHT,
            'info': Fore.CYAN + Style.BRIGHT,
            'success': Fore.GREEN + Style.BRIGHT,
            'warning': Fore.YELLOW + Style.BRIGHT,
            'error': Fore.RED + Style.BRIGHT,
            'critical': Back.RED + Fore.WHITE + Style.BRIGHT,
            'subdomain': Fore.CYAN + Style.BRIGHT,
            'ip': Fore.GREEN + Style.NORMAL,
            'dns': Fore.BLUE + Style.BRIGHT,
            'wildcard': Fore.MAGENTA + Style.BRIGHT,
            'service': Fore.YELLOW + Style.BRIGHT,
            'cloud': Fore.LIGHTCYAN_EX + Style.BRIGHT,
            'cdn': Fore.LIGHTMAGENTA_EX + Style.BRIGHT,
            'timestamp': Fore.LIGHTBLACK_EX,
            'separator': Fore.LIGHTBLACK_EX + Style.DIM,
            'highlight': Fore.YELLOW + Back.BLACK + Style.BRIGHT,
            'progress': Fore.GREEN + Style.NORMAL,
            'counter': Fore.LIGHTBLUE_EX + Style.BRIGHT,
            'stats': Fore.LIGHTGREEN_EX + Style.BRIGHT
        }
        
        # Comprehensive subdomain wordlist
        self.subdomain_wordlist = {
            'common': [
                'www', 'mail', 'ftp', 'smtp', 'pop', 'pop3', 'imap', 'webmail',
                'admin', 'adminpanel', 'administrator', 'backend', 'dashboard',
                'api', 'api1', 'api2', 'api3', 'restapi', 'graphql',
                'dev', 'development', 'staging', 'test', 'testing', 'qa',
                'prod', 'production', 'live', 'uat', 'demo',
                'mobile', 'm', 'wap', 'app', 'apps', 'application',
                'static', 'cdn', 'assets', 'media', 'images', 'img', 'video',
                'blog', 'news', 'forum', 'community', 'support', 'help',
                'shop', 'store', 'cart', 'checkout', 'payment', 'billing',
                'secure', 'ssl', 'vpn', 'remote', 'ssh', 'ftp', 'sftp',
                'ns', 'ns1', 'ns2', 'ns3', 'ns4', 'dns', 'dns1', 'dns2',
                'mx', 'mx1', 'mx2', 'mx3', 'mail1', 'mail2', 'mail3',
                'cpanel', 'whm', 'plesk', 'webdisk', 'webadmin',
                'search', 'search1', 'search2', 'elasticsearch',
                'db', 'database', 'mysql', 'postgres', 'mongodb', 'redis',
                'git', 'svn', 'jenkins', 'jenkins1', 'jenkins2',
                'monitor', 'monitoring', 'nagios', 'zabbix', 'grafana',
                'stats', 'statistics', 'analytics', 'tracking', 'metrics',
                'log', 'logs', 'logger', 'logging', 'kibana',
                'backup', 'backups', 'archive', 'archives',
                'cloud', 'cloud1', 'cloud2', 'aws', 'azure', 'gcp',
                'vpn', 'vpn1', 'vpn2', 'proxy', 'proxy1', 'proxy2',
                'firewall', 'fw', 'ids', 'ips', 'waf',
                'auth', 'authentication', 'login', 'signin', 'signup',
                'account', 'accounts', 'user', 'users', 'profile',
                'client', 'clients', 'customer', 'customers',
                'partner', 'partners', 'vendor', 'vendors',
                'service', 'services', 'microservice', 'microservices',
                'internal', 'private', 'secret', 'hidden', 'internal-api',
                'beta', 'alpha', 'gamma', 'delta', 'epsilon',
                'temp', 'temporary', 'tmp', 'temp1', 'temp2',
                'old', 'new', 'legacy', 'archive', 'historical',
                'file', 'files', 'share', 'shared', 'fileshare',
                'download', 'downloads', 'upload', 'uploads',
                'stream', 'streaming', 'video', 'audio', 'media',
                'chat', 'messaging', 'message', 'im',
                'docs', 'documentation', 'wiki', 'knowledgebase',
                'status', 'statuspage', 'uptime', 'downtime',
                'portal', 'intranet', 'extranet', 'vpn-access',
                'sandbox', 'playground', 'experiment', 'experimental',
                'autodiscover', 'autoconfig', 'exchange', 'owa', 'ews'
            ],
            
            'cloud': [
                'aws', 's3', 's3-website', 'cloudfront', 'elasticbeanstalk',
                'azure', 'blob', 'table', 'queue', 'file',
                'gcp', 'google', 'appengine', 'cloudfunctions',
                'cloud', 'cloudapp', 'cloudapp.net', 'cloudapps',
                'heroku', 'herokuapp', 'appspot', 'azurewebsites',
                'digitalocean', 'do', 'linode', 'vultr',
                'rackspace', 'rackspacecloud', 'cloudrackspace',
                'oraclecloud', 'oracle', 'ocp', 'oci'
            ],
            
            'cdn': [
                'cdn', 'cdn1', 'cdn2', 'cdn3', 'cdn4',
                'akamai', 'akamaiedge', 'akadns',
                'cloudflare', 'cf', 'cftest', 'cdn.cloudflare',
                'fastly', 'fastlylb', 'fastly.net',
                'incapdns', 'incapsula', 'imperva',
                'stackpath', 'stackpathcdn', 'stackpath.net',
                'keycdn', 'keycdns', 'kxcdn',
                'bunnycdn', 'bunny.net', 'bunnycdn.net',
                'cache', 'cache1', 'cache2', 'edge', 'edge1', 'edge2'
            ],
            
            'services': [
                'jenkins', 'jenkins1', 'jenkins2',
                'gitlab', 'gitlab-ci', 'gitlab-runner',
                'github', 'github-pages', 'github.io',
                'bitbucket', 'bitbucket.io',
                'jira', 'confluence', 'atlassian',
                'slack', 'slack-webhook', 'slack-bot',
                'teams', 'teams-api', 'teams-webhook',
                'zoom', 'zoom.us', 'zoom-cdn',
                'docker', 'docker-registry', 'registry',
                'kubernetes', 'k8s', 'kube', 'kubeapi',
                'ansible', 'ansible-tower', 'tower',
                'puppet', 'puppetmaster', 'puppetdb',
                'chef', 'chef-server', 'chef-automate',
                'splunk', 'splunk-forwarder', 'splunk-indexer',
                'elk', 'elasticsearch', 'logstash', 'kibana',
                'grafana', 'prometheus', 'alertmanager',
                'zabbix', 'nagios', 'icinga', 'observium',
                'wordpress', 'wp', 'wp-admin', 'wp-content',
                'joomla', 'joomla-admin', 'joomla-backend',
                'drupal', 'drupal-admin', 'drupal-backend',
                'magento', 'magento-admin', 'magento-backend',
                'shopify', 'shopify-admin', 'shopify-backend',
                'prestashop', 'prestashop-admin'
            ],
            
            'geographic': [
                'us', 'usa', 'americas', 'na', 'northamerica',
                'eu', 'europe', 'emea', 'europe-west', 'europe-east',
                'asia', 'apac', 'asia-pacific', 'asia-east', 'asia-south',
                'au', 'australia', 'oceania', 'anz',
                'uk', 'unitedkingdom', 'gb', 'greatbritain',
                'de', 'germany', 'fr', 'france', 'it', 'italy',
                'es', 'spain', 'nl', 'netherlands', 'se', 'sweden',
                'jp', 'japan', 'cn', 'china', 'in', 'india',
                'br', 'brazil', 'mx', 'mexico', 'ca', 'canada',
                'ru', 'russia', 'kr', 'korea', 'sg', 'singapore',
                'hk', 'hongkong', 'tw', 'taiwan', 'ae', 'uae'
            ],
            
            'tech': [
                'node', 'nodejs', 'express', 'nestjs',
                'python', 'django', 'flask', 'fastapi',
                'java', 'spring', 'springboot', 'tomcat',
                'php', 'laravel', 'symfony', 'codeigniter',
                'ruby', 'rails', 'sinatra', 'rack',
                'go', 'golang', 'gin', 'echo',
                'dotnet', 'aspnet', 'iis', 'netcore',
                'react', 'vue', 'angular', 'svelte',
                'graphql', 'rest', 'soap', 'grpc',
                'redis', 'memcached', 'rabbitmq', 'kafka',
                'mongodb', 'couchdb', 'cassandra', 'dynamodb',
                'mysql', 'postgres', 'mariadb', 'sqlserver',
                'nginx', 'apache', 'lighttpd', 'caddy',
                'haproxy', 'traefik', 'kong', 'nginx-plus'
            ]
        }
        
        # DNS record types to check
        self.dns_record_types = {
            'A': {'priority': 1, 'description': 'IPv4 Address'},
            'AAAA': {'priority': 2, 'description': 'IPv6 Address'},
            'CNAME': {'priority': 3, 'description': 'Canonical Name'},
            'MX': {'priority': 4, 'description': 'Mail Exchange'},
            'TXT': {'priority': 5, 'description': 'Text Records'},
            'NS': {'priority': 6, 'description': 'Name Server'},
            'SRV': {'priority': 7, 'description': 'Service Record'},
            'PTR': {'priority': 8, 'description': 'Pointer Record'},
            'SOA': {'priority': 9, 'description': 'Start of Authority'}
        }
        
        # Common DNS servers to use
        self.dns_servers = [
            '8.8.8.8',        # Google DNS
            '8.8.4.4',        # Google DNS Secondary
            '1.1.1.1',        # Cloudflare DNS
            '1.0.0.1',        # Cloudflare DNS Secondary
            '9.9.9.9',        # Quad9 DNS
            '208.67.222.222', # OpenDNS
            '208.67.220.220'  # OpenDNS Secondary
        ]
        
        # Service detection ports and banners
        self.service_detection = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            111: 'RPC',
            135: 'MSRPC',
            139: 'NetBIOS',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            465: 'SMTPS',
            587: 'SMTP Submission',
            993: 'IMAPS',
            995: 'POP3S',
            1433: 'MSSQL',
            1521: 'Oracle',
            1723: 'PPTP',
            2049: 'NFS',
            2082: 'cPanel',
            2083: 'cPanel SSL',
            2086: 'WHM',
            2087: 'WHM SSL',
            2095: 'Webmail',
            2096: 'Webmail SSL',
            2181: 'Zookeeper',
            2375: 'Docker',
            2376: 'Docker SSL',
            2483: 'Oracle DB',
            2484: 'Oracle DB SSL',
            3000: 'Node.js',
            3306: 'MySQL',
            3389: 'RDP',
            3690: 'SVN',
            4000: 'Ruby on Rails',
            4040: 'Spark',
            4200: 'Angular',
            4505: 'Salt',
            4506: 'Salt',
            4789: 'Docker Swarm',
            5000: 'Flask',
            5432: 'PostgreSQL',
            5601: 'Kibana',
            5672: 'RabbitMQ',
            5900: 'VNC',
            5984: 'CouchDB',
            6379: 'Redis',
            6443: 'Kubernetes',
            6666: 'IRC',
            7001: 'WebLogic',
            7077: 'Spark',
            7200: 'Cassandra',
            7687: 'Neo4j',
            8000: 'HTTP Alt',
            8008: 'HTTP Alt',
            8080: 'HTTP Proxy',
            8081: 'HTTP Alt',
            8088: 'HTTP Alt',
            8090: 'HTTP Alt',
            8091: 'Couchbase',
            8140: 'Puppet',
            8181: 'HTTP Alt',
            8200: 'Vault',
            8443: 'HTTPS Alt',
            8500: 'Consul',
            8600: 'Consul',
            8761: 'Eureka',
            8848: 'Nacos',
            8888: 'HTTP Alt',
            9000: 'SonarQube',
            9001: 'HTTP Alt',
            9042: 'Cassandra',
            9092: 'Kafka',
            9100: 'Prometheus Node',
            9200: 'Elasticsearch',
            9300: 'Elasticsearch',
            9418: 'Git',
            9999: 'HTTP Alt',
            10000: 'Webmin',
            11211: 'Memcached',
            15672: 'RabbitMQ Mgmt',
            27017: 'MongoDB',
            28015: 'RethinkDB',
            50070: 'Hadoop',
            50075: 'Hadoop',
            61616: 'ActiveMQ'
        }
        
        # Common cloud providers and their IP ranges
        self.cloud_providers = {
            'aws': [
                'amazonaws.com',
                'aws.amazon.com',
                'awsdns',
                'cloudfront.net',
                'elasticbeanstalk.com'
            ],
            'azure': [
                'azure.com',
                'azureedge.net',
                'azurewebsites.net',
                'cloudapp.net'
            ],
            'gcp': [
                'google.com',
                'googleusercontent.com',
                'cloud.google.com',
                'appspot.com'
            ],
            'cloudflare': [
                'cloudflare.com',
                'cloudflare.net',
                'cf.torch',
                'challenges.cloudflare.com'
            ],
            'akamai': [
                'akamaiedge.net',
                'akamai.net',
                'akamaitechnologies.com'
            ],
            'fastly': [
                'fastly.net',
                'fastlylb.net'
            ]
        }
        
        # Scanner configuration
        self.max_threads = 50
        self.dns_timeout = 3
        self.port_scan_timeout = 2
        self.wildcard_check_enabled = True
        self.service_detection_enabled = True
        self.cloud_detection_enabled = True
        
        # Results storage
        self.results_queue = queue.Queue()
        self.found_subdomains = set()
        self.stats = defaultdict(int)
        
        # Progress tracking
        self.scanning_active = False
        self.total_tested = 0
        self.total_found = 0

    def print_banner(self):
        """Display enhanced scanner banner"""
        banner = f"""
{self.colors['banner']}{"="*100}
{self.colors['header']}╔══════════════════════════════════════════════════════════════════════════════════╗
║ {self.colors['banner']}{self.name:^88} {self.colors['header']}║
║ {self.colors['info']}Version: {self.version:<78} {self.colors['header']}║
║ {self.colors['info']}Author: {self.author:<78} {self.colors['header']}║
╚══════════════════════════════════════════════════════════════════════════════════╝
{self.colors['banner']}{"="*100}
"""
        print(banner)

    def print_status(self, message, level="info", indent=0, subdomain=None):
        """Print colored status messages with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        prefix = {
            "info": f"{self.colors['info']}[ℹ]",
            "success": f"{self.colors['success']}[✓]",
            "warning": f"{self.colors['warning']}[⚠]",
            "error": f"{self.colors['error']}[✗]",
            "critical": f"{self.colors['critical']}[‼]",
            "subdomain": f"{self.colors['subdomain']}[🌐]",
            "dns": f"{self.colors['dns']}[🔍]",
            "wildcard": f"{self.colors['wildcard']}[🎯]",
            "service": f"{self.colors['service']}[🔧]",
            "cloud": f"{self.colors['cloud']}[☁️]",
            "cdn": f"{self.colors['cdn']}[🚀]",
            "scan": f"{self.colors['info']}[🔍]",
            "stats": f"{self.colors['stats']}[📊]"
        }.get(level, f"{self.colors['info']}[*]")
        
        indent_str = "  " * indent
        subdomain_str = f" {self.colors['subdomain']}{subdomain}" if subdomain else ""
        print(f"{self.colors['timestamp']}[{timestamp}] {prefix}{Style.RESET_ALL} {indent_str}{message}{subdomain_str}")

    def extract_domain(self, target):
        """Extract domain from URL or input"""
        # Remove protocol if present
        if '://' in target:
            target = target.split('://', 1)[1]
        
        # Remove path and query
        target = target.split('/', 1)[0]
        
        # Remove port if present
        if ':' in target:
            target = target.split(':', 1)[0]
        
        # Handle IP addresses
        try:
            socket.inet_aton(target)
            return None  # Return None for IP addresses
        except socket.error:
            pass
        
        # Extract base domain (remove subdomains)
        parts = target.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return target

    def scan(self, target, options=None):
        """Comprehensive subdomain enumeration scanning"""
        self.print_banner()
        
        results = {
            'target': target,
            'base_domain': None,
            'subdomains_found': [],
            'dns_records': defaultdict(list),
            'services_detected': [],
            'cloud_detected': [],
            'wildcard_dns': False,
            'stats': {
                'total_tested': 0,
                'total_found': 0,
                'start_time': time.time(),
                'end_time': None,
                'duration': None
            }
        }
        
        try:
            # Extract base domain
            base_domain = self.extract_domain(target)
            if not base_domain:
                self.print_status(f"Invalid domain: {target}", "error")
                return results
            
            results['base_domain'] = base_domain
            
            self.print_status(f"Initiating subdomain enumeration for: {self.colors['highlight']}{base_domain}", "info")
            
            # Phase 1: Check for wildcard DNS
            if self.wildcard_check_enabled:
                self.print_status("Phase 1: Checking for wildcard DNS...", "scan")
                wildcard_info = self.check_wildcard_dns(base_domain)
                results['wildcard_dns'] = wildcard_info['enabled']
                if wildcard_info['enabled']:
                    self.print_status(f"Wildcard DNS detected! IPs: {', '.join(wildcard_info['ips'])}", "wildcard")
            
            # Phase 2: Generate subdomain list
            self.print_status("Phase 2: Generating subdomain wordlist...", "scan")
            subdomain_list = self.generate_subdomain_list(base_domain)
            self.print_status(f"Generated {len(subdomain_list)} subdomains to test", "success")
            
            # Phase 3: DNS enumeration
            self.print_status("Phase 3: Performing DNS enumeration...", "scan")
            dns_results = self.perform_dns_enumeration(subdomain_list, base_domain)
            results['subdomains_found'] = dns_results['found']
            results['dns_records'] = dns_results['records']
            results['stats']['total_tested'] = dns_results['stats']['tested']
            results['stats']['total_found'] = len(dns_results['found'])
            
            # Phase 4: Service detection
            if self.service_detection_enabled and dns_results['found']:
                self.print_status("Phase 4: Detecting services...", "scan")
                service_results = self.detect_services(dns_results['found'])
                results['services_detected'] = service_results
            
            # Phase 5: Cloud provider detection
            if self.cloud_detection_enabled and dns_results['found']:
                self.print_status("Phase 5: Detecting cloud providers...", "scan")
                cloud_results = self.detect_cloud_providers(dns_results['found'])
                results['cloud_detected'] = cloud_results
            
            # Phase 6: Additional enumeration techniques
            self.print_status("Phase 6: Additional enumeration techniques...", "scan")
            additional_results = self.perform_additional_enumeration(base_domain)
            if additional_results:
                # Merge additional findings
                for subdomain in additional_results:
                    if subdomain not in [s['subdomain'] for s in results['subdomains_found']]:
                        results['subdomains_found'].append(subdomain)
                        results['stats']['total_found'] += 1
            
            # Complete scan
            results['stats']['end_time'] = time.time()
            results['stats']['duration'] = results['stats']['end_time'] - results['stats']['start_time']
            
            # Print comprehensive report
            self.print_summary(results)
            
            return results
            
        except Exception as e:
            self.print_status(f"Scan error: {str(e)}", "error")
            results['error'] = str(e)
            results['stats']['end_time'] = time.time()
            return results

    def generate_subdomain_list(self, base_domain):
        """Generate comprehensive subdomain list"""
        subdomain_list = []
        
        # Combine all wordlists
        for category, wordlist in self.subdomain_wordlist.items():
            for word in wordlist:
                # Create subdomain
                subdomain = f"{word}.{base_domain}"
                subdomain_list.append(subdomain)
        
        # Add permutations
        permutations = self.generate_permutations(base_domain)
        subdomain_list.extend(permutations)
        
        # Remove duplicates
        return list(set(subdomain_list))

    def generate_permutations(self, base_domain):
        """Generate subdomain permutations"""
        permutations = []
        
        # Common patterns
        patterns = [
            'dev-{word}',
            'stg-{word}',
            'prod-{word}',
            'test-{word}',
            'qa-{word}',
            '{word}-dev',
            '{word}-staging',
            '{word}-prod',
            '{word}-test',
            '{word}-qa',
            '{word}1',
            '{word}2',
            '{word}3',
            '{word}-api',
            'api-{word}',
            'svc-{word}',
            '{word}-svc'
        ]
        
        # Use common words for permutations
        common_words = ['www', 'api', 'app', 'web', 'mail', 'admin', 'test', 'dev']
        
        for pattern in patterns:
            for word in common_words:
                subdomain_word = pattern.format(word=word)
                permutations.append(f"{subdomain_word}.{base_domain}")
        
        return list(set(permutations))

    def check_wildcard_dns(self, domain):
        """Check for wildcard DNS configuration"""
        result = {
            'enabled': False,
            'ips': []
        }
        
        try:
            # Generate random subdomain
            random_string = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=16))
            test_domain = f"{random_string}.{domain}"
            
            # Try multiple DNS servers
            for dns_server in self.dns_servers[:3]:
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.nameservers = [dns_server]
                    resolver.timeout = self.dns_timeout
                    resolver.lifetime = self.dns_timeout
                    
                    answers = resolver.resolve(test_domain, 'A')
                    
                    for answer in answers:
                        ip = str(answer)
                        if ip not in result['ips']:
                            result['ips'].append(ip)
                    
                    if answers:
                        result['enabled'] = True
                        break
                    
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                    continue
                except Exception as e:
                    continue
        
        except Exception as e:
            pass
        
        return result

    def perform_dns_enumeration(self, subdomain_list, base_domain):
        """Perform DNS enumeration for subdomains"""
        results = {
            'found': [],
            'records': defaultdict(list),
            'stats': {
                'tested': 0,
                'found': 0
            }
        }
        
        self.scanning_active = True
        self.total_tested = 0
        self.total_found = 0
        
        # Create thread pool
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Submit tasks
            future_to_subdomain = {
                executor.submit(self.resolve_subdomain, subdomain): subdomain 
                for subdomain in subdomain_list[:2000]  # Limit to 2000 for performance
            }
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_subdomain):
                subdomain = future_to_subdomain[future]
                
                try:
                    dns_info = future.result(timeout=self.dns_timeout + 2)
                    results['stats']['tested'] += 1
                    self.total_tested = results['stats']['tested']
                    
                    if dns_info and dns_info['records']:
                        results['found'].append(dns_info)
                        results['stats']['found'] += 1
                        self.total_found = results['stats']['found']
                        
                        # Store records
                        for record_type, values in dns_info['records'].items():
                            for value in values:
                                results['records'][record_type].append({
                                    'subdomain': subdomain,
                                    'value': value
                                })
                        
                        # Print found subdomain
                        self.print_status(f"Found: {subdomain}", "subdomain")
                        for record_type, values in dns_info['records'].items():
                            for value in values[:2]:  # Show first 2 values
                                self.print_status(f"  {record_type}: {value}", "dns", 1)
                    
                    # Update progress
                    if results['stats']['tested'] % 100 == 0:
                        self.print_progress(results['stats']['tested'], len(subdomain_list))
                
                except concurrent.futures.TimeoutError:
                    continue
                except Exception as e:
                    continue
        
        self.scanning_active = False
        return results

    def resolve_subdomain(self, subdomain):
        """Resolve DNS records for a subdomain"""
        result = {
            'subdomain': subdomain,
            'records': defaultdict(list),
            'resolved': False
        }
        
        try:
            # Try multiple DNS servers
            for dns_server in self.dns_servers[:2]:
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.nameservers = [dns_server]
                    resolver.timeout = self.dns_timeout
                    resolver.lifetime = self.dns_timeout
                    
                    # Try A records first (most common)
                    try:
                        answers = resolver.resolve(subdomain, 'A')
                        for answer in answers:
                            result['records']['A'].append(str(answer))
                        result['resolved'] = True
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                        pass
                    
                    # Try CNAME records
                    try:
                        answers = resolver.resolve(subdomain, 'CNAME')
                        for answer in answers:
                            result['records']['CNAME'].append(str(answer.target).rstrip('.'))
                        result['resolved'] = True
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                        pass
                    
                    # Try AAAA records
                    try:
                        answers = resolver.resolve(subdomain, 'AAAA')
                        for answer in answers:
                            result['records']['AAAA'].append(str(answer))
                        result['resolved'] = True
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                        pass
                    
                    # If any record found, break
                    if result['resolved']:
                        break
                    
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                    continue
                except Exception as e:
                    continue
        
        except Exception as e:
            pass
        
        return result

    def print_progress(self, current, total):
        """Print scanning progress"""
        progress = (current / total) * 100
        
        # Create progress bar
        bar_length = 30
        filled_length = int(bar_length * progress / 100)
        bar = f"{self.colors['success']}{'█' * filled_length}" + \
              f"{self.colors['progress']}{'░' * (bar_length - filled_length)}"
        
        sys.stdout.write(f"\r{self.colors['progress']}[Progress] {bar} {progress:.1f}% | "
                       f"Tested: {current}/{total} | "
                       f"Found: {self.total_found}")
        sys.stdout.flush()

    def detect_services(self, subdomains):
        """Detect services running on subdomains"""
        services = []
        
        if not subdomains:
            return services
        
        self.print_status(f"Detecting services on {len(subdomains)} subdomains...", "service", 1)
        
        # Limit to first 50 subdomains for performance
        subdomains_to_scan = subdomains[:50]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            future_to_subdomain = {
                executor.submit(self.scan_ports, subdomain_info): subdomain_info 
                for subdomain_info in subdomains_to_scan
            }
            
            for future in concurrent.futures.as_completed(future_to_subdomain):
                subdomain_info = future_to_subdomain[future]
                
                try:
                    port_results = future.result(timeout=10)
                    if port_results:
                        for port_result in port_results:
                            services.append({
                                'subdomain': subdomain_info['subdomain'],
                                'ip': subdomain_info['records'].get('A', [''])[0] if subdomain_info['records'].get('A') else '',
                                'port': port_result['port'],
                                'service': port_result['service'],
                                'banner': port_result.get('banner', '')
                            })
                            
                            self.print_status(f"{subdomain_info['subdomain']}:{port_result['port']} - {port_result['service']}", "service", 2)
                
                except concurrent.futures.TimeoutError:
                    continue
                except Exception as e:
                    continue
        
        return services

    def scan_ports(self, subdomain_info):
        """Scan common ports on subdomain"""
        port_results = []
        
        if not subdomain_info['records'].get('A'):
            return port_results
        
        ip = subdomain_info['records']['A'][0]
        
        # Scan common ports
        common_ports = [80, 443, 22, 21, 25, 110, 143, 993, 995, 3306, 5432, 27017]
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.port_scan_timeout)
                
                result = sock.connect_ex((ip, port))
                
                if result == 0:
                    # Try to get banner
                    banner = ''
                    try:
                        sock.send(b'\r\n\r\n')
                        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    except:
                        pass
                    
                    service_name = self.service_detection.get(port, f'Unknown ({port})')
                    
                    port_results.append({
                        'port': port,
                        'service': service_name,
                        'banner': banner[:100]  # Limit banner length
                    })
                
                sock.close()
                
            except Exception as e:
                continue
        
        return port_results

    def detect_cloud_providers(self, subdomains):
        """Detect cloud providers and CDNs"""
        cloud_results = []
        
        if not subdomains:
            return cloud_results
        
        self.print_status("Detecting cloud providers and CDNs...", "cloud", 1)
        
        for subdomain_info in subdomains[:100]:  # Limit to first 100
            subdomain = subdomain_info['subdomain']
            
            # Check CNAME records
            cnames = subdomain_info['records'].get('CNAME', [])
            for cname in cnames:
                for provider, patterns in self.cloud_providers.items():
                    for pattern in patterns:
                        if pattern in cname:
                            cloud_results.append({
                                'subdomain': subdomain,
                                'provider': provider,
                                'evidence': cname,
                                'type': 'CNAME'
                            })
                            
                            self.print_status(f"{subdomain} → {provider} ({cname})", "cloud", 2)
                            break
        
        return cloud_results

    def perform_additional_enumeration(self, base_domain):
        """Perform additional enumeration techniques"""
        additional_findings = []
        
        # Technique 1: Check common patterns
        common_patterns = [
            f"*.{base_domain}",
            f"mail.{base_domain}",
            f"webmail.{base_domain}",
            f"admin.{base_domain}",
            f"api.{base_domain}",
            f"staging.{base_domain}",
            f"dev.{base_domain}",
            f"test.{base_domain}",
            f"prod.{base_domain}",
            f"mobile.{base_domain}",
            f"m.{base_domain}",
            f"cdn.{base_domain}",
            f"static.{base_domain}"
        ]
        
        self.print_status("Checking common patterns...", "scan", 1)
        
        for pattern in common_patterns:
            if pattern not in self.found_subdomains:
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.timeout = self.dns_timeout
                    
                    answers = resolver.resolve(pattern, 'A')
                    
                    if answers:
                        additional_findings.append({
                            'subdomain': pattern,
                            'records': {'A': [str(answer) for answer in answers]}
                        })
                        
                        self.print_status(f"Found via pattern: {pattern}", "subdomain", 2)
                
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    pass
                except Exception as e:
                    pass
        
        return additional_findings

    def print_summary(self, results):
        """Print comprehensive scan summary"""
        duration = results['stats'].get('duration', 0)
        
        summary = f"""
{self.colors['separator']}{"="*100}
{self.colors['header']}📊 SUBDOMAIN ENUMERATION SUMMARY
{self.colors['separator']}{"-"*100}
{self.colors['info']}Target Domain:        {results['base_domain']}
{self.colors['info']}Scan Duration:        {duration:.2f} seconds
{self.colors['info']}Subdomains Tested:    {results['stats']['total_tested']}
{self.colors['info']}Subdomains Found:     {results['stats']['total_found']}
{self.colors['info']}Wildcard DNS:         {'Yes' if results['wildcard_dns'] else 'No'}
{self.colors['separator']}{"-"*100}
"""
        print(summary)
        
        # Print subdomains found
        if results['subdomains_found']:
            print(f"\n{self.colors['header']}🌐 DISCOVERED SUBDOMAINS ({len(results['subdomains_found'])}):")
            print(f"{self.colors['separator']}{'-'*100}")
            
            # Group by record type
            for i, subdomain_info in enumerate(results['subdomains_found'][:20], 1):  # Show first 20
                print(f"{self.colors['counter']}{i:3d}. {self.colors['subdomain']}{subdomain_info['subdomain']}")
                
                # Print IP addresses
                if subdomain_info['records'].get('A'):
                    ips = ', '.join(subdomain_info['records']['A'][:3])  # Show first 3 IPs
                    print(f"{self.colors['ip']}     IPv4: {ips}")
                
                # Print CNAME records
                if subdomain_info['records'].get('CNAME'):
                    cnames = ', '.join(subdomain_info['records']['CNAME'][:2])  # Show first 2 CNAMEs
                    print(f"{self.colors['dns']}     CNAME: {cnames}")
                
                # Print AAAA records
                if subdomain_info['records'].get('AAAA'):
                    ipv6s = ', '.join(subdomain_info['records']['AAAA'][:2])  # Show first 2 IPv6s
                    print(f"{self.colors['dns']}     IPv6: {ipv6s}")
                
                if i < min(20, len(results['subdomains_found'])):
                    print(f"{self.colors['separator']}{'-'*60}")
        
        # Print services detected
        if results['services_detected']:
            print(f"\n{self.colors['header']}🔧 DETECTED SERVICES ({len(results['services_detected'])}):")
            print(f"{self.colors['separator']}{'-'*100}")
            
            for i, service in enumerate(results['services_detected'][:10], 1):
                print(f"{self.colors['service']}▶ {i}. {service['subdomain']}:{service['port']}")
                print(f"{self.colors['info']}   Service: {service['service']}")
                print(f"{self.colors['info']}   IP: {service['ip']}")
                if service['banner']:
                    print(f"{self.colors['info']}   Banner: {service['banner'][:80]}...")
                
                if i < min(10, len(results['services_detected'])):
                    print(f"{self.colors['separator']}{'-'*40}")
        
        # Print cloud providers detected
        if results['cloud_detected']:
            print(f"\n{self.colors['header']}☁️  DETECTED CLOUD PROVIDERS ({len(results['cloud_detected'])}):")
            print(f"{self.colors['separator']}{'-'*100}")
            
            # Group by provider
            providers = {}
            for detection in results['cloud_detected']:
                provider = detection['provider']
                if provider not in providers:
                    providers[provider] = []
                providers[provider].append(detection)
            
            for provider, detections in providers.items():
                color = self.colors.get('cloud', Fore.CYAN)
                print(f"{color}{provider.upper()} ({len(detections)}):")
                for detection in detections[:3]:  # Show first 3 per provider
                    print(f"{self.colors['info']}  • {detection['subdomain']} → {detection['evidence']}")
                if len(detections) > 3:
                    print(f"{self.colors['info']}  • ... and {len(detections) - 3} more")
                print()
        
        # Print statistics by record type
        if results['dns_records']:
            print(f"\n{self.colors['header']}📊 DNS RECORD STATISTICS:")
            print(f"{self.colors['separator']}{'-'*100}")
            
            for record_type, records in results['dns_records'].items():
                unique_count = len(set(r['subdomain'] for r in records))
                print(f"{self.colors['stats']}{record_type:8}: {unique_count:4d} subdomains | {len(records):4d} total records")
        
        # Print recommendations
        recommendations = self.generate_recommendations(results)
        if recommendations:
            print(f"\n{self.colors['header']}💡 RECOMMENDATIONS:")
            print(f"{self.colors['separator']}{'-'*100}")
            
            for i, rec in enumerate(recommendations, 1):
                priority_color = {
                    'high': Fore.RED + Style.BRIGHT,
                    'medium': Fore.YELLOW + Style.BRIGHT,
                    'low': Fore.BLUE + Style.BRIGHT
                }.get(rec['priority'], Fore.WHITE)
                
                print(f"{priority_color}{i}. [{rec['priority'].upper()}] {rec['title']}")
                print(f"{self.colors['info']}   {rec['description']}")
                print()
        
        # Final status
        if results['wildcard_dns']:
            print(f"{self.colors['warning']}⚠ Wildcard DNS detected. Results may include false positives.")
        
        if results['stats']['total_found'] > 0:
            print(f"{self.colors['success']}✅ Subdomain enumeration completed successfully!")
            print(f"{self.colors['stats']}📈 Found {results['stats']['total_found']} subdomains in {duration:.2f} seconds")
        else:
            print(f"{self.colors['warning']}⚠ No subdomains found. Consider expanding the wordlist or trying different techniques.")
        
        print(f"{self.colors['separator']}{'='*100}\n")

    def generate_recommendations(self, results):
        """Generate targeted recommendations"""
        recommendations = []
        
        if results['wildcard_dns']:
            recommendations.append({
                'priority': 'medium',
                'title': 'Review Wildcard DNS',
                'description': 'Consider restricting wildcard DNS to prevent unauthorized subdomain discovery'
            })
        
        if results['services_detected']:
            exposed_services = [s for s in results['services_detected'] 
                              if s['port'] in [21, 22, 23, 25, 143, 3306, 5432, 27017]]
            if exposed_services:
                recommendations.append({
                    'priority': 'high',
                    'title': 'Secure Exposed Services',
                    'description': f'Secure {len(exposed_services)} exposed services (FTP, SSH, Databases, etc.)'
                })
        
        if results['stats']['total_found'] > 50:
            recommendations.append({
                'priority': 'medium',
                'title': 'Monitor Subdomains',
                'description': 'Implement subdomain monitoring to detect unauthorized additions'
            })
        
        # General recommendations
        recommendations.extend([
            {
                'priority': 'low',
                'title': 'Regular Subdomain Audits',
                'description': 'Perform regular subdomain enumeration to maintain visibility'
            },
            {
                'priority': 'medium',
                'title': 'Implement DNS Security',
                'description': 'Consider DNSSEC and DNS monitoring solutions'
            }
        ])
        
        return recommendations

    def export_results(self, results, format='json', filename=None):
        """Export scan results to file"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"subdomain_scan_{results['base_domain']}_{timestamp}.{format}"
        
        try:
            if format.lower() == 'json':
                # Prepare data for JSON export
                export_data = {
                    'scan_info': {
                        'target': results['target'],
                        'base_domain': results['base_domain'],
                        'timestamp': datetime.now().isoformat(),
                        'duration': results['stats']['duration'],
                        'total_found': results['stats']['total_found']
                    },
                    'subdomains': results['subdomains_found'],
                    'services': results['services_detected'],
                    'cloud_providers': results['cloud_detected']
                }
                
                with open(filename, 'w') as f:
                    json.dump(export_data, f, indent=2, default=str)
                
                self.print_status(f"Results exported to {filename}", "success")
                return True
                
            elif format.lower() == 'txt':
                # Simple text export
                with open(filename, 'w') as f:
                    f.write(f"Subdomain Scan Results for {results['base_domain']}\n")
                    f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Total Found: {results['stats']['total_found']}\n\n")
                    
                    f.write("SUB DOMAINS:\n")
                    f.write("=" * 80 + "\n")
                    for subdomain_info in results['subdomains_found']:
                        f.write(f"{subdomain_info['subdomain']}\n")
                        if subdomain_info['records'].get('A'):
                            f.write(f"  IPs: {', '.join(subdomain_info['records']['A'])}\n")
                        if subdomain_info['records'].get('CNAME'):
                            f.write(f"  CNAME: {', '.join(subdomain_info['records']['CNAME'])}\n")
                        f.write("\n")
                
                self.print_status(f"Results exported to {filename}", "success")
                return True
                
            else:
                self.print_status(f"Unsupported format: {format}", "error")
                return False
                
        except Exception as e:
            self.print_status(f"Failed to export results: {e}", "error")
            return False

# Example usage
if __name__ == "__main__":
    scanner = SubdomainScanner()
    
    # Configure scanner
    scanner.max_threads = 30
    scanner.dns_timeout = 2
    scanner.service_detection_enabled = True
    
    # Run scan
    target_url = "example.com"
    results = scanner.scan(target_url)
    
    # Export results
    scanner.export_results(results, format='json', filename='subdomain_results.json')
    scanner.export_results(results, format='txt', filename='subdomain_results.txt')
    
    # Additional statistics
    print(f"\n{Fore.CYAN}Scanner Statistics:")
    print(f"{Fore.CYAN}• Wordlist size: {sum(len(wl) for wl in scanner.subdomain_wordlist.values())}")
    print(f"{Fore.CYAN}• Service ports: {len(scanner.service_detection)}")
    print(f"{Fore.CYAN}• Cloud providers: {len(scanner.cloud_providers)}")