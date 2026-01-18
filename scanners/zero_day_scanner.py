import time
import socket
import ssl
import struct
import json
import re
import hashlib
import random
import ipaddress
from datetime import datetime, timedelta
from colorama import Fore, Style, Back, init
from urllib.parse import urlparse, urlunparse
import concurrent.futures

# Initialize colorama
init(autoreset=True)

class ZeroDayScanner:
    def __init__(self):
        self.name = "🚨 ADVANCED ZERO-DAY VULNERABILITY DISCOVERY SCANNER"
        self.version = "4.2"
        self.author = "Threat Intelligence & Zero-Day Research Team"
        
        # Enhanced color scheme
        self.colors = {
            'banner': Fore.MAGENTA + Style.BRIGHT,
            'header': Fore.WHITE + Style.BRIGHT,
            'info': Fore.CYAN + Style.BRIGHT,
            'success': Fore.GREEN + Style.BRIGHT,
            'warning': Fore.YELLOW + Style.BRIGHT,
            'error': Fore.RED + Style.BRIGHT,
            'critical': Back.RED + Fore.WHITE + Style.BRIGHT,
            'zero_day': Fore.RED + Back.BLACK + Style.BRIGHT,
            'anomaly': Fore.MAGENTA + Style.BRIGHT,
            'port': Fore.BLUE + Style.BRIGHT,
            'service': Fore.GREEN + Style.NORMAL,
            'ssl': Fore.YELLOW + Style.BRIGHT,
            'header_analysis': Fore.CYAN + Style.BRIGHT,
            'behavior': Fore.LIGHTCYAN_EX + Style.BRIGHT,
            'fingerprint': Fore.LIGHTMAGENTA_EX + Style.BRIGHT,
            'timestamp': Fore.LIGHTBLACK_EX,
            'separator': Fore.LIGHTBLACK_EX + Style.DIM,
            'highlight': Fore.YELLOW + Back.BLACK + Style.BRIGHT,
            'risk': Fore.LIGHTRED_EX + Style.BRIGHT,
            'evidence': Fore.LIGHTCYAN_EX + Style.BRIGHT
        }
        
        # Comprehensive port scanning list
        self.port_categories = {
            'critical': [
                22,    # SSH
                23,    # Telnet
                21,    # FTP
                25,    # SMTP
                110,   # POP3
                143,   # IMAP
                445,   # SMB
                3389,  # RDP
                5900,  # VNC
                5432,  # PostgreSQL
                3306,  # MySQL
                1433,  # MSSQL
                27017, # MongoDB
                6379,  # Redis
                9200,  # Elasticsearch
                5601,  # Kibana
                8080,  # HTTP Proxy
                8443   # HTTPS Alt
            ],
            'common_services': [
                80,    # HTTP
                443,   # HTTPS
                53,    # DNS
                123,   # NTP
                161,   # SNMP
                389,   # LDAP
                636,   # LDAPS
                873,   # Rsync
                2049,  # NFS
                3306,  # MySQL
                5432,  # PostgreSQL
                27017, # MongoDB
                9200,  # Elasticsearch
                11211, # Memcached
                6379,  # Redis
                27017  # MongoDB
            ],
            'vulnerable_services': [
                21,    # FTP (often misconfigured)
                23,    # Telnet (clear text)
                69,    # TFTP (no auth)
                111,   # RPC
                135,   # MSRPC
                139,   # NetBIOS
                445,   # SMB
                1433,  # MSSQL
                1521,  # Oracle
                1723,  # PPTP
                2049,  # NFS
                2375,  # Docker
                2376,  # Docker SSL
                3306,  # MySQL
                5432,  # PostgreSQL
                5900,  # VNC
                5984,  # CouchDB
                6379,  # Redis
                8080,  # HTTP Proxy
                8081,  # HTTP Alt
                8443,  # HTTPS Alt
                9000,  # SonarQube
                9200,  # Elasticsearch
                27017  # MongoDB
            ],
            'backdoors_malware': [
                31337, # Back Orifice
                27374, # SubSeven
                12345, # NetBus
                12346, # NetBus
                20034, # NetBus
                6711,  # SubSeven
                6712,  # SubSeven
                6713,  # SubSeven
                6776,  # SubSeven
                666,   # Doom
                1243,  # SubSeven
                1999,  # BackDoor
                6969,  # GateCrasher
                16969, # SubSeven
                27573, # SubSeven
                27665, # SubSeven
                54283, # SubSeven
                27374  # SubSeven
            ]
        }
        
        # Security headers to check
        self.security_headers = {
            'critical': [
                'Strict-Transport-Security',
                'Content-Security-Policy',
                'X-Content-Type-Options',
                'X-Frame-Options',
                'X-XSS-Protection',
                'Referrer-Policy'
            ],
            'important': [
                'Permissions-Policy',
                'Expect-CT',
                'Feature-Policy',
                'X-Permitted-Cross-Domain-Policies',
                'X-Download-Options'
            ],
            'informational': [
                'X-Powered-By',
                'Server',
                'X-AspNet-Version',
                'X-AspNetMvc-Version',
                'X-Runtime'
            ]
        }
        
        # Weak SSL/TLS configurations
        self.weak_ssl_configs = {
            'protocols': ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1'],
            'weak_ciphers': [
                'NULL', 'EXPORT', 'DES', 'RC2', 'RC4', 'MD5',
                '3DES', 'IDEA', 'SEED', 'CAMELLIA', 'PSK',
                'SRP', 'KRB5', 'ADH', 'AECDH', 'ANON'
            ],
            'weak_curves': [
                'secp112r1', 'secp112r2', 'secp128r1', 'secp128r2',
                'secp160r1', 'secp160r2', 'secp160k1', 'sect113r1',
                'sect113r2', 'sect131r1', 'sect131r2', 'sect163r1'
            ]
        }
        
        # Anomaly detection patterns
        self.anomaly_patterns = {
            'error_leakage': [
                r'SQL syntax.*error',
                r'Warning.*mysql_.*',
                r'PostgreSQL.*ERROR',
                r'ORA-[0-9]{5}',
                r'Microsoft OLE DB',
                r'System\.Data\.SqlClient',
                r'javax\.servlet\.ServletException',
                r'java\.lang\..*Exception',
                r'Traceback.*most recent call last',
                r'File.*line.*in',
                r'PHP Warning',
                r'PHP Notice',
                r'PHP Fatal error',
                r'Stack trace:',
                r'DEBUG',
                r'Internal Server Error',
                r'ASP\.NET_SessionId',
                r'__VIEWSTATE',
                r'__EVENTVALIDATION'
            ],
            'debug_info': [
                r'X-Debug-Token',
                r'X-Debug-Token-Link',
                r'X-Powered-By:.*PHP',
                r'Server:.*Apache.*mod_',
                r'Server:.*nginx.*',
                r'X-AspNet-Version',
                r'X-AspNetMvc-Version',
                r'X-Runtime',
                r'X-Generator',
                r'X-Drupal-Cache',
                r'X-Varnish',
                r'X-Cache',
                r'X-Cacheable',
                r'X-Served-By'
            ],
            'path_traversal': [
                r'\.\./\.\./\.\./\.\./',
                r'\.\.\\\.\.\\\.\.\\\.\.\\',
                r'/etc/passwd',
                r'/etc/shadow',
                r'/proc/self/environ',
                r'C:\\Windows\\System32',
                r'file:///',
                r'php://filter',
                r'zip://',
                r'phar://',
                r'data://'
            ],
            'command_injection': [
                r';ls',
                r';cat',
                r';id',
                r';whoami',
                r';uname',
                r';ps',
                r';netstat',
                r'\|sh',
                r'\|\|sh',
                r'`.*`',
                r'\$\(.*\)',
                r'eval\(',
                r'system\(',
                r'exec\(',
                r'passthru\(',
                r'shell_exec\(',
                r'popen\(',
                r'proc_open\('
            ]
        }
        
        # Software version patterns for vulnerability correlation
        self.software_patterns = {
            'web_servers': {
                'Apache': r'Apache[/\s](\d+\.\d+(\.\d+)?)',
                'nginx': r'nginx[/\s](\d+\.\d+(\.\d+)?)',
                'IIS': r'Microsoft-IIS[/\s](\d+\.\d+)',
                'Lighttpd': r'lighttpd[/\s](\d+\.\d+(\.\d+)?)',
                'Tomcat': r'Apache-Coyote[/\s](\d+\.\d+)',
                'Jetty': r'Jetty[/\s](\d+\.\d+(\.\d+)?)'
            },
            'frameworks': {
                'PHP': r'PHP[/\s](\d+\.\d+(\.\d+)?)',
                'ASP.NET': r'ASP\.NET[/\s](\d+\.\d+(\.\d+)?)',
                'Django': r'Django[/\s](\d+\.\d+(\.\d+)?)',
                'Ruby on Rails': r'Rails[/\s](\d+\.\d+(\.\d+)?)',
                'Express': r'Express[/\s](\d+\.\d+(\.\d+)?)',
                'Laravel': r'Laravel[/\s](\d+\.\d+(\.\d+)?)'
            },
            'cms': {
                'WordPress': r'WordPress[/\s](\d+\.\d+(\.\d+)?)',
                'Joomla': r'Joomla[/\s](\d+\.\d+(\.\d+)?)',
                'Drupal': r'Drupal[/\s](\d+\.\d+(\.\d+)?)',
                'Magento': r'Magento[/\s](\d+\.\d+(\.\d+)?)',
                'Shopify': r'Shopify[/\s](\d+\.\d+(\.\d+)?)'
            }
        }
        
        # Behavioral anomaly tests
        self.behavior_tests = {
            'rate_limit': [
                (10, 1),   # 10 requests in 1 second
                (50, 5),   # 50 requests in 5 seconds
                (100, 10)  # 100 requests in 10 seconds
            ],
            'malformed_requests': [
                'GET / HTTP/0.9\r\n\r\n',
                'GET /' + 'A' * 10000 + ' HTTP/1.1\r\nHost: {}\r\n\r\n',
                'GET /?test=' + '%00' * 100 + ' HTTP/1.1\r\nHost: {}\r\n\r\n',
                'GET / HTTP/1.1\r\nHost: {}\r\nX-Forwarded-For: 127.0.0.1\r\n\r\n',
                'GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: ' + 'A' * 5000 + '\r\n\r\n'
            ],
            'protocol_anomalies': [
                ('GET', '/../../../etc/passwd'),
                ('POST', '/'),  # Without Content-Length
                ('PUT', '/test.txt'),  # Write to root
                ('DELETE', '/'),
                ('OPTIONS', '/'),
                ('TRACE', '/'),
                ('CONNECT', '/'),
                ('PATCH', '/')
            ]
        }
        
        # Zero-day heuristic patterns
        self.zero_day_heuristics = {
            'unusual_responses': [
                'Segmentation fault',
                'Core dumped',
                'Out of memory',
                'Stack overflow',
                'Buffer overflow',
                'Memory corruption',
                'Use-after-free',
                'Double free',
                'Heap overflow',
                'Format string'
            ],
            'timing_anomalies': {
                'normal_threshold': 1.0,  # seconds
                'suspicious_threshold': 5.0,
                'critical_threshold': 10.0
            }
        }
        
        # Scanner configuration
        self.max_threads = 50
        self.timeout = 10
        self.port_scan_timeout = 2
        self.ssl_timeout = 5
        
        # Risk levels
        self.risk_levels = {
            'critical': {
                'color': Back.RED + Fore.WHITE + Style.BRIGHT,
                'score': 50,
                'description': 'Zero-day indicator with active exploitation potential'
            },
            'high': {
                'color': Fore.RED + Style.BRIGHT,
                'score': 40,
                'description': 'Multiple security misconfigurations or exposed critical services'
            },
            'medium': {
                'color': Fore.YELLOW + Style.BRIGHT,
                'score': 30,
                'description': 'Security misconfiguration or information leakage'
            },
            'low': {
                'color': Fore.BLUE + Style.BRIGHT,
                'score': 20,
                'description': 'Potential security issue requiring investigation'
            },
            'info': {
                'color': Fore.CYAN + Style.BRIGHT,
                'score': 10,
                'description': 'Informational finding'
            }
        }

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

    def print_status(self, message, level="info", indent=0, target=None):
        """Print colored status messages with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        prefix = {
            "info": f"{self.colors['info']}[ℹ]",
            "success": f"{self.colors['success']}[✓]",
            "warning": f"{self.colors['warning']}[⚠]",
            "error": f"{self.colors['error']}[✗]",
            "critical": f"{self.colors['critical']}[‼]",
            "zero_day": f"{self.colors['zero_day']}[💀]",
            "anomaly": f"{self.colors['anomaly']}[🔍]",
            "port": f"{self.colors['port']}[🔌]",
            "service": f"{self.colors['service']}[⚙️]",
            "ssl": f"{self.colors['ssl']}[🔐]",
            "header": f"{self.colors['header_analysis']}[📋]",
            "behavior": f"{self.colors['behavior']}[🎭]",
            "fingerprint": f"{self.colors['fingerprint']}[🖐️]",
            "scan": f"{self.colors['info']}[🔍]"
        }.get(level, f"{self.colors['info']}[*]")
        
        indent_str = "  " * indent
        target_str = f" {self.colors['highlight']}{target}" if target else ""
        print(f"{self.colors['timestamp']}[{timestamp}] {prefix}{Style.RESET_ALL} {indent_str}{message}{target_str}")

    def scan(self, target, options=None):
        """Comprehensive zero-day vulnerability discovery scanning"""
        self.print_banner()
        
        results = {
            'target': target,
            'potential_zero_day': [],
            'anomalies_detected': [],
            'exposed_services': [],
            'security_misconfigurations': [],
            'behavioral_anomalies': [],
            'fingerprint_data': {},
            'risk_score': 0,
            'stats': {
                'start_time': time.time(),
                'end_time': None,
                'duration': None,
                'tests_performed': 0,
                'findings_count': 0
            }
        }
        
        try:
            # Parse target URL
            parsed = urlparse(target)
            hostname = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            
            self.print_status(f"Initiating zero-day discovery scan on target: {self.colors['highlight']}{target}", "info")
            
            # Phase 1: Network reconnaissance
            self.print_status("Phase 1: Network reconnaissance and service discovery...", "scan")
            network_results = self.network_reconnaissance(hostname, port)
            results['exposed_services'].extend(network_results['services'])
            results['stats']['tests_performed'] += network_results['tests_performed']
            results['stats']['findings_count'] += len(network_results['services'])
            
            # Phase 2: SSL/TLS security assessment
            self.print_status("Phase 2: SSL/TLS security assessment...", "scan")
            ssl_results = self.comprehensive_ssl_analysis(hostname, port)
            results['security_misconfigurations'].extend(ssl_results['issues'])
            results['stats']['tests_performed'] += ssl_results['tests_performed']
            results['stats']['findings_count'] += len(ssl_results['issues'])
            
            # Phase 3: HTTP header and configuration analysis
            self.print_status("Phase 3: HTTP header and configuration analysis...", "scan")
            header_results = self.comprehensive_header_analysis(target)
            results['anomalies_detected'].extend(header_results['anomalies'])
            results['fingerprint_data']['headers'] = header_results['fingerprint']
            results['stats']['tests_performed'] += header_results['tests_performed']
            results['stats']['findings_count'] += len(header_results['anomalies'])
            
            # Phase 4: Behavioral anomaly detection
            self.print_status("Phase 4: Behavioral anomaly detection...", "scan")
            behavior_results = self.behavioral_analysis(target)
            results['behavioral_anomalies'].extend(behavior_results['anomalies'])
            results['stats']['tests_performed'] += behavior_results['tests_performed']
            results['stats']['findings_count'] += len(behavior_results['anomalies'])
            
            # Phase 5: Software fingerprinting and version detection
            self.print_status("Phase 5: Software fingerprinting and version detection...", "scan")
            fingerprint_results = self.software_fingerprinting(target)
            results['fingerprint_data'].update(fingerprint_results)
            
            # Phase 6: Zero-day heuristic analysis
            self.print_status("Phase 6: Zero-day heuristic analysis...", "scan")
            zero_day_results = self.zero_day_heuristic_analysis(target, results)
            results['potential_zero_day'].extend(zero_day_results['indicators'])
            results['stats']['findings_count'] += len(zero_day_results['indicators'])
            
            # Calculate risk score
            results['risk_score'] = self.calculate_risk_score(results)
            
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

    def network_reconnaissance(self, hostname, default_port):
        """Comprehensive network reconnaissance"""
        results = {
            'services': [],
            'tests_performed': 0
        }
        
        # Combine all port categories
        all_ports = []
        for category, ports in self.port_categories.items():
            all_ports.extend(ports)
        
        # Remove duplicates and sort
        all_ports = sorted(list(set(all_ports)))
        
        self.print_status(f"Scanning {len(all_ports)} potential ports on {hostname}...", "port", 1)
        
        # Use thread pool for concurrent scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Submit port scanning tasks
            future_to_port = {
                executor.submit(self.scan_port, hostname, port): port 
                for port in all_ports[:100]  # Limit to 100 ports for performance
            }
            
            # Process results
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                results['tests_performed'] += 1
                
                try:
                    scan_result = future.result(timeout=self.port_scan_timeout + 2)
                    
                    if scan_result['status'] == 'open':
                        service_info = {
                            'port': port,
                            'service': scan_result['service'],
                            'banner': scan_result.get('banner', ''),
                            'category': self.get_port_category(port),
                            'risk_level': self.get_port_risk_level(port, scan_result['service'])
                        }
                        
                        results['services'].append(service_info)
                        
                        color = self.risk_levels.get(service_info['risk_level'], {}).get('color', Fore.RED)
                        self.print_status(f"Open port {port}: {scan_result['service']}", "port", 2)
                        
                        if scan_result.get('banner'):
                            self.print_status(f"Banner: {scan_result['banner'][:100]}", "service", 3)
                
                except concurrent.futures.TimeoutError:
                    continue
                except Exception as e:
                    continue
        
        return results

    def scan_port(self, hostname, port):
        """Scan a single port with service identification"""
        result = {
            'port': port,
            'status': 'closed',
            'service': 'Unknown',
            'banner': ''
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.port_scan_timeout)
            
            start_time = time.time()
            scan_result = sock.connect_ex((hostname, port))
            response_time = time.time() - start_time
            
            if scan_result == 0:
                result['status'] = 'open'
                result['response_time'] = response_time
                
                # Try to get banner
                try:
                    if port == 80 or port == 8080 or port == 8081:
                        sock.send(b'GET / HTTP/1.0\r\n\r\n')
                        banner = sock.recv(1024).decode('utf-8', errors='ignore')
                        result['banner'] = banner[:500]
                        result['service'] = self.identify_service_from_banner(banner, port)
                    
                    elif port == 443 or port == 8443:
                        # SSL connection
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        
                        ssl_sock = context.wrap_socket(sock, server_hostname=hostname)
                        ssl_sock.do_handshake()
                        
                        # Send HTTP request
                        ssl_sock.send(b'GET / HTTP/1.0\r\n\r\n')
                        banner = ssl_sock.recv(1024).decode('utf-8', errors='ignore')
                        result['banner'] = banner[:500]
                        result['service'] = self.identify_service_from_banner(banner, port)
                        ssl_sock.close()
                    
                    elif port == 22:
                        # SSH banner
                        banner = sock.recv(1024).decode('utf-8', errors='ignore')
                        result['banner'] = banner.strip()
                        result['service'] = 'SSH'
                    
                    elif port == 21:
                        # FTP banner
                        banner = sock.recv(1024).decode('utf-8', errors='ignore')
                        result['banner'] = banner.strip()
                        result['service'] = 'FTP'
                    
                    elif port == 25 or port == 587:
                        # SMTP banner
                        banner = sock.recv(1024).decode('utf-8', errors='ignore')
                        result['banner'] = banner.strip()
                        result['service'] = 'SMTP'
                    
                    elif port == 3306:
                        # MySQL - try to get version
                        result['service'] = 'MySQL'
                    
                    elif port == 5432:
                        # PostgreSQL
                        result['service'] = 'PostgreSQL'
                    
                    elif port == 27017:
                        # MongoDB
                        result['service'] = 'MongoDB'
                    
                    elif port == 6379:
                        # Redis
                        result['service'] = 'Redis'
                    
                    elif port == 9200:
                        # Elasticsearch
                        result['service'] = 'Elasticsearch'
                    
                    else:
                        # Generic service identification
                        result['service'] = self.identify_service_by_port(port)
                        
                        # Try to get any banner
                        try:
                            sock.send(b'\r\n\r\n')
                            banner = sock.recv(1024).decode('utf-8', errors='ignore')
                            if banner:
                                result['banner'] = banner[:500]
                        except:
                            pass
                
                except Exception as e:
                    # If banner grabbing fails, just identify by port
                    result['service'] = self.identify_service_by_port(port)
            
            sock.close()
        
        except Exception as e:
            pass
        
        return result

    def identify_service_from_banner(self, banner, port):
        """Identify service from banner text"""
        banner_lower = banner.lower()
        
        # Web servers
        if 'apache' in banner_lower:
            return 'Apache HTTP Server'
        elif 'nginx' in banner_lower:
            return 'nginx'
        elif 'microsoft-iis' in banner_lower or 'iis' in banner_lower:
            return 'Microsoft IIS'
        elif 'lighttpd' in banner_lower:
            return 'Lighttpd'
        elif 'jetty' in banner_lower:
            return 'Jetty'
        elif 'tomcat' in banner_lower:
            return 'Apache Tomcat'
        
        # Application frameworks
        if 'php' in banner_lower:
            return 'PHP'
        elif 'asp.net' in banner_lower:
            return 'ASP.NET'
        elif 'django' in banner_lower:
            return 'Django'
        elif 'rails' in banner_lower:
            return 'Ruby on Rails'
        elif 'express' in banner_lower:
            return 'Express.js'
        elif 'laravel' in banner_lower:
            return 'Laravel'
        
        # CMS
        if 'wordpress' in banner_lower:
            return 'WordPress'
        elif 'joomla' in banner_lower:
            return 'Joomla'
        elif 'drupal' in banner_lower:
            return 'Drupal'
        elif 'magento' in banner_lower:
            return 'Magento'
        
        # Fallback to port-based identification
        return self.identify_service_by_port(port)

    def identify_service_by_port(self, port):
        """Identify service by port number"""
        service_map = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            993: 'IMAPS',
            995: 'POP3S',
            1433: 'MSSQL',
            1521: 'Oracle',
            1723: 'PPTP',
            2049: 'NFS',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            5984: 'CouchDB',
            6379: 'Redis',
            8080: 'HTTP Proxy',
            8443: 'HTTPS Alt',
            9200: 'Elasticsearch',
            27017: 'MongoDB'
        }
        
        return service_map.get(port, f'Unknown (Port {port})')

    def get_port_category(self, port):
        """Get port category"""
        for category, ports in self.port_categories.items():
            if port in ports:
                return category
        return 'unknown'

    def get_port_risk_level(self, port, service):
        """Determine risk level for open port"""
        # Critical ports
        critical_ports = [22, 23, 21, 25, 445, 3389, 5900, 5432, 3306, 1433, 27017, 6379, 9200]
        if port in critical_ports:
            return 'critical'
        
        # Backdoor/malware ports
        backdoor_ports = [31337, 27374, 12345, 12346, 20034, 6711, 6712, 6713, 6776, 666, 1243, 1999, 6969]
        if port in backdoor_ports:
            return 'high'
        
        # Common service ports
        common_ports = [80, 443, 53, 123, 161, 389, 636, 873, 2049]
        if port in common_ports:
            return 'medium'
        
        return 'low'

    def comprehensive_ssl_analysis(self, hostname, port):
        """Comprehensive SSL/TLS security analysis"""
        results = {
            'issues': [],
            'tests_performed': 0
        }
        
        self.print_status(f"Analyzing SSL/TLS configuration for {hostname}:{port}...", "ssl", 1)
        
        try:
            # Test SSL/TLS protocols
            protocols = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']
            
            for protocol in protocols:
                try:
                    context = ssl.SSLContext(self.get_ssl_protocol(protocol))
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    with socket.create_connection((hostname, port), timeout=self.ssl_timeout) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            results['tests_performed'] += 1
                            
                            # Check if protocol is supported
                            cert = ssock.getpeercert()
                            cipher = ssock.cipher()
                            
                            if protocol in self.weak_ssl_configs['protocols']:
                                results['issues'].append({
                                    'type': 'Weak SSL/TLS Protocol',
                                    'protocol': protocol,
                                    'risk_level': 'high',
                                    'description': f'Weak protocol {protocol} is enabled'
                                })
                                self.print_status(f"Weak protocol enabled: {protocol}", "ssl", 2)
                            
                            # Check cipher strength
                            if cipher:
                                cipher_name = cipher[0]
                                for weak_cipher in self.weak_ssl_configs['weak_ciphers']:
                                    if weak_cipher in cipher_name:
                                        results['issues'].append({
                                            'type': 'Weak SSL Cipher',
                                            'cipher': cipher_name,
                                            'risk_level': 'high',
                                            'description': f'Weak cipher {cipher_name} is enabled'
                                        })
                                        self.print_status(f"Weak cipher: {cipher_name}", "ssl", 2)
                                        break
                            
                            # Check certificate validity
                            if cert:
                                not_after = cert.get('notAfter', '')
                                if not_after:
                                    expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                                    days_remaining = (expiry_date - datetime.now()).days
                                    
                                    if days_remaining < 0:
                                        results['issues'].append({
                                            'type': 'Expired SSL Certificate',
                                            'days_expired': abs(days_remaining),
                                            'risk_level': 'high',
                                            'description': f'SSL certificate expired {abs(days_remaining)} days ago'
                                        })
                                        self.print_status(f"Expired certificate: {abs(days_remaining)} days ago", "ssl", 2)
                                    elif days_remaining < 30:
                                        results['issues'].append({
                                            'type': 'SSL Certificate Expiring Soon',
                                            'days_remaining': days_remaining,
                                            'risk_level': 'medium',
                                            'description': f'SSL certificate expires in {days_remaining} days'
                                        })
                                        self.print_status(f"Certificate expires in {days_remaining} days", "ssl", 2)
                            
                            ssock.close()
                
                except (ssl.SSLError, socket.timeout, ConnectionRefusedError):
                    # Protocol not supported
                    continue
                except Exception as e:
                    continue
        
        except Exception as e:
            self.print_status(f"SSL analysis error: {e}", "error", 2)
        
        return results

    def get_ssl_protocol(self, protocol_name):
        """Get SSL protocol constant"""
        protocol_map = {
            'SSLv2': ssl.PROTOCOL_SSLv2,
            'SSLv3': ssl.PROTOCOL_SSLv3,
            'TLSv1.0': ssl.PROTOCOL_TLSv1,
            'TLSv1.1': ssl.PROTOCOL_TLSv1_1,
            'TLSv1.2': ssl.PROTOCOL_TLSv1_2,
            'TLSv1.3': ssl.PROTOCOL_TLS
        }
        
        # Note: SSLv2 and SSLv3 are deprecated and may not be available
        return protocol_map.get(protocol_name, ssl.PROTOCOL_TLS)

    def comprehensive_header_analysis(self, target):
        """Comprehensive HTTP header analysis"""
        results = {
            'anomalies': [],
            'fingerprint': {},
            'tests_performed': 0
        }
        
        try:
            from utils.request_wrapper import RequestWrapper
            req = RequestWrapper()
            
            response = req.get(target, timeout=self.timeout)
            results['tests_performed'] += 1
            
            headers = response.headers
            
            # Store fingerprint data
            results['fingerprint']['headers'] = dict(headers)
            results['fingerprint']['status_code'] = response.status_code
            results['fingerprint']['server'] = headers.get('Server', '')
            results['fingerprint']['content_type'] = headers.get('Content-Type', '')
            
            # Check for missing security headers
            missing_critical = []
            missing_important = []
            
            for header in self.security_headers['critical']:
                if header not in headers:
                    missing_critical.append(header)
            
            for header in self.security_headers['important']:
                if header not in headers:
                    missing_important.append(header)
            
            if missing_critical:
                results['anomalies'].append({
                    'type': 'Missing Critical Security Headers',
                    'headers': missing_critical,
                    'risk_level': 'high',
                    'description': f'Missing {len(missing_critical)} critical security headers'
                })
                self.print_status(f"Missing critical headers: {', '.join(missing_critical)}", "header", 1)
            
            if missing_important:
                results['anomalies'].append({
                    'type': 'Missing Important Security Headers',
                    'headers': missing_important,
                    'risk_level': 'medium',
                    'description': f'Missing {len(missing_important)} important security headers'
                })
            
            # Check for debug/informational headers
            debug_headers = []
            for header in self.security_headers['informational']:
                if header in headers:
                    debug_headers.append({
                        'header': header,
                        'value': headers[header]
                    })
            
            if debug_headers:
                results['anomalies'].append({
                    'type': 'Debug/Informational Headers Exposed',
                    'headers': debug_headers,
                    'risk_level': 'low',
                    'description': 'Server exposes debug or informational headers'
                })
                
                for debug in debug_headers:
                    self.print_status(f"Debug header: {debug['header']} = {debug['value'][:50]}", "header", 2)
            
            # Check for anomaly patterns in response body
            response_text = response.text
            for category, patterns in self.anomaly_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, response_text, re.IGNORECASE):
                        results['anomalies'].append({
                            'type': f'Anomaly Detected: {category.replace("_", " ").title()}',
                            'pattern': pattern,
                            'risk_level': 'medium',
                            'description': f'Found {category} pattern in response'
                        })
                        
                        match = re.search(pattern, response_text, re.IGNORECASE)
                        if match:
                            context = response_text[max(0, match.start()-50):min(len(response_text), match.end()+50)]
                            self.print_status(f"Anomaly pattern: {pattern[:50]}...", "anomaly", 2)
                            self.print_status(f"Context: {context}", "evidence", 3)
                        break
        
        except Exception as e:
            self.print_status(f"Header analysis error: {e}", "error")
        
        return results

    def behavioral_analysis(self, target):
        """Behavioral anomaly detection"""
        results = {
            'anomalies': [],
            'tests_performed': 0
        }
        
        try:
            from utils.request_wrapper import RequestWrapper
            req = RequestWrapper()
            
            self.print_status("Testing behavioral anomalies...", "behavior", 1)
            
            # Test rate limiting
            self.print_status("Testing rate limiting...", "behavior", 2)
            rate_results = self.test_rate_limiting(target, req)
            results['anomalies'].extend(rate_results['anomalies'])
            results['tests_performed'] += rate_results['tests_performed']
            
            # Test malformed requests
            self.print_status("Testing malformed requests...", "behavior", 2)
            malformed_results = self.test_malformed_requests(target, req)
            results['anomalies'].extend(malformed_results['anomalies'])
            results['tests_performed'] += malformed_results['tests_performed']
            
            # Test protocol anomalies
            self.print_status("Testing protocol anomalies...", "behavior", 2)
            protocol_results = self.test_protocol_anomalies(target, req)
            results['anomalies'].extend(protocol_results['anomalies'])
            results['tests_performed'] += protocol_results['tests_performed']
        
        except Exception as e:
            self.print_status(f"Behavioral analysis error: {e}", "error")
        
        return results

    def test_rate_limiting(self, target, req):
        """Test for rate limiting"""
        results = {
            'anomalies': [],
            'tests_performed': 0
        }
        
        try:
            for rate_limit in self.behavior_tests['rate_limit']:
                request_count, time_window = rate_limit
                
                responses = []
                start_time = time.time()
                
                for i in range(request_count):
                    try:
                        response = req.get(target, timeout=2)
                        responses.append({
                            'status': response.status_code,
                            'time': time.time()
                        })
                        results['tests_performed'] += 1
                    except Exception as e:
                        responses.append({
                            'error': str(e),
                            'time': time.time()
                        })
                    
                    time.sleep(0.01)  # Small delay between requests
                
                elapsed_time = time.time() - start_time
                
                # Analyze responses
                error_count = sum(1 for r in responses if 'error' in r)
                status_500 = sum(1 for r in responses if r.get('status', 0) >= 500)
                
                if error_count > request_count * 0.5 or status_500 > request_count * 0.5:
                    results['anomalies'].append({
                        'type': 'Potential DoS Vulnerability',
                        'request_count': request_count,
                        'time_window': time_window,
                        'error_rate': error_count / request_count * 100,
                        'risk_level': 'medium',
                        'description': f'High error rate ({error_count/request_count*100:.1f}%) during rate limit test'
                    })
                    self.print_status(f"High error rate during rate testing: {error_count/request_count*100:.1f}%", "behavior", 3)
        
        except Exception as e:
            pass
        
        return results

    def test_malformed_requests(self, target, req):
        """Test with malformed requests"""
        results = {
            'anomalies': [],
            'tests_performed': 0
        }
        
        try:
            parsed = urlparse(target)
            hostname = parsed.hostname
            
            for request_template in self.behavior_tests['malformed_requests']:
                try:
                    malformed_request = request_template.format(hostname)
                    
                    # Send raw request
                    response = req.raw_request(target, malformed_request)
                    results['tests_performed'] += 1
                    
                    # Check for abnormal responses
                    if response.status_code >= 500:
                        results['anomalies'].append({
                            'type': 'Server Error on Malformed Request',
                            'status_code': response.status_code,
                            'request_type': 'malformed',
                            'risk_level': 'medium',
                            'description': f'Server returned {response.status_code} on malformed request'
                        })
                        self.print_status(f"Server error {response.status_code} on malformed request", "behavior", 3)
                    
                    # Check for unusual error messages
                    response_text = response.text
                    for pattern in self.zero_day_heuristics['unusual_responses']:
                        if pattern in response_text:
                            results['anomalies'].append({
                                'type': 'Unusual Error Response',
                                'pattern': pattern,
                                'risk_level': 'high',
                                'description': f'Found unusual error pattern: {pattern}'
                            })
                            self.print_status(f"Unusual error pattern: {pattern}", "zero_day", 3)
                            break
                
                except Exception as e:
                    continue
        
        except Exception as e:
            pass
        
        return results

    def test_protocol_anomalies(self, target, req):
        """Test protocol anomalies"""
        results = {
            'anomalies': [],
            'tests_performed': 0
        }
        
        try:
            for method, path in self.behavior_tests['protocol_anomalies']:
                try:
                    # Test unusual HTTP methods
                    if method == 'GET':
                        response = req.get(target + path, timeout=5)
                    elif method == 'POST':
                        response = req.post(target + path, timeout=5)
                    elif method == 'PUT':
                        response = req.put(target + path, timeout=5)
                    elif method == 'DELETE':
                        response = req.delete(target + path, timeout=5)
                    elif method == 'OPTIONS':
                        response = req.options(target + path, timeout=5)
                    elif method == 'TRACE':
                        response = req.trace(target + path, timeout=5)
                    elif method == 'CONNECT':
                        # CONNECT is typically not supported
                        continue
                    elif method == 'PATCH':
                        response = req.patch(target + path, timeout=5)
                    
                    results['tests_performed'] += 1
                    
                    # Check for unusual responses
                    if response.status_code == 200 and method in ['PUT', 'DELETE', 'TRACE']:
                        results['anomalies'].append({
                            'type': 'Unusual Method Allowed',
                            'method': method,
                            'path': path,
                            'status_code': response.status_code,
                            'risk_level': 'medium',
                            'description': f'Unusual HTTP method {method} allowed and returned 200'
                        })
                        self.print_status(f"Unusual method {method} allowed with 200 OK", "behavior", 3)
                
                except Exception as e:
                    continue
        
        except Exception as e:
            pass
        
        return results

    def software_fingerprinting(self, target):
        """Software fingerprinting and version detection"""
        results = {
            'software_versions': {},
            'fingerprint_hash': '',
            'technologies': []
        }
        
        try:
            from utils.request_wrapper import RequestWrapper
            req = RequestWrapper()
            
            response = req.get(target, timeout=self.timeout)
            response_text = response.text
            
            # Create fingerprint hash
            fingerprint_data = {
                'headers': dict(response.headers),
                'status_code': response.status_code,
                'content_sample': response_text[:1000]
            }
            
            fingerprint_json = json.dumps(fingerprint_data, sort_keys=True)
            results['fingerprint_hash'] = hashlib.md5(fingerprint_json.encode()).hexdigest()
            
            # Detect software versions
            for category, patterns in self.software_patterns.items():
                for software, pattern in patterns.items():
                    match = re.search(pattern, response_text, re.IGNORECASE)
                    if match:
                        version = match.group(1)
                        results['software_versions'][software] = version
                        results['technologies'].append(f'{software} {version}')
                        
                        self.print_status(f"Detected {software} v{version}", "fingerprint", 1)
            
            # Also check headers for software info
            headers = response.headers
            server_header = headers.get('Server', '')
            if server_header:
                results['technologies'].append(f'Server: {server_header}')
                self.print_status(f"Server header: {server_header}", "fingerprint", 1)
            
            x_powered_by = headers.get('X-Powered-By', '')
            if x_powered_by:
                results['technologies'].append(f'Powered By: {x_powered_by}')
                self.print_status(f"X-Powered-By: {x_powered_by}", "fingerprint", 1)
        
        except Exception as e:
            self.print_status(f"Fingerprinting error: {e}", "error")
        
        return results

    def zero_day_heuristic_analysis(self, target, scan_results):
        """Zero-day heuristic analysis"""
        results = {
            'indicators': [],
            'confidence': 0
        }
        
        self.print_status("Performing zero-day heuristic analysis...", "zero_day", 1)
        
        # Combine findings for analysis
        all_findings = []
        all_findings.extend(scan_results.get('potential_zero_day', []))
        all_findings.extend(scan_results.get('anomalies_detected', []))
        all_findings.extend(scan_results.get('behavioral_anomalies', []))
        
        # Heuristic 1: Multiple critical findings
        critical_count = sum(1 for f in all_findings if f.get('risk_level') == 'critical')
        if critical_count >= 3:
            results['indicators'].append({
                'type': 'Multiple Critical Findings',
                'count': critical_count,
                'confidence': 70,
                'description': f'Found {critical_count} critical security issues'
            })
            self.print_status(f"Multiple critical findings: {critical_count}", "zero_day", 2)
        
        # Heuristic 2: Unusual error patterns
        unusual_errors = []
        for finding in all_findings:
            if 'pattern' in str(finding).lower():
                for unusual_pattern in self.zero_day_heuristics['unusual_responses']:
                    if unusual_pattern in str(finding):
                        unusual_errors.append(unusual_pattern)
        
        if unusual_errors:
            results['indicators'].append({
                'type': 'Unusual Error Patterns',
                'patterns': unusual_errors,
                'confidence': 60,
                'description': f'Found unusual error patterns: {", ".join(unusual_errors)}'
            })
            self.print_status(f"Unusual error patterns: {unusual_errors}", "zero_day", 2)
        
        # Heuristic 3: Exposed critical services with weak config
        exposed_critical = []
        for service in scan_results.get('exposed_services', []):
            if service.get('risk_level') == 'critical':
                exposed_critical.append(service)
        
        ssl_issues = scan_results.get('security_misconfigurations', [])
        
        if exposed_critical and ssl_issues:
            results['indicators'].append({
                'type': 'Exposed Critical Services with Weak Config',
                'services': [s.get('service') for s in exposed_critical],
                'ssl_issues': len(ssl_issues),
                'confidence': 80,
                'description': f'Critical services exposed with {len(ssl_issues)} SSL issues'
            })
            self.print_status(f"Critical services exposed with SSL issues", "zero_day", 2)
        
        # Calculate overall confidence
        if results['indicators']:
            results['confidence'] = max(ind['confidence'] for ind in results['indicators'])
        else:
            results['confidence'] = 0
        
        return results

    def calculate_risk_score(self, results):
        """Calculate overall risk score"""
        score = 0
        
        # Add scores from findings
        findings_categories = [
            'potential_zero_day',
            'anomalies_detected',
            'exposed_services',
            'security_misconfigurations',
            'behavioral_anomalies'
        ]
        
        for category in findings_categories:
            for finding in results.get(category, []):
                risk_level = finding.get('risk_level', 'info')
                score += self.risk_levels.get(risk_level, {}).get('score', 10)
        
        # Add bonus for zero-day indicators
        zero_day_indicators = results.get('potential_zero_day', [])
        if zero_day_indicators:
            score += len(zero_day_indicators) * 20
        
        # Cap at 100
        return min(score, 100)

    def print_summary(self, results):
        """Print comprehensive scan summary"""
        duration = results['stats'].get('duration', 0)
        
        summary = f"""
{self.colors['separator']}{"="*100}
{self.colors['header']}📊 ZERO-DAY DISCOVERY SCAN SUMMARY
{self.colors['separator']}{"-"*100}
{self.colors['info']}Target:               {results['target']}
{self.colors['info']}Scan Duration:        {duration:.2f} seconds
{self.colors['info']}Tests Performed:      {results['stats']['tests_performed']}
{self.colors['info']}Total Findings:       {results['stats']['findings_count']}
{self.colors['info']}Risk Score:           {results['risk_score']}/100
{self.colors['info']}Zero-Day Confidence:  {results.get('potential_zero_day', [{}])[0].get('confidence', 0) if results.get('potential_zero_day') else 0}%
{self.colors['separator']}{"-"*100}
"""
        print(summary)
        
        # Print zero-day indicators
        if results['potential_zero_day']:
            print(f"\n{self.colors['header']}🚨 ZERO-DAY INDICATORS ({len(results['potential_zero_day'])}):")
            print(f"{self.colors['separator']}{'-'*100}")
            
            for i, indicator in enumerate(results['potential_zero_day'], 1):
                color = self.risk_levels.get('critical', {}).get('color', Fore.RED)
                
                print(f"{color}▶ {i}. {indicator.get('type', 'Unknown')}")
                print(f"{self.colors['info']}   Confidence: {indicator.get('confidence', 0)}%")
                print(f"{self.colors['info']}   Description: {indicator.get('description', 'No description')}")
                
                if indicator.get('patterns'):
                    print(f"{self.colors['warning']}   Patterns: {', '.join(indicator['patterns'][:3])}")
                
                if indicator.get('services'):
                    print(f"{self.colors['service']}   Services: {', '.join(indicator['services'][:3])}")
                
                print(f"{self.colors['separator']}{'-'*40}")
        
        # Print exposed services
        if results['exposed_services']:
            print(f"\n{self.colors['header']}🔌 EXPOSED SERVICES ({len(results['exposed_services'])}):")
            print(f"{self.colors['separator']}{'-'*100}")
            
            # Group by risk level
            services_by_risk = {}
            for service in results['exposed_services']:
                risk = service.get('risk_level', 'unknown')
                if risk not in services_by_risk:
                    services_by_risk[risk] = []
                services_by_risk[risk].append(service)
            
            for risk_level in ['critical', 'high', 'medium', 'low']:
                if risk_level in services_by_risk:
                    color = self.risk_levels.get(risk_level, {}).get('color', Fore.WHITE)
                    print(f"{color}{risk_level.upper()} RISK SERVICES:")
                    
                    for service in services_by_risk[risk_level][:5]:  # Show first 5 per risk level
                        print(f"  • Port {service['port']}: {service['service']}")
                        if service.get('banner'):
                            print(f"    Banner: {service['banner'][:80]}...")
                    
                    if len(services_by_risk[risk_level]) > 5:
                        print(f"    ... and {len(services_by_risk[risk_level]) - 5} more")
                    print()
        
        # Print security misconfigurations
        if results['security_misconfigurations']:
            print(f"\n{self.colors['header']}🔐 SECURITY MISCONFIGURATIONS ({len(results['security_misconfigurations'])}):")
            print(f"{self.colors['separator']}{'-'*100}")
            
            for i, issue in enumerate(results['security_misconfigurations'][:10], 1):
                color = self.risk_levels.get(issue.get('risk_level', 'medium'), {}).get('color', Fore.YELLOW)
                
                print(f"{color}▶ {i}. {issue.get('type', 'Unknown')}")
                print(f"{self.colors['info']}   Description: {issue.get('description', 'No description')}")
                
                if issue.get('protocol'):
                    print(f"{self.colors['ssl']}   Protocol: {issue['protocol']}")
                if issue.get('cipher'):
                    print(f"{self.colors['ssl']}   Cipher: {issue['cipher']}")
                if issue.get('days_remaining'):
                    print(f"{self.colors['ssl']}   Days Remaining: {issue['days_remaining']}")
                
                if i < min(10, len(results['security_misconfigurations'])):
                    print(f"{self.colors['separator']}{'-'*40}")
        
        # Print fingerprint data
        if results['fingerprint_data']:
            print(f"\n{self.colors['header']}🖐️  FINGERPRINT DATA:")
            print(f"{self.colors['separator']}{'-'*100}")
            
            fingerprint = results['fingerprint_data']
            
            if fingerprint.get('technologies'):
                print(f"{self.colors['fingerprint']}Technologies Detected:")
                for tech in fingerprint['technologies'][:10]:
                    print(f"{self.colors['info']}  • {tech}")
                print()
            
            if fingerprint.get('fingerprint_hash'):
                print(f"{self.colors['fingerprint']}Fingerprint Hash: {fingerprint['fingerprint_hash']}")
                print()
            
            if fingerprint.get('headers'):
                print(f"{self.colors['fingerprint']}Key Headers:")
                headers = fingerprint['headers']
                important_headers = ['Server', 'X-Powered-By', 'Content-Type', 'Set-Cookie']
                for header in important_headers:
                    if header in headers:
                        print(f"{self.colors['info']}  {header}: {headers[header][:100]}")
                print()
        
        # Print recommendations
        recommendations = self.generate_recommendations(results)
        if recommendations:
            print(f"\n{self.colors['header']}💡 RECOMMENDATIONS:")
            print(f"{self.colors['separator']}{'-'*100}")
            
            for i, rec in enumerate(recommendations, 1):
                priority_color = {
                    'critical': Back.RED + Fore.WHITE,
                    'high': Fore.RED + Style.BRIGHT,
                    'medium': Fore.YELLOW + Style.BRIGHT,
                    'low': Fore.BLUE + Style.BRIGHT
                }.get(rec['priority'], Fore.WHITE)
                
                print(f"{priority_color}{i}. [{rec['priority'].upper()}] {rec['title']}")
                print(f"{self.colors['info']}   {rec['description']}")
                print()
        
        # Final status
        if results['potential_zero_day']:
            confidence = results['potential_zero_day'][0].get('confidence', 0) if results['potential_zero_day'] else 0
            if confidence > 70:
                print(f"{self.colors['critical']}⚠ CRITICAL ZERO-DAY INDICATORS DETECTED! Immediate investigation required.")
            elif confidence > 40:
                print(f"{self.colors['warning']}⚠ Potential zero-day indicators found. Further analysis recommended.")
        elif results['risk_score'] > 70:
            print(f"{self.colors['critical']}⚠ CRITICAL SECURITY ISSUES DETECTED! Immediate remediation required.")
        elif results['risk_score'] > 40:
            print(f"{self.colors['warning']}⚠ Multiple security issues found. Review and address findings.")
        else:
            print(f"{self.colors['success']}✅ No critical zero-day indicators detected. Maintain regular security monitoring.")
        
        print(f"{self.colors['separator']}{'='*100}\n")

    def generate_recommendations(self, results):
        """Generate targeted recommendations"""
        recommendations = []
        
        # Check for specific issues
        if results['potential_zero_day']:
            recommendations.append({
                'priority': 'critical',
                'title': 'Investigate Zero-Day Indicators',
                'description': f'Immediately investigate {len(results["potential_zero_day"])} potential zero-day indicators'
            })
        
        if results['exposed_services']:
            critical_services = [s for s in results['exposed_services'] if s.get('risk_level') == 'critical']
            if critical_services:
                recommendations.append({
                    'priority': 'high',
                    'title': 'Secure Exposed Critical Services',
                    'description': f'Secure {len(critical_services)} exposed critical services'
                })
        
        if results['security_misconfigurations']:
            ssl_issues = [i for i in results['security_misconfigurations'] if 'SSL' in i.get('type', '')]
            if ssl_issues:
                recommendations.append({
                    'priority': 'high',
                    'title': 'Fix SSL/TLS Misconfigurations',
                    'description': f'Fix {len(ssl_issues)} SSL/TLS security misconfigurations'
                })
        
        if results['anomalies_detected']:
            header_issues = [a for a in results['anomalies_detected'] if 'header' in a.get('type', '').lower()]
            if header_issues:
                recommendations.append({
                    'priority': 'medium',
                    'title': 'Implement Security Headers',
                    'description': 'Implement missing security headers and remove debug headers'
                })
        
        # General recommendations
        recommendations.extend([
            {
                'priority': 'high',
                'title': 'Conduct Penetration Testing',
                'description': 'Perform comprehensive penetration testing by security professionals'
            },
            {
                'priority': 'medium',
                'title': 'Implement WAF and IDS/IPS',
                'description': 'Deploy Web Application Firewall and Intrusion Detection/Prevention Systems'
            },
            {
                'priority': 'low',
                'title': 'Regular Security Audits',
                'description': 'Schedule regular security audits and vulnerability assessments'
            }
        ])
        
        return sorted(recommendations, key=lambda x: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}[x['priority']])

# Example usage
if __name__ == "__main__":
    scanner = ZeroDayScanner()
    
    # Configure scanner
    scanner.max_threads = 30
    scanner.timeout = 15
    
    # Run scan
    target_url = "https://example.com"
    results = scanner.scan(target_url)
    
    # Advanced scan with custom options
    options = {
        'deep_scan': True,
        'port_scan_limit': 50,
        'ssl_test_all': True
    }
    
    advanced_results = scanner.scan(target_url, options)
    
    # Print statistics
    print(f"\n{Fore.CYAN}Scanner Statistics:")
    print(f"{Fore.CYAN}• Port categories: {len(scanner.port_categories)}")
    print(f"{Fore.CYAN}• Security headers: {sum(len(h) for h in scanner.security_headers.values())}")
    print(f"{Fore.CYAN}• Anomaly patterns: {sum(len(p) for p in scanner.anomaly_patterns.values())}")
    print(f"{Fore.CYAN}• Software patterns: {sum(len(p) for p in scanner.software_patterns.values())}")