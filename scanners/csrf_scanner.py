import re
import time
from bs4 import BeautifulSoup
from colorama import Fore, Style, Back, init
from urllib.parse import urljoin, urlparse
import json
from datetime import datetime

# Initialize colorama
init(autoreset=True)

class CSRFScanner:
    def __init__(self):
        self.name = "🛡️ ADVANCED CSRF VULNERABILITY SCANNER"
        self.version = "2.8"
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
            'vulnerable': Fore.RED + Style.BRIGHT,
            'safe': Fore.GREEN + Style.NORMAL,
            'form': Fore.BLUE + Style.BRIGHT,
            'token': Fore.YELLOW + Style.BRIGHT,
            'parameter': Fore.CYAN + Style.NORMAL,
            'method': Fore.MAGENTA + Style.NORMAL,
            'timestamp': Fore.LIGHTBLACK_EX,
            'separator': Fore.LIGHTBLACK_EX + Style.DIM,
            'highlight': Fore.YELLOW + Back.BLACK + Style.BRIGHT,
            'detail': Fore.LIGHTWHITE_EX + Style.NORMAL
        }
        
        # CSRF token patterns
        self.csrf_patterns = [
            r'csrf[-_]?token',
            r'csrf[-_]?middleware[-_]?token',
            r'anticsrf',
            r'__requestverificationtoken',
            r'_token',
            r'csrfprotection',
            r'csrf_token',
            r'csrfmiddlewaretoken',
            r'csrftoken',
            r'authenticity[-_]?token',
            r'xsrf[-_]?token',
            r'_csrf',
            r'csrfkey',
            r'csrfnonce',
            r'security[-_]?token',
            r'nonce',
            r'form[-_]?token',
            r'request[-_]?token'
        ]
        
        # CSRF protection headers
        self.csrf_headers = [
            'X-CSRF-Token',
            'X-XSRF-Token',
            'X-CSRFToken',
            'X-Requested-With',
            'X-CSRF-Protection',
            'CSRF-Token'
        ]
        
        # Form methods that should have CSRF protection
        self.protected_methods = ['POST', 'PUT', 'DELETE', 'PATCH']
        
        # Common form actions to ignore (external, logout, etc.)
        self.ignore_actions = [
            'logout',
            'signout',
            'exit',
            'external',
            '#',
            'javascript:',
            'mailto:',
            'tel:'
        ]
        
        # Risk levels and descriptions
        self.risk_levels = {
            'critical': {
                'color': Back.RED + Fore.WHITE + Style.BRIGHT,
                'description': 'No CSRF protection on sensitive forms'
            },
            'high': {
                'color': Fore.RED + Style.BRIGHT,
                'description': 'Weak or predictable CSRF tokens'
            },
            'medium': {
                'color': Fore.YELLOW + Style.BRIGHT,
                'description': 'Missing SameSite cookie attribute'
            },
            'low': {
                'color': Fore.BLUE + Style.BRIGHT,
                'description': 'Informational findings'
            },
            'safe': {
                'color': Fore.GREEN + Style.BRIGHT,
                'description': 'Proper CSRF protection implemented'
            }
        }

    def print_banner(self):
        """Display enhanced scanner banner"""
        banner = f"""
{self.colors['banner']}{"="*80}
{self.colors['header']}╔══════════════════════════════════════════════════════════════════════╗
║ {self.colors['banner']}{self.name:^68} {self.colors['header']}║
║ {self.colors['info']}Version: {self.version:<60} {self.colors['header']}║
║ {self.colors['info']}Author: {self.author:<60} {self.colors['header']}║
╚══════════════════════════════════════════════════════════════════════╝
{self.colors['banner']}{"="*80}
"""
        print(banner)

    def print_status(self, message, level="info", indent=0):
        """Print colored status messages with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        prefix = {
            "info": f"{self.colors['info']}[ℹ]",
            "success": f"{self.colors['success']}[✓]",
            "warning": f"{self.colors['warning']}[⚠]",
            "error": f"{self.colors['error']}[✗]",
            "critical": f"{self.colors['critical']}[‼]",
            "scan": f"{self.colors['form']}[🔍]",
            "form": f"{self.colors['form']}[📋]",
            "token": f"{self.colors['token']}[🗝️]"
        }.get(level, f"{self.colors['info']}[*]")
        
        indent_str = "  " * indent
        print(f"{self.colors['timestamp']}[{timestamp}] {prefix}{Style.RESET_ALL} {indent_str}{message}")

    def scan(self, target, options=None):
        """Comprehensive CSRF vulnerability scanning"""
        self.print_banner()
        
        results = {
            'target': target,
            'forms_analyzed': 0,
            'csrf_protected': 0,
            'vulnerabilities_found': 0,
            'vulnerabilities': [],
            'forms': [],
            'cookies_analyzed': [],
            'headers_analyzed': [],
            'start_time': time.time(),
            'end_time': None,
            'risk_score': 0,
            'recommendations': []
        }
        
        try:
            from utils.request_wrapper import RequestWrapper
            req = RequestWrapper()
            
            self.print_status(f"Initiating CSRF scan on target: {self.colors['highlight']}{target}", "info")
            
            # Make initial request
            response = req.get(target)
            results['initial_response_code'] = response.status_code
            
            # Check for CSRF protection headers in response
            self.print_status("Analyzing response headers for CSRF protection...", "scan")
            header_results = self.analyze_response_headers(response.headers)
            results['headers_analyzed'] = header_results
            
            # Analyze cookies for SameSite attribute
            self.print_status("Analyzing cookies for SameSite attribute...", "scan")
            cookie_results = self.analyze_cookies(response.headers.get('set-cookie', ''))
            results['cookies_analyzed'] = cookie_results
            
            # Parse HTML for forms
            self.print_status("Parsing HTML for form elements...", "scan")
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all forms
            forms = soup.find_all('form')
            self.print_status(f"Found {len(forms)} form(s) to analyze", "success")
            
            # Analyze each form
            for i, form in enumerate(forms, 1):
                self.print_status(f"Analyzing form {i}/{len(forms)}...", "form", 1)
                
                form_analysis = self.analyze_form_detailed(form, target, response)
                results['forms'].append(form_analysis)
                results['forms_analyzed'] += 1
                
                # Check for vulnerabilities
                if not form_analysis.get('csrf_protected', False):
                    vulnerability = self.create_vulnerability_report(form_analysis, i)
                    results['vulnerabilities'].append(vulnerability)
                    results['vulnerabilities_found'] += 1
                else:
                    results['csrf_protected'] += 1
                
                # Add delay to avoid overwhelming server
                time.sleep(0.1)
            
            # Analyze JavaScript for AJAX requests
            self.print_status("Analyzing JavaScript for AJAX endpoints...", "scan")
            js_analysis = self.analyze_javascript(soup)
            if js_analysis:
                results['javascript_analysis'] = js_analysis
            
            # Calculate risk score
            results['risk_score'] = self.calculate_risk_score(results)
            
            # Generate recommendations
            results['recommendations'] = self.generate_recommendations(results)
            
            # Complete scan
            results['end_time'] = time.time()
            results['scan_duration'] = results['end_time'] - results['start_time']
            
            # Print comprehensive report
            self.print_summary(results)
            
            return results
            
        except Exception as e:
            self.print_status(f"CSRF scan error: {str(e)}", "error")
            results['error'] = str(e)
            results['end_time'] = time.time()
            return results

    def analyze_response_headers(self, headers):
        """Analyze response headers for CSRF protection"""
        header_analysis = []
        
        for header_name, header_value in headers.items():
            header_info = {
                'name': header_name,
                'value': header_value,
                'csrf_relevant': False,
                'protection_level': 'none'
            }
            
            # Check for CSRF-related headers
            for csrf_header in self.csrf_headers:
                if csrf_header.lower() in header_name.lower():
                    header_info['csrf_relevant'] = True
                    header_info['protection_level'] = 'partial'
                    self.print_status(f"Found CSRF header: {header_name}", "token", 2)
                    break
            
            # Check for CORS headers
            if 'access-control-allow-origin' in header_name.lower():
                header_info['csrf_relevant'] = True
                if header_value == '*':
                    header_info['protection_level'] = 'weak'
                    self.print_status(f"⚠ CORS allows all origins: {header_value}", "warning", 2)
            
            header_analysis.append(header_info)
        
        return header_analysis

    def analyze_cookies(self, set_cookie_header):
        """Analyze cookies for SameSite attribute"""
        cookie_analysis = []
        
        if not set_cookie_header:
            self.print_status("No cookies set in response", "warning", 2)
            return cookie_analysis
        
        cookies = set_cookie_header.split(',')
        
        for cookie_str in cookies:
            cookie_info = {
                'name': 'unknown',
                'samesite': 'None',
                'secure': False,
                'httponly': False
            }
            
            # Parse cookie attributes
            parts = cookie_str.split(';')
            cookie_info['name'] = parts[0].split('=')[0].strip()
            
            for part in parts:
                part = part.strip().lower()
                if 'samesite' in part:
                    cookie_info['samesite'] = part.split('=')[1].title()
                elif 'secure' in part:
                    cookie_info['secure'] = True
                elif 'httponly' in part:
                    cookie_info['httponly'] = True
            
            # Evaluate cookie security
            if cookie_info['samesite'] == 'None' and not cookie_info['secure']:
                cookie_info['risk'] = 'high'
                self.print_status(f"⚠ Cookie '{cookie_info['name']}' has SameSite=None without Secure flag", "warning", 2)
            elif cookie_info['samesite'] == 'Lax':
                cookie_info['risk'] = 'medium'
                self.print_status(f"✓ Cookie '{cookie_info['name']}' has SameSite=Lax", "success", 2)
            elif cookie_info['samesite'] == 'Strict':
                cookie_info['risk'] = 'low'
                self.print_status(f"✓ Cookie '{cookie_info['name']}' has SameSite=Strict", "success", 2)
            
            cookie_analysis.append(cookie_info)
        
        return cookie_analysis

    def analyze_form_detailed(self, form, base_url, response):
        """Perform detailed analysis of HTML form"""
        form_details = {
            'id': form.get('id', f'form_{id(form)}'),
            'name': form.get('name', ''),
            'action': self.resolve_form_action(form, base_url),
            'method': form.get('method', 'GET').upper(),
            'inputs': [],
            'csrf_tokens': [],
            'csrf_protected': False,
            'vulnerability_level': 'safe',
            'risk_factors': []
        }
        
        # Check if action should be ignored
        if self.should_ignore_action(form_details['action']):
            form_details['ignore'] = True
            return form_details
        
        self.print_status(f"Form action: {form_details['action']}", "form", 2)
        self.print_status(f"Form method: {form_details['method']}", "method", 2)
        
        # Analyze all input elements
        input_elements = form.find_all(['input', 'textarea', 'select'])
        
        for element in input_elements:
            input_info = self.analyze_form_element(element)
            form_details['inputs'].append(input_info)
            
            # Check for CSRF tokens
            if self.is_csrf_token_element(input_info):
                form_details['csrf_tokens'].append(input_info)
                self.print_status(f"Found CSRF token: {input_info['name']}", "token", 3)
        
        # Check for meta tags with CSRF tokens
        meta_tags = form.find_all('meta')
        for meta in meta_tags:
            meta_name = meta.get('name', '').lower()
            meta_content = meta.get('content', '')
            
            if 'csrf' in meta_name or 'token' in meta_name:
                token_info = {
                    'type': 'meta',
                    'name': meta_name,
                    'value': meta_content[:50] + ('...' if len(meta_content) > 50 else ''),
                    'is_csrf_token': True
                }
                form_details['csrf_tokens'].append(token_info)
                self.print_status(f"Found CSRF token in meta tag: {meta_name}", "token", 3)
        
        # Determine CSRF protection status
        form_details['csrf_protected'] = self.evaluate_csrf_protection(form_details)
        
        # If not protected, determine vulnerability level
        if not form_details['csrf_protected'] and form_details['method'] in self.protected_methods:
            form_details['vulnerability_level'] = self.determine_vulnerability_level(form_details)
            form_details['risk_factors'] = self.identify_risk_factors(form_details)
        
        return form_details

    def analyze_form_element(self, element):
        """Analyze individual form element"""
        element_type = element.name
        element_info = {
            'type': element_type,
            'name': element.get('name', ''),
            'id': element.get('id', ''),
            'value': element.get('value', ''),
            'required': element.has_attr('required'),
            'readonly': element.has_attr('readonly'),
            'disabled': element.has_attr('disabled'),
            'hidden': element.get('type') == 'hidden' if element_type == 'input' else False,
            'is_csrf_token': False
        }
        
        # Check for CSRF token patterns
        element_name_lower = element_info['name'].lower()
        for pattern in self.csrf_patterns:
            if re.search(pattern, element_name_lower, re.IGNORECASE):
                element_info['is_csrf_token'] = True
                break
        
        # Check value characteristics (CSRF tokens are often long and alphanumeric)
        if len(element_info['value']) > 20:
            if re.match(r'^[A-Za-z0-9+/=]+$', element_info['value']):
                element_info['is_csrf_token'] = True
        
        return element_info

    def is_csrf_token_element(self, element_info):
        """Check if element is a CSRF token"""
        return element_info.get('is_csrf_token', False)

    def evaluate_csrf_protection(self, form_details):
        """Evaluate if form has adequate CSRF protection"""
        
        # Check for CSRF tokens in form
        if form_details['csrf_tokens']:
            self.print_status("✓ Form has CSRF token(s)", "success", 3)
            return True
        
        # Check for non-modifying methods
        if form_details['method'] not in self.protected_methods:
            self.print_status("✓ Safe method (GET) doesn't require CSRF token", "success", 3)
            return True
        
        # Check for AJAX headers (X-Requested-With)
        # This would require actual request testing
        
        self.print_status("✗ No CSRF protection detected", "error", 3)
        return False

    def determine_vulnerability_level(self, form_details):
        """Determine the vulnerability level of the form"""
        
        # Check if form has sensitive actions
        action = form_details['action'].lower()
        sensitive_patterns = [
            r'delete', r'update', r'create', r'edit', r'add',
            r'remove', r'change', r'set', r'config', r'admin',
            r'password', r'email', r'profile', r'account',
            r'payment', r'credit', r'purchase', r'buy',
            r'transfer', r'withdraw', r'deposit'
        ]
        
        sensitive_count = 0
        for pattern in sensitive_patterns:
            if re.search(pattern, action):
                sensitive_count += 1
        
        if sensitive_count >= 2:
            return 'critical'
        elif sensitive_count == 1:
            return 'high'
        else:
            return 'medium'

    def identify_risk_factors(self, form_details):
        """Identify specific risk factors for the form"""
        risk_factors = []
        
        # Check method
        if form_details['method'] in ['POST', 'PUT', 'DELETE']:
            risk_factors.append(f"Form uses {form_details['method']} method without CSRF protection")
        
        # Check for sensitive input fields
        sensitive_fields = ['password', 'credit', 'card', 'ssn', 'secret']
        for input_info in form_details['inputs']:
            input_name = input_info['name'].lower()
            for sensitive in sensitive_fields:
                if sensitive in input_name:
                    risk_factors.append(f"Sensitive field '{input_info['name']}' without CSRF protection")
                    break
        
        # Check for hidden fields (potential for sensitive data)
        hidden_fields = [i for i in form_details['inputs'] if i.get('hidden')]
        if hidden_fields:
            risk_factors.append(f"Contains {len(hidden_fields)} hidden field(s) without CSRF protection")
        
        return risk_factors

    def resolve_form_action(self, form, base_url):
        """Resolve form action URL"""
        action = form.get('action', '')
        
        if not action or action == '#':
            return base_url
        
        # Check if action is absolute
        if action.startswith(('http://', 'https://')):
            return action
        
        # Resolve relative URL
        return urljoin(base_url, action)

    def should_ignore_action(self, action):
        """Determine if form action should be ignored"""
        action_lower = action.lower()
        
        for ignore in self.ignore_actions:
            if ignore in action_lower:
                return True
        
        # Ignore external URLs (cross-domain)
        parsed_base = urlparse(action)
        if parsed_base.netloc and not parsed_base.netloc.endswith(urlparse(action).netloc):
            return True
        
        return False

    def analyze_javascript(self, soup):
        """Analyze JavaScript for potential CSRF vulnerabilities"""
        js_analysis = {
            'ajax_endpoints': [],
            'potential_vulnerabilities': []
        }
        
        # Find all script tags
        script_tags = soup.find_all('script')
        
        for script in script_tags:
            script_content = script.string
            if not script_content:
                continue
            
            # Look for AJAX requests
            ajax_patterns = [
                r'\.ajax\(({[^}]+})\)',
                r'fetch\(([^)]+)\)',
                r'XMLHttpRequest\(\)',
                r'axios\.(?:get|post|put|delete)\(([^)]+)\)'
            ]
            
            for pattern in ajax_patterns:
                matches = re.finditer(pattern, script_content, re.DOTALL)
                for match in matches:
                    endpoint_info = {
                        'code_snippet': match.group(0)[:100] + '...',
                        'line_number': self.get_line_number(script_content, match.start())
                    }
                    js_analysis['ajax_endpoints'].append(endpoint_info)
        
        return js_analysis

    def get_line_number(self, text, position):
        """Get line number from position in text"""
        return text[:position].count('\n') + 1

    def create_vulnerability_report(self, form_analysis, form_number):
        """Create detailed vulnerability report"""
        vulnerability = {
            'id': f"CSRF-{form_number:03d}",
            'form_id': form_analysis['id'],
            'form_name': form_analysis['name'],
            'action': form_analysis['action'],
            'method': form_analysis['method'],
            'vulnerability_level': form_analysis['vulnerability_level'],
            'risk_factors': form_analysis['risk_factors'],
            'description': self.generate_vulnerability_description(form_analysis),
            'impact': self.get_impact_level(form_analysis['vulnerability_level']),
            'remediation': self.get_remediation_steps(form_analysis),
            'evidence': {
                'form_details': {
                    'action': form_analysis['action'],
                    'method': form_analysis['method'],
                    'input_count': len(form_analysis['inputs'])
                }
            }
        }
        
        # Print vulnerability finding
        color = self.risk_levels.get(vulnerability['vulnerability_level'], {}).get('color', Fore.RED)
        self.print_status(f"{color}VULNERABILITY FOUND: {vulnerability['description']}", "critical", 2)
        
        return vulnerability

    def generate_vulnerability_description(self, form_analysis):
        """Generate descriptive vulnerability text"""
        base_desc = f"CSRF vulnerability in {form_analysis['method']} form at '{form_analysis['action']}'"
        
        if form_analysis['risk_factors']:
            factors = ', '.join(form_analysis['risk_factors'][:2])
            return f"{base_desc} - {factors}"
        
        return base_desc

    def get_impact_level(self, vulnerability_level):
        """Get impact description based on vulnerability level"""
        impacts = {
            'critical': 'Account takeover, financial loss, data corruption',
            'high': 'Unauthorized actions, data modification',
            'medium': 'Limited unauthorized actions',
            'low': 'Information disclosure'
        }
        return impacts.get(vulnerability_level, 'Unknown')

    def get_remediation_steps(self, form_analysis):
        """Get remediation steps for the vulnerability"""
        steps = [
            "Implement CSRF tokens for all state-changing operations",
            "Use anti-CSRF libraries/frameworks",
            "Set SameSite=Strict or Lax for session cookies",
            "Implement double-submit cookie pattern",
            "Use custom request headers for AJAX requests"
        ]
        
        if form_analysis['method'] == 'GET':
            steps.insert(0, "Change form method to POST for state-changing operations")
        
        return steps

    def calculate_risk_score(self, results):
        """Calculate overall risk score (0-100)"""
        score = 0
        
        # Base score for each vulnerable form
        for vuln in results['vulnerabilities']:
            level_weights = {
                'critical': 30,
                'high': 20,
                'medium': 10,
                'low': 5
            }
            score += level_weights.get(vuln['vulnerability_level'], 0)
        
        # Adjust based on cookies
        for cookie in results.get('cookies_analyzed', []):
            if cookie.get('risk') == 'high':
                score += 15
            elif cookie.get('risk') == 'medium':
                score += 5
        
        # Cap at 100
        return min(score, 100)

    def generate_recommendations(self, results):
        """Generate targeted recommendations"""
        recommendations = []
        
        if results['vulnerabilities_found'] > 0:
            recommendations.append({
                'priority': 'high',
                'title': 'Implement CSRF Protection',
                'description': f'Add CSRF tokens to {results["vulnerabilities_found"]} vulnerable forms'
            })
        
        # Check cookies
        insecure_cookies = [c for c in results.get('cookies_analyzed', []) 
                          if c.get('samesite') == 'None' and not c.get('secure')]
        if insecure_cookies:
            recommendations.append({
                'priority': 'high',
                'title': 'Secure Cookies',
                'description': f'Secure {len(insecure_cookies)} cookies with SameSite and Secure flags'
            })
        
        # General recommendations
        recommendations.extend([
            {
                'priority': 'medium',
                'title': 'Implement CORS Policy',
                'description': 'Configure proper CORS headers to restrict cross-origin requests'
            },
            {
                'priority': 'low',
                'title': 'Security Headers',
                'description': 'Add security headers like X-Content-Type-Options, X-Frame-Options'
            }
        ])
        
        return recommendations

    def print_summary(self, results):
        """Print comprehensive scan summary"""
        duration = results.get('scan_duration', 0)
        
        summary = f"""
{self.colors['separator']}{"="*80}
{self.colors['header']}📊 CSRF SCAN SUMMARY
{self.colors['separator']}{"-"*80}
{self.colors['detail']}Target URL:           {results['target']}
{self.colors['detail']}Scan Duration:        {duration:.2f} seconds
{self.colors['detail']}Forms Analyzed:       {results['forms_analyzed']}
{self.colors['detail']}Protected Forms:      {results.get('csrf_protected', 0)}
{self.colors['detail']}Vulnerabilities:      {results['vulnerabilities_found']}
{self.colors['detail']}Risk Score:           {results['risk_score']}/100
{self.colors['separator']}{"-"*80}
"""
        print(summary)
        
        # Print vulnerabilities found
        if results['vulnerabilities']:
            print(f"{self.colors['header']}🚨 VULNERABILITIES FOUND:")
            print(f"{self.colors['separator']}{'-'*80}")
            
            for i, vuln in enumerate(results['vulnerabilities'], 1):
                color = self.risk_levels.get(vuln['vulnerability_level'], {}).get('color', Fore.RED)
                
                print(f"{color}▶ {i}. {vuln['vulnerability_level'].upper()}: {vuln['description']}")
                print(f"{self.colors['detail']}   Form: {vuln['action']} [{vuln['method']}]")
                print(f"{self.colors['detail']}   Impact: {vuln['impact']}")
                
                if vuln['risk_factors']:
                    print(f"{self.colors['warning']}   Risk Factors:")
                    for factor in vuln['risk_factors'][:3]:
                        print(f"{self.colors['warning']}     • {factor}")
                
                print(f"{self.colors['success']}   Remediation:")
                for step in vuln['remediation'][:2]:
                    print(f"{self.colors['success']}     • {step}")
                
                print(f"{self.colors['separator']}{'-'*40}")
        
        # Print recommendations
        if results['recommendations']:
            print(f"\n{self.colors['header']}💡 RECOMMENDATIONS:")
            print(f"{self.colors['separator']}{'-'*80}")
            
            for rec in sorted(results['recommendations'], key=lambda x: x['priority'], reverse=True):
                priority_color = {
                    'high': Fore.RED + Style.BRIGHT,
                    'medium': Fore.YELLOW + Style.BRIGHT,
                    'low': Fore.BLUE + Style.BRIGHT
                }.get(rec['priority'], Fore.WHITE)
                
                print(f"{priority_color}[{rec['priority'].upper()}] {rec['title']}")
                print(f"{self.colors['detail']}  {rec['description']}")
                print()
        
        # Final status
        if results['vulnerabilities_found'] > 0:
            print(f"{self.colors['critical']}⚠ CSRF VULNERABILITIES DETECTED! Immediate action required.")
        else:
            print(f"{self.colors['success']}✅ No CSRF vulnerabilities detected. Security controls appear adequate.")
        
        print(f"{self.colors['separator']}{'='*80}\n")

    def export_report(self, results, format='json', filename=None):
        """Export scan results to file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"csrf_scan_{timestamp}.{format}"
        
        try:
            if format.lower() == 'json':
                with open(filename, 'w') as f:
                    json.dump(results, f, indent=2, default=str)
                self.print_status(f"Report exported to {filename}", "success")
            elif format.lower() == 'html':
                # HTML report generation
                html_report = self.generate_html_report(results)
                with open(filename, 'w') as f:
                    f.write(html_report)
                self.print_status(f"HTML report exported to {filename}", "success")
            else:
                self.print_status(f"Unsupported format: {format}", "error")
        except Exception as e:
            self.print_status(f"Failed to export report: {e}", "error")

    def generate_html_report(self, results):
        """Generate HTML report"""
        # Simplified HTML report - can be expanded
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>CSRF Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .vulnerable {{ color: red; font-weight: bold; }}
        .safe {{ color: green; }}
        .warning {{ color: orange; }}
    </style>
</head>
<body>
    <h1>CSRF Vulnerability Scan Report</h1>
    <p>Target: {results['target']}</p>
    <p>Vulnerabilities Found: {results['vulnerabilities_found']}</p>
</body>
</html>
"""
        return html

# Example usage
if __name__ == "__main__":
    scanner = CSRFScanner()
    
    # Run scan
    target_url = "http://example.com/login"
    results = scanner.scan(target_url)
    
    # Export results
    scanner.export_report(results, format='json', filename='csrf_scan_results.json")