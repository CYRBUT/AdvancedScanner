import re
import time
from bs4 import BeautifulSoup
from colorama import Fore, Style

class CSRFScanner:
    def __init__(self):
        self.name = "CSRF Scanner"
        self.version = "1.5"
        
    def scan(self, target, options=None):
        """Scan for CSRF vulnerabilities"""
        from utils.request_wrapper import RequestWrapper
        
        results = {
            'vulnerabilities': [],
            'forms_analyzed': 0,
            'timestamp': time.time()
        }
        
        try:
            req = RequestWrapper()
            response = req.get(target)
            
            # Parse HTML for forms
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                results['forms_analyzed'] += 1
                
                form_details = self.analyze_form(form, target)
                
                # Check for CSRF protection
                if not self.has_csrf_protection(form):
                    vuln = {
                        'type': 'Cross-Site Request Forgery (CSRF)',
                        'form_action': form_details.get('action'),
                        'form_method': form_details.get('method'),
                        'missing_protection': 'CSRF token',
                        'evidence': form_details
                    }
                    results['vulnerabilities'].append(vuln)
                    print(f"{Fore.RED}[!] CSRF vulnerability found in form")
            
            return results
            
        except Exception as e:
            print(f"{Fore.RED}[-] CSRF scan error: {e}")
            return results
    
    def analyze_form(self, form, base_url):
        """Analyze HTML form for security features"""
        form_details = {
            'action': form.get('action', ''),
            'method': form.get('method', 'GET').upper(),
            'inputs': [],
            'csrf_tokens': []
        }
        
        # Analyze input fields
        for input_tag in form.find_all('input'):
            input_type = input_tag.get('type', 'text')
            input_name = input_tag.get('name', '')
            input_value = input_tag.get('value', '')
            
            input_info = {
                'type': input_type,
                'name': input_name,
                'value': input_value
            }
            
            form_details['inputs'].append(input_info)
            
            # Check for CSRF tokens
            if self.is_csrf_token(input_name, input_value):
                form_details['csrf_tokens'].append(input_info)
        
        return form_details
    
    def has_csrf_protection(self, form):
        """Check if form has CSRF protection"""
        csrf_keywords = ['csrf', 'token', 'nonce', '_token', 'authenticity_token']
        
        # Check input fields
        for input_tag in form.find_all('input'):
            input_name = input_tag.get('name', '').lower()
            input_value = input_tag.get('value', '')
            
            for keyword in csrf_keywords:
                if keyword in input_name:
                    return True
            
            # Check value length (CSRF tokens are usually long)
            if len(input_value) > 20:
                return True
        
        return False
    
    def is_csrf_token(self, name, value):
        """Check if input is CSRF token"""
        csrf_patterns = [
            r'csrf',
            r'token',
            r'nonce',
            r'_token$',
            r'csrfmiddlewaretoken',
            r'anticsrf',
            r'__requestverificationtoken'
        ]
        
        name_lower = name.lower()
        
        for pattern in csrf_patterns:
            if re.search(pattern, name_lower):
                return True
        
        # Check value characteristics
        if len(value) > 20 and re.match(r'^[A-Za-z0-9+/=]+$', value):
            return True
        
        return False