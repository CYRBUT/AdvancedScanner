import re
import hashlib
from bs4 import BeautifulSoup
import requests

class CSRFScanner:
    def __init__(self, target):
        self.target = target
        self.vulnerabilities = []
        self.csrf_tokens = []
        
    def scan(self):
        """Scan for CSRF vulnerabilities"""
        print(f"[CSRF] Scanning {self.target}...")
        
        # Analyze forms for CSRF protection
        forms = self._extract_forms()
        
        for form in forms:
            if not self._has_csrf_protection(form):
                self.vulnerabilities.append({
                    'form': form['action'],
                    'method': form['method'],
                    'reason': 'No CSRF token found',
                    'severity': 'MEDIUM'
                })
                
        # Check CORS settings
        cors_vuln = self._check_cors()
        if cors_vuln:
            self.vulnerabilities.append(cors_vuln)
            
        return {
            "target": self.target,
            "vulnerabilities": self.vulnerabilities,
            "count": len(self.vulnerabilities),
            "risk_level": "MEDIUM" if self.vulnerabilities else "LOW"
        }
    
    def _extract_forms(self):
        """Extract all forms from target"""
        forms = []
        
        try:
            response = requests.get(self.target, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for form in soup.find_all('form'):
                forms.append({
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get').lower(),
                    'inputs': [
                        {
                            'name': inp.get('name'),
                            'type': inp.get('type'),
                            'value': inp.get('value')
                        }
                        for inp in form.find_all(['input', 'textarea', 'select'])
                        if inp.get('name')
                    ]
                })
                
        except Exception as e:
            print(f"[CSRF] Form extraction error: {e}")
            
        return forms
    
    def _has_csrf_protection(self, form):
        """Check if form has CSRF protection"""
        csrf_indicators = ['csrf', 'token', '_token', 'authenticity', 'nonce']
        
        for inp in form['inputs']:
            if inp['name']:
                name_lower = inp['name'].lower()
                if any(indicator in name_lower for indicator in csrf_indicators):
                    self.csrf_tokens.append(inp['name'])
                    return True
                    
        return False
    
    def _check_cors(self):
        """Check CORS misconfigurations"""
        try:
            headers = {
                'Origin': 'https://evil.com',
                'Access-Control-Request-Method': 'POST',
                'Access-Control-Request-Headers': 'X-Requested-With'
            }
            
            response = requests.options(self.target, headers=headers, timeout=5)
            
            cors_headers = response.headers.get('Access-Control-Allow-Origin', '')
            cors_credentials = response.headers.get('Access-Control-Allow-Credentials', '')
            
            if cors_headers == '*' or 'evil.com' in cors_headers:
                if cors_credentials == 'true':
                    return {
                        'type': 'CORS Misconfiguration',
                        'details': 'Credentials allowed with wildcard origin',
                        'severity': 'HIGH'
                    }
                    
        except Exception:
            pass
            
        return None