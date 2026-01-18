import time
import json
import re
from colorama import Fore, Style

class MonologHijackScanner:
    def __init__(self):
        self.name = "Monolog Hijack Scanner"
        self.version = "1.3"
        
    def scan(self, target, options=None):
        """Scan for Monolog hijacking vulnerabilities"""
        from utils.request_wrapper import RequestWrapper
        
        results = {
            'vulnerabilities': [],
            'tested_endpoints': 0,
            'timestamp': time.time()
        }
        
        try:
            req = RequestWrapper()
            
            # Common Monolog endpoints
            endpoints = [
                '/logs',
                '/monolog',
                '/_logs',
                '/app/logs',
                '/var/log',
                '/storage/logs',
                '/log',
                '/debug/log',
                '/api/logs',
                '/admin/logs'
            ]
            
            for endpoint in endpoints:
                url = f"{target.rstrip('/')}{endpoint}"
                
                try:
                    response = req.get(url)
                    results['tested_endpoints'] += 1
                    
                    if self.is_monolog_endpoint(response):
                        vuln = {
                            'type': 'Monolog Hijacking',
                            'endpoint': endpoint,
                            'url': url,
                            'risk': 'HIGH',
                            'evidence': self.analyze_monolog_response(response)
                        }
                        results['vulnerabilities'].append(vuln)
                        print(f"{Fore.RED}[!] Monolog endpoint found: {url}")
                        
                except Exception as e:
                    continue
                
                time.sleep(0.3)
            
            return results
            
        except Exception as e:
            print(f"{Fore.RED}[-] Monolog scan error: {e}")
            return results
    
    def is_monolog_endpoint(self, response):
        """Check if response is from Monolog"""
        monolog_indicators = [
            'monolog',
            'channel',
            'level_name',
            'datetime',
            'message',
            'context',
            'extra',
            'log_record',
            'handlers',
            'processors'
        ]
        
        response_text = response.text.lower()
        
        # Check for JSON structure typical of Monolog
        try:
            data = json.loads(response.text)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        for key in ['channel', 'level_name', 'datetime', 'message']:
                            if key in item:
                                return True
        except:
            pass
        
        # Check for HTML with Monolog indicators
        indicator_count = 0
        for indicator in monolog_indicators:
            if indicator in response_text:
                indicator_count += 1
        
        return indicator_count >= 3
    
    def analyze_monolog_response(self, response):
        """Analyze Monolog response for sensitive data"""
        evidence = {
            'status_code': response.status_code,
            'content_type': response.headers.get('content-type', ''),
            'sensitive_data_leaked': False,
            'data_types_found': []
        }
        
        # Check for sensitive information patterns
        sensitive_patterns = {
            'passwords': r'pass(word|wd|)["\']?\s*[:=]\s*["\']([^"\'\s]+)["\']?',
            'tokens': r'(token|key|secret|api[_-]?key)["\']?\s*[:=]\s*["\']([^"\'\s]+)["\']?',
            'emails': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'ip_addresses': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            'sql_queries': r'(SELECT|INSERT|UPDATE|DELETE).*FROM',
            'stack_traces': r'at\s+\w+\.\w+\([^)]+\)',
            'file_paths': r'/([a-zA-Z0-9_\-\.]+/)*[a-zA-Z0-9_\-\.]+\.(php|js|py|java)'
        }
        
        for data_type, pattern in sensitive_patterns.items():
            matches = re.findall(pattern, response.text, re.IGNORECASE)
            if matches:
                evidence['data_types_found'].append(data_type)
                evidence['sensitive_data_leaked'] = True
        
        return evidence