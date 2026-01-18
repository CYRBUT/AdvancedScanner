import re
import json
from bs4 import BeautifulSoup
import requests

class InfoDisclosureScanner:
    def __init__(self, target):
        self.target = target
        self.disclosures = []
        
    def scan(self):
        """Scan for information disclosure"""
        print(f"[Info Disclosure] Scanning {self.target}...")
        
        # Get main page
        response = self._get_response(self.target)
        if response:
            self._analyze_response(response)
            
        # Check common files
        self._check_common_files()
        
        # Check headers
        self._check_headers(response)
        
        # Check comments
        self._check_comments(response)
        
        # Check error messages
        self._check_error_messages()
        
        return {
            "target": self.target,
            "disclosures": self.disclosures,
            "count": len(self.disclosures),
            "risk_level": "MEDIUM" if self.disclosures else "LOW"
        }
    
    def _get_response(self, url):
        """Get HTTP response"""
        try:
            return requests.get(url, timeout=10, verify=False)
        except:
            return None
    
    def _analyze_response(self, response):
        """Analyze response for disclosures"""
        # Check for sensitive info in response
        sensitive_patterns = [
            r'password\s*[:=]\s*[\'"]([^\'"]+)[\'"]',
            r'api[_-]?key\s*[:=]\s*[\'"]([^\'"]+)[\'"]',
            r'token\s*[:=]\s*[\'"]([^\'"]+)[\'"]',
            r'secret\s*[:=]\s*[\'"]([^\'"]+)[\'"]',
            r'private[_-]?key\s*[:=]\s*[\'"]([^\'"]+)[\'"]',
            r'database\s*[:=]\s*[\'"]([^\'"]+)[\'"]',
            r'host\s*[:=]\s*[\'"]([^\'"]+)[\'"]',
            r'user\s*[:=]\s*[\'"]([^\'"]+)[\'"]',
            r'pass\s*[:=]\s*[\'"]([^\'"]+)[\'"]',
            r'admin\s*[:=]\s*[\'"]([^\'"]+)[\'"]',
            r'root\s*[:=]\s*[\'"]([^\'"]+)[\'"]'
        ]
        
        for pattern in sensitive_patterns:
            matches = re.findall(pattern, response.text, re.IGNORECASE)
            for match in matches:
                if len(match) > 3:  # Filter short matches
                    self.disclosures.append({
                        'type': 'Sensitive Data in Response',
                        'pattern': pattern,
                        'data': match[:50] + '...' if len(match) > 50 else match,
                        'severity': 'HIGH'
                    })
    
    def _check_common_files(self):
        """Check common sensitive files"""
        common_files = [
            '/.git/config',
            '/.env',
            '/config/database.yml',
            '/wp-config.php',
            '/app/config/parameters.yml',
            '/application/config/database.php',
            '/.htaccess',
            '/robots.txt',
            '/sitemap.xml',
            '/package.json',
            '/composer.json',
            '/yarn.lock',
            '/phpinfo.php',
            '/test.php',
            '/info.php',
            '/.DS_Store',
            '/.svn/entries',
            '/.hg/store',
            '/WEB-INF/web.xml',
            '/crossdomain.xml',
            '/clientaccesspolicy.xml'
        ]
        
        for file in common_files:
            url = urljoin(self.target, file)
            response = self._get_response(url)
            
            if response and response.status_code == 200:
                self.disclosures.append({
                    'type': 'Exposed File',
                    'file': file,
                    'url': url,
                    'size': len(response.text),
                    'severity': 'MEDIUM'
                })
    
    def _check_headers(self, response):
        """Check HTTP headers for disclosures"""
        if not response:
            return
            
        sensitive_headers = [
            'Server', 'X-Powered-By', 'X-AspNet-Version',
            'X-AspNetMvc-Version', 'X-Runtime', 'X-Version',
            'X-Generator', 'X-Drupal-Cache'
        ]
        
        for header in sensitive_headers:
            if header in response.headers:
                self.disclosures.append({
                    'type': 'Information in Header',
                    'header': header,
                    'value': response.headers[header],
                    'severity': 'LOW'
                })
    
    def _check_comments(self, response):
        """Check HTML comments for sensitive info"""
        if not response:
            return
            
        soup = BeautifulSoup(response.text, 'html.parser')
        comments = soup.find_all(string=lambda text: isinstance(text, str) and '<!--' in text)
        
        sensitive_in_comments = ['TODO', 'FIXME', 'BUG', 'HACK', 'password', 'key', 'secret']
        
        for comment in comments:
            for sensitive in sensitive_in_comments:
                if sensitive.lower() in comment.lower():
                    self.disclosures.append({
                        'type': 'Sensitive Info in Comment',
                        'comment': comment[:100] + '...',
                        'indicator': sensitive,
                        'severity': 'LOW'
                    })
                    break
    
    def _check_error_messages(self):
        """Check for verbose error messages"""
        error_tests = [
            f"{self.target}?id='",
            f"{self.target}?page=non_existent",
            f"{self.target}/../",
            f"{self.target}?action=debug"
        ]
        
        for test_url in error_tests:
            response = self._get_response(test_url)
            
            if response and response.status_code >= 400:
                error_indicators = [
                    'Stack trace:', 'SQLSTATE', 'MySQL Error',
                    'PostgreSQL', 'SQLite', 'ODBC', 'PDO',
                    'Exception', 'Error in', 'Warning:',
                    'Notice:', 'on line', 'in file'
                ]
                
                for indicator in error_indicators:
                    if indicator in response.text:
                        self.disclosures.append({
                            'type': 'Verbose Error Message',
                            'url': test_url,
                            'indicator': indicator,
                            'severity': 'MEDIUM'
                        })
                        break