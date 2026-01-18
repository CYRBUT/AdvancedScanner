import re
import time
import os
from colorama import Fore, Style

class InfoDisclosureScanner:
    def __init__(self):
        self.name = "Information Disclosure Scanner"
        self.version = "2.0"
        
    def scan(self, target, options=None):
        """Scan for information disclosure vulnerabilities"""
        from utils.request_wrapper import RequestWrapper
        
        results = {
            'vulnerabilities': [],
            'files_found': 0,
            'timestamp': time.time()
        }
        
        try:
            req = RequestWrapper()
            
            # Common sensitive files and directories
            sensitive_paths = [
                # Configuration files
                '/.env',
                '/config.php',
                '/configuration.php',
                '/wp-config.php',
                '/config/database.php',
                '/app/config/database.php',
                '/application/config/database.php',
                '/settings.py',
                '/config.json',
                '/secrets.json',
                
                # Backup files
                '/backup.zip',
                '/backup.tar.gz',
                '/backup.sql',
                '/dump.sql',
                '/database.sql',
                
                # Git files
                '/.git/config',
                '/.git/HEAD',
                '/.git/logs/HEAD',
                
                # Source code
                '/.DS_Store',
                '/.htaccess',
                '/robots.txt',
                '/sitemap.xml',
                '/package.json',
                '/composer.json',
                
                # Log files
                '/logs/access.log',
                '/logs/error.log',
                '/var/log/access.log',
                '/var/log/error.log',
                
                # Debug files
                '/debug.log',
                '/phpinfo.php',
                '/test.php',
                '/info.php',
                
                # Administration
                '/admin/',
                '/administrator/',
                '/wp-admin/',
                '/dashboard/',
                '/cpanel/',
                '/webadmin/'
            ]
            
            for path in sensitive_paths:
                url = f"{target.rstrip('/')}{path}"
                
                try:
                    response = req.get(url)
                    results['files_found'] += 1
                    
                    if self.is_sensitive_file(response, path):
                        vuln = {
                            'type': 'Information Disclosure',
                            'file_path': path,
                            'url': url,
                            'status_code': response.status_code,
                            'evidence': self.analyze_sensitive_content(response, path)
                        }
                        results['vulnerabilities'].append(vuln)
                        print(f"{Fore.RED}[!] Sensitive file found: {url}")
                        
                except Exception as e:
                    continue
                
                time.sleep(0.2)
            
            # Check for directory listing
            dir_listing = self.check_directory_listing(target, req)
            if dir_listing:
                results['vulnerabilities'].extend(dir_listing)
            
            return results
            
        except Exception as e:
            print(f"{Fore.RED}[-] Info Disclosure scan error: {e}")
            return results
    
    def is_sensitive_file(self, response, path):
        """Check if file contains sensitive information"""
        if response.status_code not in [200, 403]:
            return False
        
        # Common file extensions that may contain sensitive info
        sensitive_extensions = ['.env', '.php', '.sql', '.json', '.yml', '.yaml', '.log']
        
        for ext in sensitive_extensions:
            if path.endswith(ext) and response.status_code == 200:
                return True
        
        # Check content for sensitive patterns
        sensitive_patterns = [
            r'DB_(PASSWORD|USERNAME|HOST|NAME)',
            r'API_(KEY|SECRET)',
            r'SECRET_KEY',
            r'PASSWORD\s*=',
            r'password\s*:',
            r'aws_access_key',
            r'aws_secret_key',
            r'private_key',
            r'BEGIN RSA PRIVATE KEY',
            r'BEGIN PRIVATE KEY',
            r'DATABASE_URL=',
            r'REDIS_PASSWORD='
        ]
        
        for pattern in sensitive_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                return True
        
        return False
    
    def check_directory_listing(self, target, req):
        """Check for directory listing vulnerabilities"""
        vulnerabilities = []
        
        common_dirs = [
            '/images/',
            '/uploads/',
            '/files/',
            '/assets/',
            '/static/',
            '/media/',
            '/documents/',
            '/backup/',
            '/tmp/',
            '/temp/'
        ]
        
        for directory in common_dirs:
            url = f"{target.rstrip('/')}{directory}"
            
            try:
                response = req.get(url)
                
                if self.is_directory_listing(response):
                    vuln = {
                        'type': 'Directory Listing',
                        'directory': directory,
                        'url': url,
                        'status_code': response.status_code,
                        'risk': 'MEDIUM'
                    }
                    vulnerabilities.append(vuln)
                    print(f"{Fore.RED}[!] Directory listing enabled: {url}")
                    
            except Exception as e:
                continue
        
        return vulnerabilities
    
    def is_directory_listing(self, response):
        """Check if response shows directory listing"""
        directory_listing_indicators = [
            '<title>Index of',
            '<h1>Index of',
            'Directory listing for',
            'Parent Directory',
            'Last modified',
            'Size</th>',
            'Name</th>',
            'To Parent Directory'
        ]
        
        for indicator in directory_listing_indicators:
            if indicator in response.text:
                return True
        
        return False
    
    def analyze_sensitive_content(self, response, path):
        """Analyze sensitive file content"""
        evidence = {
            'content_length': len(response.content),
            'sensitive_patterns_found': [],
            'preview': response.text[:200]  # First 200 chars
        }
        
        # Check for specific sensitive data
        patterns = {
            'database_credentials': r'DB_(PASSWORD|USER|HOST|NAME)\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
            'api_keys': r'API_(KEY|SECRET|TOKEN)\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
            'passwords': r'[Pp]assword\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
            'private_keys': r'-----BEGIN (RSA )?PRIVATE KEY-----',
            'emails': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        }
        
        for pattern_name, pattern in patterns.items():
            matches = re.findall(pattern, response.text, re.IGNORECASE)
            if matches:
                evidence['sensitive_patterns_found'].append(pattern_name)
        
        return evidence