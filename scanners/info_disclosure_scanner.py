import re
import time
import os
import json
import hashlib
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style, Back, init
from datetime import datetime

# Initialize colorama
init(autoreset=True)

class InfoDisclosureScanner:
    def __init__(self):
        self.name = "🔍 ADVANCED INFORMATION DISCLOSURE SCANNER"
        self.version = "3.5"
        self.author = "Security Intelligence Team"
        
        # Enhanced color scheme
        self.colors = {
            'banner': Fore.MAGENTA + Style.BRIGHT,
            'header': Fore.WHITE + Style.BRIGHT,
            'info': Fore.CYAN + Style.BRIGHT,
            'success': Fore.GREEN + Style.BRIGHT,
            'warning': Fore.YELLOW + Style.BRIGHT,
            'error': Fore.RED + Style.BRIGHT,
            'critical': Back.RED + Fore.WHITE + Style.BRIGHT,
            'sensitive': Fore.RED + Back.BLACK + Style.BRIGHT,
            'directory': Fore.BLUE + Style.BRIGHT,
            'config': Fore.YELLOW + Style.BRIGHT,
            'backup': Fore.MAGENTA + Style.BRIGHT,
            'git': Fore.GREEN + Style.BRIGHT,
            'log': Fore.RED + Style.NORMAL,
            'debug': Fore.YELLOW + Style.NORMAL,
            'timestamp': Fore.LIGHTBLACK_EX,
            'separator': Fore.LIGHTBLACK_EX + Style.DIM,
            'highlight': Fore.YELLOW + Back.BLACK + Style.BRIGHT,
            'data': Fore.LIGHTCYAN_EX + Style.NORMAL,
            'path': Fore.LIGHTBLUE_EX + Style.NORMAL
        }
        
        # Sensitive patterns with severity levels
        self.sensitive_patterns = {
            'critical': [
                r'DB_(PASSWORD|PASS|PWD|USER|USERNAME|HOST|NAME)\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'API_(KEY|SECRET|TOKEN)\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'(SECRET|PRIVATE)_KEY\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'AWS_(ACCESS_KEY|SECRET_KEY)\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
                r'-----BEGIN PRIVATE KEY-----',
                r'password\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'passwd\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'DATABASE_URL\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'REDIS_PASSWORD\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'MYSQL_ROOT_PASSWORD\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'JWT_SECRET\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'ENCRYPTION_KEY\s*[=:]\s*[\'"]([^\'"]+)[\'"]'
            ],
            'high': [
                r'EMAIL_(PASSWORD|PASS)\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'SMTP_(PASSWORD|PASS)\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'ADMIN_(PASSWORD|PASS)\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'ROOT_PASSWORD\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'CLIENT_(SECRET|ID)\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'oauth_token\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'access_token\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'secret_key_base\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'session_secret\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
                r'csrf_token\s*[=:]\s*[\'"]([^\'"]+)[\'"]'
            ],
            'medium': [
                r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
                r'DEBUG\s*[=:]\s*true',
                r'ENVIRONMENT\s*[=:]\s*[\'"]development[\'"]',
                r'APP_DEBUG\s*[=:]\s*true',
                r'phpinfo\(\)',
                r'display_errors\s*[=:]\s*On',
                r'error_reporting\(E_ALL\)',
                r'expose_php\s*[=:]\s*On'
            ],
            'low': [
                r'@\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                r'Version:\s*[\'"]([^\'"]+)[\'"]',
                r'v\d+\.\d+\.\d+',
                r'\b\d{4}-\d{2}-\d{2}\b',
                r'\b\d{2}:\d{2}:\d{2}\b'
            ]
        }
        
        # Comprehensive sensitive file list
        self.sensitive_files = {
            'configuration': [
                # Environment files
                '/.env', '/.env.local', '/.env.production', '/.env.development',
                '/.env.test', '/.env.example', '/.env.sample',
                # PHP Configuration
                '/config.php', '/configuration.php', '/config.inc.php',
                '/config/database.php', '/config/settings.php',
                '/app/config/database.php', '/application/config/database.php',
                '/includes/config.php', '/system/config.php',
                # WordPress
                '/wp-config.php', '/wp-config-sample.php',
                '/wp-content/debug.log', '/wp-content/uploads/.htaccess',
                # Laravel
                '/.env.example', '/config/app.php', '/config/database.php',
                # Django
                '/settings.py', '/local_settings.py', '/production.py',
                # Ruby
                '/config/database.yml', '/config/secrets.yml',
                '/config/application.yml',
                # Node.js
                '/config.json', '/config/config.json', '/config/default.json',
                '/.npmrc', '/.yarnrc',
                # Java
                '/application.properties', '/application.yml',
                '/application-production.yml',
                # General
                '/secrets.json', '/credentials.json', '/keys.json',
                '/settings.json', '/security.json'
            ],
            'backup': [
                # Database backups
                '/backup.zip', '/backup.tar.gz', '/backup.tar',
                '/backup.sql', '/dump.sql', '/database.sql',
                '/db_backup.sql', '/db_dump.sql', '/mysql_dump.sql',
                '/export.sql', '/data.sql',
                # File backups
                '/backup/', '/backups/', '/backup/files/',
                '/old/', '/archive/', '/archives/',
                '/temp_backup/', '/tmp_backup/',
                # Versioned backups
                '/backup_2024.zip', '/backup_2023.tar.gz',
                '/db_backup_2024.sql', '/full_backup.tar'
            ],
            'git': [
                # Git internals
                '/.git/', '/.git/config', '/.git/HEAD',
                '/.git/logs/HEAD', '/.git/index',
                '/.git/refs/heads/master', '/.git/refs/heads/main',
                '/.git/objects/', '/.git/hooks/',
                # Git-related
                '/.gitignore', '/.gitmodules', '/.gitattributes',
                '/.git-credentials', '/.gitconfig'
            ],
            'log': [
                # Access logs
                '/logs/access.log', '/logs/error.log',
                '/var/log/access.log', '/var/log/error.log',
                '/var/log/nginx/access.log', '/var/log/nginx/error.log',
                '/var/log/apache2/access.log', '/var/log/apache2/error.log',
                '/var/log/httpd/access_log', '/var/log/httpd/error_log',
                # Application logs
                '/storage/logs/laravel.log', '/storage/logs/error.log',
                '/log/production.log', '/log/development.log',
                '/tmp/logs/', '/temp/logs/',
                # Debug logs
                '/debug.log', '/php_error.log', '/error_log',
                '/app/logs/', '/application/logs/'
            ],
            'debug': [
                '/phpinfo.php', '/info.php', '/test.php',
                '/debug.php', '/admin/debug.php',
                '/status.php', '/server-status',
                '/server-info', '/.htinfo',
                '/web.config', '/web.xml',
                '/WEB-INF/web.xml', '/META-INF/context.xml'
            ],
            'source': [
                # IDE files
                '/.idea/', '/.vscode/', '/.project',
                '/.classpath', '/.settings/',
                # OS files
                '/.DS_Store', '/Thumbs.db', '/desktop.ini',
                # Web server
                '/.htaccess', '/.htpasswd',
                '/robots.txt', '/sitemap.xml', '/sitemap.txt',
                '/crossdomain.xml', '/clientaccesspolicy.xml',
                # Package managers
                '/package.json', '/composer.json', '/composer.lock',
                '/yarn.lock', '/Gemfile', '/Gemfile.lock',
                '/requirements.txt', '/Pipfile', '/Pipfile.lock',
                # Build files
                '/Dockerfile', '/docker-compose.yml',
                '/Makefile', '/build.xml', '/pom.xml',
                # Documentation
                '/README.md', '/CHANGELOG.md', '/LICENSE',
                '/SECURITY.md', '/CONTRIBUTING.md'
            ],
            'admin': [
                '/admin/', '/administrator/', '/wp-admin/',
                '/dashboard/', '/cpanel/', '/webadmin/',
                '/controlpanel/', '/cp/', '/admincp/',
                '/backend/', '/manager/', '/sysadmin/',
                '/phpmyadmin/', '/adminer/', '/mysql-admin/',
                '/pgadmin/', '/sqlite/', '/redis-admin/'
            ]
        }
        
        # Directory listing test directories
        self.directory_listing_dirs = [
            '/images/', '/uploads/', '/files/', '/assets/',
            '/static/', '/media/', '/documents/', '/backup/',
            '/tmp/', '/temp/', '/cache/', '/logs/',
            '/var/', '/public/', '/downloads/', '/export/',
            '/data/', '/resources/', '/content/', '/userfiles/'
        ]
        
        # File extensions to check for source code
        self.source_extensions = [
            '.php', '.py', '.js', '.java', '.rb', '.go',
            '.c', '.cpp', '.cs', '.sql', '.html', '.css',
            '.xml', '.json', '.yml', '.yaml', '.ini',
            '.conf', '.cfg', '.properties'
        ]
        
        # Risk levels
        self.risk_levels = {
            'critical': {
                'color': Back.RED + Fore.WHITE + Style.BRIGHT,
                'score': 50,
                'description': 'Credentials, API keys, private keys exposed'
            },
            'high': {
                'color': Fore.RED + Style.BRIGHT,
                'score': 30,
                'description': 'Sensitive configuration, admin interfaces'
            },
            'medium': {
                'color': Fore.YELLOW + Style.BRIGHT,
                'score': 20,
                'description': 'Debug information, error details'
            },
            'low': {
                'color': Fore.BLUE + Style.BRIGHT,
                'score': 10,
                'description': 'Version info, email addresses'
            },
            'info': {
                'color': Fore.CYAN + Style.BRIGHT,
                'score': 5,
                'description': 'Informational findings'
            }
        }

    def print_banner(self):
        """Display enhanced scanner banner"""
        banner = f"""
{self.colors['banner']}{"="*85}
{self.colors['header']}╔══════════════════════════════════════════════════════════════════════════╗
║ {self.colors['banner']}{self.name:^73} {self.colors['header']}║
║ {self.colors['info']}Version: {self.version:<63} {self.colors['header']}║
║ {self.colors['info']}Author: {self.author:<63} {self.colors['header']}║
╚══════════════════════════════════════════════════════════════════════════╝
{self.colors['banner']}{"="*85}
"""
        print(banner)

    def print_status(self, message, level="info", indent=0, url=None):
        """Print colored status messages with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        prefix = {
            "info": f"{self.colors['info']}[ℹ]",
            "success": f"{self.colors['success']}[✓]",
            "warning": f"{self.colors['warning']}[⚠]",
            "error": f"{self.colors['error']}[✗]",
            "critical": f"{self.colors['critical']}[‼]",
            "config": f"{self.colors['config']}[⚙]",
            "backup": f"{self.colors['backup']}[💾]",
            "git": f"{self.colors['git']}[🐙]",
            "log": f"{self.colors['log']}[📋]",
            "debug": f"{self.colors['debug']}[🐛]",
            "directory": f"{self.colors['directory']}[📁]",
            "sensitive": f"{self.colors['sensitive']}[🔐]",
            "scan": f"{self.colors['info']}[🔍]"
        }.get(level, f"{self.colors['info']}[*]")
        
        indent_str = "  " * indent
        url_str = f" {self.colors['path']}{url}" if url else ""
        print(f"{self.colors['timestamp']}[{timestamp}] {prefix}{Style.RESET_ALL} {indent_str}{message}{url_str}")

    def scan(self, target, options=None):
        """Comprehensive information disclosure scanning"""
        self.print_banner()
        
        results = {
            'target': target,
            'files_found': 0,
            'directories_found': 0,
            'sensitive_files': [],
            'directory_listings': [],
            'source_code_leaks': [],
            'sensitive_data_found': [],
            'total_checks': 0,
            'risk_score': 0,
            'start_time': time.time(),
            'end_time': None,
            'scan_duration': None
        }
        
        try:
            from utils.request_wrapper import RequestWrapper
            req = RequestWrapper()
            
            self.print_status(f"Initiating information disclosure scan on: {self.colors['highlight']}{target}", "info")
            
            # Phase 1: Check sensitive files
            self.print_status("Phase 1: Checking for sensitive files...", "scan")
            sensitive_results = self.scan_sensitive_files(target, req)
            results['sensitive_files'].extend(sensitive_results['found'])
            results['files_found'] += len(sensitive_results['found'])
            results['total_checks'] += sensitive_results['checked']
            
            # Phase 2: Check for directory listing
            self.print_status("Phase 2: Checking for directory listing...", "scan")
            dir_results = self.scan_directory_listing(target, req)
            results['directory_listings'].extend(dir_results['found'])
            results['directories_found'] += len(dir_results['found'])
            results['total_checks'] += dir_results['checked']
            
            # Phase 3: Check for source code leaks
            self.print_status("Phase 3: Checking for source code leaks...", "scan")
            source_results = self.scan_source_code(target, req)
            results['source_code_leaks'].extend(source_results['found'])
            results['files_found'] += len(source_results['found'])
            results['total_checks'] += source_results['checked']
            
            # Phase 4: Deep content analysis of found files
            self.print_status("Phase 4: Analyzing file contents for sensitive data...", "scan")
            data_results = self.analyze_found_content(results['sensitive_files'] + results['source_code_leaks'], req)
            results['sensitive_data_found'].extend(data_results)
            
            # Calculate risk score
            results['risk_score'] = self.calculate_risk_score(results)
            
            # Complete scan
            results['end_time'] = time.time()
            results['scan_duration'] = results['end_time'] - results['start_time']
            
            # Print comprehensive report
            self.print_summary(results)
            
            return results
            
        except Exception as e:
            self.print_status(f"Scan error: {str(e)}", "error")
            results['error'] = str(e)
            results['end_time'] = time.time()
            return results

    def scan_sensitive_files(self, target, req):
        """Scan for sensitive files"""
        results = {
            'found': [],
            'checked': 0
        }
        
        # Combine all sensitive file categories
        all_files = []
        for category, files in self.sensitive_files.items():
            for file_path in files:
                all_files.append((file_path, category))
        
        self.print_status(f"Checking {len(all_files)} sensitive file patterns...", "info", 1)
        
        for file_path, category in all_files:
            url = urljoin(target.rstrip('/') + '/', file_path.lstrip('/'))
            results['checked'] += 1
            
            try:
                response = req.get(url, timeout=10)
                
                if response.status_code == 200:
                    file_info = {
                        'url': url,
                        'path': file_path,
                        'category': category,
                        'status_code': response.status_code,
                        'content_length': len(response.content),
                        'content_type': response.headers.get('content-type', 'unknown'),
                        'hash': hashlib.md5(response.content).hexdigest()[:8],
                        'risk_level': self.get_file_risk_level(category, response)
                    }
                    
                    # Check if file actually contains sensitive content
                    if self.contains_sensitive_content(response.text, category):
                        results['found'].append(file_info)
                        
                        # Print finding with appropriate color
                        color = self.get_category_color(category)
                        self.print_status(f"Found {category} file: {file_path}", category, 2, url)
                        
                        # Print file info
                        self.print_status(f"Size: {len(response.content)} bytes | Type: {response.headers.get('content-type', 'unknown')}", "info", 3)
                
                # Also check for 403 (Forbidden) - indicates file exists but protected
                elif response.status_code == 403:
                    self.print_status(f"File exists but forbidden: {file_path}", "warning", 2, url)
                    
                time.sleep(0.1)  # Rate limiting
                
            except Exception as e:
                continue
        
        return results

    def scan_directory_listing(self, target, req):
        """Scan for directory listing vulnerabilities"""
        results = {
            'found': [],
            'checked': 0
        }
        
        self.print_status(f"Checking {len(self.directory_listing_dirs)} directories for listing...", "info", 1)
        
        for directory in self.directory_listing_dirs:
            url = urljoin(target.rstrip('/') + '/', directory.lstrip('/'))
            results['checked'] += 1
            
            try:
                response = req.get(url, timeout=10)
                
                if response.status_code == 200:
                    if self.is_directory_listing(response.text):
                        dir_info = {
                            'url': url,
                            'directory': directory,
                            'status_code': response.status_code,
                            'page_title': self.extract_page_title(response.text),
                            'file_count': self.count_listed_files(response.text),
                            'risk_level': 'medium'
                        }
                        results['found'].append(dir_info)
                        
                        self.print_status(f"Directory listing enabled: {directory}", "directory", 2, url)
                        
                        # List some files found
                        files = self.extract_listed_files(response.text)[:5]
                        if files:
                            self.print_status(f"Sample files: {', '.join(files[:3])}", "info", 3)
                
                time.sleep(0.1)
                
            except Exception as e:
                continue
        
        return results

    def scan_source_code(self, target, req):
        """Scan for source code leaks"""
        results = {
            'found': [],
            'checked': 0
        }
        
        # Generate common source code file patterns
        source_files = []
        
        # Common file names with extensions
        common_names = ['index', 'main', 'app', 'config', 'database', 'settings',
                       'admin', 'login', 'register', 'api', 'user', 'profile']
        
        for name in common_names:
            for ext in self.source_extensions:
                source_files.append(f'/{name}{ext}')
                source_files.append(f'/{name}.bak{ext}')
                source_files.append(f'/{name}.old{ext}')
                source_files.append(f'/{name}~{ext}')
        
        # Add backup extensions
        backup_exts = ['.bak', '.backup', '.old', '.tmp', '.temp', '.save', '.orig']
        for ext in self.source_extensions:
            for backup_ext in backup_exts:
                source_files.append(f'/config{ext}{backup_ext}')
                source_files.append(f'/database{ext}{backup_ext}')
        
        self.print_status(f"Checking {len(source_files)} source code patterns...", "info", 1)
        
        for file_path in source_files:
            url = urljoin(target.rstrip('/') + '/', file_path.lstrip('/'))
            results['checked'] += 1
            
            try:
                response = req.get(url, timeout=10)
                
                if response.status_code == 200:
                    # Check if content looks like source code
                    if self.is_source_code(response.text, file_path):
                        file_info = {
                            'url': url,
                            'path': file_path,
                            'status_code': response.status_code,
                            'content_length': len(response.content),
                            'language': self.detect_programming_language(file_path, response.text),
                            'risk_level': 'medium'
                        }
                        results['found'].append(file_info)
                        
                        self.print_status(f"Source code found: {file_path}", "debug", 2, url)
                        self.print_status(f"Language: {file_info['language']} | Size: {len(response.content)} bytes", "info", 3)
                
                time.sleep(0.1)
                
            except Exception as e:
                continue
        
        return results

    def analyze_found_content(self, files, req):
        """Analyze found files for sensitive data"""
        results = []
        
        if not files:
            return results
        
        self.print_status(f"Analyzing {len(files)} found files for sensitive data...", "scan", 1)
        
        for file_info in files:
            try:
                response = req.get(file_info['url'], timeout=10)
                content = response.text
                
                # Check for sensitive patterns
                findings = self.find_sensitive_patterns(content, file_info['path'])
                
                if findings:
                    file_info['sensitive_findings'] = findings
                    results.append(file_info)
                    
                    # Print findings
                    for level, patterns in findings.items():
                        for pattern in patterns:
                            color = self.risk_levels.get(level, {}).get('color', Fore.WHITE)
                            self.print_status(f"{color}{level.upper()}: Found {pattern} in {file_info['path']}", "sensitive", 2)
            
            except Exception as e:
                continue
        
        return results

    def contains_sensitive_content(self, content, category):
        """Check if content contains sensitive information"""
        content_lower = content.lower()
        
        # Quick checks based on category
        if category == 'configuration':
            return any(pattern in content_lower for pattern in ['password', 'secret', 'key', 'token'])
        elif category == 'git':
            return '[core]' in content or 'repositoryformatversion' in content_lower
        elif category == 'log':
            return any(pattern in content_lower for pattern in ['error', 'exception', 'stack trace'])
        elif category == 'debug':
            return any(pattern in content_lower for pattern in ['phpinfo', 'debug', 'test'])
        
        return len(content.strip()) > 0  # Non-empty content for other categories

    def is_directory_listing(self, content):
        """Check if content shows directory listing"""
        indicators = [
            '<title>Index of',
            '<h1>Index of',
            'Directory listing for',
            'Parent Directory</a>',
            'Last modified</th>',
            'Size</th>',
            'Name</th>',
            'To Parent Directory',
            '<DIR>',
            'bytes</td>',
            'directory</a>'
        ]
        
        return any(indicator in content for indicator in indicators)

    def is_source_code(self, content, file_path):
        """Check if content is source code"""
        # Check file extension
        ext = os.path.splitext(file_path)[1].lower()
        if ext in self.source_extensions:
            return True
        
        # Check content patterns
        code_indicators = [
            '<?php', 'function', 'class ', 'def ', 'import ',
            'require', 'include', 'public ', 'private ', 'protected ',
            'var ', 'const ', 'let ', 'const ', 'export ',
            'package ', 'namespace ', 'using ', '#include'
        ]
        
        return any(indicator in content[:500] for indicator in code_indicators)

    def find_sensitive_patterns(self, content, file_path):
        """Find sensitive patterns in content"""
        findings = {}
        
        for level, patterns in self.sensitive_patterns.items():
            level_findings = []
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    # Extract matched value (be careful with groups)
                    matched_text = match.group(0)[:100]  # First 100 chars
                    level_findings.append({
                        'pattern': pattern[:50] + '...' if len(pattern) > 50 else pattern,
                        'match': matched_text + '...' if len(matched_text) > 100 else matched_text,
                        'line': content[:match.start()].count('\n') + 1
                    })
            
            if level_findings:
                findings[level] = level_findings[:5]  # Limit to 5 findings per level
        
        return findings

    def extract_page_title(self, content):
        """Extract page title from HTML"""
        title_match = re.search(r'<title>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
        if title_match:
            return title_match.group(1).strip()[:50]
        return "No title"

    def count_listed_files(self, content):
        """Count files in directory listing"""
        # Simple counting of <a href> tags that aren't parent directory
        links = re.findall(r'<a href="([^"]+)"', content)
        return len([link for link in links if not link.startswith('?') and link != '../'])

    def extract_listed_files(self, content):
        """Extract listed files from directory listing"""
        files = []
        links = re.findall(r'<a href="([^"]+)"', content)
        
        for link in links:
            if link and not link.startswith('?') and link != '../':
                files.append(link)
        
        return files[:10]  # Return first 10 files

    def detect_programming_language(self, file_path, content):
        """Detect programming language from file"""
        ext = os.path.splitext(file_path)[1].lower()
        
        language_map = {
            '.php': 'PHP',
            '.py': 'Python',
            '.js': 'JavaScript',
            '.java': 'Java',
            '.rb': 'Ruby',
            '.go': 'Go',
            '.c': 'C',
            '.cpp': 'C++',
            '.cs': 'C#',
            '.sql': 'SQL',
            '.html': 'HTML',
            '.css': 'CSS',
            '.xml': 'XML',
            '.json': 'JSON',
            '.yml': 'YAML',
            '.yaml': 'YAML',
            '.ini': 'INI',
            '.conf': 'Configuration',
            '.properties': 'Properties'
        }
        
        if ext in language_map:
            return language_map[ext]
        
        # Fallback to content analysis
        if '<?php' in content[:100]:
            return 'PHP'
        elif 'import ' in content[:100] or 'def ' in content[:100]:
            return 'Python'
        elif 'function(' in content[:100] or 'var ' in content[:100]:
            return 'JavaScript'
        
        return 'Unknown'

    def get_file_risk_level(self, category, response):
        """Determine risk level for file category"""
        risk_map = {
            'configuration': 'critical',
            'backup': 'high',
            'git': 'high',
            'log': 'medium',
            'debug': 'medium',
            'source': 'low',
            'admin': 'high'
        }
        return risk_map.get(category, 'medium')

    def get_category_color(self, category):
        """Get color for file category"""
        color_map = {
            'configuration': 'config',
            'backup': 'backup',
            'git': 'git',
            'log': 'log',
            'debug': 'debug',
            'source': 'info',
            'admin': 'warning'
        }
        return color_map.get(category, 'info')

    def calculate_risk_score(self, results):
        """Calculate overall risk score"""
        score = 0
        
        # Add scores for sensitive files
        for file_info in results['sensitive_files']:
            risk_level = file_info.get('risk_level', 'medium')
            score += self.risk_levels.get(risk_level, {}).get('score', 10)
        
        # Add scores for directory listings
        for dir_info in results['directory_listings']:
            score += 15
        
        # Add scores for source code leaks
        for source_info in results['source_code_leaks']:
            score += 10
        
        # Add scores for sensitive data findings
        for data_info in results['sensitive_data_found']:
            for level in data_info.get('sensitive_findings', {}).keys():
                score += self.risk_levels.get(level, {}).get('score', 5)
        
        return min(score, 100)

    def print_summary(self, results):
        """Print comprehensive scan summary"""
        duration = results.get('scan_duration', 0)
        
        summary = f"""
{self.colors['separator']}{"="*85}
{self.colors['header']}📊 INFORMATION DISCLOSURE SCAN SUMMARY
{self.colors['separator']}{"-"*85}
{self.colors['data']}Target URL:           {results['target']}
{self.colors['data']}Scan Duration:        {duration:.2f} seconds
{self.colors['data']}Total Checks:         {results['total_checks']}
{self.colors['data']}Files Found:          {results['files_found']}
{self.colors['data']}Directories Found:    {results['directories_found']}
{self.colors['data']}Risk Score:           {results['risk_score']}/100
{self.colors['separator']}{"-"*85}
"""
        print(summary)
        
        # Print findings by category
        categories = [
            ('🚨 SENSITIVE FILES', results['sensitive_files'], 'sensitive_files'),
            ('📁 DIRECTORY LISTINGS', results['directory_listings'], 'directory_listings'),
            ('💻 SOURCE CODE LEAKS', results['source_code_leaks'], 'source_code_leaks'),
            ('🔐 SENSITIVE DATA', results['sensitive_data_found'], 'sensitive_data_found')
        ]
        
        for title, items, key in categories:
            if items:
                print(f"\n{self.colors['header']}{title} ({len(items)}):")
                print(f"{self.colors['separator']}{'-'*85}")
                
                for i, item in enumerate(items[:10], 1):  # Show first 10 items
                    if key == 'sensitive_files':
                        color = self.get_category_color(item['category'])
                        print(f"{self.colors[color]}▶ {i}. {item['category'].upper()}: {item['path']}")
                        print(f"{self.colors['data']}   URL: {item['url']}")
                        print(f"{self.colors['data']}   Size: {item.get('content_length', 0)} bytes | Risk: {item.get('risk_level', 'medium')}")
                    
                    elif key == 'directory_listings':
                        print(f"{self.colors['directory']}▶ {i}. Directory: {item['directory']}")
                        print(f"{self.colors['data']}   URL: {item['url']}")
                        print(f"{self.colors['data']}   Files: ~{item.get('file_count', 0)} items")
                    
                    elif key == 'source_code_leaks':
                        print(f"{self.colors['debug']}▶ {i}. Source: {item['path']}")
                        print(f"{self.colors['data']}   Language: {item.get('language', 'Unknown')}")
                        print(f"{self.colors['data']}   URL: {item['url']}")
                    
                    elif key == 'sensitive_data_found':
                        print(f"{self.colors['sensitive']}▶ {i}. File: {item['path']}")
                        findings = item.get('sensitive_findings', {})
                        for level, level_findings in findings.items():
                            color = self.risk_levels.get(level, {}).get('color', Fore.WHITE)
                            print(f"{color}   {level.upper()} findings: {len(level_findings)}")
                    
                    if i < len(items[:10]):
                        print(f"{self.colors['separator']}{'-'*40}")
        
        # Print recommendations
        recommendations = self.generate_recommendations(results)
        if recommendations:
            print(f"\n{self.colors['header']}💡 RECOMMENDATIONS:")
            print(f"{self.colors['separator']}{'-'*85}")
            
            for i, rec in enumerate(recommendations, 1):
                priority_color = {
                    'critical': Back.RED + Fore.WHITE,
                    'high': Fore.RED + Style.BRIGHT,
                    'medium': Fore.YELLOW + Style.BRIGHT,
                    'low': Fore.BLUE + Style.BRIGHT
                }.get(rec['priority'], Fore.WHITE)
                
                print(f"{priority_color}{i}. [{rec['priority'].upper()}] {rec['title']}")
                print(f"{self.colors['data']}   {rec['description']}")
                print()
        
        # Final status
        if results['risk_score'] > 70:
            print(f"{self.colors['critical']}⚠ CRITICAL INFORMATION DISCLOSURE DETECTED! Immediate action required.")
        elif results['risk_score'] > 40:
            print(f"{self.colors['warning']}⚠ Multiple information disclosure issues found. Review findings.")
        else:
            print(f"{self.colors['success']}✅ Minimal information disclosure detected. Maintain current security controls.")
        
        print(f"{self.colors['separator']}{'='*85}\n")

    def generate_recommendations(self, results):
        """Generate targeted recommendations"""
        recommendations = []
        
        if results['sensitive_files']:
            recommendations.append({
                'priority': 'high',
                'title': 'Remove Sensitive Files',
                'description': f'Remove or restrict access to {len(results["sensitive_files"])} sensitive files'
            })
        
        if results['directory_listings']:
            recommendations.append({
                'priority': 'medium',
                'title': 'Disable Directory Listing',
                'description': f'Disable directory listing on {len(results["directory_listings"])} directories'
            })
        
        if results['sensitive_data_found']:
            recommendations.append({
                'priority': 'critical',
                'title': 'Remove Sensitive Data',
                'description': 'Remove credentials and sensitive data from exposed files'
            })
        
        # General recommendations
        recommendations.extend([
            {
                'priority': 'high',
                'title': 'Implement Access Controls',
                'description': 'Use .htaccess, web.config, or application logic to restrict access'
            },
            {
                'priority': 'medium',
                'title': 'Remove Backup Files',
                'description': 'Regularly clean up backup, temporary, and debug files'
            },
            {
                'priority': 'low',
                'title': 'Monitor File Permissions',
                'description': 'Regularly audit file permissions and access controls'
            }
        ])
        
        return sorted(recommendations, key=lambda x: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}[x['priority']])

    def export_report(self, results, format='json', filename=None):
        """Export scan results to file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"info_disclosure_scan_{timestamp}.{format}"
        
        try:
            if format.lower() == 'json':
                # Clean up results for JSON serialization
                export_data = {
                    'scan_summary': {
                        'target': results.get('target'),
                        'timestamp': datetime.now().isoformat(),
                        'duration': results.get('scan_duration'),
                        'risk_score': results.get('risk_score'),
                        'total_findings': results.get('files_found', 0) + results.get('directories_found', 0)
                    },
                    'findings': {
                        'sensitive_files': results.get('sensitive_files', []),
                        'directory_listings': results.get('directory_listings', []),
                        'source_code_leaks': results.get('source_code_leaks', []),
                        'sensitive_data': results.get('sensitive_data_found', [])
                    }
                }
                
                with open(filename, 'w') as f:
                    json.dump(export_data, f, indent=2, default=str)
                self.print_status(f"JSON report exported to {filename}", "success")
            
            elif format.lower() == 'html':
                html_report = self.generate_html_report(results)
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(html_report)
                self.print_status(f"HTML report exported to {filename}", "success")
            
            else:
                self.print_status(f"Unsupported format: {format}", "error")
                
        except Exception as e:
            self.print_status(f"Failed to export report: {e}", "error")

    def generate_html_report(self, results):
        """Generate HTML report"""
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Information Disclosure Scan Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; background: #1a1a1a; color: #e0e0e0; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 40px; border-radius: 10px; margin-bottom: 30px; }}
        .header h1 {{ color: white; margin: 0; font-size: 2.5em; }}
        .summary {{ background: #2d2d2d; padding: 25px; border-radius: 8px; margin-bottom: 30px; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }}
        .summary-item {{ background: #3d3d3d; padding: 15px; border-radius: 6px; }}
        .summary-value {{ font-size: 2em; font-weight: bold; color: #667eea; }}
        .findings {{ margin-top: 30px; }}
        .finding-card {{ background: #2d2d2d; border-left: 4px solid #667eea; padding: 20px; margin: 15px 0; border-radius: 4px; }}
        .critical {{ border-left-color: #ff4757; }}
        .high {{ border-left-color: #ff6348; }}
        .medium {{ border-left-color: #ffa502; }}
        .low {{ border-left-color: #2ed573; }}
        .url {{ color: #70a1ff; word-break: break-all; }}
        .risk-score {{ font-size: 3em; font-weight: bold; text-align: center; margin: 20px 0; }}
        .critical-score {{ color: #ff4757; }}
        .high-score {{ color: #ff6348; }}
        .medium-score {{ color: #ffa502; }}
        .low-score {{ color: #2ed573; }}
        pre {{ background: #252525; padding: 15px; border-radius: 6px; overflow-x: auto; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Information Disclosure Scan Report</h1>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="summary">
            <h2>Scan Summary</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <div class="summary-label">Target</div>
                    <div class="summary-value">{results.get('target', 'N/A')}</div>
                </div>
                <div class="summary-item">
                    <div class="summary-label">Duration</div>
                    <div class="summary-value">{results.get('scan_duration', 0):.2f}s</div>
                </div>
                <div class="summary-item">
                    <div class="summary-label">Files Found</div>
                    <div class="summary-value">{results.get('files_found', 0)}</div>
                </div>
                <div class="summary-item">
                    <div class="summary-label">Risk Score</div>
                    <div class="summary-value risk-score {'critical-score' if results.get('risk_score', 0) > 70 else 'high-score' if results.get('risk_score', 0) > 40 else 'medium-score' if results.get('risk_score', 0) > 20 else 'low-score'}">
                        {results.get('risk_score', 0)}/100
                    </div>
                </div>
            </div>
        </div>
        
        <div class="findings">
            <h2>Findings</h2>
            
            <h3>Sensitive Files ({len(results.get('sensitive_files', []))})</h3>
            {self.generate_findings_html(results.get('sensitive_files', []), 'sensitive')}
            
            <h3>Directory Listings ({len(results.get('directory_listings', []))})</h3>
            {self.generate_findings_html(results.get('directory_listings', []), 'directory')}
            
            <h3>Sensitive Data Found ({len(results.get('sensitive_data_found', []))})</h3>
            {self.generate_findings_html(results.get('sensitive_data_found', []), 'data')}
        </div>
        
        <div class="summary">
            <h2>Recommendations</h2>
            <ol>
                <li><strong>Remove Sensitive Files:</strong> Delete or restrict access to configuration files, backups, and logs</li>
                <li><strong>Disable Directory Listing:</strong> Configure web server to prevent directory browsing</li>
                <li><strong>Implement Access Controls:</strong> Use authentication and authorization for sensitive areas</li>
                <li><strong>Regular Audits:</strong> Schedule regular security scans and file permission checks</li>
            </ol>
        </div>
    </div>
</body>
</html>"""
        return html

    def generate_findings_html(self, findings, type):
        """Generate HTML for findings section"""
        if not findings:
            return "<p>No findings in this category.</p>"
        
        html = ""
        for i, finding in enumerate(findings[:10], 1):
            risk_class = finding.get('risk_level', 'medium').lower()
            html += f"""
            <div class="finding-card {risk_class}">
                <h4>Finding #{i}: {finding.get('path', finding.get('directory', 'Unknown'))}</h4>
                <p><strong>URL:</strong> <span class="url">{finding.get('url', 'N/A')}</span></p>
                <p><strong>Status:</strong> {finding.get('status_code', 'N/A')}</p>
                <p><strong>Size:</strong> {finding.get('content_length', 'N/A')} bytes</p>
                <p><strong>Risk Level:</strong> <span class="{risk_class}">{finding.get('risk_level', 'medium').upper()}</span></p>
            </div>
            """
        return html

# Example usage
if __name__ == "__main__":
    scanner = InfoDisclosureScanner()
    
    # Run scan
    target_url = "http://example.com"
    results = scanner.scan(target_url)
    
    # Export results
    scanner.export_report(results, format='json', filename='info_disclosure_results.json')
    scanner.export_report(results, format='html', filename='info_disclosure_report.html')