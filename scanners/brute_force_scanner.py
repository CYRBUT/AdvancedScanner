import time
import threading
import queue
from colorama import Fore, Style

class BruteForceScanner:
    def __init__(self):
        self.name = "Brute Force Scanner"
        self.version = "2.5"
        self.common_usernames = [
            'admin', 'administrator', 'root', 'user', 'test',
            'guest', 'admin123', 'superuser', 'manager', 'system'
        ]
        
        self.common_passwords = [
            'admin', 'admin123', 'password', '123456', 'password123',
            '12345678', '123456789', 'qwerty', 'abc123', 'letmein',
            'welcome', 'monkey', 'password1', '1234567', 'sunshine',
            'master', 'hello', 'freedom', 'whatever', 'qazwsx'
        ]
        
        self.max_threads = 5
        self.timeout = 10
    
    def scan(self, target, options=None):
        """Perform brute force scanning"""
        results = {
            'credentials_found': [],
            'tested_combinations': 0,
            'timestamp': time.time()
        }
        
        try:
            # Check common login endpoints
            login_endpoints = [
                '/admin/login',
                '/wp-login.php',
                '/administrator',
                '/login',
                '/auth/login',
                '/signin',
                '/user/login',
                '/admin',
                '/dashboard'
            ]
            
            from utils.request_wrapper import RequestWrapper
            req = RequestWrapper()
            
            for endpoint in login_endpoints:
                login_url = f"{target.rstrip('/')}{endpoint}"
                
                print(f"{Fore.YELLOW}[*] Testing login endpoint: {login_url}")
                
                response = req.get(login_url)
                
                if response.status_code == 200:
                    print(f"{Fore.GREEN}[+] Found login page: {login_url}")
                    
                    # Test default credentials
                    credentials = self.test_default_credentials(login_url)
                    if credentials:
                        results['credentials_found'].extend(credentials)
                
                time.sleep(0.5)
            
            return results
            
        except Exception as e:
            print(f"{Fore.RED}[-] Brute Force scan error: {e}")
            return results
    
    def test_default_credentials(self, login_url):
        """Test default credentials on login page"""
        credentials_found = []
        
        from utils.request_wrapper import RequestWrapper
        req = RequestWrapper()
        
        # Common credential pairs
        common_pairs = [
            ('admin', 'admin'),
            ('admin', 'admin123'),
            ('admin', 'password'),
            ('administrator', 'administrator'),
            ('root', 'root'),
            ('test', 'test'),
            ('guest', 'guest')
        ]
        
        for username, password in common_pairs:
            try:
                # Try POST request with credentials
                data = {
                    'username': username,
                    'password': password,
                    'email': username,
                    'user': username
                }
                
                response = req.post(login_url, data=data)
                
                # Check for successful login indicators
                if self.is_login_successful(response):
                    creds = {
                        'url': login_url,
                        'username': username,
                        'password': password,
                        'method': 'POST'
                    }
                    credentials_found.append(creds)
                    print(f"{Fore.RED}[!] Found credentials: {username}:{password}")
                    
            except Exception as e:
                continue
        
        return credentials_found
    
    def is_login_successful(self, response):
        """Determine if login was successful"""
        success_indicators = [
            'logout',
            'dashboard',
            'welcome',
            'successfully',
            'my account',
            'profile',
            'Logout',
            'Dashboard',
            'Welcome'
        ]
        
        failure_indicators = [
            'invalid',
            'incorrect',
            'failed',
            'error',
            'try again'
        ]
        
        response_text = response.text.lower()
        
        # Check for success indicators
        for indicator in success_indicators:
            if indicator.lower() in response_text:
                return True
        
        # Check for absence of failure indicators
        failure_count = 0
        for indicator in failure_indicators:
            if indicator in response_text:
                failure_count += 1
        
        # Also check for redirect (common on successful login)
        if response.status_code in [301, 302, 303]:
            return True
        
        return False