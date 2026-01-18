import time
import socket
import ssl
import struct
from colorama import Fore, Style

class ZeroDayScanner:
    def __init__(self):
        self.name = "Zero-Day Vulnerability Scanner"
        self.version = "3.0"
        
    def scan(self, target, options=None):
        """Scan for potential zero-day vulnerabilities"""
        from utils.request_wrapper import RequestWrapper
        
        results = {
            'potential_vulnerabilities': [],
            'anomalies_detected': [],
            'timestamp': time.time()
        }
        
        try:
            # Parse target URL
            from urllib.parse import urlparse
            parsed = urlparse(target)
            hostname = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            
            # 1. Check for unusual headers
            headers_analysis = self.analyze_headers(target)
            if headers_analysis:
                results['anomalies_detected'].extend(headers_analysis)
            
            # 2. Check for uncommon ports
            port_analysis = self.scan_uncommon_ports(hostname)
            if port_analysis:
                results['potential_vulnerabilities'].extend(port_analysis)
            
            # 3. Check SSL/TLS configuration
            ssl_analysis = self.check_ssl_security(hostname, port)
            if ssl_analysis:
                results['anomalies_detected'].extend(ssl_analysis)
            
            # 4. Check for exposed services
            services_analysis = self.identify_services(hostname)
            if services_analysis:
                results['potential_vulnerabilities'].extend(services_analysis)
            
            # 5. Check for abnormal responses
            response_analysis = self.check_abnormal_responses(target)
            if response_analysis:
                results['anomalies_detected'].extend(response_analysis)
            
            return results
            
        except Exception as e:
            print(f"{Fore.RED}[-] Zero-Day scan error: {e}")
            return results
    
    def analyze_headers(self, target):
        """Analyze HTTP headers for anomalies"""
        from utils.request_wrapper import RequestWrapper
        
        anomalies = []
        
        try:
            req = RequestWrapper()
            response = req.get(target)
            
            headers = response.headers
            
            # Check for missing security headers
            security_headers = [
                'X-Content-Type-Options',
                'X-Frame-Options',
                'X-XSS-Protection',
                'Strict-Transport-Security',
                'Content-Security-Policy',
                'Referrer-Policy'
            ]
            
            missing_headers = []
            for header in security_headers:
                if header not in headers:
                    missing_headers.append(header)
            
            if missing_headers:
                anomalies.append({
                    'type': 'Missing Security Headers',
                    'headers': missing_headers,
                    'risk': 'MEDIUM'
                })
                print(f"{Fore.YELLOW}[!] Missing security headers: {missing_headers}")
            
            # Check for debug headers
            debug_headers = ['X-Debug-Token', 'X-Debug-Token-Link', 'X-Powered-By']
            for header in debug_headers:
                if header in headers:
                    anomalies.append({
                        'type': 'Debug Header Exposed',
                        'header': header,
                        'value': headers[header],
                        'risk': 'LOW'
                    })
                    print(f"{Fore.YELLOW}[!] Debug header exposed: {header}")
            
            return anomalies
            
        except Exception as e:
            return anomalies
    
    def scan_uncommon_ports(self, hostname):
        """Scan for uncommon open ports"""
        vulnerabilities = []
        
        uncommon_ports = [
            21,    # FTP
            22,    # SSH
            23,    # Telnet
            25,    # SMTP
            69,    # TFTP
            110,   # POP3
            143,   # IMAP
            161,   # SNMP
            389,   # LDAP
            445,   # SMB
            1433,  # MSSQL
            3306,  # MySQL
            3389,  # RDP
            5432,  # PostgreSQL
            5900,  # VNC
            6379,  # Redis
            27017, # MongoDB
            9200   # Elasticsearch
        ]
        
        print(f"{Fore.YELLOW}[*] Scanning uncommon ports on {hostname}...")
        
        for port in uncommon_ports[:10]:  # Scan first 10 ports for speed
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                
                result = sock.connect_ex((hostname, port))
                if result == 0:
                    service = self.identify_service(hostname, port)
                    
                    vuln = {
                        'type': 'Exposed Service',
                        'port': port,
                        'service': service,
                        'host': hostname,
                        'risk': 'HIGH'
                    }
                    vulnerabilities.append(vuln)
                    print(f"{Fore.RED}[!] Exposed service on port {port}: {service}")
                
                sock.close()
                
            except:
                continue
        
        return vulnerabilities
    
    def identify_service(self, hostname, port):
        """Identify service running on port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((hostname, port))
            
            # Try to get banner
            if port == 80 or port == 443:
                return "HTTP/HTTPS"
            elif port == 22:
                return "SSH"
            elif port == 21:
                return "FTP"
            elif port == 25:
                return "SMTP"
            elif port == 3306:
                return "MySQL"
            elif port == 5432:
                return "PostgreSQL"
            elif port == 27017:
                return "MongoDB"
            else:
                return "Unknown"
                
        except:
            return "Unknown"
    
    def check_ssl_security(self, hostname, port):
        """Check SSL/TLS security configuration"""
        anomalies = []
        
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    # Check certificate expiration
                    from datetime import datetime
                    not_after = cert.get('notAfter', '')
                    if not_after:
                        expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        days_remaining = (expiry_date - datetime.now()).days
                        
                        if days_remaining < 30:
                            anomalies.append({
                                'type': 'SSL Certificate Expiring Soon',
                                'days_remaining': days_remaining,
                                'risk': 'MEDIUM'
                            })
                    
                    # Check cipher strength
                    if cipher:
                        cipher_name = cipher[0]
                        if 'NULL' in cipher_name or 'EXPORT' in cipher_name or 'RC4' in cipher_name:
                            anomalies.append({
                                'type': 'Weak SSL Cipher',
                                'cipher': cipher_name,
                                'risk': 'HIGH'
                            })
            
        except Exception as e:
            anomalies.append({
                'type': 'SSL/TLS Error',
                'error': str(e),
                'risk': 'MEDIUM'
            })
        
        return anomalies
    
    def check_abnormal_responses(self, target):
        """Check for abnormal server responses"""
        from utils.request_wrapper import RequestWrapper
        
        anomalies = []
        
        try:
            req = RequestWrapper()
            
            # Test with malformed requests
            malformed_requests = [
                ('GET /../../../../etc/passwd HTTP/1.1\r\nHost: {}\r\n\r\n'.format(target)),
                ('GET /?test=<script>alert(1)</script> HTTP/1.1\r\nHost: {}\r\n\r\n'.format(target)),
                ('GET / HTTP/0.9\r\n\r\n'),
                ('GET /' + 'A' * 10000 + ' HTTP/1.1\r\nHost: {}\r\n\r\n'.format(target))
            ]
            
            for request in malformed_requests[:2]:  # Test first 2
                try:
                    response = req.raw_request(target, request)
                    
                    # Check for abnormal status codes or error messages
                    if response.status_code >= 500:
                        anomalies.append({
                            'type': 'Server Error on Malformed Request',
                            'status_code': response.status_code,
                            'request': request[:100],
                            'risk': 'MEDIUM'
                        })
                        
                except Exception as e:
                    continue
            
        except Exception as e:
            pass
        
        return anomalies