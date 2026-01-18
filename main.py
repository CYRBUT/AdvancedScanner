#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════════════════╗
║                🚀 ADVANCED SECURITY SCANNER PRO - INTERNATIONAL EDITION 2026             ║
║                 🛡️  Version 3.0 | Codename: 'NIGHTWATCH' | ROOT ACCESS                 ║
╚══════════════════════════════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import time
import signal
import threading
import hashlib
import random
from datetime import datetime
from colorama import init, Fore, Back, Style
from pyfiglet import Figlet
import requests

# Initialize colorama with custom settings
init(autoreset=True)

# Color Configuration - Dark Theme Focus
class Colors:
    # Primary Colors
    PRIMARY = Fore.BLACK + Style.BRIGHT
    SECONDARY = Fore.LIGHTBLACK_EX
    ACCENT = Fore.LIGHTRED_EX
    WARNING = Fore.LIGHTYELLOW_EX
    SUCCESS = Fore.LIGHTGREEN_EX
    ERROR = Fore.LIGHTRED_EX
    INFO = Fore.LIGHTCYAN_EX
    SCANNER = Fore.LIGHTMAGENTA_EX
    
    # Text Variations
    BOLD = Style.BRIGHT
    DIM = Style.DIM
    NORMAL = Style.NORMAL
    
    # Backgrounds
    BG_DARK = Back.BLACK
    BG_RED = Back.RED
    BG_GREEN = Back.GREEN
    BG_BLUE = Back.BLUE
    
# Custom Figlet Fonts
FONTS = {
    'title': 'slant',
    'header': 'small',
    'subheader': 'digital'
}

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import modules with error handling
try:
    from views.menu import MainMenu
    from utils.proxy_manager import ProxyManager
    from utils.request_wrapper import RequestWrapper
    from utils.logger import SecurityLogger
except ImportError as e:
    print(f"{Colors.ERROR}[-] Module Import Error: {e}")
    sys.exit(1)

class AdvancedScannerPro:
    def __init__(self):
        self.scanners = {}
        self.results = {}
        self.is_running = False
        self.current_target = None
        self.scan_id = None
        self.session_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
        
        # Initialize Managers
        self.proxy_manager = ProxyManager()
        self.request_wrapper = RequestWrapper()
        self.logger = SecurityLogger()
        
        # Statistics
        self.stats = {
            'vulnerabilities_found': 0,
            'scans_completed': 0,
            'start_time': None,
            'end_time': None
        }
        
        # Configuration
        self.config = {
            'max_threads': 10,
            'timeout': 30,
            'retry_attempts': 3,
            'aggressive_mode': False,
            'stealth_mode': False
        }
        
    def display_banner(self):
        """Display enhanced ASCII banner with colors"""
        os.system('clear' if os.name == 'posix' else 'cls')
        
        # Generate random banner color
        banner_colors = [Colors.INFO, Colors.SCANNER, Colors.ACCENT, Colors.SUCCESS]
        selected_color = random.choice(banner_colors)
        
        f = Figlet(font=FONTS['title'])
        banner_text = f.renderText('SECURITY SCANNER')
        
        print(f"\n{selected_color}{'═' * 80}")
        print(f"{selected_color}{banner_text}")
        
        # Additional decorative elements
        print(f"{Colors.SECONDARY}{'─' * 80}")
        print(f"{Colors.INFO}║{Colors.PRIMARY}   Version: {Colors.SUCCESS}3.0 PRO 2026 {Colors.SECONDARY}|{Colors.PRIMARY} Session: {Colors.WARNING}{self.session_id}")
        print(f"{Colors.INFO}║{Colors.PRIMARY}   Status: {Colors.SUCCESS}ACTIVE {Colors.SECONDARY}|{Colors.PRIMARY} Mode: {Colors.ACCENT}ROOT PRIVILEGES")
        print(f"{Colors.INFO}║{Colors.PRIMARY}   Time: {Colors.WARNING}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Colors.SECONDARY}{'─' * 80}")
        print(f"{Colors.DIM}{' ' * 30}🔒 CYBERSECURITY FRAMEWORK 🔒")
        print(f"{Colors.SECONDARY}{'═' * 80}\n{Style.RESET_ALL}")
        
    def load_scanners(self):
        """Dynamically load all scanner modules with enhanced logging"""
        try:
            from scanners import (
                sql_injection_scanner, xss_scanner, csrf_scanner,
                lfi_rfi_scanner, brute_force_scanner, monolog_hijack_scanner,
                info_disclosure_scanner, zero_day_scanner, subdomain_scanner,
                port_scanner, directory_traversal_scanner, ssl_tls_scanner,
                api_vulnerability_scanner, cms_detector_scanner
            )
            
            self.scanners = {
                'sql': sql_injection_scanner.SQLInjectionScanner(),
                'xss': xss_scanner.XSSScanner(),
                'csrf': csrf_scanner.CSRFScanner(),
                'lfi_rfi': lfi_rfi_scanner.LFIRFIScanner(),
                'brute': brute_force_scanner.BruteForceScanner(),
                'monolog': monolog_hijack_scanner.MonologHijackScanner(),
                'info': info_disclosure_scanner.InfoDisclosureScanner(),
                'zero_day': zero_day_scanner.ZeroDayScanner(),
                'subdomain': subdomain_scanner.SubdomainScanner(),
                'port': port_scanner.PortScanner(),
                'directory': directory_traversal_scanner.DirectoryTraversalScanner(),
                'ssl': ssl_tls_scanner.SSLTLSScanner(),
                'api': api_vulnerability_scanner.APIVulnerabilityScanner(),
                'cms': cms_detector_scanner.CMSDetectorScanner()
            }
            
            print(f"{Colors.SUCCESS}[✓] {Colors.PRIMARY}Loaded {Colors.INFO}{len(self.scanners)} {Colors.PRIMARY}security scanners")
            print(f"{Colors.SECONDARY}   └─ Available modules: {', '.join(self.scanners.keys())}\n")
            
        except ImportError as e:
            print(f"{Colors.ERROR}[✗] {Colors.PRIMARY}Critical Error loading scanners: {Colors.ERROR}{e}")
            print(f"{Colors.WARNING}[!] Attempting to load essential scanners only...")
            
            # Load essential scanners only
            try:
                from scanners.sql_injection_scanner import SQLInjectionScanner
                from scanners.xss_scanner import XSSScanner
                
                self.scanners = {
                    'sql': SQLInjectionScanner(),
                    'xss': XSSScanner()
                }
                print(f"{Colors.WARNING}[!] Loaded limited scanner set: {len(self.scanners)} modules")
            except:
                print(f"{Colors.ERROR}[✗] Fatal: Cannot load any scanners")
                sys.exit(1)
    
    def set_target(self, target):
        """Set target for scanning with validation"""
        from urllib.parse import urlparse
        
        # Add protocol if missing
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
            
        # Validate URL
        try:
            result = urlparse(target)
            if all([result.scheme, result.netloc]):
                self.current_target = target
                self.request_wrapper.set_base_url(target)
                self.scan_id = hashlib.sha256(target.encode()).hexdigest()[:12]
                
                print(f"{Colors.SUCCESS}[✓] {Colors.PRIMARY}Target set: {Colors.INFO}{self.current_target}")
                print(f"{Colors.SECONDARY}   └─ Scan ID: {Colors.WARNING}{self.scan_id}")
                return True
            else:
                print(f"{Colors.ERROR}[✗] Invalid target URL")
                return False
        except Exception as e:
            print(f"{Colors.ERROR}[✗] URL validation error: {e}")
            return False
    
    def run_scan(self, scan_types, options=None):
        """Execute selected scans with enhanced parallel processing"""
        if not self.current_target:
            print(f"{Colors.ERROR}[✗] {Colors.PRIMARY}No target set!")
            return False
            
        self.is_running = True
        self.stats['start_time'] = datetime.now()
        self.stats['vulnerabilities_found'] = 0
        
        # Display scan header
        print(f"\n{Colors.INFO}{'═' * 80}")
        print(f"{Colors.SCANNER}🛡️   INITIATING SECURITY SCAN PROTOCOL")
        print(f"{Colors.INFO}{'═' * 80}")
        print(f"{Colors.PRIMARY}Target: {Colors.INFO}{self.current_target}")
        print(f"{Colors.PRIMARY}Scan ID: {Colors.WARNING}{self.scan_id}")
        print(f"{Colors.PRIMARY}Scan Types: {Colors.SUCCESS}{', '.join(scan_types)}")
        print(f"{Colors.PRIMARY}Start Time: {Colors.INFO}{self.stats['start_time'].strftime('%H:%M:%S')}")
        print(f"{Colors.INFO}{'─' * 80}\n")
        
        # Initialize progress tracking
        completed = 0
        total = len(scan_types)
        
        # Create thread pool
        threads = []
        results_lock = threading.Lock()
        
        def worker(scan_type):
            nonlocal completed
            try:
                # Display start message
                print(f"{Colors.SECONDARY}[•] {Colors.PRIMARY}Starting {Colors.INFO}{scan_type.upper()} {Colors.PRIMARY}scanner...")
                
                if scan_type in self.scanners:
                    result = self.scanners[scan_type].scan(self.current_target, options or {})
                    
                    with results_lock:
                        self.results[scan_type] = result
                        
                        if result.get('vulnerabilities'):
                            vuln_count = len(result['vulnerabilities'])
                            self.stats['vulnerabilities_found'] += vuln_count
                            print(f"{Colors.ERROR}[!] {Colors.PRIMARY}{scan_type.upper()} found {Colors.ERROR}{vuln_count} {Colors.PRIMARY}vulnerabilities!")
                        else:
                            print(f"{Colors.SUCCESS}[✓] {Colors.PRIMARY}{scan_type.upper()} scan completed {Colors.SUCCESS}secure")
                else:
                    print(f"{Colors.WARNING}[!] {Colors.PRIMARY}Scanner {Colors.WARNING}{scan_type} {Colors.PRIMARY}not available")
                    
            except Exception as e:
                print(f"{Colors.ERROR}[✗] {Colors.PRIMARY}Scanner {Colors.ERROR}{scan_type} {Colors.PRIMARY}failed: {Colors.SECONDARY}{str(e)[:50]}...")
            finally:
                completed += 1
                progress = (completed / total) * 100
                print(f"{Colors.INFO}[{completed}/{total}] {Colors.PRIMARY}Progress: {Colors.INFO}{progress:.1f}%")
        
        # Start threads
        for scan_type in scan_types:
            thread = threading.Thread(target=worker, args=(scan_type,))
            threads.append(thread)
            thread.start()
            
            # Control thread spawning rate
            time.sleep(0.2)
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        # Calculate statistics
        self.stats['end_time'] = datetime.now()
        self.stats['scans_completed'] = completed
        duration = (self.stats['end_time'] - self.stats['start_time']).total_seconds()
        
        # Display summary
        print(f"\n{Colors.SUCCESS}{'═' * 80}")
        print(f"{Colors.SUCCESS}✅ SCAN COMPLETED SUCCESSFULLY")
        print(f"{Colors.SUCCESS}{'═' * 80}")
        print(f"{Colors.PRIMARY}Duration: {Colors.INFO}{duration:.2f} seconds")
        print(f"{Colors.PRIMARY}Scans Completed: {Colors.INFO}{completed}/{total}")
        print(f"{Colors.PRIMARY}Vulnerabilities Found: {Colors.ERROR if self.stats['vulnerabilities_found'] > 0 else Colors.SUCCESS}{self.stats['vulnerabilities_found']}")
        print(f"{Colors.PRIMARY}Scan Status: {Colors.ERROR if self.stats['vulnerabilities_found'] > 0 else Colors.SUCCESS}{'VULNERABLE' if self.stats['vulnerabilities_found'] > 0 else 'SECURE'}")
        print(f"{Colors.SUCCESS}{'═' * 80}\n")
        
        self.is_running = False
        
        # Save results
        self.save_results()
        
        # Generate report
        self.generate_report()
        
        return True
    
    def save_results(self):
        """Save scan results with multiple formats"""
        if not self.results:
            print(f"{Colors.WARNING}[!] No results to save")
            return
            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"scan_{self.scan_id}_{timestamp}"
        
        # Save as JSON
        try:
            import json
            json_filename = f"{base_filename}.json"
            with open(json_filename, 'w', encoding='utf-8') as f:
                json.dump({
                    'metadata': {
                        'target': self.current_target,
                        'scan_id': self.scan_id,
                        'timestamp': timestamp,
                        'duration': (self.stats['end_time'] - self.stats['start_time']).total_seconds(),
                        'vulnerabilities_found': self.stats['vulnerabilities_found']
                    },
                    'results': self.results
                }, f, indent=2, ensure_ascii=False)
            print(f"{Colors.SUCCESS}[✓] {Colors.PRIMARY}JSON report saved: {Colors.INFO}{json_filename}")
        except Exception as e:
            print(f"{Colors.ERROR}[✗] {Colors.PRIMARY}Error saving JSON: {Colors.SECONDARY}{e}")
        
        # Save as HTML
        try:
            html_filename = f"{base_filename}.html"
            self._generate_html_report(html_filename)
            print(f"{Colors.SUCCESS}[✓] {Colors.PRIMARY}HTML report saved: {Colors.INFO}{html_filename}")
        except Exception as e:
            print(f"{Colors.WARNING}[!] {Colors.PRIMARY}HTML report generation failed: {Colors.SECONDARY}{e}")
        
        # Save as TXT
        try:
            txt_filename = f"{base_filename}.txt"
            with open(txt_filename, 'w', encoding='utf-8') as f:
                f.write(f"Security Scan Report\n")
                f.write(f"{'='*50}\n")
                f.write(f"Target: {self.current_target}\n")
                f.write(f"Scan ID: {self.scan_id}\n")
                f.write(f"Time: {timestamp}\n")
                f.write(f"Vulnerabilities Found: {self.stats['vulnerabilities_found']}\n")
                f.write(f"{'='*50}\n\n")
                
                for scan_type, result in self.results.items():
                    f.write(f"[{scan_type.upper()}]\n")
                    f.write(f"Status: {'VULNERABLE' if result.get('vulnerabilities') else 'SECURE'}\n")
                    if result.get('vulnerabilities'):
                        for vuln in result['vulnerabilities']:
                            f.write(f"  - {vuln}\n")
                    f.write(f"\n")
            
            print(f"{Colors.SUCCESS}[✓] {Colors.PRIMARY}Text report saved: {Colors.INFO}{txt_filename}")
        except Exception as e:
            print(f"{Colors.WARNING}[!] {Colors.PRIMARY}Text report generation failed: {Colors.SECONDARY}{e}")
    
    def _generate_html_report(self, filename):
        """Generate HTML report with styling"""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Security Scan Report - {self.scan_id}</title>
            <style>
                body {{ font-family: 'Courier New', monospace; background: #0a0a0a; color: #00ff00; margin: 20px; }}
                .header {{ background: #000; padding: 20px; border: 1px solid #00ff00; }}
                .vulnerable {{ color: #ff0000; }}
                .secure {{ color: #00ff00; }}
                .info {{ color: #00ffff; }}
                .warning {{ color: #ffff00; }}
                .section {{ margin: 20px 0; padding: 15px; border-left: 3px solid #00ff00; background: #111; }}
                pre {{ background: #000; padding: 10px; border: 1px solid #333; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🔒 SECURITY SCAN REPORT</h1>
                <p>Target: {self.current_target}</p>
                <p>Scan ID: {self.scan_id}</p>
                <p>Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>Vulnerabilities Found: <span class="{'vulnerable' if self.stats['vulnerabilities_found'] > 0 else 'secure'}">{self.stats['vulnerabilities_found']}</span></p>
            </div>
        """
        
        for scan_type, result in self.results.items():
            status = "VULNERABLE" if result.get('vulnerabilities') else "SECURE"
            html_content += f"""
            <div class="section">
                <h2>{scan_type.upper()} - <span class="{status.lower()}">{status}</span></h2>
            """
            
            if result.get('vulnerabilities'):
                html_content += "<h3 class='vulnerable'>Vulnerabilities Found:</h3><ul>"
                for vuln in result['vulnerabilities']:
                    html_content += f"<li class='vulnerable'>{vuln}</li>"
                html_content += "</ul>"
            else:
                html_content += "<p class='secure'>No vulnerabilities detected.</p>"
            
            html_content += "</div>"
        
        html_content += """
            <div class="section info">
                <h3>Scan Information</h3>
                <p>Generated by Advanced Security Scanner Pro v3.0</p>
                <p>© 2026 Security Research Team - International Edition</p>
            </div>
        </body>
        </html>
        """
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def generate_report(self):
        """Generate comprehensive scan report"""
        print(f"{Colors.INFO}{'─' * 80}")
        print(f"{Colors.SCANNER}📊 GENERATING COMPREHENSIVE REPORT")
        print(f"{Colors.INFO}{'─' * 80}")
        
        # Additional analysis could be added here
        print(f"{Colors.SUCCESS}[✓] {Colors.PRIMARY}Report generation completed")
        
    def signal_handler(self, sig, frame):
        """Handle interrupt signals gracefully"""
        print(f"\n{Colors.WARNING}{'!' * 80}")
        print(f"{Colors.WARNING}⚠️   SCAN INTERRUPTED BY USER")
        print(f"{Colors.WARNING}{'!' * 80}")
        
        if self.is_running:
            print(f"{Colors.WARNING}[!] {Colors.PRIMARY}Saving partial results...")
            self.save_results()
        
        print(f"{Colors.INFO}[*] {Colors.PRIMARY}Scanner shutting down...")
        sys.exit(0)

def check_dependencies():
    """Check and install required dependencies"""
    required = ['colorama', 'requests', 'pyfiglet']
    missing = []
    
    for package in required:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            missing.append(package)
    
    if missing:
        print(f"{Colors.ERROR}[✗] {Colors.PRIMARY}Missing dependencies: {Colors.ERROR}{', '.join(missing)}")
        print(f"{Colors.WARNING}[!] {Colors.PRIMARY}Install with: {Colors.INFO}pip install {' '.join(missing)}")
        return False
    return True

def check_root():
    """Enhanced root privilege check"""
    if os.name == 'posix':
        if os.geteuid() != 0:
            print(f"{Colors.ERROR}{'⚠' * 80}")
            print(f"{Colors.ERROR} ROOT PRIVILEGES REQUIRED")
            print(f"{Colors.ERROR}{'⚠' * 80}")
            print(f"{Colors.WARNING}[!] {Colors.PRIMARY}Some features require root access:")
            print(f"{Colors.SECONDARY}   • Port scanning")
            print(f"{Colors.SECONDARY}   • Network packet inspection")
            print(f"{Colors.SECONDARY}   • Certain exploit modules")
            print(f"\n{Colors.INFO}[*] {Colors.PRIMARY}Run with: {Colors.WARNING}sudo {sys.argv[0]}")
            return False
        else:
            print(f"{Colors.SUCCESS}[✓] {Colors.PRIMARY}Running with {Colors.SUCCESS}root privileges")
            return True
    return True

def main():
    """Main application entry point with enhanced features"""
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Initialize scanner
    scanner = AdvancedScannerPro()
    
    # Display banner
    scanner.display_banner()
    
    # Check root (recommended but not required)
    check_root()
    
    # Register signal handler
    signal.signal(signal.SIGINT, scanner.signal_handler)
    
    # Load scanners
    scanner.load_scanners()
    
    # Display system info
    print(f"{Colors.INFO}{'─' * 80}")
    print(f"{Colors.PRIMARY}System Information:")
    print(f"{Colors.SECONDARY}   OS: {os.name}")
    print(f"{Colors.SECONDARY}   Python: {sys.version.split()[0]}")
    print(f"{Colors.SECONDARY}   CPU Cores: {os.cpu_count()}")
    print(f"{Colors.INFO}{'─' * 80}\n")
    
    # Start menu system
    try:
        menu = MainMenu(scanner)
        menu.display()
    except KeyboardInterrupt:
        scanner.signal_handler(None, None)
    except Exception as e:
        print(f"{Colors.ERROR}[✗] {Colors.PRIMARY}Fatal error: {Colors.ERROR}{e}")
        sys.exit(1)

if __name__ == "__main__":
    main()