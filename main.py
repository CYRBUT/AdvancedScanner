#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced Security Scanner - Main Application
Version: 3.0 (2026 Edition)
Author: Security Research Team
License: MIT
"""

import os
import sys
import time
import signal
import threading
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from views.menu import MainMenu
from utils.proxy_manager import ProxyManager
from utils.request_wrapper import RequestWrapper

class AdvancedScanner:
    def __init__(self):
        self.scanners = {}
        self.results = {}
        self.is_running = False
        self.current_target = None
        self.proxy_manager = ProxyManager()
        self.request_wrapper = RequestWrapper()
        
    def load_scanners(self):
        """Dynamically load all scanner modules"""
        try:
            from scanners import (
                sql_injection_scanner, xss_scanner, csrf_scanner,
                lfi_rfi_scanner, brute_force_scanner, monolog_hijack_scanner,
                info_disclosure_scanner, zero_day_scanner, subdomain_scanner
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
                'subdomain': subdomain_scanner.SubdomainScanner()
            }
            print(f"{Fore.GREEN}[+] Loaded {len(self.scanners)} security scanners")
        except Exception as e:
            print(f"{Fore.RED}[-] Error loading scanners: {e}")
            sys.exit(1)
    
    def set_target(self, target):
        """Set target for scanning"""
        self.current_target = target
        self.request_wrapper.set_base_url(target)
        
    def run_scan(self, scan_types, options=None):
        """Execute selected scans"""
        if not self.current_target:
            print(f"{Fore.RED}[-] No target set!")
            return
            
        self.is_running = True
        start_time = time.time()
        
        print(f"\n{Fore.CYAN}[*] Starting scan on: {self.current_target}")
        print(f"{Fore.CYAN}[*] Scan types: {', '.join(scan_types)}")
        print(f"{Fore.CYAN}[*] Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        # Run scans in parallel
        threads = []
        for scan_type in scan_types:
            if scan_type in self.scanners:
                thread = threading.Thread(
                    target=self._run_single_scan,
                    args=(scan_type, options)
                )
                threads.append(thread)
                thread.start()
                time.sleep(0.1)  # Small delay between thread starts
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        end_time = time.time()
        duration = end_time - start_time
        
        print(f"\n{Fore.GREEN}[+] Scan completed in {duration:.2f} seconds")
        self.is_running = False
        
        # Display results
        from views.results_display import ResultsDisplay
        display = ResultsDisplay(self.results)
        display.show_summary()
        
        # Save results to file
        self.save_results()
    
    def _run_single_scan(self, scan_type, options):
        """Run individual scanner"""
        try:
            print(f"{Fore.YELLOW}[*] Running {scan_type} scanner...")
            result = self.scanners[scan_type].scan(self.current_target, options)
            self.results[scan_type] = result
            
            if result.get('vulnerabilities'):
                print(f"{Fore.RED}[!] {scan_type.upper()} vulnerabilities found: {len(result['vulnerabilities'])}")
            else:
                print(f"{Fore.GREEN}[+] {scan_type.upper()} scan completed - No vulnerabilities found")
                
        except Exception as e:
            print(f"{Fore.RED}[-] Error in {scan_type} scanner: {e}")
    
    def save_results(self):
        """Save scan results to file"""
        if not self.results:
            return
            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_results_{timestamp}.json"
        
        try:
            import json
            with open(filename, 'w') as f:
                json.dump({
                    'target': self.current_target,
                    'timestamp': timestamp,
                    'results': self.results
                }, f, indent=2)
            print(f"{Fore.GREEN}[+] Results saved to: {filename}")
        except Exception as e:
            print(f"{Fore.RED}[-] Error saving results: {e}")
    
    def signal_handler(self, sig, frame):
        """Handle interrupt signals"""
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user")
        self.is_running = False
        sys.exit(0)

def check_root():
    """Check if running with root privileges"""
    if os.name == 'posix':
        if os.geteuid() != 0:
            print(f"{Fore.YELLOW}[!] Warning: Running without root privileges")
            print(f"{Fore.YELLOW}[!] Some features may require root access")
            return False
    return True

def main():
    """Main application entry point"""
    print(f"""{Fore.CYAN}
    ╔══════════════════════════════════════════════════════════╗
    ║                ADVANCED SECURITY SCANNER                 ║
    ║                    Version 3.0 (2026)                    ║
    ║               International Edition - Root               ║
    ╚══════════════════════════════════════════════════════════╝
    {Style.RESET_ALL}""")
    
    # Register signal handler
    signal.signal(signal.SIGINT, AdvancedScanner().signal_handler)
    
    # Check for root (optional)
    check_root()
    
    # Initialize scanner
    scanner = AdvancedScanner()
    scanner.load_scanners()
    
    # Start menu system
    menu = MainMenu(scanner)
    menu.display()

if __name__ == "__main__":
    main()