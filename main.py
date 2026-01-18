#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ADVANCED SCANNER v2026.1.0
Ultimate Pentesting Suite with AI & Quantum Computing Readiness
Akses Root Required untuk Fungsi Maksimal
"""

import os
import sys
import time
import json
import signal
import threading
from pathlib import Path

# Force root privileges
if os.geteuid() != 0:
    print("[!] Restarting with sudo privileges...")
    os.execvp("sudo", ["sudo", sys.executable] + sys.argv)

# Global imports
from scanners import (
    SQLInjectionScanner,
    XSSScanner,
    CSRFScanner,
    LFIRFIScanner,
    BruteForceScanner,
    MonologHijackScanner,
    InfoDisclosureScanner,
    ZeroDayScanner,
    SubdomainScanner
)
from utils.proxy_manager import ProxyManager
from utils.request_wrapper import RequestWrapper
from views.menu import MainMenu
from views.results_display import ResultsDisplay

class AdvancedScanner:
    def __init__(self):
        self.target = None
        self.scanners = []
        self.results = {}
        self.is_running = False
        
        # Enable kernel-level optimizations
        self._enable_kernel_tuning()
        
    def _enable_kernel_tuning(self):
        """Enable maximum performance tuning"""
        os.system("sysctl -w net.core.rmem_max=134217728")
        os.system("sysctl -w net.core.wmem_max=134217728")
        os.system("sysctl -w net.ipv4.tcp_window_scaling=1")
        os.system("sysctl -w net.ipv4.tcp_timestamps=1")
        os.system("sysctl -w net.ipv4.tcp_sack=1")
        
    def setup_scanners(self, target, options):
        """Initialize all scanner modules"""
        self.target = target
        
        # Initialize all scanners with root privileges
        self.scanners = [
            SQLInjectionScanner(target, deep_scan=options.get('deep', True)),
            XSSScanner(target, aggressive=options.get('aggressive', True)),
            CSRFScanner(target),
            LFIRFIScanner(target, root_access=True),
            BruteForceScanner(target, wordlist="/usr/share/wordlists/rockyou.txt"),
            MonologHijackScanner(target),
            InfoDisclosureScanner(target),
            ZeroDayScanner(target, ai_enabled=True),
            SubdomainScanner(target, brute_force=True)
        ]
        
    def run_all_scans(self):
        """Execute all scanners in parallel"""
        self.is_running = True
        threads = []
        
        for scanner in self.scanners:
            thread = threading.Thread(target=self._run_scanner, args=(scanner,))
            thread.daemon = True
            threads.append(thread)
            thread.start()
            
        # Wait for completion
        for thread in threads:
            thread.join()
            
        self.is_running = False
        return self.results
        
    def _run_scanner(self, scanner):
        """Run individual scanner and collect results"""
        try:
            scanner_name = scanner.__class__.__name__
            print(f"[+] Starting {scanner_name}...")
            
            result = scanner.scan()
            self.results[scanner_name] = result
            
            # Save to encrypted log
            self._save_results(scanner_name, result)
            
        except Exception as e:
            self.results[scanner.__class__.__name__] = {"error": str(e)}
            
    def _save_results(self, scanner_name, data):
        """Save results with military-grade encryption"""
        from cryptography.fernet import Fernet
        
        # Generate or load key
        key_path = "/root/.scanner_key"
        if os.path.exists(key_path):
            with open(key_path, 'rb') as f:
                key = f.read()
        else:
            key = Fernet.generate_key()
            with open(key_path, 'wb') as f:
                f.write(key)
                
        cipher = Fernet(key)
        encrypted = cipher.encrypt(json.dumps(data).encode())
        
        log_dir = "/var/log/advanced_scanner"
        os.makedirs(log_dir, exist_ok=True, mode=0o700)
        
        log_file = f"{log_dir}/{scanner_name}_{int(time.time())}.enc"
        with open(log_file, 'wb') as f:
            f.write(encrypted)
            
    def export_results(self, format="json"):
        """Export results in various formats"""
        if format == "json":
            with open(f"scan_results_{int(time.time())}.json", 'w') as f:
                json.dump(self.results, f, indent=4)
        elif format == "html":
            ResultsDisplay.generate_html_report(self.results)
        elif format == "pdf":
            ResultsDisplay.generate_pdf_report(self.results)
            
        return True

def main():
    """Main execution function"""
    try:
        # Clear screen and show banner
        os.system("clear")
        print("""
╔══════════════════════════════════════════════════════════╗
║                ADVANCED SCANNER v2026.1.0                ║
║        Ultimate Security Assessment Platform             ║
║         Root Access: ENABLED | AI Mode: ACTIVE           ║
╚══════════════════════════════════════════════════════════╝
        """)
        
        # Initialize scanner
        scanner = AdvancedScanner()
        
        # Show menu
        menu = MainMenu()
        target, options = menu.get_scan_parameters()
        
        if not target:
            print("[!] No target specified. Exiting.")
            sys.exit(1)
            
        # Setup and run scans
        print(f"\n[+] Target: {target}")
        print("[+] Initializing scanners with root privileges...")
        
        scanner.setup_scanners(target, options)
        results = scanner.run_all_scans()
        
        # Display results
        ResultsDisplay.show(results)
        
        # Export options
        if menu.ask_export():
            format_choice = menu.get_export_format()
            scanner.export_results(format_choice)
            print(f"[+] Results exported as {format_choice.upper()}")
            
        print("\n[+] Scan completed successfully!")
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Critical error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()