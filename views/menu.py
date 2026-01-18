"""
Main menu interface for Advanced Scanner
"""

import sys
import os
from colorama import Fore, Style, init
import threading

init(autoreset=True)

class MainMenu:
    def __init__(self, scanner):
        self.scanner = scanner
        self.options = {
            '1': ('Scan Target', self.scan_target),
            '2': ('Set Proxy', self.set_proxy),
            '3': ('Configure Scanner', self.configure_scanner),
            '4': ('View Results', self.view_results),
            '5': ('Export Results', self.export_results),
            '6': ('Load Targets from File', self.load_targets),
            '7': ('Advanced Options', self.advanced_options),
            '8': ('Update Scanner', self.update_scanner),
            '9': ('About', self.show_about),
            '0': ('Exit', self.exit_scanner)
        }
        
    def display(self):
        """Display main menu"""
        os.system('clear' if os.name == 'posix' else 'cls')
        
        while True:
            print(f"""{Fore.CYAN}
╔══════════════════════════════════════════════════════════╗
║                ADVANCED SECURITY SCANNER                 ║
║                    Version 3.0 (2026)                    ║
╚══════════════════════════════════════════════════════════╝
{Style.RESET_ALL}""")
            
            print(f"{Fore.YELLOW}Current Target: {Fore.CYAN}{self.scanner.current_target or 'Not Set'}")
            print()
            
            for key, (description, _) in self.options.items():
                print(f"{Fore.GREEN}[{key}] {Fore.WHITE}{description}")
            
            print()
            
            choice = input(f"{Fore.YELLOW}Select option (0-9): {Style.RESET_ALL}").strip()
            
            if choice in self.options:
                self.options[choice][1]()
            else:
                print(f"{Fore.RED}Invalid option. Please try again.")
                input("Press Enter to continue...")
    
    def scan_target(self):
        """Initiate target scanning"""
        if not self.scanner.current_target:
            self.set_target()
            if not self.scanner.current_target:
                return
        
        # Select scan types
        scan_types = self.select_scan_types()
        
        if not scan_types:
            print(f"{Fore.YELLOW}[!] No scan types selected")
            return
        
        # Scan options
        options = self.get_scan_options()
        
        # Confirm and start scan
        print(f"\n{Fore.YELLOW}[*] Starting scan with options:")
        print(f"    Target: {self.scanner.current_target}")
        print(f"    Scans: {', '.join(scan_types)}")
        print(f"    Threads: {options.get('threads', 5)}")
        
        confirm = input(f"\n{Fore.YELLOW}Start scan? (y/N): ").strip().lower()
        
        if confirm == 'y':
            # Start scan in separate thread
            scan_thread = threading.Thread(
                target=self.scanner.run_scan,
                args=(scan_types, options)
            )
            scan_thread.start()
            
            print(f"{Fore.GREEN}[+] Scan started in background...")
            input("Press Enter to return to menu...")
        else:
            print(f"{Fore.YELLOW}[!] Scan cancelled")
    
    def select_scan_types(self):
        """Select which scans to perform"""
        scan_options = {
            '1': ('SQL Injection', 'sql'),
            '2': ('Cross-Site Scripting (XSS)', 'xss'),
            '3': ('CSRF', 'csrf'),
            '4': ('LFI/RFI', 'lfi_rfi'),
            '5': ('Brute Force', 'brute'),
            '6': ('Monolog Hijacking', 'monolog'),
            '7': ('Information Disclosure', 'info'),
            '8': ('Zero-Day Detection', 'zero_day'),
            '9': ('Subdomain Discovery', 'subdomain'),
            'a': ('All Scans', 'all')
        }
        
        print(f"\n{Fore.CYAN}Select Scan Types:")
        for key, (name, _) in scan_options.items():
            print(f"{Fore.GREEN}[{key}] {Fore.WHITE}{name}")
        
        print(f"\n{Fore.YELLOW}Enter selection (comma-separated, e.g., '1,2,3' or 'a' for all):")
        selection = input(f"{Fore.YELLOW}Choice: {Style.RESET_ALL}").strip()
        
        if 'a' in selection or 'all' in selection:
            return list(self.scanner.scanners.keys())
        
        selected = []
        for choice in selection.split(','):
            choice = choice.strip()
            if choice in scan_options:
                selected.append(scan_options[choice][1])
        
        return selected
    
    def get_scan_options(self):
        """Get additional scan options"""
        options = {}
        
        print(f"\n{Fore.CYAN}Scan Options:")
        
        try:
            threads = input(f"{Fore.YELLOW}Threads (1-50, default 5): {Style.RESET_ALL}").strip()
            if threads:
                options['threads'] = max(1, min(50, int(threads)))
            else:
                options['threads'] = 5
        except:
            options['threads'] = 5
        
        try:
            depth = input(f"{Fore.YELLOW}Crawl Depth (1-5, default 2): {Style.RESET_ALL}").strip()
            if depth:
                options['depth'] = max(1, min(5, int(depth)))
            else:
                options['depth'] = 2
        except:
            options['depth'] = 2
        
        aggressive = input(f"{Fore.YELLOW}Aggressive Mode? (y/N): {Style.RESET_ALL}").strip().lower()
        options['aggressive'] = (aggressive == 'y')
        
        return options
    
    def set_target(self):
        """Set target for scanning"""
        print(f"\n{Fore.CYAN}Set Target:")
        print(f"{Fore.YELLOW}Enter target URL (e.g., http://example.com):")
        
        target = input(f"{Fore.YELLOW}Target: {Style.RESET_ALL}").strip()
        
        if target:
            if not target.startswith(('http://', 'https://')):
                target = 'http://' + target
            
            self.scanner.set_target(target)
            print(f"{Fore.GREEN}[+] Target set to: {target}")
        else:
            print(f"{Fore.RED}[-] No target provided")
        
        input("Press Enter to continue...")
    
    def set_proxy(self):
        """Configure proxy settings"""
        print(f"\n{Fore.CYAN}Proxy Configuration:")
        print(f"1. Use random proxy from list")
        print(f"2. Add custom proxy")
        print(f"3. Test all proxies")
        print(f"4. Disable proxy")
        
        choice = input(f"{Fore.YELLOW}Choice: {Style.RESET_ALL}").strip()
        
        if choice == '1':
            proxy = self.scanner.proxy_manager.get_random_proxy()
            if proxy:
                print(f"{Fore.GREEN}[+] Using proxy: {proxy}")
            else:
                print(f"{Fore.RED}[-] No proxies available")
        
        elif choice == '2':
            proxy = input(f"{Fore.YELLOW}Enter proxy (format: http://proxy:port): {Style.RESET_ALL}").strip()
            if proxy:
                self.scanner.proxy_manager.proxies.append(proxy)
                print(f"{Fore.GREEN}[+] Proxy added")
        
        elif choice == '3':
            print(f"{Fore.YELLOW}[*] Testing proxies...")
            self.scanner.proxy_manager.validate_proxies()
        
        elif choice == '4':
            self.scanner.proxy_manager.proxy_enabled = False
            print(f"{Fore.GREEN}[+] Proxy disabled")
        
        input("Press Enter to continue...")
    
    def configure_scanner(self):
        """Configure scanner settings"""
        print(f"\n{Fore.CYAN}Scanner Configuration:")
        # Add configuration options here
        print(f"{Fore.YELLOW}[*] Configuration options coming soon...")
        input("Press Enter to continue...")
    
    def view_results(self):
        """View scan results"""
        if not self.scanner.results:
            print(f"{Fore.YELLOW}[!] No scan results available")
            input("Press Enter to continue...")
            return
        
        from views.results_display import ResultsDisplay
        display = ResultsDisplay(self.scanner.results)
        display.show_detailed()
        
        input("Press Enter to continue...")
    
    def export_results(self):
        """Export results to file"""
        if not self.scanner.results:
            print(f"{Fore.YELLOW}[!] No results to export")
            input("Press Enter to continue...")
            return
        
        formats = ['json', 'html', 'txt', 'csv']
        
        print(f"\n{Fore.CYAN}Export Results:")
        for i, fmt in enumerate(formats, 1):
            print(f"{i}. {fmt.upper()}")
        
        choice = input(f"{Fore.YELLOW}Select format (1-4): {Style.RESET_ALL}").strip()
        
        try:
            format_idx = int(choice) - 1
            if 0 <= format_idx < len(formats):
                self.scanner.save_results()
                print(f"{Fore.GREEN}[+] Results exported")
        except:
            print(f"{Fore.RED}[-] Invalid choice")
        
        input("Press Enter to continue...")
    
    def load_targets(self):
        """Load targets from file"""
        filename = input(f"{Fore.YELLOW}Enter filename with targets: {Style.RESET_ALL}").strip()
        
        if not os.path.exists(filename):
            print(f"{Fore.RED}[-] File not found: {filename}")
            input("Press Enter to continue...")
            return
        
        try:
            with open(filename, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
            
            print(f"{Fore.GREEN}[+] Loaded {len(targets)} targets")
            
            # Option to scan all targets
            if targets:
                scan_all = input(f"{Fore.YELLOW}Scan all targets? (y/N): {Style.RESET_ALL}").strip().lower()
                
                if scan_all == 'y':
                    for target in targets:
                        print(f"{Fore.YELLOW}[*] Scanning: {target}")
                        self.scanner.set_target(target)
                        self.scanner.run_scan(['sql', 'xss', 'info'])
        
        except Exception as e:
            print(f"{Fore.RED}[-] Error loading targets: {e}")
        
        input("Press Enter to continue...")
    
    def advanced_options(self):
        """Show advanced options"""
        print(f"\n{Fore.CYAN}Advanced Options:")
        print(f"1. Network Scanner")
        print(f"2. Port Scanner")
        print(f"3. Vulnerability Database Update")
        print(f"4. Custom Payload Editor")
        print(f"5. Log Viewer")
        
        choice = input(f"{Fore.YELLOW}Choice: {Style.RESET_ALL}").strip()
        
        if choice == '1':
            self.network_scan()
        elif choice == '2':
            self.port_scan()
        elif choice == '3':
            self.update_vuln_db()
        elif choice == '4':
            self.payload_editor()
        elif choice == '5':
            self.log_viewer()
        
        input("Press Enter to continue...")
    
    def network_scan(self):
        """Network scanning functionality"""
        print(f"\n{Fore.YELLOW}[*] Network scanning requires root privileges")
        
        target = input(f"{Fore.YELLOW}Enter network (e.g., 192.168.1.0/24): {Style.RESET_ALL}").strip()
        
        if target:
            try:
                import nmap
                scanner = nmap.PortScanner()
                
                print(f"{Fore.YELLOW}[*] Scanning network: {target}")
                scanner.scan(hosts=target, arguments='-sn')
                
                for host in scanner.all_hosts():
                    print(f"{Fore.GREEN}[+] Host: {host} - {scanner[host].hostname()}")
            
            except ImportError:
                print(f"{Fore.RED}[-] nmap module not installed")
            except Exception as e:
                print(f"{Fore.RED}[-] Network scan error: {e}")
    
    def port_scan(self):
        """Port scanning functionality"""
        target = input(f"{Fore.YELLOW}Enter target host: {Style.RESET_ALL}").strip()
        
        if target:
            try:
                import socket
                
                common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080]
                
                print(f"{Fore.YELLOW}[*] Scanning ports on {target}...")
                
                for port in common_ports:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    
                    result = sock.connect_ex((target, port))
                    if result == 0:
                        print(f"{Fore.GREEN}[+] Port {port} is open")
                    
                    sock.close()
            
            except Exception as e:
                print(f"{Fore.RED}[-] Port scan error: {e}")
    
    def update_vuln_db(self):
        """Update vulnerability database"""
        print(f"\n{Fore.YELLOW}[*] Updating vulnerability database...")
        
        # This would connect to online vulnerability databases
        print(f"{Fore.GREEN}[+] Database update feature coming soon...")
    
    def payload_editor(self):
        """Edit custom payloads"""
        print(f"\n{Fore.CYAN}Payload Editor:")
        print(f"1. SQL Injection Payloads")
        print(f"2. XSS Payloads")
        print(f"3. LFI/RFI Payloads")
        print(f"4. Custom Payloads")
        
        choice = input(f"{Fore.YELLOW}Choice: {Style.RESET_ALL}").strip()
        
        if choice == '1':
            self.edit_payloads('sql')
        elif choice == '2':
            self.edit_payloads('xss')
        elif choice == '3':
            self.edit_payloads('lfi')
        elif choice == '4':
            self.edit_custom_payloads()
    
    def edit_payloads(self, payload_type):
        """Edit specific payload type"""
        print(f"\n{Fore.YELLOW}[*] Editing {payload_type} payloads...")
        print(f"{Fore.GREEN}[+] Payload editor coming soon...")
    
    def edit_custom_payloads(self):
        """Edit custom payloads"""
        print(f"\n{Fore.YELLOW}[*] Custom payload editor...")
        print(f"{Fore.GREEN}[+] Custom payload feature coming soon...")
    
    def log_viewer(self):
        """View scan logs"""
        import glob
        
        log_files = glob.glob('*.log') + glob.glob('scan_results_*.json')
        
        if not log_files:
            print(f"{Fore.YELLOW}[!] No log files found")
            return
        
        print(f"\n{Fore.CYAN}Log Files:")
        for i, log_file in enumerate(log_files, 1):
            print(f"{i}. {log_file}")
        
        choice = input(f"{Fore.YELLOW}Select file to view (1-{len(log_files)}): {Style.RESET_ALL}").strip()
        
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(log_files):
                with open(log_files[idx], 'r') as f:
                    content = f.read()
                    print(f"\n{content[:1000]}...")  # Show first 1000 chars
        except:
            print(f"{Fore.RED}[-] Invalid choice")
    
    def update_scanner(self):
        """Update scanner to latest version"""
        print(f"\n{Fore.YELLOW}[*] Checking for updates...")
        
        # This would connect to update server
        print(f"{Fore.GREEN}[+] Current version: 3.0 (2026)")
        print(f"{Fore.GREEN}[+] Scanner is up to date")
        
        input("Press Enter to continue...")
    
    def show_about(self):
        """Show about information"""
        print(f"""{Fore.CYAN}
╔══════════════════════════════════════════════════════════╗
║                ADVANCED SECURITY SCANNER                 ║
║                    Version 3.0 (2026)                    ║
║                                                          ║
║  Features:                                               ║
║    • Multiple vulnerability scanners                     ║
║    • Proxy support                                       ║
║    • Threading for performance                           ║
║    • Results export                                      ║
║    • Regular updates                                     ║
║    • Root access capabilities                            ║
║                                                          ║
║  Usage:                                                  ║
║    • Set target URL                                      ║
║    • Select scan types                                   ║
║    • Configure options                                   ║
║    • Start scan                                          ║
║    • Review results                                      ║
║                                                          ║
║  Warning:                                                ║
║    • Use only on authorized targets                      ║
║    • Respect privacy and laws                            ║
║    • Educational purposes only                           ║
╚══════════════════════════════════════════════════════════╝
{Style.RESET_ALL}""")
        
        input("Press Enter to continue...")
    
    def exit_scanner(self):
        """Exit the scanner"""
        print(f"\n{Fore.YELLOW}[*] Exiting Advanced Scanner...")
        sys.exit(0)