import sys
import os
from colorama import init, Fore, Style

init(autoreset=True)

class MainMenu:
    def __init__(self):
        self.options = {}
        
    def show_banner(self):
        """Display ASCII banner"""
        banner = f"""
{Fore.RED}╔══════════════════════════════════════════════════════════╗
{Fore.RED}║                ADVANCED SCANNER v2026.1.0                ║
{Fore.RED}║        Ultimate Security Assessment Platform             ║
{Fore.RED}║         Root Access: {Fore.GREEN}ENABLED{Fore.RED} | AI Mode: {Fore.GREEN}ACTIVE{Fore.RED}           ║
{Fore.RED}╚══════════════════════════════════════════════════════════╝
{Fore.YELLOW}
        [1] Full Comprehensive Scan
        [2] Custom Scan Selection
        [3] Bruteforce Only
        [4] Web Vulnerability Scan
        [5] Network Reconnaissance
        [6] Zero-Day Detection
        [7] Stealth Mode Scan
        [8] AI-Powered Deep Analysis
        [9] Load Previous Session
        [0] Exit
        """
        print(banner)
        
    def get_choice(self):
        """Get user menu choice"""
        while True:
            try:
                choice = input(f"{Fore.CYAN}[?] Select option (0-9): {Style.RESET_ALL}").strip()
                if choice.isdigit() and 0 <= int(choice) <= 9:
                    return int(choice)
                else:
                    print(f"{Fore.RED}[!] Invalid choice. Please enter 0-9.")
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}[!] Interrupted by user.")
                sys.exit(0)
                
    def get_scan_parameters(self):
        """Get scan target and options"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}               SCAN CONFIGURATION")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        # Get target
        target = input(f"{Fore.GREEN}[+] Enter target URL/IP: {Style.RESET_ALL}").strip()
        
        if not target:
            return None, {}
            
        # Get options
        options = {}
        
        print(f"\n{Fore.YELLOW}[*] Scan Options:")
        
        # Deep scan
        deep = input(f"{Fore.CYAN}[?] Enable deep scan? (y/n, default: y): {Style.RESET_ALL}").strip().lower()
        options['deep'] = deep != 'n'
        
        # Aggressive mode
        aggressive = input(f"{Fore.CYAN}[?] Enable aggressive mode? (y/n, default: y): {Style.RESET_ALL}").strip().lower()
        options['aggressive'] = aggressive != 'n'
        
        # Stealth mode
        stealth = input(f"{Fore.CYAN}[?] Enable stealth mode? (y/n, default: n): {Style.RESET_ALL}").strip().lower()
        options['stealth'] = stealth == 'y'
        
        # AI analysis
        ai = input(f"{Fore.CYAN}[?] Enable AI analysis? (y/n, default: y): {Style.RESET_ALL}").strip().lower()
        options['ai'] = ai != 'n'
        
        return target, options
        
    def ask_export(self):
        """Ask if user wants to export results"""
        export = input(f"\n{Fore.CYAN}[?] Export results? (y/n): {Style.RESET_ALL}").strip().lower()
        return export == 'y'
        
    def get_export_format(self):
        """Get export format choice"""
        print(f"\n{Fore.YELLOW}[*] Export Formats:")
        print(f"  {Fore.CYAN}[1]{Style.RESET_ALL} JSON")
        print(f"  {Fore.CYAN}[2]{Style.RESET_ALL} HTML")
        print(f"  {Fore.CYAN}[3]{Style.RESET_ALL} PDF")
        print(f"  {Fore.CYAN}[4]{Style.RESET_ALL} CSV")
        
        while True:
            choice = input(f"{Fore.CYAN}[?] Select format (1-4): {Style.RESET_ALL}").strip()
            if choice == '1':
                return 'json'
            elif choice == '2':
                return 'html'
            elif choice == '3':
                return 'pdf'
            elif choice == '4':
                return 'csv'
            else:
                print(f"{Fore.RED}[!] Invalid choice.")