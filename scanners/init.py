"""
🔐 ADVANCED SECURITY SCANNER MODULES PACKAGE
Comprehensive Security Testing Framework

Version: 4.0
Author: Security Research Team
"""

__all__ = [
    'sql_injection_scanner',
    'xss_scanner', 
    'csrf_scanner',
    'lfi_rfi_scanner',
    'brute_force_scanner',
    'monolog_hijack_scanner',
    'info_disclosure_scanner',
    'zero_day_scanner',
    'subdomain_scanner'
]

import importlib
import sys
from datetime import datetime
from colorama import Fore, Style, Back, init

# Initialize colorama for cross-platform colored output
init(autoreset=True)

class ScannerManager:
    """
    🚀 Advanced Scanner Manager
    Central controller for all security scanning modules
    """
    
    def __init__(self):
        self.version = "4.0"
        self.build_date = "2024-01-01"
        self.scanners = {}
        self.scan_history = []
        self.results = {}
        
        # Color scheme for the manager
        self.colors = {
            'banner': Fore.MAGENTA + Style.BRIGHT,
            'header': Fore.WHITE + Style.BRIGHT,
            'success': Fore.GREEN + Style.BRIGHT,
            'warning': Fore.YELLOW + Style.BRIGHT,
            'error': Fore.RED + Style.BRIGHT,
            'critical': Back.RED + Fore.WHITE + Style.BRIGHT,
            'info': Fore.CYAN + Style.BRIGHT,
            'module': Fore.BLUE + Style.BRIGHT,
            'scan': Fore.YELLOW + Style.BRIGHT,
            'timestamp': Fore.LIGHTBLACK_EX,
            'separator': Fore.LIGHTBLACK_EX + Style.DIM,
            'progress': Fore.GREEN + Style.NORMAL,
            'highlight': Fore.YELLOW + Back.BLACK + Style.BRIGHT
        }
        
        # Scanner metadata
        self.scanner_metadata = {
            'sql_injection_scanner': {
                'name': 'SQL Injection Scanner',
                'description': 'Detects SQL injection vulnerabilities in web applications',
                'risk_level': 'Critical',
                'version': '3.2',
                'dependencies': [],
                'category': 'Injection'
            },
            'xss_scanner': {
                'name': 'Cross-Site Scripting Scanner',
                'description': 'Detects XSS vulnerabilities including reflected, stored, and DOM-based',
                'risk_level': 'High',
                'version': '3.1',
                'dependencies': [],
                'category': 'Injection'
            },
            'csrf_scanner': {
                'name': 'CSRF Vulnerability Scanner',
                'description': 'Identifies Cross-Site Request Forgery vulnerabilities',
                'risk_level': 'Medium',
                'version': '2.8',
                'dependencies': [],
                'category': 'Authentication'
            },
            'lfi_rfi_scanner': {
                'name': 'LFI/RFI Scanner',
                'description': 'Detects Local/Remote File Inclusion vulnerabilities',
                'risk_level': 'High',
                'version': '2.5',
                'dependencies': [],
                'category': 'Injection'
            },
            'brute_force_scanner': {
                'name': 'Brute Force Scanner',
                'description': 'Tests authentication systems for weak credentials',
                'risk_level': 'Medium',
                'version': '3.0',
                'dependencies': [],
                'category': 'Authentication'
            },
            'monolog_hijack_scanner': {
                'name': 'Monolog Hijack Scanner',
                'description': 'Detects Monolog log injection vulnerabilities',
                'risk_level': 'Critical',
                'version': '1.8',
                'dependencies': [],
                'category': 'Logging'
            },
            'info_disclosure_scanner': {
                'name': 'Information Disclosure Scanner',
                'description': 'Finds sensitive information leaks in applications',
                'risk_level': 'Medium',
                'version': '3.5',
                'dependencies': [],
                'category': 'Information'
            },
            'zero_day_scanner': {
                'name': 'Zero-Day Vulnerability Scanner',
                'description': 'Advanced heuristic scanning for unknown vulnerabilities',
                'risk_level': 'Critical',
                'version': '2.0',
                'dependencies': [],
                'category': 'Advanced'
            },
            'subdomain_scanner': {
                'name': 'Subdomain Enumeration Scanner',
                'description': 'Discovers subdomains and associated vulnerabilities',
                'risk_level': 'Low',
                'version': '2.3',
                'dependencies': [],
                'category': 'Reconnaissance'
            }
        }
    
    def print_banner(self):
        """Display the main scanner package banner"""
        banner = f"""
{self.colors['banner']}{"="*100}
{self.colors['header']}╔══════════════════════════════════════════════════════════════════════════════════╗
║                                                                                      ║
║    {Fore.MAGENTA}╔═╗╦ ╦╔═╗╔╗╔╔╦╗╔═╗╦═╗╔═╗  ╔═╗╔═╗ ╦ ╦╔═╗╔╦╗╔═╗╦═╗╔═╗╦  ╦╔═╗╔╗╔╔╦╗{Fore.WHITE}          ║
║    {Fore.MAGENTA}╠═╣║ ║║╣ ║║║ ║ ║╣ ╠╦╝║╣   ║  ║ ║ ║ ║╠═╣║║║║╣ ╠╦╝║╣ ║  ║║╣ ║║║ ║ {Fore.WHITE}          ║
║    {Fore.MAGENTA}╩ ╩╚═╝╚═╝╝╚╝ ╩ ╚═╝╩╚═╚═╝  ╚═╝╚═╝╚╩╝╩ ╩╩ ╩╚═╝╩╚═╚═╝╩═╝╩╚═╝╝╚╝ ╩ {Fore.WHITE}          ║
║                                                                                      ║
║    {self.colors['info']}Advanced Security Scanner Framework v{self.version} | Build: {self.build_date}                {self.colors['header']}║
║    {self.colors['info']}Comprehensive Vulnerability Assessment and Penetration Testing Toolkit          {self.colors['header']}║
║                                                                                      ║
╚══════════════════════════════════════════════════════════════════════════════════╝
{self.colors['banner']}{"="*100}
"""
        print(banner)
    
    def load_all_scanners(self):
        """Dynamically load all available scanner modules"""
        print(f"\n{self.colors['info']}🔄 Loading scanner modules...")
        print(f"{self.colors['separator']}{'-'*80}")
        
        loaded_count = 0
        failed_count = 0
        
        for scanner_name in __all__:
            try:
                module = importlib.import_module(f'.{scanner_name}', package='advanced_scanners')
                scanner_class = getattr(module, scanner_name.title().replace('_', ''))
                
                # Initialize scanner
                scanner_instance = scanner_class()
                self.scanners[scanner_name] = {
                    'instance': scanner_instance,
                    'metadata': self.scanner_metadata.get(scanner_name, {}),
                    'loaded': True
                }
                
                loaded_count += 1
                print(f"{self.colors['success']}✅ {scanner_name:25} v{self.scanner_metadata[scanner_name]['version']} - LOADED")
                
            except ImportError as e:
                self.scanners[scanner_name] = {
                    'instance': None,
                    'metadata': self.scanner_metadata.get(scanner_name, {}),
                    'loaded': False,
                    'error': str(e)
                }
                failed_count += 1
                print(f"{self.colors['error']}❌ {scanner_name:25} - FAILED: {e}")
            
            except Exception as e:
                self.scanners[scanner_name] = {
                    'instance': None,
                    'metadata': self.scanner_metadata.get(scanner_name, {}),
                    'loaded': False,
                    'error': str(e)
                }
                failed_count += 1
                print(f"{self.colors['error']}❌ {scanner_name:25} - ERROR: {e}")
        
        print(f"{self.colors['separator']}{'-'*80}")
        print(f"{self.colors['success']}📊 Loaded: {loaded_count} | Failed: {failed_count} | Total: {len(__all__)}")
        return loaded_count
    
    def list_scanners(self, show_details=False):
        """List all available scanners with details"""
        print(f"\n{self.colors['header']}📋 AVAILABLE SCANNERS")
        print(f"{self.colors['separator']}{'='*80}")
        
        # Group scanners by category
        categories = {}
        for scanner_name, data in self.scanners.items():
            if data['loaded']:
                category = data['metadata'].get('category', 'Uncategorized')
                if category not in categories:
                    categories[category] = []
                categories[category].append((scanner_name, data))
        
        # Display by category
        for category, scanners in categories.items():
            print(f"\n{self.colors['module']}📁 {category.upper()} CATEGORY")
            print(f"{self.colors['separator']}{'-'*50}")
            
            for scanner_name, data in scanners:
                metadata = data['metadata']
                status_color = self.colors['success'] if data['loaded'] else self.colors['error']
                status_icon = "✅" if data['loaded'] else "❌"
                
                print(f"{status_color}{status_icon} {metadata['name']:30} v{metadata['version']}")
                print(f"   {self.colors['info']}{metadata['description']}")
                
                if show_details:
                    print(f"   {self.colors['timestamp']}Risk Level: {metadata['risk_level']}")
                    print(f"   {self.colors['timestamp']}Internal Name: {scanner_name}")
                
                print()
    
    def get_scanner(self, scanner_name):
        """Get a specific scanner instance"""
        if scanner_name in self.scanners:
            if self.scanners[scanner_name]['loaded']:
                return self.scanners[scanner_name]['instance']
            else:
                print(f"{self.colors['error']}Scanner '{scanner_name}' is not loaded")
                if 'error' in self.scanners[scanner_name]:
                    print(f"{self.colors['error']}Error: {self.scanners[scanner_name]['error']}")
        else:
            print(f"{self.colors['error']}Scanner '{scanner_name}' not found")
        
        return None
    
    def run_scanner(self, scanner_name, target, options=None):
        """Run a specific scanner on a target"""
        if scanner_name not in self.scanners:
            print(f"{self.colors['error']}Scanner '{scanner_name}' not available")
            return None
        
        if not self.scanners[scanner_name]['loaded']:
            print(f"{self.colors['error']}Scanner '{scanner_name}' is not loaded")
            return None
        
        scanner = self.scanners[scanner_name]['instance']
        metadata = self.scanners[scanner_name]['metadata']
        
        # Log the scan
        scan_id = f"SCAN-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{scanner_name[:3].upper()}"
        
        print(f"\n{self.colors['scan']}{'🚀'*5} STARTING SCAN {scan_id} {'🚀'*5}")
        print(f"{self.colors['header']}Scanner: {metadata['name']}")
        print(f"{self.colors['info']}Target: {target}")
        print(f"{self.colors['timestamp']}Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{self.colors['separator']}{'-'*80}")
        
        try:
            # Run the scan
            start_time = datetime.now()
            results = scanner.scan(target, options)
            end_time = datetime.now()
            
            duration = (end_time - start_time).total_seconds()
            
            # Store results
            scan_record = {
                'id': scan_id,
                'scanner': scanner_name,
                'target': target,
                'start_time': start_time,
                'end_time': end_time,
                'duration': duration,
                'results': results,
                'metadata': metadata
            }
            
            self.scan_history.append(scan_record)
            
            if scanner_name not in self.results:
                self.results[scanner_name] = []
            self.results[scanner_name].append(results)
            
            # Print summary
            print(f"\n{self.colors['success']}{'✅'*5} SCAN COMPLETED {'✅'*5}")
            print(f"{self.colors['info']}Duration: {duration:.2f} seconds")
            
            # Extract key metrics from results
            if results:
                vulnerabilities = results.get('vulnerabilities_found', 
                                            results.get('vulnerabilities', []))
                if isinstance(vulnerabilities, list):
                    print(f"{self.colors['warning']}Vulnerabilities Found: {len(vulnerabilities)}")
                elif isinstance(vulnerabilities, dict):
                    print(f"{self.colors['warning']}Vulnerabilities Found: {len(vulnerabilities.get('items', []))}")
            
            return results
            
        except Exception as e:
            print(f"{self.colors['error']}❌ Scan failed: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def run_comprehensive_scan(self, target, scanners=None, options=None):
        """Run multiple scanners in sequence"""
        if scanners is None:
            scanners = [s for s in self.scanners.keys() if self.scanners[s]['loaded']]
        
        print(f"\n{self.colors['header']}🔍 COMPREHENSIVE SECURITY ASSESSMENT")
        print(f"{self.colors['info']}Target: {target}")
        print(f"{self.colors['info']}Scanners to run: {len(scanners)}")
        print(f"{self.colors['separator']}{'='*80}")
        
        comprehensive_results = {
            'target': target,
            'start_time': datetime.now(),
            'scans': {},
            'summary': {
                'total_scans': 0,
                'completed_scans': 0,
                'failed_scans': 0,
                'total_vulnerabilities': 0,
                'risk_score': 0
            }
        }
        
        for i, scanner_name in enumerate(scanners, 1):
            print(f"\n{self.colors['info']}📊 [{i}/{len(scanners)}] Running: {scanner_name}")
            
            try:
                results = self.run_scanner(scanner_name, target, options)
                
                if results:
                    comprehensive_results['scans'][scanner_name] = results
                    comprehensive_results['summary']['completed_scans'] += 1
                    
                    # Count vulnerabilities
                    vulnerabilities = results.get('vulnerabilities_found', 
                                                results.get('vulnerabilities', []))
                    if isinstance(vulnerabilities, list):
                        count = len(vulnerabilities)
                    elif isinstance(vulnerabilities, dict):
                        count = len(vulnerabilities.get('items', []))
                    else:
                        count = 0
                    
                    comprehensive_results['summary']['total_vulnerabilities'] += count
                    
                    # Add risk score
                    risk_score = results.get('risk_score', 0)
                    comprehensive_results['summary']['risk_score'] += risk_score
                    
                else:
                    comprehensive_results['summary']['failed_scans'] += 1
                    
            except Exception as e:
                print(f"{self.colors['error']}Failed to run {scanner_name}: {e}")
                comprehensive_results['summary']['failed_scans'] += 1
            
            comprehensive_results['summary']['total_scans'] += 1
        
        # Finalize comprehensive scan
        comprehensive_results['end_time'] = datetime.now()
        duration = (comprehensive_results['end_time'] - 
                   comprehensive_results['start_time']).total_seconds()
        comprehensive_results['duration'] = duration
        
        # Print comprehensive summary
        self.print_comprehensive_summary(comprehensive_results)
        
        return comprehensive_results
    
    def print_comprehensive_summary(self, results):
        """Print a comprehensive scan summary"""
        print(f"\n{self.colors['success']}{'📊'*5} COMPREHENSIVE SCAN SUMMARY {'📊'*5}")
        print(f"{self.colors['separator']}{'='*80}")
        
        summary = results['summary']
        
        print(f"{self.colors['header']}📈 SCAN METRICS")
        print(f"{self.colors['info']}Target: {results['target']}")
        print(f"{self.colors['info']}Duration: {results['duration']:.2f} seconds")
        print(f"{self.colors['info']}Scans Completed: {summary['completed_scans']}/{summary['total_scans']}")
        print(f"{self.colors['info']}Scans Failed: {summary['failed_scans']}")
        print(f"{self.colors['warning']}Total Vulnerabilities: {summary['total_vulnerabilities']}")
        print(f"{self.colors['warning']}Overall Risk Score: {summary['risk_score']}/100")
        
        # Calculate risk level
        risk_score = summary['risk_score']
        if risk_score > 70:
            risk_level = f"{self.colors['critical']}CRITICAL"
        elif risk_score > 40:
            risk_level = f"{self.colors['error']}HIGH"
        elif risk_score > 20:
            risk_level = f"{self.colors['warning']}MEDIUM"
        elif risk_score > 0:
            risk_level = f"{self.colors['info']}LOW"
        else:
            risk_level = f"{self.colors['success']}NONE"
        
        print(f"{self.colors['header']}Overall Risk Level: {risk_level}")
        
        # Breakdown by scanner
        print(f"\n{self.colors['header']}🔍 SCANNER BREAKDOWN")
        print(f"{self.colors['separator']}{'-'*80}")
        
        for scanner_name, scan_results in results['scans'].items():
            metadata = self.scanner_metadata.get(scanner_name, {})
            
            vulnerabilities = scan_results.get('vulnerabilities_found', 
                                             scan_results.get('vulnerabilities', []))
            if isinstance(vulnerabilities, list):
                vuln_count = len(vulnerabilities)
            elif isinstance(vulnerabilities, dict):
                vuln_count = len(vulnerabilities.get('items', []))
            else:
                vuln_count = 0
            
            risk_score = scan_results.get('risk_score', 0)
            
            # Color code based on vulnerability count
            if vuln_count > 0:
                if vuln_count > 5:
                    color = self.colors['critical']
                elif vuln_count > 2:
                    color = self.colors['error']
                else:
                    color = self.colors['warning']
            else:
                color = self.colors['success']
            
            print(f"{color}▶ {metadata.get('name', scanner_name):30}")
            print(f"{self.colors['timestamp']}   Vulnerabilities: {vuln_count:3d} | Risk Score: {risk_score:3d}/100")
        
        print(f"\n{self.colors['success']}✅ Comprehensive scan completed successfully!")
        print(f"{self.colors['separator']}{'='*80}\n")
    
    def export_results(self, results, format='json', filename=None):
        """Export scan results to various formats"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"security_scan_{timestamp}.{format}"
        
        try:
            if format.lower() == 'json':
                import json
                
                # Create export data
                export_data = {
                    'metadata': {
                        'export_date': datetime.now().isoformat(),
                        'scanner_version': self.version,
                        'total_scans': len(results.get('scans', {}))
                    },
                    'results': results
                }
                
                with open(filename, 'w') as f:
                    json.dump(export_data, f, indent=2, default=str)
                
                print(f"{self.colors['success']}✅ Results exported to {filename}")
                return True
                
            elif format.lower() == 'html':
                # Simple HTML export
                html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Security Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .vulnerability {{ color: red; }}
        .info {{ color: blue; }}
        .warning {{ color: orange; }}
    </style>
</head>
<body>
    <h1>Security Scan Report</h1>
    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <p>Target: {results.get('target', 'Unknown')}</p>
    <p>Total Vulnerabilities: {results['summary'].get('total_vulnerabilities', 0)}</p>
</body>
</html>
"""
                with open(filename, 'w') as f:
                    f.write(html)
                
                print(f"{self.colors['success']}✅ HTML report exported to {filename}")
                return True
                
            else:
                print(f"{self.colors['error']}Unsupported export format: {format}")
                return False
                
        except Exception as e:
            print(f"{self.colors['error']}Failed to export results: {e}")
            return False
    
    def print_help(self):
        """Print help information"""
        help_text = f"""
{self.colors['header']}🆘 ADVANCED SCANNER PACKAGE - HELP
{self.colors['separator']}{'='*80}

{self.colors['info']}Available Commands:
{self.colors['success']}  manager.load_all_scanners()      {self.colors['timestamp']}Load all scanner modules
{self.colors['success']}  manager.list_scanners()          {self.colors['timestamp']}List available scanners
{self.colors['success']}  manager.get_scanner(name)        {self.colors['timestamp']}Get specific scanner instance
{self.colors['success']}  manager.run_scanner(name, target) {self.colors['timestamp']}Run specific scanner
{self.colors['success']}  manager.run_comprehensive_scan(target) {self.colors['timestamp']}Run all scanners
{self.colors['success']}  manager.export_results(results, format) {self.colors['timestamp']}Export results

{self.colors['info']}Example Usage:
{self.colors['highlight']}  manager = ScannerManager()
{self.colors['highlight']}  manager.load_all_scanners()
{self.colors['highlight']}  results = manager.run_comprehensive_scan('http://example.com')
{self.colors['highlight']}  manager.export_results(results, 'json')

{self.colors['info']}Available Export Formats:
{self.colors['timestamp']}  • json - JSON format (recommended)
{self.colors['timestamp']}  • html - HTML report

{self.colors['separator']}{'='*80}
"""
        print(help_text)

# Create a global instance for easy access
manager = None

def init_manager():
    """Initialize the scanner manager"""
    global manager
    manager = ScannerManager()
    manager.print_banner()
    return manager

def get_scanner(scanner_name):
    """Convenience function to get a scanner"""
    if manager is None:
        init_manager()
    return manager.get_scanner(scanner_name)

def run_scan(scanner_name, target, options=None):
    """Convenience function to run a scan"""
    if manager is None:
        init_manager()
    return manager.run_scanner(scanner_name, target, options)

# Example: Direct scanner imports (for backward compatibility)
try:
    from .sql_injection_scanner import SqlInjectionScanner
    from .xss_scanner import XssScanner
    from .csrf_scanner import CsrcScanner
    from .lfi_rfi_scanner import LfiRfiScanner
    from .brute_force_scanner import BruteForceScanner
    from .monolog_hijack_scanner import MonologHijackScanner
    from .info_disclosure_scanner import InfoDisclosureScanner
    from .zero_day_scanner import ZeroDayScanner
    from .subdomain_scanner import SubdomainScanner
    
    # Create alias for backward compatibility
    CSRFScanner = CsrcScanner  # Typo fix
    
except ImportError as e:
    print(f"{Fore.RED}Warning: Some scanner modules failed to import: {e}")
    print(f"{Fore.YELLOW}Use ScannerManager for dynamic loading instead.")

# Version information
__version__ = "4.0"
__author__ = "Security Research Team"
__email__ = "security@example.com"
__license__ = "MIT"

# Main execution guard
if __name__ == "__main__":
    # Initialize and test the scanner manager
    manager = init_manager()
    manager.load_all_scanners()
    manager.list_scanners(show_details=True)
    
    print(f"\n{Fore.CYAN}Advanced Scanner Package v{__version__} initialized successfully!")
    print(f"{Fore.YELLOW}Use 'manager' object to control scanners.")
    print(f"{Fore.GREEN}Example: manager.run_comprehensive_scan('http://test.com')")