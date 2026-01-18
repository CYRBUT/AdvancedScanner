"""
Results display and reporting
"""

import json
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

class ResultsDisplay:
    def __init__(self, results):
        self.results = results
    
    def show_summary(self):
        """Display scan summary"""
        print(f"\n{Fore.CYAN}╔{'═'*60}╗")
        print(f"{Fore.CYAN}║{'SCAN SUMMARY'.center(60)}║")
        print(f"{Fore.CYAN}╚{'═'*60}╝{Style.RESET_ALL}")
        
        total_vulnerabilities = 0
        scanner_results = {}
        
        for scan_type, result in self.results.items():
            vuln_count = len(result.get('vulnerabilities', []))
            total_vulnerabilities += vuln_count
            scanner_results[scan_type] = vuln_count
        
        # Print summary
        print(f"{Fore.YELLOW}Total Vulnerabilities Found: {Fore.CYAN}{total_vulnerabilities}")
        print()
        
        if total_vulnerabilities > 0:
            print(f"{Fore.YELLOW}Breakdown by Scanner:")
            for scanner, count in scanner_results.items():
                if count > 0:
                    print(f"  {Fore.GREEN}{scanner.upper():<20} {Fore.RED}{count}")
        
        # Show critical findings
        critical_findings = self.get_critical_findings()
        if critical_findings:
            print(f"\n{Fore.RED}CRITICAL FINDINGS:")
            for finding in critical_findings[:5]:  # Show top 5
                print(f"  • {finding}")
    
    def show_detailed(self):
        """Display detailed results"""
        print(f"\n{Fore.CYAN}╔{'═'*80}╗")
        print(f"{Fore.CYAN}║{'DETAILED SCAN RESULTS'.center(80)}║")
        print(f"{Fore.CYAN}╚{'═'*80}╝{Style.RESET_ALL}")
        
        for scan_type, result in self.results.items():
            vulnerabilities = result.get('vulnerabilities', [])
            
            if vulnerabilities:
                print(f"\n{Fore.YELLOW}{'='*60}")
                print(f"{Fore.CYAN}{scan_type.upper()} Vulnerabilities ({len(vulnerabilities)}):")
                print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
                
                for i, vuln in enumerate(vulnerabilities, 1):
                    print(f"\n{Fore.GREEN}[{i}] {vuln.get('type', 'Unknown')}")
                    
                    if 'parameter' in vuln:
                        print(f"   {Fore.YELLOW}Parameter: {Fore.WHITE}{vuln['parameter']}")
                    
                    if 'payload' in vuln:
                        print(f"   {Fore.YELLOW}Payload: {Fore.WHITE}{vuln['payload'][:50]}...")
                    
                    if 'url' in vuln:
                        print(f"   {Fore.YELLOW}URL: {Fore.WHITE}{vuln['url']}")
                    
                    if 'risk' in vuln:
                        risk_color = Fore.RED if vuln['risk'] == 'HIGH' else Fore.YELLOW
                        print(f"   {Fore.YELLOW}Risk: {risk_color}{vuln['risk']}")
    
    def get_critical_findings(self):
        """Extract critical findings from results"""
        critical = []
        
        for scan_type, result in self.results.items():
            for vuln in result.get('vulnerabilities', []):
                if vuln.get('type') in ['SQL Injection', 'Remote File Inclusion', 'Information Disclosure']:
                    critical.append(f"{vuln['type']} at {vuln.get('url', 'Unknown')}")
        
        return critical
    
    def export_json(self, filename=None):
        """Export results to JSON file"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_results_{timestamp}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2, default=str)
            
            print(f"{Fore.GREEN}[+] Results exported to {filename}")
            return filename
            
        except Exception as e:
            print(f"{Fore.RED}[-] Export failed: {e}")
            return None
    
    def export_html(self, filename=None):
        """Export results to HTML report"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_report_{timestamp}.html"
        
        try:
            html_content = self._generate_html_report()
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            print(f"{Fore.GREEN}[+] HTML report saved to {filename}")
            return filename
            
        except Exception as e:
            print(f"{Fore.RED}[-] HTML export failed: {e}")
            return None
    
    def _generate_html_report(self):
        """Generate HTML report content"""
        html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .vulnerability { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }
        .critical { border-left: 5px solid #e74c3c; }
        .high { border-left: 5px solid #e67e22; }
        .medium { border-left: 5px solid #f1c40f; }
        .low { border-left: 5px solid #3498db; }
        .summary { background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Scan Report</h1>
        <p>Generated: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
    </div>
    
    <div class="summary">
        <h2>Scan Summary</h2>
        <p>Total vulnerabilities found: <strong>""" + str(self._count_vulnerabilities()) + """</strong></p>
    </div>
    
    <h2>Detailed Findings</h2>
"""
        
        # Add vulnerability details
        for scan_type, result in self.results.items():
            vulnerabilities = result.get('vulnerabilities', [])
            
            if vulnerabilities:
                html += f'<h3>{scan_type.upper()} ({len(vulnerabilities)} findings)</h3>'
                
                for vuln in vulnerabilities:
                    risk_class = vuln.get('risk', 'medium').lower()
                    html += f"""
                    <div class="vulnerability {risk_class}">
                        <h4>{vuln.get('type', 'Unknown')}</h4>
                        <p><strong>URL:</strong> {vuln.get('url', 'N/A')}</p>
                        <p><strong>Risk:</strong> {vuln.get('risk', 'Medium')}</p>
                        <p><strong>Details:</strong> {vuln.get('evidence', {}).get('description', 'N/A')}</p>
                    </div>
                    """
        
        html += """
</body>
</html>"""
        
        return html
    
    def _count_vulnerabilities(self):
        """Count total vulnerabilities"""
        count = 0
        for result in self.results.values():
            count += len(result.get('vulnerabilities', []))
        return count
    
    def print_colored_report(self):
        """Print colored console report"""
        print(f"\n{Fore.CYAN}{'='*80}")
        print(f"{'SECURITY SCAN REPORT'.center(80)}")
        print(f"{'='*80}{Style.RESET_ALL}")
        
        for scan_type, result in self.results.items():
            vulns = result.get('vulnerabilities', [])
            
            if vulns:
                color = Fore.RED if len(vulns) > 0 else Fore.GREEN
                print(f"\n{color}{scan_type.upper():<20} {len(vulns):>3} findings{Style.RESET_ALL}")
                
                for vuln in vulns[:3]:  # Show top 3 per type
                    print(f"  {Fore.YELLOW}• {vuln.get('type', 'Unknown')}")
                    if 'parameter' in vuln:
                        print(f"    {Fore.WHITE}Param: {vuln['parameter']}")