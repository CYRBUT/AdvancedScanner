import json
from colorama import Fore, Style
from datetime import datetime

class ResultsDisplay:
    @staticmethod
    def show(results):
        """Display scan results"""
        print(f"\n{Fore.GREEN}{'='*80}")
        print(f"{Fore.GREEN}                    SCAN RESULTS SUMMARY")
        print(f"{Fore.GREEN}{'='*80}{Style.RESET_ALL}")
        
        total_vulns = 0
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        
        for scanner, result in results.items():
            if not result:
                continue
                
            print(f"\n{Fore.CYAN}[{scanner}]{Style.RESET_ALL}")
            print(f"  Target: {result.get('target', 'N/A')}")
            
            vulns = result.get('vulnerabilities', [])
            count = result.get('count', 0)
            risk = result.get('risk_level', 'UNKNOWN')
            
            if vulns:
                print(f"  Vulnerabilities found: {count}")
                
                for vuln in vulns[:3]:  # Show first 3
                    severity = vuln.get('severity', 'UNKNOWN')
                    severity_color = {
                        'CRITICAL': Fore.RED,
                        'HIGH': Fore.YELLOW,
                        'MEDIUM': Fore.BLUE,
                        'LOW': Fore.GREEN
                    }.get(severity, Fore.WHITE)
                    
                    print(f"    {severity_color}{severity}{Style.RESET_ALL}: {vuln.get('type', 'Unknown')}")
                    
                if count > 3:
                    print(f"    ... and {count - 3} more")
                    
                # Count by severity
                for vuln in vulns:
                    severity = vuln.get('severity', 'UNKNOWN').upper()
                    if severity == 'CRITICAL':
                        critical_count += 1
                    elif severity == 'HIGH':
                        high_count += 1
                    elif severity == 'MEDIUM':
                        medium_count += 1
                    elif severity == 'LOW':
                        low_count += 1
                        
                total_vulns += count
            else:
                print(f"  Status: {Fore.GREEN}No vulnerabilities found{Style.RESET_ALL}")
                
        # Summary
        print(f"\n{Fore.YELLOW}{'='*80}")
        print(f"{Fore.YELLOW}                      SCAN SUMMARY")
        print(f"{Fore.YELLOW}{'='*80}{Style.RESET_ALL}")
        print(f"  Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Total vulnerabilities: {total_vulns}")
        print(f"  {Fore.RED}Critical: {critical_count}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}High: {high_count}{Style.RESET_ALL}")
        print(f"  {Fore.BLUE}Medium: {medium_count}{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}Low: {low_count}{Style.RESET_ALL}")
        
        if total_vulns > 0:
            print(f"\n{Fore.RED}[!] SECURITY ALERT: Vulnerabilities detected!{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.GREEN}[✓] No critical vulnerabilities found.{Style.RESET_ALL}")
            
    @staticmethod
    def generate_html_report(results):
        """Generate HTML report"""
        html = """<!DOCTYPE html>
<html>
<head>
    <title>Advanced Scanner Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #0f0f23; color: #ccc; }
        h1 { color: #ff5555; border-bottom: 2px solid #ff5555; padding-bottom: 10px; }
        .scanner { background: #1a1a2e; padding: 20px; margin: 20px 0; border-radius: 10px; border-left: 5px solid #5555ff; }
        .critical { color: #ff5555; font-weight: bold; }
        .high { color: #ffaa55; }
        .medium { color: #5555ff; }
        .low { color: #55aa55; }
        .vuln { background: #2a2a3e; padding: 10px; margin: 10px 0; border-radius: 5px; }
        .summary { background: #2a2a3e; padding: 20px; border-radius: 10px; margin: 20px 0; }
    </style>
</head>
<body>
    <h1>Advanced Scanner Security Report</h1>
    <div class="summary">
        <h2>Scan Summary</h2>
        <p>Generated: """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</p>
    </div>
"""
        
        for scanner, result in results.items():
            if result:
                html += f"""
    <div class="scanner">
        <h2>{scanner}</h2>
        <p><strong>Target:</strong> {result.get('target', 'N/A')}</p>
        <p><strong>Vulnerabilities:</strong> {result.get('count', 0)}</p>
"""
                
                for vuln in result.get('vulnerabilities', []):
                    severity = vuln.get('severity', 'UNKNOWN')
                    severity_class = severity.lower()
                    
                    html += f"""
        <div class="vuln">
            <p class="{severity_class}"><strong>{severity}:</strong> {vuln.get('type', 'Unknown')}</p>
            <p>{vuln.get('details', '')}</p>
        </div>
"""
                    
                html += """
    </div>
"""
                
        html += """
</body>
</html>
"""
        
        filename = f"scan_report_{int(datetime.now().timestamp())}.html"
        with open(filename, 'w') as f:
            f.write(html)
            
        return filename
    
    @staticmethod
    def generate_pdf_report(results):
        """Generate PDF report"""
        # Placeholder for PDF generation
        # Would use reportlab or similar
        pass