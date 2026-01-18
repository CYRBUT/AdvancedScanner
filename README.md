# Advanced Security Scanner v3.0 (2026)

## 🚀 Features
- **Multiple Vulnerability Scanners**
  - SQL Injection Scanner
  - Cross-Site Scripting (XSS) Scanner
  - CSRF Scanner
  - LFI/RFI Scanner
  - Brute Force Scanner
  - Monolog Hijacking Scanner
  - Information Disclosure Scanner
  - Zero-Day Detection
  - Subdomain Discovery

- **Advanced Features**
  - Multi-threaded scanning
  - Proxy support with rotation
  - Custom payload support
  - Detailed reporting (JSON, HTML, TXT, CSV)
  - Network scanning capabilities
  - Regular updates and maintenance

## 📋 Requirements
- Python 3.8+
- Root access recommended (for full functionality)
- Internet connection (for updates and proxy functionality)

## 🛠 Installation

### 1. Clone Repository
```bash
git clone https://github.com/CYRBUT/AdvancedScanner.git
cd AdvancedScanner


# Install system dependencies
sudo apt-get update
sudo apt-get install python3 python3-pip nmap

# Install Python packages
pip3 install -r requirements.txt


# Make main script executable
chmod +x main.py

# Run with root privileges for full functionality
sudo python3 main.py


# Run scanner
python3 main.py

# Run with root privileges (recommended)
sudo python3 main.py


# Direct scan without menu
python3 main.py --target http://example.com --scan sql,xss

# Specific scan with output
python3 main.py --target http://example.com --scan all --output report.html

# Use proxy list
python3 main.py --target http://example.com --proxies proxies.txt




Menu Options
1. Scan Target - Set target and start scanning
2. Set Proxy - Configure proxy settings
3. Configure Scanner-Advanced scanner configuration
4. View Results - Display scan results
5. Export Results - Export results to various formats
6. Load Targets - Load multiple targets from file
7. Advanced Options - Network scan, port scan, etc.
8. Update Scanner - Check for updates
9. About - Show program information
O. Exit - Close the scanner
Configuration
Proxy Setup
Create proxies. txt in the project root:

http://proxy1.example.com:8080
http://proxy2.example.com:8080
socks5://proxy3.example.com:1080



Custom Payloads
Edit payload files in scanners/ directory:
•sql_payloads.txt- SQL injection payloads
•xss_payloads.txt- XSS payloads
•lfi_payloads.txt- LFI/RFI payloads
Output Formats
The scanner supports multiple output formats:
· JSON - Machine-readable format for further processing
· HTML - Visual report with styling
•TXT - Simple text report
• CSV - Spreadsheet compatible format
Legal Disclaimer
WARNING: This tool is for educational and authorized testing
purposes only.
· Only scan systems you own or have explicit permission to test
· Unauthorized scanning is illegal and unethical
· The developers are not responsible for misuse
• Comply with all applicable laws and regulations
a Security Features
• Rate limiting to avoid detection
· Randomized User-Agent headers
· Proxy rotation for anonymity
• SSL/TLS verification options
· Custom timeout settings
Advanced Features
Network Scanning


bash# Requires root privileges
sudo python3 main.py --network-scan 192.168.1.0/24


bash# Scan common ports
python3 main.py --port-scan example.com


Vulnerability Database
Regular updates to vulnerability signatures and payloads.
Sos
Troubleshooting
Common Issues
1. Permission Errors

# Run with sudo
sudo python3 main.py

# Reinstall requirements
pip3 install --upgrade -r requirements.txt



3. Proxy Not Working
• Verify proxy addresses in proxies.txt
· Test proxies individually
· Check firewall settings
4. Scan Too Slow
· Adjust thread count in settings
· Use faster proxies
• Increase timeout values
Performance Tips
1. Optimal Thread Count: 5-10 threads for most scans
2. Proxy Selection: Use reliable, fast proxies
3. Timeout Settings: Adjust based on target responsiveness
4. Payload Selection: Use targeted payloads for specific
technologies
Updates
The scanner includes automatic update checking. Manual update:

git pull origin master
pip3 install --upgrade -r requirements.txt

if error use command

cd AdvancedScanner
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt



🤝Contributing
1. Fork the repository
2. Create a feature branch
3. Commit changes
4. Push to branch
5. Create Pull Request
License
MIT License - See LICENSE file for details
Authors
Security Research Team
• Advanced Scanner Development Group
Support
GitHub Issues: https://github.com/CYRBUT/AdvancedScanner/issues
Acknowledgments
• OWASP for vulnerability references
· Security research community
Open source contributors



## **Setup Instructions**

1. **Create the directory structure:**
```bash
mkdir -p AdvancedScanner/{scanners,utils,views,assets}


pip install -r requirements.txt

# Normal mode
python main.py

# With root privileges (recommended)
sudo python main.py

Key Features:
Multi-scanner support (SQLi, XSS, CSRF, LFI/RFI, Brute Force,
etc.)
Proxy support with rotation
Multi-threaded scanning
Detailed reporting (JSON, HTML, TXT, CSV)
Root access capabilities
International support
Easy to use menu system
Regular updates
Educational purposes only
Security Note:
A This tool is for educational and authorized testing only.
A Only use on systems you own or have permission to test.
A Unauthorized scanning is illegal.












