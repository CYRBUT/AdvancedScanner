"""
╔══════════════════════════════════════════════════════════════════════════════╗
║            𝗔𝗗𝗩𝗔𝗡𝗖𝗘𝗗 𝗥𝗘𝗦𝗨𝗟𝗧𝗦 𝗗𝗜𝗦𝗣𝗟𝗔𝗬 𝗔𝗡𝗗 𝗥𝗘𝗣𝗢𝗥𝗧𝗜𝗡𝗚              ║
║           Professional Security Reports with Visualization Engine            ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import json
import csv
import sys
import os
import time
import hashlib
import base64
import webbrowser
import threading
import queue
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, field, asdict
from enum import Enum, auto
from pathlib import Path
from collections import defaultdict, OrderedDict
import html
from colorama import Fore, Back, Style, init, AnsiToWin32
import jinja2
import markdown
import pdfkit
from io import StringIO, BytesIO
import zipfile
import xml.etree.ElementTree as ET
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from matplotlib.backends.backend_pdf import PdfPages
import numpy as np
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
from reportlab.lib.units import inch
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics import renderPDF

# Initialize colorama
init(autoreset=True)

class ReportColors:
    """Enhanced color palette for reporting with rich black variations"""
    
    # Black Text Variations
    BLACK = '\033[30m'
    BLACK_BOLD = '\033[1;30m'
    BLACK_ITALIC = '\033[3;30m'
    BLACK_UNDERLINE = '\033[4;30m'
    BLACK_BLINK = '\033[5;30m'
    BLACK_REVERSE = '\033[7;30m'
    BLACK_STRIKETHROUGH = '\033[9;30m'
    BLACK_FADED = '\033[2;30m'
    
    # Gray Scale Text
    DARK_GRAY = '\033[90m'
    DARK_GRAY_BOLD = '\033[1;90m'
    DIM_GRAY = '\033[38;5;8m'
    CHARCOAL = '\033[38;5;236m'
    GUNMETAL = '\033[38;5;238m'
    SLATE = '\033[38;5;240m'
    STEEL = '\033[38;5;245m'
    SILVER = '\033[38;5;7m'
    ASH = '\033[38;5;248m'
    
    # Gradient Blacks
    BLACK_GRADIENT_1 = '\033[38;5;232m'
    BLACK_GRADIENT_2 = '\033[38;5;233m'
    BLACK_GRADIENT_3 = '\033[38;5;234m'
    BLACK_GRADIENT_4 = '\033[38;5;235m'
    
    # Backgrounds
    ON_BLACK = '\033[40m'
    ON_DARK_GRAY = '\033[100m'
    ON_CHARCOAL = '\033[48;5;236m'
    ON_STEEL = '\033[48;5;245m'
    ON_SILVER = '\033[47m'
    
    # Risk Level Colors
    ON_CRITICAL = '\033[48;5;196m'  # Bright Red
    ON_HIGH = '\033[48;5;208m'      # Orange
    ON_MEDIUM = '\033[48;5;220m'    # Yellow
    ON_LOW = '\033[48;5;76m'        # Green
    ON_INFO = '\033[48;5;27m'       # Blue
    
    # Text Colors for Backgrounds
    BLACK_ON_CRITICAL = '\033[30;48;5;196m'
    BLACK_ON_HIGH = '\033[30;48;5;208m'
    BLACK_ON_MEDIUM = '\033[30;48;5;220m'
    BLACK_ON_LOW = '\033[30;48;5;76m'
    BLACK_ON_INFO = '\033[30;48;5;27m'
    
    # Status Colors
    ON_SUCCESS = '\033[42m'
    ON_WARNING = '\033[43m'
    ON_DANGER = '\033[41m'
    ON_INFO = '\033[44m'
    ON_PURPLE = '\033[45m'
    ON_CYAN = '\033[46m'
    
    RESET = '\033[0m'

class RiskLevel(Enum):
    """Risk level enumeration"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"
    
    @classmethod
    def from_string(cls, value: str):
        """Convert string to RiskLevel"""
        value = value.lower()
        for level in cls:
            if level.value == value:
                return level
        return cls.INFO
    
    @property
    def color_code(self):
        """Get color code for risk level"""
        colors = {
            RiskLevel.CRITICAL: ReportColors.BLACK_ON_CRITICAL,
            RiskLevel.HIGH: ReportColors.BLACK_ON_HIGH,
            RiskLevel.MEDIUM: ReportColors.BLACK_ON_MEDIUM,
            RiskLevel.LOW: ReportColors.BLACK_ON_LOW,
            RiskLevel.INFO: ReportColors.BLACK_ON_INFO,
        }
        return colors.get(self, ReportColors.BLACK_ON_INFO)

class ReportType(Enum):
    """Report type enumeration"""
    CONSOLE = "console"
    HTML = "html"
    PDF = "pdf"
    JSON = "json"
    CSV = "csv"
    XML = "xml"
    MARKDOWN = "markdown"
    EXCEL = "excel"
    WORD = "word"
    DASHBOARD = "dashboard"
    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    REMEDIATION = "remediation"

@dataclass
class Vulnerability:
    """Vulnerability data structure"""
    id: str
    type: str
    severity: RiskLevel
    title: str
    description: str
    impact: str
    remediation: str
    cvss_score: float
    cvss_vector: str
    affected_url: str
    affected_parameter: Optional[str] = None
    payload: Optional[str] = None
    evidence: Optional[str] = None
    http_method: Optional[str] = None
    http_status: Optional[int] = None
    request_data: Optional[str] = None
    response_data: Optional[str] = None
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    owasp_category: Optional[str] = None
    discovery_date: datetime = field(default_factory=datetime.now)
    verified: bool = False
    false_positive: bool = False
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    screenshots: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def risk_color(self) -> str:
        """Get color for risk level"""
        return self.severity.color_code
    
    @property
    def formatted_cvss(self) -> str:
        """Get formatted CVSS score"""
        if self.cvss_score >= 9.0:
            return f"{ReportColors.BLACK_ON_CRITICAL}{self.cvss_score:.1f}{ReportColors.RESET}"
        elif self.cvss_score >= 7.0:
            return f"{ReportColors.BLACK_ON_HIGH}{self.cvss_score:.1f}{ReportColors.RESET}"
        elif self.cvss_score >= 4.0:
            return f"{ReportColors.BLACK_ON_MEDIUM}{self.cvss_score:.1f}{ReportColors.RESET}"
        else:
            return f"{ReportColors.BLACK_ON_LOW}{self.cvss_score:.1f}{ReportColors.RESET}"

@dataclass
class ScanMetadata:
    """Scan metadata"""
    target: str
    start_time: datetime
    end_time: datetime
    duration: timedelta
    scanner_version: str
    scanner_name: str
    scan_type: str
    parameters: Dict[str, Any]
    authenticated: bool = False
    auth_type: Optional[str] = None
    user_agent: Optional[str] = None
    proxy_used: Optional[str] = None
    total_requests: int = 0
    total_responses: int = 0
    crawl_urls: int = 0
    test_cases: int = 0
    environment: Dict[str, str] = field(default_factory=dict)

@dataclass
class ScanResults:
    """Complete scan results"""
    metadata: ScanMetadata
    vulnerabilities: List[Vulnerability]
    statistics: Dict[str, Any]
    summary: Dict[str, Any]
    recommendations: List[str]
    appendix: Dict[str, Any] = field(default_factory=dict)

class StatisticsGenerator:
    """Generate comprehensive statistics from scan results"""
    
    @staticmethod
    def generate(results: ScanResults) -> Dict[str, Any]:
        """Generate comprehensive statistics"""
        stats = {
            'overview': StatisticsGenerator._overview_stats(results),
            'risk_distribution': StatisticsGenerator._risk_distribution(results),
            'vulnerability_types': StatisticsGenerator._vulnerability_types(results),
            'timeline': StatisticsGenerator._timeline_stats(results),
            'technical': StatisticsGenerator._technical_stats(results),
            'severity_trends': StatisticsGenerator._severity_trends(results),
            'affected_components': StatisticsGenerator._affected_components(results),
        }
        return stats
    
    @staticmethod
    def _overview_stats(results: ScanResults) -> Dict[str, Any]:
        """Generate overview statistics"""
        total_vulns = len(results.vulnerabilities)
        critical_vulns = len([v for v in results.vulnerabilities if v.severity == RiskLevel.CRITICAL])
        high_vulns = len([v for v in results.vulnerabilities if v.severity == RiskLevel.HIGH])
        medium_vulns = len([v for v in results.vulnerabilities if v.severity == RiskLevel.MEDIUM])
        low_vulns = len([v for v in results.vulnerabilities if v.severity == RiskLevel.LOW])
        
        avg_cvss = sum(v.cvss_score for v in results.vulnerabilities) / total_vulns if total_vulns > 0 else 0
        max_cvss = max((v.cvss_score for v in results.vulnerabilities), default=0)
        
        return {
            'total_vulnerabilities': total_vulns,
            'critical_vulnerabilities': critical_vulns,
            'high_vulnerabilities': high_vulns,
            'medium_vulnerabilities': medium_vulns,
            'low_vulnerabilities': low_vulns,
            'average_cvss_score': round(avg_cvss, 2),
            'maximum_cvss_score': max_cvss,
            'scan_duration': str(results.metadata.duration),
            'total_requests': results.metadata.total_requests,
            'requests_per_second': round(results.metadata.total_requests / max(results.metadata.duration.total_seconds(), 1), 2),
        }
    
    @staticmethod
    def _risk_distribution(results: ScanResults) -> Dict[str, Any]:
        """Generate risk distribution statistics"""
        vulns = results.vulnerabilities
        
        distribution = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
        }
        
        for vuln in vulns:
            distribution[vuln.severity.value] += 1
        
        # Calculate percentages
        total = len(vulns)
        if total > 0:
            for key in distribution:
                distribution[f'{key}_percentage'] = round((distribution[key] / total) * 100, 1)
        
        return distribution
    
    @staticmethod
    def _vulnerability_types(results: ScanResults) -> Dict[str, Any]:
        """Group vulnerabilities by type"""
        type_counts = defaultdict(int)
        type_severity = defaultdict(list)
        
        for vuln in results.vulnerabilities:
            type_counts[vuln.type] += 1
            type_severity[vuln.type].append(vuln.severity)
        
        # Calculate severity breakdown per type
        type_analysis = {}
        for vuln_type, count in type_counts.items():
            severities = type_severity[vuln_type]
            severity_dist = {
                'critical': severities.count(RiskLevel.CRITICAL),
                'high': severities.count(RiskLevel.HIGH),
                'medium': severities.count(RiskLevel.MEDIUM),
                'low': severities.count(RiskLevel.LOW),
                'info': severities.count(RiskLevel.INFO),
            }
            type_analysis[vuln_type] = {
                'count': count,
                'severity_distribution': severity_dist,
                'percentage': round((count / len(results.vulnerabilities)) * 100, 1) if results.vulnerabilities else 0
            }
        
        return dict(type_analysis)
    
    @staticmethod
    def _timeline_stats(results: ScanResults) -> Dict[str, Any]:
        """Generate timeline statistics"""
        vulns_by_hour = defaultdict(int)
        
        for vuln in results.vulnerabilities:
            hour = vuln.discovery_date.strftime('%H:00')
            vulns_by_hour[hour] += 1
        
        return dict(vulns_by_hour)
    
    @staticmethod
    def _technical_stats(results: ScanResults) -> Dict[str, Any]:
        """Generate technical statistics"""
        methods = defaultdict(int)
        status_codes = defaultdict(int)
        parameters = defaultdict(int)
        
        for vuln in results.vulnerabilities:
            if vuln.http_method:
                methods[vuln.http_method] += 1
            if vuln.http_status:
                status_codes[vuln.http_status] += 1
            if vuln.affected_parameter:
                parameters[vuln.affected_parameter] += 1
        
        return {
            'http_methods': dict(methods),
            'status_codes': dict(status_codes),
            'top_parameters': dict(sorted(parameters.items(), key=lambda x: x[1], reverse=True)[:10]),
        }
    
    @staticmethod
    def _severity_trends(results: ScanResults) -> Dict[str, Any]:
        """Generate severity trends over time"""
        # Group by hour and severity
        trends = defaultdict(lambda: defaultdict(int))
        
        for vuln in results.vulnerabilities:
            hour = vuln.discovery_date.strftime('%H:00')
            trends[hour][vuln.severity.value] += 1
        
        return trends
    
    @staticmethod
    def _affected_components(results: ScanResults) -> Dict[str, Any]:
        """Analyze affected components"""
        components = defaultdict(lambda: defaultdict(int))
        
        for vuln in results.vulnerabilities:
            # Extract component from URL
            url = vuln.affected_url
            parsed = urllib.parse.urlparse(url)
            
            # Count by path segments
            path = parsed.path
            if path:
                segments = path.split('/')
                if len(segments) > 1:
                    component = segments[1] if segments[1] else 'root'
                    components[component][vuln.severity.value] += 1
        
        return dict(components)

class AdvancedResultsDisplay:
    """Advanced results display and reporting system"""
    
    def __init__(self, results: Union[Dict, ScanResults]):
        """Initialize with scan results"""
        if isinstance(results, dict):
            self.results = self._convert_dict_to_results(results)
        else:
            self.results = results
        
        self.stats = StatisticsGenerator.generate(self.results)
        self._print_banner()
    
    def _print_banner(self):
        """Print initialization banner"""
        banner = f"""
{ReportColors.ON_CHARCOAL}{ReportColors.BLACK_BOLD}{'═' * 80}{ReportColors.RESET}
{ReportColors.ON_CHARCOAL}{ReportColors.BLACK_UNDERLINE}{'ADVANCED RESULTS DISPLAY & REPORTING SYSTEM':^80}{ReportColors.RESET}
{ReportColors.ON_CHARCOAL}{ReportColors.BLACK_ITALIC}{'Professional Security Reports • Real-time Analytics • Multi-format Export':^80}{ReportColors.RESET}
{ReportColors.ON_CHARCOAL}{ReportColors.BLACK_BOLD}{'═' * 80}{ReportColors.RESET}
{ReportColors.DARK_GRAY_BOLD}[*] Target: {self.results.metadata.target}{ReportColors.RESET}
{ReportColors.DARK_GRAY_BOLD}[*] Scan Duration: {self.results.metadata.duration}{ReportColors.RESET}
        """
        print(banner)
    
    def _convert_dict_to_results(self, data: Dict) -> ScanResults:
        """Convert dictionary to ScanResults object"""
        # This is a simplified conversion - in production, you'd want more robust conversion
        return ScanResults(
            metadata=ScanMetadata(
                target=data.get('target', 'Unknown'),
                start_time=datetime.fromisoformat(data.get('start_time', datetime.now().isoformat())),
                end_time=datetime.fromisoformat(data.get('end_time', datetime.now().isoformat())),
                duration=timedelta(seconds=data.get('duration_seconds', 0)),
                scanner_version=data.get('scanner_version', '1.0.0'),
                scanner_name=data.get('scanner_name', 'Advanced Scanner'),
                scan_type=data.get('scan_type', 'Comprehensive'),
                parameters=data.get('parameters', {}),
                authenticated=data.get('authenticated', False),
                total_requests=data.get('total_requests', 0),
            ),
            vulnerabilities=[
                Vulnerability(
                    id=v.get('id', str(i)),
                    type=v.get('type', 'Unknown'),
                    severity=RiskLevel.from_string(v.get('severity', 'info')),
                    title=v.get('title', 'Unnamed Vulnerability'),
                    description=v.get('description', ''),
                    impact=v.get('impact', ''),
                    remediation=v.get('remediation', ''),
                    cvss_score=v.get('cvss_score', 0.0),
                    cvss_vector=v.get('cvss_vector', ''),
                    affected_url=v.get('affected_url', ''),
                    affected_parameter=v.get('affected_parameter'),
                    payload=v.get('payload'),
                    evidence=v.get('evidence'),
                    http_method=v.get('http_method'),
                    http_status=v.get('http_status'),
                    cwe_id=v.get('cwe_id'),
                    cve_id=v.get('cve_id'),
                    discovery_date=datetime.fromisoformat(v.get('discovery_date', datetime.now().isoformat())),
                    verified=v.get('verified', False),
                    false_positive=v.get('false_positive', False),
                )
                for i, v in enumerate(data.get('vulnerabilities', []))
            ],
            statistics=data.get('statistics', {}),
            summary=data.get('summary', {}),
            recommendations=data.get('recommendations', []),
            appendix=data.get('appendix', {}),
        )
    
    def display_dashboard(self, live_update: bool = False):
        """Display interactive dashboard view"""
        print(f"\n{ReportColors.ON_CHARCOAL}{ReportColors.BLACK_BOLD}{' SECURITY SCAN DASHBOARD ':{'═'}^80}{ReportColors.RESET}")
        
        # Overall stats
        self._print_summary_box()
        
        # Risk distribution
        self._print_risk_distribution()
        
        # Top vulnerabilities
        self._print_top_vulnerabilities()
        
        # Scan metrics
        self._print_scan_metrics()
        
        # Timeline visualization
        if live_update:
            self._print_timeline_chart()
    
    def _print_summary_box(self):
        """Print summary box with key metrics"""
        stats = self.stats['overview']
        
        print(f"\n{ReportColors.BLACK_UNDERLINE}OVERVIEW SUMMARY{ReportColors.RESET}")
        print(f"{ReportColors.DARK_GRAY}{'─' * 80}{ReportColors.RESET}")
        
        # Row 1
        print(f"{ReportColors.BLACK_BOLD}Total Vulnerabilities:{ReportColors.RESET} "
              f"{ReportColors.BLACK_ON_DANGER}{stats['total_vulnerabilities']:>6}{ReportColors.RESET}")
        
        print(f"{ReportColors.BLACK_BOLD}Critical:{ReportColors.RESET} "
              f"{ReportColors.BLACK_ON_CRITICAL}{stats['critical_vulnerabilities']:>6}{ReportColors.RESET} "
              f"{ReportColors.BLACK_BOLD}High:{ReportColors.RESET} "
              f"{ReportColors.BLACK_ON_HIGH}{stats['high_vulnerabilities']:>6}{ReportColors.RESET} "
              f"{ReportColors.BLACK_BOLD}Medium:{ReportColors.RESET} "
              f"{ReportColors.BLACK_ON_MEDIUM}{stats['medium_vulnerabilities']:>6}{ReportColors.RESET}")
        
        # Row 2
        print(f"{ReportColors.BLACK_BOLD}Avg CVSS:{ReportColors.RESET} "
              f"{stats['average_cvss_score']:.1f} "
              f"{ReportColors.BLACK_BOLD}Max CVSS:{ReportColors.RESET} "
              f"{stats['maximum_cvss_score']:.1f} "
              f"{ReportColors.BLACK_BOLD}RPS:{ReportColors.RESET} "
              f"{stats['requests_per_second']:.1f}")
    
    def _print_risk_distribution(self):
        """Print risk distribution chart"""
        distribution = self.stats['risk_distribution']
        
        print(f"\n{ReportColors.BLACK_UNDERLINE}RISK DISTRIBUTION{ReportColors.RESET}")
        print(f"{ReportColors.DARK_GRAY}{'─' * 80}{ReportColors.RESET}")
        
        total = distribution.get('critical', 0) + distribution.get('high', 0) + \
                distribution.get('medium', 0) + distribution.get('low', 0) + distribution.get('info', 0)
        
        if total == 0:
            print(f"{ReportColors.DARK_GRAY}No vulnerabilities found{ReportColors.RESET}")
            return
        
        # Calculate bar lengths (max 50 characters)
        max_width = 50
        crit_len = int((distribution.get('critical', 0) / total) * max_width)
        high_len = int((distribution.get('high', 0) / total) * max_width)
        med_len = int((distribution.get('medium', 0) / total) * max_width)
        low_len = int((distribution.get('low', 0) / total) * max_width)
        info_len = int((distribution.get('info', 0) / total) * max_width)
        
        # Print bars
        print(f"{ReportColors.BLACK_ON_CRITICAL}{'█' * crit_len}{ReportColors.RESET}"
              f"{ReportColors.BLACK_ON_HIGH}{'█' * high_len}{ReportColors.RESET}"
              f"{ReportColors.BLACK_ON_MEDIUM}{'█' * med_len}{ReportColors.RESET}"
              f"{ReportColors.BLACK_ON_LOW}{'█' * low_len}{ReportColors.RESET}"
              f"{ReportColors.BLACK_ON_INFO}{'█' * info_len}{ReportColors.RESET}")
        
        # Print legend
        print(f"{ReportColors.BLACK_ON_CRITICAL} Critical {distribution.get('critical', 0)} "
              f"{ReportColors.BLACK_ON_HIGH} High {distribution.get('high', 0)} "
              f"{ReportColors.BLACK_ON_MEDIUM} Medium {distribution.get('medium', 0)} "
              f"{ReportColors.BLACK_ON_LOW} Low {distribution.get('low', 0)} "
              f"{ReportColors.BLACK_ON_INFO} Info {distribution.get('info', 0)}")
    
    def _print_top_vulnerabilities(self):
        """Print top vulnerabilities"""
        vulns = sorted(self.results.vulnerabilities, 
                      key=lambda x: x.cvss_score, 
                      reverse=True)[:5]
        
        if not vulns:
            return
        
        print(f"\n{ReportColors.BLACK_UNDERLINE}TOP VULNERABILITIES{ReportColors.RESET}")
        print(f"{ReportColors.DARK_GRAY}{'─' * 80}{ReportColors.RESET}")
        
        for i, vuln in enumerate(vulns, 1):
            print(f"{ReportColors.BLACK_BOLD}{i:2}. {vuln.type:<30} "
                  f"{vuln.formatted_cvss} {ReportColors.RESET}")
            print(f"   {ReportColors.DARK_GRAY}{vuln.affected_url[:60]}...{ReportColors.RESET}")
    
    def _print_scan_metrics(self):
        """Print scan metrics"""
        meta = self.results.metadata
        
        print(f"\n{ReportColors.BLACK_UNDERLINE}SCAN METRICS{ReportColors.RESET}")
        print(f"{ReportColors.DARK_GRAY}{'─' * 40}{ReportColors.RESET}")
        
        print(f"{ReportColors.BLACK_BOLD}Target:{ReportColors.RESET} {meta.target}")
        print(f"{ReportColors.BLACK_BOLD}Start Time:{ReportColors.RESET} {meta.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{ReportColors.BLACK_BOLD}Duration:{ReportColors.RESET} {meta.duration}")
        print(f"{ReportColors.BLACK_BOLD}Total Requests:{ReportColors.RESET} {meta.total_requests:,}")
        print(f"{ReportColors.BLACK_BOLD}Scanner:{ReportColors.RESET} {meta.scanner_name} {meta.scanner_version}")
    
    def _print_timeline_chart(self):
        """Print timeline chart (ASCII)"""
        timeline = self.stats['timeline']
        
        if not timeline:
            return
        
        print(f"\n{ReportColors.BLACK_UNDERLINE}VULNERABILITY TIMELINE{ReportColors.RESET}")
        print(f"{ReportColors.DARK_GRAY}{'─' * 80}{ReportColors.RESET}")
        
        max_vulns = max(timeline.values()) if timeline.values() else 1
        
        for hour in sorted(timeline.keys()):
            count = timeline[hour]
            bar_length = int((count / max_vulns) * 30)
            print(f"{ReportColors.CHARCOAL}{hour:5} {ReportColors.BLACK_ON_HIGH}{'█' * bar_length}{ReportColors.RESET} {count}")
    
    def display_detailed_results(self, filter_level: Optional[RiskLevel] = None):
        """Display detailed vulnerability results"""
        print(f"\n{ReportColors.ON_CHARCOAL}{ReportColors.BLACK_BOLD}{' DETAILED VULNERABILITY REPORT ':{'═'}^80}{ReportColors.RESET}")
        
        vulns = self.results.vulnerabilities
        if filter_level:
            vulns = [v for v in vulns if v.severity == filter_level]
        
        if not vulns:
            print(f"\n{ReportColors.DARK_GRAY}No vulnerabilities found")
            if filter_level:
                print(f"Filter: {filter_level.value.upper()}{ReportColors.RESET}")
            return
        
        # Group by severity
        grouped_vulns = defaultdict(list)
        for vuln in vulns:
            grouped_vulns[vuln.severity].append(vuln)
        
        # Display by severity (Critical -> Info)
        for severity in [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW, RiskLevel.INFO]:
            if severity in grouped_vulns:
                self._display_severity_section(severity, grouped_vulns[severity])
    
    def _display_severity_section(self, severity: RiskLevel, vulns: List[Vulnerability]):
        """Display vulnerabilities for a specific severity"""
        print(f"\n{severity.color_code} {severity.value.upper()} ({len(vulns)}) {'─' * (70 - len(severity.value))}{ReportColors.RESET}")
        
        for i, vuln in enumerate(vulns, 1):
            print(f"\n{ReportColors.BLACK_BOLD}{i}. {vuln.type}{ReportColors.RESET}")
            print(f"   {ReportColors.DARK_GRAY}ID: {vuln.id}{ReportColors.RESET}")
            print(f"   {ReportColors.BLACK_BOLD}URL:{ReportColors.RESET} {vuln.affected_url}")
            
            if vuln.affected_parameter:
                print(f"   {ReportColors.BLACK_BOLD}Parameter:{ReportColors.RESET} {vuln.affected_parameter}")
            
            print(f"   {ReportColors.BLACK_BOLD}CVSS:{ReportColors.RESET} {vuln.formatted_cvss} ({vuln.cvss_vector})")
            
            if vuln.cve_id:
                print(f"   {ReportColors.BLACK_BOLD}CVE:{ReportColors.RESET} {vuln.cve_id}")
            
            if vuln.cwe_id:
                print(f"   {ReportColors.BLACK_BOLD}CWE:{ReportColors.RESET} {vuln.cwe_id}")
            
            # Brief description
            desc = vuln.description[:100] + "..." if len(vuln.description) > 100 else vuln.description
            print(f"   {ReportColors.DARK_GRAY}{desc}{ReportColors.RESET}")
    
    def export_report(self, report_type: ReportType, filename: Optional[str] = None, 
                     options: Optional[Dict] = None) -> str:
        """Export report in specified format"""
        if options is None:
            options = {}
        
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"security_report_{self.results.metadata.target}_{timestamp}"
        
        export_methods = {
            ReportType.CONSOLE: self._export_console,
            ReportType.HTML: self._export_html,
            ReportType.PDF: self._export_pdf,
            ReportType.JSON: self._export_json,
            ReportType.CSV: self._export_csv,
            ReportType.MARKDOWN: self._export_markdown,
            ReportType.XML: self._export_xml,
        }
        
        if report_type in export_methods:
            try:
                return export_methods[report_type](filename, options)
            except Exception as e:
                print(f"{ReportColors.BLACK_ON_RED}[!] Export failed: {e}{ReportColors.RESET}")
                return ""
        else:
            print(f"{ReportColors.BLACK_ON_RED}[!] Unsupported report type: {report_type}{ReportColors.RESET}")
            return ""
    
    def _export_console(self, filename: str, options: Dict) -> str:
        """Export to console (pretty print)"""
        self.display_dashboard()
        self.display_detailed_results()
        return "console"
    
    def _export_html(self, filename: str, options: Dict) -> str:
        """Export to HTML report"""
        full_path = f"{filename}.html"
        
        # Generate HTML using Jinja2 template
        template_str = self._get_html_template()
        template = jinja2.Template(template_str)
        
        # Prepare data for template
        context = {
            'results': self.results,
            'stats': self.stats,
            'generation_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'risk_colors': {
                'critical': '#ff4444',
                'high': '#ff8800',
                'medium': '#ffcc00',
                'low': '#00cc44',
                'info': '#0099cc',
            }
        }
        
        html_content = template.render(**context)
        
        # Write to file
        with open(full_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"{ReportColors.BLACK_ON_GREEN}[✓] HTML report saved to: {full_path}{ReportColors.RESET}")
        
        # Open in browser if requested
        if options.get('open_browser', False):
            webbrowser.open(f'file://{os.path.abspath(full_path)}')
        
        return full_path
    
    def _get_html_template(self) -> str:
        """Get HTML template"""
        return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - {{ results.metadata.target }}</title>
    <style>
        :root {
            --critical: {{ risk_colors.critical }};
            --high: {{ risk_colors.high }};
            --medium: {{ risk_colors.medium }};
            --low: {{ risk_colors.low }};
            --info: {{ risk_colors.info }};
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }
        
        .header {
            background: linear-gradient(135deg, #2c3e50 0%, #4a6491 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            margin: 0;
            font-size: 2.5em;
        }
        
        .header .subtitle {
            font-size: 1.2em;
            opacity: 0.9;
        }
        
        .card {
            background: white;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            text-align: center;
            padding: 20px;
            border-radius: 8px;
            color: white;
        }
        
        .stat-card.critical { background: var(--critical); }
        .stat-card.high { background: var(--high); }
        .stat-card.medium { background: var(--medium); }
        .stat-card.low { background: var(--low); }
        .stat-card.info { background: var(--info); }
        
        .stat-card .value {
            font-size: 2.5em;
            font-weight: bold;
            margin: 10px 0;
        }
        
        .vulnerability {
            border-left: 4px solid #ddd;
            padding: 15px;
            margin: 15px 0;
            transition: all 0.3s ease;
        }
        
        .vulnerability:hover {
            transform: translateX(5px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }
        
        .vulnerability.critical { border-left-color: var(--critical); }
        .vulnerability.high { border-left-color: var(--high); }
        .vulnerability.medium { border-left-color: var(--medium); }
        .vulnerability.low { border-left-color: var(--low); }
        .vulnerability.info { border-left-color: var(--info); }
        
        .risk-badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 20px;
            color: white;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        .badge-critical { background: var(--critical); }
        .badge-high { background: var(--high); }
        .badge-medium { background: var(--medium); }
        .badge-low { background: var(--low); }
        .badge-info { background: var(--info); }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        
        th {
            background: #f8f9fa;
            font-weight: bold;
        }
        
        .footer {
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
            border-top: 1px solid #ddd;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Scan Report</h1>
        <div class="subtitle">
            Target: {{ results.metadata.target }} | 
            Date: {{ generation_date }} | 
            Scanner: {{ results.metadata.scanner_name }} v{{ results.metadata.scanner_version }}
        </div>
    </div>
    
    <div class="stats-grid">
        <div class="stat-card critical">
            <div class="label">Critical</div>
            <div class="value">{{ stats.risk_distribution.critical }}</div>
            <div class="percentage">{{ stats.risk_distribution.critical_percentage }}%</div>
        </div>
        <div class="stat-card high">
            <div class="label">High</div>
            <div class="value">{{ stats.risk_distribution.high }}</div>
            <div class="percentage">{{ stats.risk_distribution.high_percentage }}%</div>
        </div>
        <div class="stat-card medium">
            <div class="label">Medium</div>
            <div class="value">{{ stats.risk_distribution.medium }}</div>
            <div class="percentage">{{ stats.risk_distribution.medium_percentage }}%</div>
        </div>
        <div class="stat-card low">
            <div class="label">Low</div>
            <div class="value">{{ stats.risk_distribution.low }}</div>
            <div class="percentage">{{ stats.risk_distribution.low_percentage }}%</div>
        </div>
    </div>
    
    <div class="card">
        <h2>Executive Summary</h2>
        <p>
            This security assessment discovered <strong>{{ stats.overview.total_vulnerabilities }}</strong> 
            vulnerabilities in the target application. The most critical issues require immediate attention.
        </p>
        
        <h3>Key Findings</h3>
        <ul>
            {% if stats.overview.critical_vulnerabilities > 0 %}
            <li><strong>{{ stats.overview.critical_vulnerabilities }} Critical</strong> vulnerabilities that could lead to complete system compromise</li>
            {% endif %}
            {% if stats.overview.high_vulnerabilities > 0 %}
            <li><strong>{{ stats.overview.high_vulnerabilities }} High</strong> risk vulnerabilities that could lead to significant data loss</li>
            {% endif %}
            <li>Overall risk score: <strong>{{ stats.overview.average_cvss_score|round(1) }}/10</strong></li>
        </ul>
    </div>
    
    <div class="card">
        <h2>Detailed Findings</h2>
        {% for vuln in results.vulnerabilities %}
        <div class="vulnerability {{ vuln.severity.value }}">
            <h3>
                <span class="risk-badge badge-{{ vuln.severity.value }}">{{ vuln.severity.value|upper }}</span>
                {{ vuln.type }}
            </h3>
            <p><strong>URL:</strong> {{ vuln.affected_url }}</p>
            {% if vuln.affected_parameter %}
            <p><strong>Parameter:</strong> {{ vuln.affected_parameter }}</p>
            {% endif %}
            <p><strong>CVSS Score:</strong> {{ vuln.cvss_score }}/10 ({{ vuln.cvss_vector }})</p>
            <p><strong>Description:</strong> {{ vuln.description }}</p>
            <p><strong>Impact:</strong> {{ vuln.impact }}</p>
            <p><strong>Recommendation:</strong> {{ vuln.remediation }}</p>
            {% if vuln.cve_id %}
            <p><strong>CVE:</strong> {{ vuln.cve_id }}</p>
            {% endif %}
        </div>
        {% endfor %}
    </div>
    
    <div class="card">
        <h2>Technical Details</h2>
        <table>
            <tr>
                <th>Scan Start Time</th>
                <td>{{ results.metadata.start_time.strftime('%Y-%m-%d %H:%M:%S') }}</td>
            </tr>
            <tr>
                <th>Scan Duration</th>
                <td>{{ results.metadata.duration }}</td>
            </tr>
            <tr>
                <th>Total Requests</th>
                <td>{{ results.metadata.total_requests }}</td>
            </tr>
            <tr>
                <th>Requests per Second</th>
                <td>{{ stats.overview.requests_per_second }}</td>
            </tr>
        </table>
    </div>
    
    <div class="footer">
        <p>Report generated by {{ results.metadata.scanner_name }} v{{ results.metadata.scanner_version }}</p>
        <p>Confidential - For authorized personnel only</p>
    </div>
</body>
</html>'''
    
    def _export_pdf(self, filename: str, options: Dict) -> str:
        """Export to PDF report using ReportLab"""
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        except ImportError:
            print(f"{ReportColors.BLACK_ON_RED}[!] ReportLab not installed. Install with: pip install reportlab{ReportColors.RESET}")
            return ""
        
        full_path = f"{filename}.pdf"
        
        # Create PDF document
        doc = SimpleDocTemplate(full_path, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.HexColor('#2c3e50')
        )
        
        # Title
        story.append(Paragraph("Security Scan Report", title_style))
        
        # Metadata table
        meta_data = [
            ["Target:", self.results.metadata.target],
            ["Scan Date:", self.results.metadata.start_time.strftime("%Y-%m-%d %H:%M:%S")],
            ["Duration:", str(self.results.metadata.duration)],
            ["Scanner:", f"{self.results.metadata.scanner_name} v{self.results.metadata.scanner_version}"],
            ["Total Vulnerabilities:", str(len(self.results.vulnerabilities))],
        ]
        
        meta_table = Table(meta_data, colWidths=[100, 400])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#ecf0f1')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
        ]))
        
        story.append(meta_table)
        story.append(Spacer(1, 20))
        
        # Vulnerability table
        if self.results.vulnerabilities:
            story.append(Paragraph("Vulnerability Summary", styles['Heading2']))
            
            vuln_data = [["Severity", "Type", "URL", "CVSS"]]
            
            for vuln in self.results.vulnerabilities[:50]:  # Limit to 50 for PDF
                vuln_data.append([
                    vuln.severity.value.upper(),
                    vuln.type,
                    vuln.affected_url[:50] + "..." if len(vuln.affected_url) > 50 else vuln.affected_url,
                    str(vuln.cvss_score)
                ])
            
            vuln_table = Table(vuln_data, colWidths=[60, 100, 200, 50])
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            
            story.append(vuln_table)
        
        # Build PDF
        doc.build(story)
        
        print(f"{ReportColors.BLACK_ON_GREEN}[✓] PDF report saved to: {full_path}{ReportColors.RESET}")
        return full_path
    
    def _export_json(self, filename: str, options: Dict) -> str:
        """Export to JSON format"""
        full_path = f"{filename}.json"
        
        # Convert results to serializable format
        result_dict = {
            'metadata': asdict(self.results.metadata),
            'vulnerabilities': [asdict(v) for v in self.results.vulnerabilities],
            'statistics': self.stats,
            'summary': self.results.summary,
            'recommendations': self.results.recommendations,
            'generation_date': datetime.now().isoformat(),
        }
        
        # Convert datetime objects to strings
        def json_serializer(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            if isinstance(obj, timedelta):
                return str(obj)
            if isinstance(obj, RiskLevel):
                return obj.value
            raise TypeError(f"Type {type(obj)} not serializable")
        
        with open(full_path, 'w') as f:
            json.dump(result_dict, f, indent=2, default=json_serializer)
        
        print(f"{ReportColors.BLACK_ON_GREEN}[✓] JSON report saved to: {full_path}{ReportColors.RESET}")
        return full_path
    
    def _export_csv(self, filename: str, options: Dict) -> str:
        """Export to CSV format"""
        full_path = f"{filename}.csv"
        
        with open(full_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow([
                'Severity', 'Type', 'URL', 'Parameter', 'CVSS Score',
                'CVSS Vector', 'CVE ID', 'CWE ID', 'Description',
                'Impact', 'Remediation', 'Discovery Date'
            ])
            
            # Write vulnerability data
            for vuln in self.results.vulnerabilities:
                writer.writerow([
                    vuln.severity.value.upper(),
                    vuln.type,
                    vuln.affected_url,
                    vuln.affected_parameter or '',
                    vuln.cvss_score,
                    vuln.cvss_vector,
                    vuln.cve_id or '',
                    vuln.cwe_id or '',
                    vuln.description[:100],
                    vuln.impact[:100],
                    vuln.remediation[:100],
                    vuln.discovery_date.isoformat()
                ])
        
        print(f"{ReportColors.BLACK_ON_GREEN}[✓] CSV report saved to: {full_path}{ReportColors.RESET}")
        return full_path
    
    def _export_markdown(self, filename: str, options: Dict) -> str:
        """Export to Markdown format"""
        full_path = f"{filename}.md"
        
        md_content = f"""# Security Scan Report

## Executive Summary

**Target:** {self.results.metadata.target}
**Scan Date:** {self.results.metadata.start_time.strftime('%Y-%m-%d %H:%M:%S')}
**Duration:** {self.results.metadata.duration}
**Scanner:** {self.results.metadata.scanner_name} v{self.results.metadata.scanner_version}

### Key Statistics

- **Total Vulnerabilities:** {len(self.results.vulnerabilities)}
- **Critical:** {self.stats['overview']['critical_vulnerabilities']}
- **High:** {self.stats['overview']['high_vulnerabilities']}
- **Medium:** {self.stats['overview']['medium_vulnerabilities']}
- **Low:** {self.stats['overview']['low_vulnerabilities']}
- **Average CVSS:** {self.stats['overview']['average_cvss_score']:.1f}/10

## Detailed Findings

"""
        
        # Group by severity
        grouped_vulns = defaultdict(list)
        for vuln in self.results.vulnerabilities:
            grouped_vulns[vuln.severity].append(vuln)
        
        for severity in [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW, RiskLevel.INFO]:
            if severity in grouped_vulns:
                md_content += f"\n### {severity.value.upper()} Risk ({len(grouped_vulns[severity])})\n\n"
                
                for vuln in grouped_vulns[severity]:
                    md_content += f"#### {vuln.type}\n\n"
                    md_content += f"- **URL:** {vuln.affected_url}\n"
                    if vuln.affected_parameter:
                        md_content += f"- **Parameter:** {vuln.affected_parameter}\n"
                    md_content += f"- **CVSS:** {vuln.cvss_score}/10 ({vuln.cvss_vector})\n"
                    if vuln.cve_id:
                        md_content += f"- **CVE:** {vuln.cve_id}\n"
                    if vuln.cwe_id:
                        md_content += f"- **CWE:** {vuln.cwe_id}\n"
                    md_content += f"- **Description:** {vuln.description}\n"
                    md_content += f"- **Impact:** {vuln.impact}\n"
                    md_content += f"- **Remediation:** {vuln.remediation}\n\n"
        
        with open(full_path, 'w', encoding='utf-8') as f:
            f.write(md_content)
        
        print(f"{ReportColors.BLACK_ON_GREEN}[✓] Markdown report saved to: {full_path}{ReportColors.RESET}")
        return full_path
    
    def _export_xml(self, filename: str, options: Dict) -> str:
        """Export to XML format"""
        full_path = f"{filename}.xml"
        
        root = ET.Element("SecurityScanReport")
        
        # Metadata
        meta_elem = ET.SubElement(root, "Metadata")
        ET.SubElement(meta_elem, "Target").text = self.results.metadata.target
        ET.SubElement(meta_elem, "StartTime").text = self.results.metadata.start_time.isoformat()
        ET.SubElement(meta_elem, "Duration").text = str(self.results.metadata.duration)
        ET.SubElement(meta_elem, "Scanner").text = self.results.metadata.scanner_name
        ET.SubElement(meta_elem, "Version").text = self.results.metadata.scanner_version
        
        # Statistics
        stats_elem = ET.SubElement(root, "Statistics")
        for key, value in self.stats['overview'].items():
            ET.SubElement(stats_elem, key.replace('_', '')).text = str(value)
        
        # Vulnerabilities
        vulns_elem = ET.SubElement(root, "Vulnerabilities")
        for vuln in self.results.vulnerabilities:
            vuln_elem = ET.SubElement(vulns_elem, "Vulnerability")
            ET.SubElement(vuln_elem, "ID").text = vuln.id
            ET.SubElement(vuln_elem, "Type").text = vuln.type
            ET.SubElement(vuln_elem, "Severity").text = vuln.severity.value
            ET.SubElement(vuln_elem, "URL").text = vuln.affected_url
            ET.SubElement(vuln_elem, "CVSS").text = str(vuln.cvss_score)
            ET.SubElement(vuln_elem, "Description").text = vuln.description
        
        # Write XML file
        tree = ET.ElementTree(root)
        tree.write(full_path, encoding='utf-8', xml_declaration=True)
        
        print(f"{ReportColors.BLACK_ON_GREEN}[✓] XML report saved to: {full_path}{ReportColors.RESET}")
        return full_path
    
    def generate_executive_summary(self) -> str:
        """Generate executive summary report"""
        summary = f"""
{ReportColors.ON_CHARCOAL}{ReportColors.BLACK_BOLD}{' EXECUTIVE SUMMARY REPORT ':{'═'}^80}{ReportColors.RESET}

{ReportColors.BLACK_BOLD}TO: Management & Security Team
FROM: Security Operations
DATE: {datetime.now().strftime('%Y-%m-%d')}
SUBJECT: Security Assessment of {self.results.metadata.target}

{ReportColors.BLACK_UNDERLINE}1. EXECUTIVE OVERVIEW{ReportColors.RESET}

A comprehensive security assessment was conducted on {self.results.metadata.target} 
from {self.results.metadata.start_time.strftime('%Y-%m-%d %H:%M')} to 
{self.results.metadata.end_time.strftime('%Y-%m-%d %H:%M')}.

{ReportColors.BLACK_UNDERLINE}2. KEY FINDINGS{ReportColors.RESET}

• Total Vulnerabilities Identified: {len(self.results.vulnerabilities)}
• Critical Risk Findings: {self.stats['overview']['critical_vulnerabilities']}
• High Risk Findings: {self.stats['overview']['high_vulnerabilities']}
• Overall Risk Score: {self.stats['overview']['average_cvss_score']:.1f}/10

{ReportColors.BLACK_UNDERLINE}3. RISK ASSESSMENT{ReportColors.RESET}

The assessment reveals {self.stats['overview']['critical_vulnerabilities']} critical 
vulnerabilities that require immediate remediation. These issues pose significant 
risk to the confidentiality, integrity, and availability of the application.

{ReportColors.BLACK_UNDERLINE}4. RECOMMENDATIONS{ReportColors.RESET}

1. Address critical vulnerabilities within 24-48 hours
2. Implement regular security scanning in development pipeline
3. Conduct developer security awareness training
4. Establish vulnerability management process

{ReportColors.BLACK_UNDERLINE}5. NEXT STEPS{ReportColors.RESET}

• Schedule remediation planning session
• Assign priority-based mitigation tasks
• Establish verification testing schedule
• Plan for follow-up assessment in 30 days

{ReportColors.ON_CHARCOAL}{ReportColors.BLACK_BOLD}{'═' * 80}{ReportColors.RESET}
        """
        return summary
    
    def create_remediation_plan(self) -> str:
        """Create detailed remediation plan"""
        plan = f"""
{ReportColors.ON_CHARCOAL}{ReportColors.BLACK_BOLD}{' REMEDIATION ACTION PLAN ':{'═'}^80}{ReportColors.RESET}

{ReportColors.BLACK_BOLD}Target: {self.results.metadata.target}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

{ReportColors.BLACK_UNDERLINE}PRIORITY CLASSIFICATION{ReportColors.RESET}

{ReportColors.BLACK_ON_CRITICAL} P1 - Critical: Remediate within 24-48 hours {ReportColors.RESET}
{ReportColors.BLACK_ON_HIGH} P2 - High: Remediate within 1 week {ReportColors.RESET}
{ReportColors.BLACK_ON_MEDIUM} P3 - Medium: Remediate within 2 weeks {ReportColors.RESET}
{ReportColors.BLACK_ON_LOW} P4 - Low: Remediate within 1 month {ReportColors.RESET}

{ReportColors.BLACK_UNDERLINE}ACTION ITEMS{ReportColors.RESET}
"""
        
        # Group vulnerabilities by priority
        for severity, priority in [
            (RiskLevel.CRITICAL, "P1"),
            (RiskLevel.HIGH, "P2"),
            (RiskLevel.MEDIUM, "P3"),
            (RiskLevel.LOW, "P4")
        ]:
            vulns = [v for v in self.results.vulnerabilities if v.severity == severity]
            if vulns:
                plan += f"\n{severity.color_code} {priority} - {severity.value.upper()} PRIORITY ({len(vulns)}) {ReportColors.RESET}\n"
                
                for vuln in vulns:
                    plan += f"\n{ReportColors.BLACK_BOLD}• {vuln.type}{ReportColors.RESET}"
                    plan += f"\n  URL: {vuln.affected_url}"
                    plan += f"\n  Action: {vuln.remediation[:100]}..."
                    plan += f"\n  Owner: TBD | Due: TBD | Status: Pending\n"
        
        plan += f"""
{ReportColors.BLACK_UNDERLINE}REMEDIATION TRACKING{ReportColors.RESET}

Total Actions: {len(self.results.vulnerabilities)}
Estimated Effort: {len(self.results.vulnerabilities) * 2} hours
Target Completion Date: {(datetime.now() + timedelta(days=14)).strftime('%Y-%m-%d')}

{ReportColors.ON_CHARCOAL}{ReportColors.BLACK_BOLD}{'═' * 80}{ReportColors.RESET}
        """
        return plan

# Export main classes
__all__ = [
    'AdvancedResultsDisplay',
    'Vulnerability',
    'ScanResults',
    'ScanMetadata',
    'RiskLevel',
    'ReportType',
    'ReportColors',
    'StatisticsGenerator',
]

# Example usage
if __name__ == "__main__":
    print(f"{ReportColors.ON_CHARCOAL}{ReportColors.BLACK_BOLD}{' TESTING ADVANCED RESULTS DISPLAY ':{'═'}^80}{ReportColors.RESET}")
    
    # Create sample data
    sample_results = ScanResults(
        metadata=ScanMetadata(
            target="https://example.com",
            start_time=datetime.now() - timedelta(hours=1),
            end_time=datetime.now(),
            duration=timedelta(hours=1),
            scanner_version="2.5.0",
            scanner_name="Advanced Security Scanner",
            scan_type="Comprehensive Web Application Scan",
            parameters={"depth": "deep", "threads": 10},
            total_requests=1250,
        ),
        vulnerabilities=[
            Vulnerability(
                id="SQLI-001",
                type="SQL Injection",
                severity=RiskLevel.CRITICAL,
                title="Blind SQL Injection in Login Form",
                description="SQL injection vulnerability in the login form allows attackers to extract database information",
                impact="Full database compromise, credential theft",
                remediation="Implement parameterized queries and input validation",
                cvss_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                affected_url="https://example.com/login",
                affected_parameter="username",
                payload="admin' OR '1'='1",
                cwe_id="CWE-89",
                cve_id="CVE-2023-12345",
            ),
            Vulnerability(
                id="XSS-001",
                type="Cross-Site Scripting",
                severity=RiskLevel.HIGH,
                title="Reflected XSS in Search Parameter",
                description="Reflected XSS vulnerability in search functionality",
                impact="Session hijacking, credential theft",
                remediation="Implement output encoding and Content Security Policy",
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
                affected_url="https://example.com/search",
                affected_parameter="q",
                payload="<script>alert('XSS')</script>",
                cwe_id="CWE-79",
            ),
        ],
        statistics={},
        summary={},
        recommendations=[
            "Implement Web Application Firewall",
            "Conduct secure code training",
            "Establish vulnerability management process",
        ],
    )
    
    # Initialize display
    display = AdvancedResultsDisplay(sample_results)
    
    # Display dashboard
    display.display_dashboard()
    
    # Generate executive summary
    print(display.generate_executive_summary())
    
    # Generate remediation plan
    print(display.create_remediation_plan())
    
    # Export to different formats
    print(f"\n{ReportColors.DARK_GRAY_BOLD}[*] Exporting reports...{ReportColors.RESET}")
    
    # Export JSON
    json_file = display.export_report(ReportType.JSON, "test_report")
    
    # Export HTML
    html_file = display.export_report(ReportType.HTML, "test_report", {"open_browser": False})
    
    # Export Markdown
    md_file = display.export_report(ReportType.MARKDOWN, "test_report")
    
    print(f"\n{ReportColors.BLACK_ON_CHARCOAL}{' TEST COMPLETE ':{'═'}^80}{ReportColors.RESET}")