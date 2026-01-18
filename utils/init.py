"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    𝗔𝗗𝗩𝗔𝗡𝗖𝗘𝗗 𝗦𝗖𝗔𝗡𝗡𝗘𝗥 𝗨𝗧𝗜𝗟𝗜𝗧𝗜𝗘𝗦                      ║
║                   𝘾𝙤𝙢𝙥𝙧𝙚𝙝𝙚𝙣𝙨𝙞𝙫𝙚 𝙎𝙚𝙘𝙪𝙧𝙞𝙩𝙮 𝙏𝙤𝙤𝙡𝙠𝙞𝙩                       ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import inspect
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum, auto
from datetime import datetime
import importlib.util
from colorama import Fore, Back, Style, init

# Initialize colorama for cross-platform colored output
init(autoreset=True)

class TextColors:
    """Enhanced black and gray text colors for maximum contrast"""
    
    # Black Text Variations
    BLACK = '\033[30m'
    BLACK_BOLD = '\033[1;30m'
    BLACK_ITALIC = '\033[3;30m'
    BLACK_UNDERLINE = '\033[4;30m'
    BLACK_BLINK = '\033[5;30m'
    BLACK_REVERSE = '\033[7;30m'
    BLACK_INVISIBLE = '\033[8;30m'
    BLACK_STRIKETHROUGH = '\033[9;30m'
    
    # Gray Scale Text
    DARK_GRAY = '\033[90m'
    DARK_GRAY_BOLD = '\033[1;90m'
    LIGHT_GRAY = '\033[37m'
    SILVER = '\033[38;5;7m'
    DIM_GRAY = '\033[38;5;8m'
    CHARCOAL = '\033[38;5;236m'
    GUNMETAL = '\033[38;5;238m'
    
    # Black Backgrounds
    ON_BLACK = '\033[40m'
    ON_DARK_GRAY = '\033[100m'
    ON_GRAY = '\033[47m'
    ON_CHARCOAL = '\033[48;5;236m'
    
    # Gradient Blacks
    BLACK_GRADIENT_1 = '\033[38;5;232m'  # Near black
    BLACK_GRADIENT_2 = '\033[38;5;233m'
    BLACK_GRADIENT_3 = '\033[38;5;234m'
    BLACK_GRADIENT_4 = '\033[38;5;235m'
    
    # Utility Colors
    DEEP_BLUE = '\033[38;5;18m'
    NAVY = '\033[38;5;17m'
    MIDNIGHT = '\033[38;5;16m'
    
    # Reset
    RESET = '\033[0m'

class ModuleCategory(Enum):
    """Categories for scanner modules"""
    CORE = auto()
    ENCODING = auto()
    NETWORK = auto()
    RECON = auto()
    SECURITY = auto()
    EXPLOITATION = auto()
    UTILITY = auto()
    VISUALIZATION = auto()
    AI_ML = auto()
    CRYPTO = auto()
    WEB = auto()
    MOBILE = auto()
    CLOUD = auto()
    IOT = auto()
    FORENSIC = auto()
    REPORTING = auto()

@dataclass
class ModuleInfo:
    """Detailed information about a utility module"""
    name: str
    category: ModuleCategory
    description: str
    author: str = "Advanced Scanner Team"
    version: str = "2.0.0"
    dependencies: List[str] = field(default_factory=list)
    required_packages: List[str] = field(default_factory=list)
    is_active: bool = True
    is_experimental: bool = False
    risk_level: int = 0  # 0-10, where 0 is safe, 10 is dangerous
    last_updated: datetime = field(default_factory=datetime.now)
    tags: Set[str] = field(default_factory=set)
    aliases: List[str] = field(default_factory=list)
    examples: List[str] = field(default_factory=list)

class ModuleRegistry:
    """Central registry for all utility modules"""
    
    def __init__(self):
        self.modules: Dict[str, ModuleInfo] = {}
        self._initialize_modules()
    
    def _initialize_modules(self):
        """Initialize all utility modules with detailed information"""
        
        # Encoding Modules
        self.modules['encoding'] = ModuleInfo(
            name="encoding",
            category=ModuleCategory.ENCODING,
            description="Advanced encoding/decoding utilities (Base64, Hex, URL, HTML, Binary, ROT13, Morse, etc.)",
            dependencies=["base64", "urllib", "binascii", "html"],
            required_packages=["colorama"],
            tags={"encoding", "decoding", "crypto", "transformation"},
            aliases=["encode", "decode", "crypto_utils"],
            examples=[
                "encoding.base64_encode('secret')",
                "encoding.url_encode('test param')",
                "encoding.generate_variations('<script>alert(1)</script>')"
            ]
        )
        
        # Proxy Management
        self.modules['proxy_manager'] = ModuleInfo(
            name="proxy_manager",
            category=ModuleCategory.NETWORK,
            description="Advanced proxy rotation, validation, and management with SOCKS/HTTP/HTTPS support",
            dependencies=["requests", "socket"],
            required_packages=["socks", "proxy-tools"],
            tags={"proxy", "network", "anonymity", "rotation"},
            aliases=["proxy", "proxy_handler", "anonymizer"],
            examples=[
                "proxy_manager.rotate_proxies()",
                "proxy_manager.validate_proxy('http://proxy:8080')",
                "proxy_manager.get_random_proxy()"
            ]
        )
        
        # Request Wrapper
        self.modules['request_wrapper'] = ModuleInfo(
            name="request_wrapper",
            category=ModuleCategory.NETWORK,
            description="Intelligent HTTP request handling with retries, timeouts, headers manipulation, and anti-detection",
            dependencies=["requests", "time"],
            required_packages=["aiohttp", "curl_cffi"],
            risk_level=2,
            tags={"http", "requests", "network", "scraping"},
            aliases=["http_client", "requester", "scraper"],
            examples=[
                "request_wrapper.get(url, use_proxy=True)",
                "request_wrapper.post(url, data, retries=3)",
                "request_wrapper.spoof_headers()"
            ]
        )
        
        # Subdomain Finder
        self.modules['subdomain_finder'] = ModuleInfo(
            name="subdomain_finder",
            category=ModuleCategory.RECON,
            description="Comprehensive subdomain enumeration using multiple techniques (DNS, web scraping, APIs, certificates)",
            dependencies=["dns.resolver", "requests"],
            required_packages=["dnspython", "tldextract"],
            tags={"recon", "subdomain", "enumeration", "dns"},
            aliases=["subdomain_enum", "domain_scanner", "dns_bruteforce"],
            examples=[
                "subdomain_finder.enumerate('example.com')",
                "subdomain_finder.bruteforce('target.com', wordlist)",
                "subdomain_finder.certificate_transparency('org')"
            ]
        )
        
        # Additional essential modules
        self._add_essential_modules()
        self._add_specialized_modules()
    
    def _add_essential_modules(self):
        """Add essential utility modules"""
        
        essential_modules = [
            ModuleInfo(
                name="vulnerability_scanner",
                category=ModuleCategory.SECURITY,
                description="Automated vulnerability detection and assessment engine",
                required_packages=["vulners", "cve_search"],
                risk_level=3,
                tags={"vulnerability", "scanning", "security", "assessment"}
            ),
            ModuleInfo(
                name="payload_generator",
                category=ModuleCategory.EXPLOITATION,
                description="Generate exploitation payloads for various vulnerabilities",
                required_packages=["metasploit", "payloadsallthethings"],
                risk_level=8,
                tags={"payload", "exploitation", "pentest", "malicious"},
                is_experimental=True
            ),
            ModuleInfo(
                name="report_generator",
                category=ModuleCategory.REPORTING,
                description="Generate professional security reports in multiple formats",
                required_packages=["jinja2", "reportlab", "pandas"],
                tags={"report", "documentation", "export", "professional"}
            ),
            ModuleInfo(
                name="log_analyzer",
                category=ModuleCategory.FORENSIC,
                description="Advanced log analysis and anomaly detection",
                required_packages=["logparser", "pandas", "numpy"],
                tags={"logs", "analysis", "forensic", "siem"}
            ),
            ModuleInfo(
                name="ai_assistant",
                category=ModuleCategory.AI_ML,
                description="AI-powered security analysis and recommendations",
                required_packages=["openai", "transformers", "torch"],
                is_experimental=True,
                tags={"ai", "machine_learning", "analysis", "intelligence"}
            )
        ]
        
        for module in essential_modules:
            self.modules[module.name] = module
    
    def _add_specialized_modules(self):
        """Add specialized utility modules"""
        
        specialized_modules = [
            # Network Modules
            ("port_scanner", ModuleCategory.NETWORK, "Intelligent port scanning with service detection"),
            ("packet_sniffer", ModuleCategory.NETWORK, "Packet capture and analysis"),
            ("dns_enum", ModuleCategory.NETWORK, "DNS enumeration and record collection"),
            
            # Web Security
            ("xss_scanner", ModuleCategory.WEB, "Cross-Site Scripting vulnerability detection"),
            ("sql_injection", ModuleCategory.WEB, "SQL Injection testing and exploitation"),
            ("csrf_detector", ModuleCategory.WEB, "CSRF vulnerability detection"),
            
            # Cryptography
            ("crypto_breaker", ModuleCategory.CRYPTO, "Cryptographic analysis and cipher breaking"),
            ("hash_identifier", ModuleCategory.CRYPTO, "Hash type identification and cracking"),
            
            # Mobile Security
            ("apk_analyzer", ModuleCategory.MOBILE, "Android APK analysis and reverse engineering"),
            ("ios_scanner", ModuleCategory.MOBILE, "iOS application security assessment"),
            
            # Cloud Security
            ("aws_scanner", ModuleCategory.CLOUD, "AWS security misconfiguration scanner"),
            ("azure_auditor", ModuleCategory.CLOUD, "Microsoft Azure security auditing"),
            
            # IoT Security
            ("iot_discover", ModuleCategory.IOT, "IoT device discovery and fingerprinting"),
            ("firmware_analyzer", ModuleCategory.IOT, "Firmware analysis and reverse engineering"),
            
            # Forensics
            ("memory_analyzer", ModuleCategory.FORENSIC, "Memory dump analysis and artifact extraction"),
            ("disk_forensics", ModuleCategory.FORENSIC, "Disk image forensic analysis"),
            
            # Visualization
            ("network_mapper", ModuleCategory.VISUALIZATION, "Network topology mapping and visualization"),
            ("attack_graph", ModuleCategory.VISUALIZATION, "Attack path visualization and modeling"),
        ]
        
        for name, category, desc in specialized_modules:
            self.modules[name] = ModuleInfo(
                name=name,
                category=category,
                description=desc,
                tags={cat.name.lower() for cat in ModuleCategory}
            )

class ModuleLoader:
    """Dynamic module loading and management system"""
    
    def __init__(self, modules_dir: str = "modules"):
        self.registry = ModuleRegistry()
        self.modules_dir = Path(modules_dir)
        self.loaded_modules: Dict[str, Any] = {}
        self.failed_modules: Dict[str, str] = {}
        
    def load_module(self, module_name: str) -> bool:
        """Dynamically load a module by name"""
        if module_name not in self.registry.modules:
            print(f"{TextColors.BLACK_ON_RED}Module '{module_name}' not found{TextColors.RESET}")
            return False
        
        module_info = self.registry.modules[module_name]
        
        # Check dependencies
        if not self._check_dependencies(module_info):
            print(f"{TextColors.BLACK_ON_YELLOW}Missing dependencies for {module_name}{TextColors.RESET}")
            return False
        
        try:
            # Try to import the module
            module_path = self.modules_dir / f"{module_name}.py"
            if module_path.exists():
                spec = importlib.util.spec_from_file_location(module_name, module_path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                self.loaded_modules[module_name] = module
                
                print(f"{TextColors.BLACK_ON_GREEN}✓ Loaded module: {module_name}{TextColors.RESET}")
                return True
            else:
                # Module file doesn't exist, create a stub
                self._create_module_stub(module_name, module_info)
                self.loaded_modules[module_name] = None  # Placeholder
                print(f"{TextColors.BLACK_ON_CYAN}⚠ Created stub for module: {module_name}{TextColors.RESET}")
                return True
                
        except Exception as e:
            self.failed_modules[module_name] = str(e)
            print(f"{TextColors.BLACK_ON_RED}✗ Failed to load {module_name}: {e}{TextColors.RESET}")
            return False
    
    def _check_dependencies(self, module_info: ModuleInfo) -> bool:
        """Check if all required packages are installed"""
        missing = []
        for package in module_info.required_packages:
            try:
                __import__(package.replace('-', '_'))
            except ImportError:
                missing.append(package)
        
        if missing:
            print(f"{TextColors.BLACK_BOLD}Missing packages: {', '.join(missing)}{TextColors.RESET}")
            return False
        return True
    
    def _create_module_stub(self, module_name: str, module_info: ModuleInfo):
        """Create a stub module file if it doesn't exist"""
        stub_content = f'''"""
{module_info.description}

Module: {module_name}
Category: {module_info.category.name}
Version: {module_info.version}
Author: {module_info.author}
"""

class {module_name.title().replace('_', '')}:
    """Implementation of {module_name} module"""
    
    def __init__(self):
        self.name = "{module_name}"
        self.version = "{module_info.version}"
    
    def example_method(self):
        """Example method - implement your functionality here"""
        return f"{{self.name}} module is working!"
    
    # TODO: Implement module functionality
    # Add your methods and classes here

# Export the main class
{module_name} = {module_name.title().replace('_', '')}()

if __name__ == "__main__":
    # Test the module
    module = {module_name.title().replace('_', '')}()
    print(module.example_method())
'''
        
        module_path = self.modules_dir / f"{module_name}.py"
        module_path.parent.mkdir(exist_ok=True)
        module_path.write_text(stub_content, encoding='utf-8')

class ModuleVisualizer:
    """Visualization utilities for modules"""
    
    @staticmethod
    def print_module_banner(module_name: str):
        """Print a decorative banner for a module"""
        module_info = ModuleRegistry().modules.get(module_name)
        if not module_info:
            return
        
        banner = f"""
{TextColors.ON_CHARCOAL}{TextColors.BLACK_BOLD}{'═' * 80}{TextColors.RESET}
{TextColors.ON_CHARCOAL}{TextColors.BLACK_UNDERLINE}{'MODULE:'.center(80)}{TextColors.RESET}
{TextColors.ON_CHARCOAL}{TextColors.BLACK_BOLD}{module_name.upper().center(80)}{TextColors.RESET}
{TextColors.ON_CHARCOAL}{TextColors.BLACK_ITALIC}{module_info.description.center(80)}{TextColors.RESET}
{TextColors.ON_CHARCOAL}{TextColors.BLACK_BOLD}{'═' * 80}{TextColors.RESET}
        """
        print(banner)
    
    @staticmethod
    def print_category_tree():
        """Print all modules organized by category"""
        registry = ModuleRegistry()
        
        print(f"\n{TextColors.BLACK_BOLD}{'ADVANCED SCANNER MODULE CATALOG':^80}{TextColors.RESET}")
        print(f"{TextColors.BLACK_GRADIENT_1}{'━' * 80}{TextColors.RESET}")
        
        for category in ModuleCategory:
            modules_in_category = [
                name for name, info in registry.modules.items() 
                if info.category == category
            ]
            
            if modules_in_category:
                print(f"\n{TextColors.BLACK_UNDERLINE}{category.name.replace('_', ' ').title():<30}{TextColors.RESET}")
                print(f"{TextColors.DARK_GRAY}{'─' * 30}{TextColors.RESET}")
                
                for module in modules_in_category:
                    info = registry.modules[module]
                    status = "✓" if info.is_active else "✗"
                    exp = "⚡" if info.is_experimental else " "
                    risk = "🔴" * min(info.risk_level, 3)
                    
                    print(f"  {status} {exp} {TextColors.BLACK_BOLD}{module:<25}{TextColors.RESET} "
                          f"{TextColors.DARK_GRAY}{info.description[:40]}...{TextColors.RESET} {risk}")
    
    @staticmethod
    def print_detailed_view(module_name: str):
        """Print detailed information about a module"""
        registry = ModuleRegistry()
        if module_name not in registry.modules:
            print(f"{TextColors.BLACK_ON_RED}Module not found: {module_name}{TextColors.RESET}")
            return
        
        info = registry.modules[module_name]
        
        print(f"\n{TextColors.ON_CHARCOAL}{TextColors.BLACK_BOLD}{' MODULE DETAILS ':{'═'}^80}{TextColors.RESET}")
        print(f"\n{TextColors.BLACK_BOLD}Name:{TextColors.RESET} {TextColors.BLACK_UNDERLINE}{info.name}{TextColors.RESET}")
        print(f"{TextColors.BLACK_BOLD}Category:{TextColors.RESET} {TextColors.DARK_GRAY}{info.category.name}{TextColors.RESET}")
        print(f"{TextColors.BLACK_BOLD}Description:{TextColors.RESET} {TextColors.DARK_GRAY}{info.description}{TextColors.RESET}")
        print(f"{TextColors.BLACK_BOLD}Version:{TextColors.RESET} {TextColors.DIM_GRAY}{info.version}{TextColors.RESET}")
        print(f"{TextColors.BLACK_BOLD}Author:{TextColors.RESET} {TextColors.GUNMETAL}{info.author}{TextColors.RESET}")
        
        if info.tags:
            print(f"{TextColors.BLACK_BOLD}Tags:{TextColors.RESET} {', '.join(sorted(info.tags))}")
        
        if info.aliases:
            print(f"{TextColors.BLACK_BOLD}Aliases:{TextColors.RESET} {', '.join(info.aliases)}")
        
        if info.dependencies:
            print(f"\n{TextColors.BLACK_BOLD}Dependencies:{TextColors.RESET}")
            for dep in info.dependencies:
                print(f"  {TextColors.DARK_GRAY}• {dep}{TextColors.RESET}")
        
        if info.required_packages:
            print(f"\n{TextColors.BLACK_BOLD}Required Packages:{TextColors.RESET}")
            for pkg in info.required_packages:
                print(f"  {TextColors.CHARCOAL}• {pkg}{TextColors.RESET}")
        
        if info.examples:
            print(f"\n{TextColors.BLACK_BOLD}Examples:{TextColors.RESET}")
            for ex in info.examples:
                print(f"  {TextColors.BLACK_GRADIENT_3}{ex}{TextColors.RESET}")
        
        print(f"\n{TextColors.BLACK_BOLD}Status:{TextColors.RESET} ", end="")
        if info.is_active:
            print(f"{TextColors.BLACK_ON_GREEN} ACTIVE {TextColors.RESET}", end="")
        else:
            print(f"{TextColors.BLACK_ON_RED} INACTIVE {TextColors.RESET}", end="")
        
        if info.is_experimental:
            print(f" {TextColors.BLACK_ON_YELLOW} EXPERIMENTAL {TextColors.RESET}")
        
        print(f"{TextColors.BLACK_BOLD}Risk Level:{TextColors.RESET} [{info.risk_level}/10]")
        print(f"{TextColors.BLACK_BOLD}Last Updated:{TextColors.RESET} {info.last_updated.strftime('%Y-%m-%d %H:%M:%S')}")

# Export the main utility modules
__all__ = [
    # Core modules from original request
    'encoding',
    'proxy_manager', 
    'request_wrapper',
    'subdomain_finder',
    
    # Enhanced utility systems
    'ModuleRegistry',
    'ModuleLoader',
    'ModuleVisualizer',
    'TextColors',
    'ModuleCategory',
    
    # Additional essential modules
    'vulnerability_scanner',
    'payload_generator',
    'report_generator',
    'log_analyzer',
    'ai_assistant',
    
    # Network modules
    'port_scanner',
    'packet_sniffer',
    'dns_enum',
    
    # Security modules
    'xss_scanner',
    'sql_injection',
    'csrf_detector',
    
    # Cryptography
    'crypto_breaker',
    'hash_identifier',
    
    # Specialized scanners
    'apk_analyzer',
    'aws_scanner',
    'iot_discover',
    
    # Forensic tools
    'memory_analyzer',
    'disk_forensics',
    
    # Visualization
    'network_mapper',
    'attack_graph'
]

# Initialize global module manager
module_manager = ModuleLoader()

def get_all_modules() -> List[str]:
    """Get list of all available modules"""
    return list(ModuleRegistry().modules.keys())

def get_module(module_name: str) -> Optional[Any]:
    """Get a loaded module by name"""
    return module_manager.loaded_modules.get(module_name)

def load_all_modules() -> Dict[str, bool]:
    """Load all available modules"""
    results = {}
    for module_name in get_all_modules():
        results[module_name] = module_manager.load_module(module_name)
    return results

def print_module_summary():
    """Print a summary of all modules"""
    visualizer = ModuleVisualizer()
    visualizer.print_category_tree()
    
    stats = {
        'total': len(get_all_modules()),
        'loaded': len(module_manager.loaded_modules),
        'failed': len(module_manager.failed_modules),
        'categories': len(ModuleCategory)
    }
    
    print(f"\n{TextColors.BLACK_BOLD}{'MODULE STATISTICS':^80}{TextColors.RESET}")
    print(f"{TextColors.BLACK_GRADIENT_2}{'─' * 80}{TextColors.RESET}")
    print(f"{TextColors.BLACK_BOLD}Total Modules:{TextColors.RESET} {stats['total']}")
    print(f"{TextColors.BLACK_BOLD}Loaded Modules:{TextColors.RESET} {stats['loaded']}")
    print(f"{TextColors.BLACK_BOLD}Failed Loads:{TextColors.RESET} {stats['failed']}")
    print(f"{TextColors.BLACK_BOLD}Categories:{TextColors.RESET} {stats['categories']}")
    
    if module_manager.failed_modules:
        print(f"\n{TextColors.BLACK_ON_RED}Failed Modules:{TextColors.RESET}")
        for module, error in module_manager.failed_modules.items():
            print(f"  {TextColors.DARK_GRAY}{module}: {error}{TextColors.RESET}")

# Main execution for demonstration
if __name__ == "__main__":
    print(f"{TextColors.ON_CHARCOAL}{TextColors.BLACK_BOLD}{' ADVANCED SCANNER UTILITIES ':═^80}{TextColors.RESET}")
    print(f"{TextColors.BLACK_ITALIC}Initializing utility modules...{TextColors.RESET}\n")
    
    # Load core modules
    core_modules = ['encoding', 'proxy_manager', 'request_wrapper', 'subdomain_finder']
    for module in core_modules:
        module_manager.load_module(module)
    
    # Show module details
    ModuleVisualizer.print_detailed_view('encoding')
    ModuleVisualizer.print_detailed_view('proxy_manager')
    
    # Print summary
    print_module_summary()
    
    # Show available modules
    ModuleVisualizer.print_category_tree()
    
    print(f"\n{TextColors.BLACK_ON_CHARCOAL}{' READY FOR SECURITY OPERATIONS ':{'═'}^80}{TextColors.RESET}")