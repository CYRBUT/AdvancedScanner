"""
╔══════════════════════════════════════════════════════════════════════════════╗
║               𝗔𝗗𝗩𝗔𝗡𝗖𝗘𝗗 𝗩𝗜𝗘𝗪 𝗠𝗢𝗗𝗨𝗟𝗘𝗦 𝗙𝗢𝗥 𝗨𝗜               ║
║          Professional Interface Components for Security Scanner             ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import time
import threading
import queue
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Union, Callable
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from colorama import Fore, Back, Style, init, Cursor
import curses
import readline
import asyncio

# Initialize colorama
init(autoreset=True)

class ViewColors:
    """Advanced color palette for view modules"""
    
    # Black Text Variations
    BLACK = '\033[30m'
    BLACK_BOLD = '\033[1;30m'
    BLACK_ITALIC = '\033[3;30m'
    BLACK_UNDERLINE = '\033[4;30m'
    BLACK_BLINK = '\033[5;30m'
    BLACK_REVERSE = '\033[7;30m'
    BLACK_STRIKETHROUGH = '\033[9;30m'
    BLACK_FADED = '\033[2;30m'
    
    # Gray Scale
    DARK_GRAY = '\033[90m'
    DARK_GRAY_BOLD = '\033[1;90m'
    DIM_GRAY = '\033[38;5;8m'
    CHARCOAL = '\033[38;5;236m'
    GUNMETAL = '\033[38;5;238m'
    SLATE = '\033[38;5;240m'
    STEEL = '\033[38;5;245m'
    SILVER = '\033[38;5;7m'
    
    # Gradient Blacks
    BLACK_GRADIENT_1 = '\033[38;5;232m'
    BLACK_GRADIENT_2 = '\033[38;5;233m'
    BLACK_GRADIENT_3 = '\033[38;5;234m'
    
    # Backgrounds
    ON_BLACK = '\033[40m'
    ON_DARK_GRAY = '\033[100m'
    ON_CHARCOAL = '\033[48;5;236m'
    ON_STEEL = '\033[48;5;245m'
    ON_SILVER = '\033[47m'
    
    # Status Colors
    ON_SUCCESS = '\033[42m'
    ON_WARNING = '\033[43m'
    ON_DANGER = '\033[41m'
    ON_INFO = '\033[44m'
    ON_PURPLE = '\033[45m'
    ON_CYAN = '\033[46m'
    
    # Interactive Elements
    ON_HIGHLIGHT = '\033[48;5;240m'
    ON_SELECTED = '\033[48;5;238m'
    ON_INACTIVE = '\033[48;5;236m'
    
    RESET = '\033[0m'

class ComponentType(Enum):
    """UI Component types"""
    MENU = auto()
    DASHBOARD = auto()
    MODAL = auto()
    FORM = auto()
    TABLE = auto()
    CHART = auto()
    PROGRESS = auto()
    NOTIFICATION = auto()
    TERMINAL = auto()
    SIDEBAR = auto()
    HEADER = auto()
    FOOTER = auto()

class AnimationType(Enum):
    """Animation types for UI components"""
    FADE = auto()
    SLIDE = auto()
    ZOOM = auto()
    BOUNCE = auto()
    SPIN = auto()
    PROGRESS = auto()
    TYPING = auto()
    MARQUEE = auto()

@dataclass
class UIComponent:
    """Base UI component"""
    component_id: str
    component_type: ComponentType
    position: Tuple[int, int]
    size: Tuple[int, int]
    content: Any
    style: Dict[str, Any] = field(default_factory=dict)
    animations: List[AnimationType] = field(default_factory=list)
    is_visible: bool = True
    is_interactive: bool = False
    parent_id: Optional[str] = None
    children: List[str] = field(default_factory=list)
    
    def render(self) -> str:
        """Render component to string"""
        return f"{self.component_type.name}: {self.content}"
    
    def update(self, **kwargs):
        """Update component properties"""
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)

class TerminalManager:
    """Advanced terminal management"""
    
    def __init__(self):
        self.width, self.height = self.get_terminal_size()
        self.cursor_position = (0, 0)
        self.screen_buffer = []
        self._init_screen()
    
    def get_terminal_size(self) -> Tuple[int, int]:
        """Get terminal dimensions"""
        try:
            size = os.get_terminal_size()
            return size.columns, size.lines
        except:
            return 80, 24
    
    def _init_screen(self):
        """Initialize screen buffer"""
        self.screen_buffer = [[' ' for _ in range(self.width)] for _ in range(self.height)]
    
    def clear(self):
        """Clear terminal"""
        os.system('clear' if os.name == 'posix' else 'cls')
        self._init_screen()
    
    def set_cursor(self, x: int, y: int):
        """Set cursor position"""
        print(f"\033[{y};{x}H", end='')
        self.cursor_position = (x, y)
    
    def save_cursor(self):
        """Save cursor position"""
        print("\033[s", end='')
    
    def restore_cursor(self):
        """Restore cursor position"""
        print("\033[u", end='')
    
    def hide_cursor(self):
        """Hide cursor"""
        print("\033[?25l", end='')
    
    def show_cursor(self):
        """Show cursor"""
        print("\033[?25h", end='')
    
    def draw_box(self, x: int, y: int, width: int, height: int, 
                title: str = "", style: str = "single"):
        """Draw a box in terminal"""
        # Box drawing characters
        boxes = {
            "single": {
                "tl": "┌", "tr": "┐", "bl": "└", "br": "┘",
                "h": "─", "v": "│", "cross": "┼"
            },
            "double": {
                "tl": "╔", "tr": "╗", "bl": "╚", "br": "╝",
                "h": "═", "v": "║", "cross": "╬"
            },
            "rounded": {
                "tl": "╭", "tr": "╮", "bl": "╰", "br": "╯",
                "h": "─", "v": "│", "cross": "┼"
            },
            "bold": {
                "tl": "┏", "tr": "┓", "bl": "┗", "br": "┛",
                "h": "━", "v": "┃", "cross": "╋"
            }
        }
        
        box_chars = boxes.get(style, boxes["single"])
        
        # Draw top border
        self.set_cursor(x, y)
        print(box_chars["tl"] + box_chars["h"] * (width - 2) + box_chars["tr"], end='')
        
        # Draw title if provided
        if title:
            title_pos = x + 2
            if title_pos + len(title) < x + width - 1:
                self.set_cursor(title_pos, y)
                print(f" {title} ", end='')
        
        # Draw sides
        for i in range(1, height - 1):
            self.set_cursor(x, y + i)
            print(box_chars["v"], end='')
            self.set_cursor(x + width - 1, y + i)
            print(box_chars["v"], end='')
        
        # Draw bottom border
        self.set_cursor(x, y + height - 1)
        print(box_chars["bl"] + box_chars["h"] * (width - 2) + box_chars["br"], end='')
    
    def draw_text(self, x: int, y: int, text: str, color: str = "", 
                 bold: bool = False, underline: bool = False):
        """Draw text at position"""
        self.set_cursor(x, y)
        
        style = ""
        if color:
            style += color
        if bold:
            style += Style.BRIGHT
        if underline:
            style += '\033[4m'
        
        print(f"{style}{text}{Style.RESET_ALL}", end='')
    
    def draw_progress_bar(self, x: int, y: int, width: int, progress: float, 
                         label: str = "", show_percentage: bool = True):
        """Draw a progress bar"""
        filled_width = int(width * progress)
        bar = "█" * filled_width + "░" * (width - filled_width)
        
        self.set_cursor(x, y)
        print(f"[{bar}]", end='')
        
        if show_percentage:
            self.set_cursor(x + width + 2, y)
            print(f"{progress * 100:.1f}%", end='')
        
        if label:
            self.set_cursor(x, y + 1)
            print(label, end='')
    
    def create_modal(self, title: str, content: str, width: int = 50, 
                    height: int = 10, buttons: List[str] = None):
        """Create a modal dialog"""
        center_x = (self.width - width) // 2
        center_y = (self.height - height) // 2
        
        # Draw modal background
        for i in range(height):
            self.set_cursor(center_x, center_y + i)
            print(" " * width, end='')
        
        # Draw modal box
        self.draw_box(center_x, center_y, width, height, title, "double")
        
        # Draw content
        content_lines = content.split('\n')
        for i, line in enumerate(content_lines[:height - 4]):
            self.draw_text(center_x + 2, center_y + 2 + i, line[:width - 4])
        
        # Draw buttons
        if buttons:
            button_y = center_y + height - 2
            total_width = sum(len(btn) + 4 for btn in buttons)
            start_x = center_x + (width - total_width) // 2
            
            for i, button in enumerate(buttons):
                btn_x = start_x + sum(len(buttons[j]) + 4 for j in range(i))
                self.draw_box(btn_x, button_y, len(button) + 2, 1)
                self.draw_text(btn_x + 1, button_y, button, ViewColors.BLACK_ON_HIGHLIGHT)
        
        return center_x, center_y, width, height

# ============================================
# MENU MODULE
# ============================================

class AdvancedMenu:
    """Advanced interactive menu system"""
    
    def __init__(self, title: str = "Menu", width: int = 80, height: int = 24):
        self.title = title
        self.width = width
        self.height = height
        self.terminal = TerminalManager()
        self.items = []
        self.selected_index = 0
        self.history = []
        self.breadcrumbs = []
        self.callbacks = {}
        self.is_running = False
        self.event_queue = queue.Queue()
        self.key_bindings = self._init_key_bindings()
        self.theme = self._init_theme()
        self.animations_enabled = True
        self._init_menu()
    
    def _init_key_bindings(self) -> Dict[str, Callable]:
        """Initialize key bindings"""
        return {
            'up': self._move_up,
            'down': self._move_down,
            'enter': self._select_item,
            'escape': self._go_back,
            'home': self._go_home,
            'end': self._go_end,
            'page_up': self._page_up,
            'page_down': self._page_down,
            'tab': self._next_tab,
            'shift+tab': self._prev_tab,
            'f1': self._show_help,
            'f5': self._refresh,
            'ctrl+c': self._exit,
        }
    
    def _init_theme(self) -> Dict[str, Any]:
        """Initialize theme settings"""
        return {
            'background': ViewColors.BLACK,
            'foreground': ViewColors.DARK_GRAY,
            'accent': ViewColors.BLACK_ON_HIGHLIGHT,
            'selected': ViewColors.BLACK_ON_SELECTED,
            'title': ViewColors.BLACK_BOLD,
            'border': ViewColors.CHARCOAL,
            'highlight': ViewColors.BLACK_ON_CYAN,
            'warning': ViewColors.BLACK_ON_WARNING,
            'error': ViewColors.BLACK_ON_DANGER,
            'success': ViewColors.BLACK_ON_SUCCESS,
        }
    
    def _init_menu(self):
        """Initialize menu display"""
        self.terminal.clear()
        self.terminal.hide_cursor()
    
    def add_item(self, item_id: str, label: str, callback: Callable = None, 
                icon: str = "•", shortcut: str = None, enabled: bool = True,
                tooltip: str = None, category: str = None):
        """Add item to menu"""
        item = {
            'id': item_id,
            'label': label,
            'callback': callback,
            'icon': icon,
            'shortcut': shortcut,
            'enabled': enabled,
            'tooltip': tooltip,
            'category': category,
            'indent': 0,
        }
        self.items.append(item)
        
        if callback:
            self.callbacks[item_id] = callback
    
    def add_separator(self, label: str = ""):
        """Add separator to menu"""
        self.items.append({
            'id': f"separator_{len(self.items)}",
            'label': label,
            'type': 'separator',
            'enabled': False,
        })
    
    def add_category(self, category_name: str):
        """Add category header"""
        self.items.append({
            'id': f"category_{category_name}",
            'label': category_name.upper(),
            'type': 'category',
            'enabled': False,
            'indent': 0,
        })
    
    def create_submenu(self, parent_id: str, submenu_items: List[Dict]):
        """Create submenu for an item"""
        for i, item in enumerate(self.items):
            if item['id'] == parent_id:
                # Add submenu items with indentation
                for subitem in submenu_items:
                    subitem['indent'] = 2
                    self.items.insert(i + 1, subitem)
                break
    
    def display(self):
        """Display the menu"""
        self.is_running = True
        self._draw_menu()
        
        # Main event loop
        while self.is_running:
            try:
                # Check for input
                if sys.platform == 'win32':
                    import msvcrt
                    if msvcrt.kbhit():
                        key = msvcrt.getch()
                        self._handle_key(key)
                else:
                    import select
                    import tty
                    import termios
                    
                    fd = sys.stdin.fileno()
                    old_settings = termios.tcgetattr(fd)
                    
                    try:
                        tty.setraw(sys.stdin.fileno())
                        if select.select([sys.stdin], [], [], 0.1)[0]:
                            key = sys.stdin.read(1)
                            self._handle_key(key)
                    finally:
                        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
                
                # Process events
                self._process_events()
                
                # Small delay to prevent high CPU usage
                time.sleep(0.01)
                
            except KeyboardInterrupt:
                self._exit()
            except Exception as e:
                self._show_error(f"Menu error: {e}")
    
    def _draw_menu(self):
        """Draw the menu interface"""
        self.terminal.clear()
        
        # Draw header
        self._draw_header()
        
        # Draw breadcrumbs
        self._draw_breadcrumbs()
        
        # Draw menu items
        self._draw_items()
        
        # Draw footer
        self._draw_footer()
        
        # Draw help bar
        self._draw_help()
    
    def _draw_header(self):
        """Draw menu header"""
        # Title box
        self.terminal.draw_box(1, 1, self.width - 2, 3, self.title, "double")
        
        # Time and status
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.terminal.draw_text(self.width - 20, 2, current_time, ViewColors.DARK_GRAY)
        
        # User info (placeholder)
        self.terminal.draw_text(self.width - 40, 2, "User: Security Analyst", ViewColors.DIM_GRAY)
    
    def _draw_breadcrumbs(self):
        """Draw breadcrumb navigation"""
        if self.breadcrumbs:
            breadcrumb_text = " > ".join(self.breadcrumbs)
            self.terminal.draw_box(1, 5, self.width - 2, 2, "Navigation", "single")
            self.terminal.draw_text(3, 6, breadcrumb_text, ViewColors.BLACK_BOLD)
    
    def _draw_items(self):
        """Draw menu items"""
        start_y = 8
        max_items = self.height - start_y - 6
        
        # Calculate visible range
        visible_start = max(0, self.selected_index - max_items // 2)
        visible_end = min(len(self.items), visible_start + max_items)
        
        # Adjust if at boundaries
        if visible_end - visible_start < max_items:
            visible_start = max(0, visible_end - max_items)
        
        # Draw visible items
        for i in range(visible_start, visible_end):
            item = self.items[i]
            y_pos = start_y + (i - visible_start)
            
            # Highlight selected item
            is_selected = (i == self.selected_index)
            
            # Set colors based on item type and state
            if item.get('type') == 'category':
                color = ViewColors.BLACK_ON_STEEL
                icon = "📁"
            elif item.get('type') == 'separator':
                # Draw separator line
                self.terminal.draw_text(3, y_pos, "─" * (self.width - 6), ViewColors.CHARCOAL)
                continue
            elif not item.get('enabled', True):
                color = ViewColors.DIM_GRAY
                icon = item.get('icon', '○')
            elif is_selected:
                color = self.theme['selected']
                icon = "▶" if item.get('has_submenu') else item.get('icon', '•')
            else:
                color = self.theme['foreground']
                icon = item.get('icon', '•')
            
            # Prepare item text
            indent = " " * (item.get('indent', 0))
            label = f"{indent}{icon} {item['label']}"
            
            # Add shortcut if available
            if item.get('shortcut') and not is_selected:
                label += f" [{item['shortcut']}]"
            
            # Truncate if too long
            max_len = self.width - 10
            if len(label) > max_len:
                label = label[:max_len-3] + "..."
            
            # Draw item
            self.terminal.draw_text(3, y_pos, label, color)
            
            # Draw selection indicator
            if is_selected:
                self.terminal.draw_text(1, y_pos, ">", ViewColors.BLACK_ON_CYAN)
            
            # Draw tooltip indicator
            if item.get('tooltip') and is_selected:
                self.terminal.draw_text(self.width - 4, y_pos, "ⓘ", ViewColors.BLACK_ON_INFO)
    
    def _draw_footer(self):
        """Draw menu footer"""
        footer_y = self.height - 4
        
        # Status bar
        self.terminal.draw_box(1, footer_y, self.width - 2, 3, "Status", "single")
        
        # Item count
        total_items = len(self.items)
        enabled_items = sum(1 for item in self.items if item.get('enabled', True))
        status_text = f"Items: {enabled_items}/{total_items} | Selected: {self.selected_index + 1}"
        
        self.terminal.draw_text(3, footer_y + 1, status_text, ViewColors.DARK_GRAY)
        
        # Selected item info
        if self.items:
            selected_item = self.items[self.selected_index]
            if selected_item.get('tooltip'):
                self.terminal.draw_text(self.width // 2, footer_y + 1, 
                                      selected_item['tooltip'], ViewColors.DIM_GRAY)
    
    def _draw_help(self):
        """Draw help bar at bottom"""
        help_y = self.height - 1
        
        help_items = [
            ("↑↓", "Navigate"),
            ("Enter", "Select"),
            ("Esc", "Back"),
            ("F1", "Help"),
            ("Ctrl+C", "Exit"),
        ]
        
        help_text = " | ".join(f"{key}: {desc}" for key, desc in help_items)
        self.terminal.draw_text(1, help_y, help_text, ViewColors.DARK_GRAY_BOLD)
    
    def _handle_key(self, key: str):
        """Handle keyboard input"""
        key_map = {
            '\x1b[A': 'up',        # Up arrow
            '\x1b[B': 'down',      # Down arrow
            '\r': 'enter',         # Enter
            '\n': 'enter',         # Enter
            '\x1b': 'escape',      # Escape
            '\x1b[H': 'home',      # Home
            '\x1b[F': 'end',       # End
            '\x1b[5~': 'page_up',  # Page Up
            '\x1b[6~': 'page_down', # Page Down
            '\t': 'tab',           # Tab
            '\x1b[Z': 'shift+tab', # Shift+Tab
            '\x1bOP': 'f1',        # F1
            '\x1bOQ': 'f2',        # F2
            '\x1bOR': 'f3',        # F3
            '\x1bOS': 'f4',        # F4
            '\x1b[15~': 'f5',      # F5
            '\x03': 'ctrl+c',      # Ctrl+C
        }
        
        action = key_map.get(key, None)
        if action and action in self.key_bindings:
            self.key_bindings[action]()
            self._draw_menu()
    
    def _move_up(self):
        """Move selection up"""
        if self.selected_index > 0:
            self.selected_index -= 1
            # Skip disabled items and separators
            while (self.selected_index > 0 and 
                   (not self.items[self.selected_index].get('enabled', True) or
                    self.items[self.selected_index].get('type') == 'separator')):
                self.selected_index -= 1
    
    def _move_down(self):
        """Move selection down"""
        if self.selected_index < len(self.items) - 1:
            self.selected_index += 1
            # Skip disabled items and separators
            while (self.selected_index < len(self.items) - 1 and 
                   (not self.items[self.selected_index].get('enabled', True) or
                    self.items[self.selected_index].get('type') == 'separator')):
                self.selected_index += 1
    
    def _select_item(self):
        """Select current item"""
        if self.items:
            item = self.items[self.selected_index]
            
            if item.get('enabled', True) and item.get('type') not in ['category', 'separator']:
                # Add to history
                self.history.append({
                    'index': self.selected_index,
                    'item': item,
                    'timestamp': datetime.now()
                })
                
                # Execute callback if available
                if item.get('callback'):
                    try:
                        item['callback']()
                    except Exception as e:
                        self._show_error(f"Error executing {item['label']}: {e}")
                else:
                    # If no callback, maybe it's a submenu trigger
                    if item.get('has_submenu'):
                        self._enter_submenu(item)
                    else:
                        self._show_notification(f"Selected: {item['label']}")
    
    def _go_back(self):
        """Go back to previous menu"""
        if self.breadcrumbs:
            self.breadcrumbs.pop()
            self._draw_menu()
        elif self.history:
            prev = self.history.pop()
            self.selected_index = prev['index']
            self._draw_menu()
    
    def _go_home(self):
        """Go to first item"""
        self.selected_index = 0
        while (self.selected_index < len(self.items) and 
               (not self.items[self.selected_index].get('enabled', True) or
                self.items[self.selected_index].get('type') == 'separator')):
            self.selected_index += 1
    
    def _go_end(self):
        """Go to last item"""
        self.selected_index = len(self.items) - 1
        while (self.selected_index > 0 and 
               (not self.items[self.selected_index].get('enabled', True) or
                self.items[self.selected_index].get('type') == 'separator')):
            self.selected_index -= 1
    
    def _page_up(self):
        """Page up"""
        page_size = self.height - 15  # Approximate visible items
        self.selected_index = max(0, self.selected_index - page_size)
    
    def _page_down(self):
        """Page down"""
        page_size = self.height - 15  # Approximate visible items
        self.selected_index = min(len(self.items) - 1, self.selected_index + page_size)
    
    def _next_tab(self):
        """Next tab/category"""
        # Find next category
        for i in range(self.selected_index + 1, len(self.items)):
            if self.items[i].get('type') == 'category':
                self.selected_index = i + 1  # Select first item after category
                break
    
    def _prev_tab(self):
        """Previous tab/category"""
        # Find previous category
        for i in range(self.selected_index - 1, -1, -1):
            if self.items[i].get('type') == 'category':
                self.selected_index = i + 1  # Select first item after category
                break
    
    def _show_help(self):
        """Show help modal"""
        help_content = """
Advanced Menu System Help:

Navigation:
• Use ↑/↓ arrows to navigate
• Press Enter to select item
• Use Esc to go back
• Tab/Shift+Tab for categories

Features:
• F1: Show this help
• F5: Refresh menu
• Ctrl+C: Exit application

Tips:
• Items with [ⓘ] have tooltips
• Disabled items are grayed out
• Categories are in bold headers
        """
        
        self._show_modal("Help", help_content, ["OK"])
    
    def _refresh(self):
        """Refresh menu display"""
        self._draw_menu()
    
    def _exit(self):
        """Exit menu"""
        self.is_running = False
        self.terminal.show_cursor()
        self.terminal.clear()
    
    def _enter_submenu(self, item: Dict):
        """Enter submenu"""
        self.breadcrumbs.append(item['label'])
        self._draw_menu()
    
    def _show_notification(self, message: str, level: str = "info"):
        """Show notification"""
        colors = {
            'info': ViewColors.BLACK_ON_INFO,
            'warning': ViewColors.BLACK_ON_WARNING,
            'error': ViewColors.BLACK_ON_DANGER,
            'success': ViewColors.BLACK_ON_SUCCESS,
        }
        
        color = colors.get(level, ViewColors.BLACK_ON_INFO)
        
        # Show notification at bottom
        self.terminal.save_cursor()
        self.terminal.draw_box(10, self.height - 6, 60, 3, "Notification")
        self.terminal.draw_text(12, self.height - 5, message, color)
        self.terminal.restore_cursor()
        
        # Auto-hide after delay
        threading.Timer(2.0, self._draw_menu).start()
    
    def _show_error(self, message: str):
        """Show error message"""
        self._show_modal("Error", message, ["OK"])
    
    def _show_modal(self, title: str, content: str, buttons: List[str]):
        """Show modal dialog"""
        modal_x, modal_y, modal_w, modal_h = self.terminal.create_modal(
            title, content, 60, len(content.split('\n')) + 6, buttons
        )
        
        # For now, just display and wait for key
        self.terminal.show_cursor()
        input("\nPress Enter to continue...")
        self.terminal.hide_cursor()
        self._draw_menu()
    
    def _process_events(self):
        """Process queued events"""
        try:
            while True:
                event = self.event_queue.get_nowait()
                self._handle_event(event)
        except queue.Empty:
            pass
    
    def _handle_event(self, event: Dict):
        """Handle custom event"""
        event_type = event.get('type')
        
        if event_type == 'update_item':
            item_id = event.get('item_id')
            updates = event.get('updates', {})
            self._update_item(item_id, updates)
        
        elif event_type == 'add_item':
            item = event.get('item')
            self.add_item(**item)
        
        elif event_type == 'notification':
            message = event.get('message')
            level = event.get('level', 'info')
            self._show_notification(message, level)
        
        elif event_type == 'refresh':
            self._draw_menu()
    
    def _update_item(self, item_id: str, updates: Dict):
        """Update menu item"""
        for i, item in enumerate(self.items):
            if item['id'] == item_id:
                self.items[i].update(updates)
                break

# ============================================
# RESULTS DISPLAY MODULE
# ============================================

class ResultsDisplay:
    """Advanced results display system"""
    
    def __init__(self, terminal: TerminalManager = None):
        self.terminal = terminal or TerminalManager()
        self.results = {}
        self.current_view = 'summary'
        self.views = {}
        self.filters = {}
        self.sort_by = None
        self.sort_reverse = False
        self.selected_result = None
        self._init_views()
    
    def _init_views(self):
        """Initialize available views"""
        self.views = {
            'summary': self._show_summary_view,
            'detailed': self._show_detailed_view,
            'table': self._show_table_view,
            'grid': self._show_grid_view,
            'timeline': self._show_timeline_view,
            'chart': self._show_chart_view,
            'export': self._show_export_view,
        }
    
    def set_results(self, results: Dict):
        """Set results to display"""
        self.results = results
        self._process_results()
    
    def _process_results(self):
        """Process results for display"""
        # Extract statistics
        self.stats = {
            'total': len(self.results.get('vulnerabilities', [])),
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
        }
        
        for vuln in self.results.get('vulnerabilities', []):
            severity = vuln.get('severity', 'info').lower()
            if severity in self.stats:
                self.stats[severity] += 1
        
        # Calculate percentages
        total = self.stats['total']
        if total > 0:
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                self.stats[f'{severity}_percent'] = (self.stats[severity] / total) * 100
    
    def display(self, view_type: str = 'summary'):
        """Display results in specified view"""
        self.current_view = view_type
        
        if view_type in self.views:
            self.terminal.clear()
            self.views[view_type]()
        else:
            self._show_summary_view()
    
    def _show_summary_view(self):
        """Show summary view of results"""
        self.terminal.draw_box(1, 1, self.terminal.width - 2, self.terminal.height - 2, 
                              "Scan Results Summary", "double")
        
        # Draw statistics
        stats_y = 3
        self.terminal.draw_text(3, stats_y, "VULNERABILITY SUMMARY", ViewColors.BLACK_BOLD)
        
        # Severity breakdown
        stats_y += 2
        for severity, count in self.stats.items():
            if severity.endswith('_percent'):
                continue
            
            if count > 0:
                color_map = {
                    'critical': ViewColors.BLACK_ON_DANGER,
                    'high': ViewColors.BLACK_ON_WARNING,
                    'medium': ViewColors.BLACK_ON_INFO,
                    'low': ViewColors.BLACK_ON_SUCCESS,
                    'info': ViewColors.DARK_GRAY,
                }
                
                color = color_map.get(severity, ViewColors.DARK_GRAY)
                percent = self.stats.get(f'{severity}_percent', 0)
                
                self.terminal.draw_text(5, stats_y, 
                                       f"{severity.upper():<10}: {count:>4} ({percent:.1f}%)", 
                                       color)
                stats_y += 1
        
        # Draw progress bars for severity distribution
        stats_y += 1
        self.terminal.draw_text(3, stats_y, "SEVERITY DISTRIBUTION", ViewColors.BLACK_BOLD)
        
        stats_y += 1
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            if self.stats[severity] > 0:
                percent = self.stats.get(f'{severity}_percent', 0)
                bar_width = 40
                filled = int(bar_width * percent / 100)
                
                color_map = {
                    'critical': ViewColors.BLACK_ON_DANGER,
                    'high': ViewColors.BLACK_ON_WARNING,
                    'medium': ViewColors.BLACK_ON_INFO,
                    'low': ViewColors.BLACK_ON_SUCCESS,
                    'info': ViewColors.DARK_GRAY,
                }
                
                color = color_map.get(severity, ViewColors.DARK_GRAY)
                bar = "█" * filled + "░" * (bar_width - filled)
                
                self.terminal.draw_text(5, stats_y, 
                                       f"{severity.upper():<10} [{bar}] {percent:5.1f}%", 
                                       color)
                stats_y += 1
        
        # Draw scan metadata
        meta_y = stats_y + 2
        metadata = self.results.get('metadata', {})
        
        self.terminal.draw_text(3, meta_y, "SCAN METADATA", ViewColors.BLACK_BOLD)
        meta_y += 1
        
        if metadata:
            fields = [
                ('Target', metadata.get('target', 'N/A')),
                ('Start Time', metadata.get('start_time', 'N/A')),
                ('Duration', metadata.get('duration', 'N/A')),
                ('Scanner', f"{metadata.get('scanner_name', 'N/A')} v{metadata.get('scanner_version', 'N/A')}"),
                ('Total Requests', metadata.get('total_requests', 'N/A')),
            ]
            
            for label, value in fields:
                self.terminal.draw_text(5, meta_y, f"{label:<15}: {value}", ViewColors.DIM_GRAY)
                meta_y += 1
        
        # Draw action buttons
        action_y = self.terminal.height - 4
        actions = [
            ("F1", "Detailed View"),
            ("F2", "Table View"),
            ("F3", "Export"),
            ("F4", "Filter"),
            ("F5", "Refresh"),
        ]
        
        action_x = 5
        for key, label in actions:
            self.terminal.draw_box(action_x, action_y, len(label) + 4, 1)
            self.terminal.draw_text(action_x + 2, action_y, label, ViewColors.BLACK_ON_HIGHLIGHT)
            self.terminal.draw_text(action_x + 1, action_y - 1, key, ViewColors.BLACK_BOLD)
            action_x += len(label) + 8
    
    def _show_detailed_view(self):
        """Show detailed view of vulnerabilities"""
        vulnerabilities = self.results.get('vulnerabilities', [])
        
        self.terminal.draw_box(1, 1, self.terminal.width - 2, self.terminal.height - 2, 
                              "Detailed Vulnerability Report", "double")
        
        if not vulnerabilities:
            self.terminal.draw_text(self.terminal.width // 2 - 10, self.terminal.height // 2,
                                   "No vulnerabilities found", ViewColors.DARK_GRAY)
            return
        
        # Show first 10 vulnerabilities
        start_y = 3
        max_items = self.terminal.height - start_y - 4
        
        for i, vuln in enumerate(vulnerabilities[:max_items]):
            y_pos = start_y + i
            
            # Severity color
            severity = vuln.get('severity', 'info').lower()
            color_map = {
                'critical': ViewColors.BLACK_ON_DANGER,
                'high': ViewColors.BLACK_ON_WARNING,
                'medium': ViewColors.BLACK_ON_INFO,
                'low': ViewColors.BLACK_ON_SUCCESS,
                'info': ViewColors.DARK_GRAY,
            }
            color = color_map.get(severity, ViewColors.DARK_GRAY)
            
            # Vulnerability info
            vuln_type = vuln.get('type', 'Unknown')
            url = vuln.get('affected_url', 'N/A')
            
            # Truncate if needed
            if len(url) > self.terminal.width - 30:
                url = url[:self.terminal.width - 33] + "..."
            
            # Draw vulnerability
            self.terminal.draw_text(3, y_pos, 
                                   f"[{severity.upper():<9}] {vuln_type:<25} {url}", 
                                   color)
        
        # Pagination info
        if len(vulnerabilities) > max_items:
            self.terminal.draw_text(3, self.terminal.height - 3,
                                   f"Showing 1-{max_items} of {len(vulnerabilities)} vulnerabilities",
                                   ViewColors.DARK_GRAY)
    
    def _show_table_view(self):
        """Show table view of results"""
        vulnerabilities = self.results.get('vulnerabilities', [])
        
        self.terminal.draw_box(1, 1, self.terminal.width - 2, self.terminal.height - 2, 
                              "Vulnerability Table", "double")
        
        # Table headers
        headers = ["Severity", "Type", "URL", "Parameter", "CVSS", "Status"]
        col_widths = [10, 20, 40, 15, 8, 10]
        
        # Draw headers
        start_x = 3
        y_pos = 3
        
        for i, (header, width) in enumerate(zip(headers, col_widths)):
            self.terminal.draw_box(start_x, y_pos - 1, width + 2, 3)
            self.terminal.draw_text(start_x + 1, y_pos, header, ViewColors.BLACK_BOLD)
            start_x += width + 3
        
        # Draw table data
        y_pos += 2
        max_rows = self.terminal.height - y_pos - 2
        
        for i, vuln in enumerate(vulnerabilities[:max_rows]):
            row_y = y_pos + i
            
            # Extract data
            severity = vuln.get('severity', 'info').lower()
            vuln_type = vuln.get('type', 'Unknown')
            url = vuln.get('affected_url', 'N/A')
            param = vuln.get('affected_parameter', 'N/A')
            cvss = vuln.get('cvss_score', 'N/A')
            status = vuln.get('status', 'Open')
            
            # Truncate fields
            if len(url) > 37:
                url = url[:34] + "..."
            if len(vuln_type) > 17:
                vuln_type = vuln_type[:14] + "..."
            if len(param) > 12:
                param = param[:9] + "..."
            
            # Severity color
            color_map = {
                'critical': ViewColors.BLACK_ON_DANGER,
                'high': ViewColors.BLACK_ON_WARNING,
                'medium': ViewColors.BLACK_ON_INFO,
                'low': ViewColors.BLACK_ON_SUCCESS,
                'info': ViewColors.DARK_GRAY,
            }
            color = color_map.get(severity, ViewColors.DARK_GRAY)
            
            # Draw row
            start_x = 3
            fields = [severity.upper(), vuln_type, url, param, str(cvss), status]
            
            for j, (field, width) in enumerate(zip(fields, col_widths)):
                self.terminal.draw_text(start_x + 1, row_y, field.ljust(width), 
                                       color if j == 0 else ViewColors.DARK_GRAY)
                start_x += width + 3
    
    def _show_grid_view(self):
        """Show grid/card view of vulnerabilities"""
        vulnerabilities = self.results.get('vulnerabilities', [])
        
        self.terminal.draw_box(1, 1, self.terminal.width - 2, self.terminal.height - 2, 
                              "Vulnerability Grid", "double")
        
        # Card dimensions
        card_width = 35
        card_height = 8
        cards_per_row = (self.terminal.width - 4) // (card_width + 2)
        
        start_x = 3
        start_y = 3
        
        for i, vuln in enumerate(vulnerabilities):
            if i >= 12:  # Limit to 12 cards for display
                break
            
            row = i // cards_per_row
            col = i % cards_per_row
            
            card_x = start_x + col * (card_width + 2)
            card_y = start_y + row * (card_height + 1)
            
            # Check if card fits
            if card_y + card_height >= self.terminal.height - 3:
                break
            
            self._draw_vulnerability_card(vuln, card_x, card_y, card_width, card_height)
    
    def _draw_vulnerability_card(self, vuln: Dict, x: int, y: int, width: int, height: int):
        """Draw a vulnerability card"""
        # Card background
        self.terminal.draw_box(x, y, width, height, "", "single")
        
        # Severity color bar
        severity = vuln.get('severity', 'info').lower()
        color_map = {
            'critical': ViewColors.BLACK_ON_DANGER,
            'high': ViewColors.BLACK_ON_WARNING,
            'medium': ViewColors.BLACK_ON_INFO,
            'low': ViewColors.BLACK_ON_SUCCESS,
            'info': ViewColors.DARK_GRAY,
        }
        color = color_map.get(severity, ViewColors.DARK_GRAY)
        
        # Draw severity header
        self.terminal.draw_text(x + 1, y, " " * (width - 2), color)
        self.terminal.draw_text(x + 2, y, severity.upper(), ViewColors.BLACK_BOLD)
        
        # Vulnerability info
        info_y = y + 2
        
        # Type
        vuln_type = vuln.get('type', 'Unknown')
        if len(vuln_type) > width - 4:
            vuln_type = vuln_type[:width - 7] + "..."
        self.terminal.draw_text(x + 2, info_y, vuln_type, ViewColors.BLACK_BOLD)
        
        # URL (truncated)
        url = vuln.get('affected_url', 'N/A')
        if len(url) > width - 4:
            url = url[:width - 7] + "..."
        self.terminal.draw_text(x + 2, info_y + 1, url, ViewColors.DIM_GRAY)
        
        # CVSS Score
        cvss = vuln.get('cvss_score', 'N/A')
        cvss_text = f"CVSS: {cvss}"
        self.terminal.draw_text(x + 2, info_y + 2, cvss_text, ViewColors.DARK_GRAY)
        
        # Status
        status = vuln.get('status', 'Open')
        status_color = ViewColors.BLACK_ON_SUCCESS if status == 'Fixed' else ViewColors.BLACK_ON_WARNING
        status_x = x + width - len(status) - 2
        self.terminal.draw_text(status_x, info_y + 2, status, status_color)
    
    def _show_timeline_view(self):
        """Show timeline view of vulnerabilities"""
        vulnerabilities = self.results.get('vulnerabilities', [])
        
        self.terminal.draw_box(1, 1, self.terminal.width - 2, self.terminal.height - 2, 
                              "Vulnerability Timeline", "double")
        
        if not vulnerabilities:
            self.terminal.draw_text(self.terminal.width // 2 - 10, self.terminal.height // 2,
                                   "No vulnerabilities found", ViewColors.DARK_GRAY)
            return
        
        # Group by date
        timeline = {}
        for vuln in vulnerabilities:
            date_str = vuln.get('discovery_date', datetime.now().isoformat())
            date = date_str[:10]  # Get YYYY-MM-DD
            
            if date not in timeline:
                timeline[date] = []
            timeline[date].append(vuln)
        
        # Sort dates
        sorted_dates = sorted(timeline.keys())
        
        # Draw timeline
        y_pos = 3
        max_items = self.terminal.height - y_pos - 4
        
        for i, date in enumerate(sorted_dates[:max_items]):
            vulns_on_date = timeline[date]
            
            # Draw date
            self.terminal.draw_text(3, y_pos + i, date, ViewColors.BLACK_BOLD)
            
            # Draw timeline marker
            self.terminal.draw_text(15, y_pos + i, "│", ViewColors.CHARCOAL)
            
            # Draw vulnerability count
            count = len(vulns_on_date)
            count_text = f"{count} vulnerability{'s' if count != 1 else ''}"
            
            # Severity breakdown
            severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            for vuln in vulns_on_date:
                severity = vuln.get('severity', 'info').lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1
            
            # Build severity string
            severity_parts = []
            for sev, cnt in severity_counts.items():
                if cnt > 0:
                    color_map = {
                        'critical': ViewColors.BLACK_ON_DANGER,
                        'high': ViewColors.BLACK_ON_WARNING,
                        'medium': ViewColors.BLACK_ON_INFO,
                        'low': ViewColors.BLACK_ON_SUCCESS,
                        'info': ViewColors.DARK_GRAY,
                    }
                    color = color_map.get(sev, ViewColors.DARK_GRAY)
                    
                    # Store severity info (we'll draw separately)
                    severity_parts.append((sev.upper()[:1], cnt, color))
            
            # Draw count and severity breakdown
            start_x = 18
            self.terminal.draw_text(start_x, y_pos + i, count_text, ViewColors.DARK_GRAY)
            
            # Draw severity indicators
            indicator_x = start_x + len(count_text) + 2
            for sev_char, cnt, color in severity_parts:
                if cnt > 0:
                    self.terminal.draw_text(indicator_x, y_pos + i, 
                                           f"{sev_char}:{cnt}", color)
                    indicator_x += 6
    
    def _show_chart_view(self):
        """Show chart/graph view of results"""
        self.terminal.draw_box(1, 1, self.terminal.width - 2, self.terminal.height - 2, 
                              "Statistics Charts", "double")
        
        # Draw bar chart for severity distribution
        chart_x = 5
        chart_y = 5
        chart_width = 60
        chart_height = 15
        
        self.terminal.draw_text(chart_x, chart_y - 1, "Severity Distribution", ViewColors.BLACK_BOLD)
        
        # Draw chart background
        self.terminal.draw_box(chart_x, chart_y, chart_width, chart_height, "", "single")
        
        # Calculate bar heights
        max_count = max(self.stats[sev] for sev in ['critical', 'high', 'medium', 'low', 'info'])
        if max_count > 0:
            bar_scale = (chart_height - 2) / max_count
        else:
            bar_scale = 1
        
        # Draw bars
        severities = ['critical', 'high', 'medium', 'low', 'info']
        bar_width = chart_width // (len(severities) + 1)
        
        for i, severity in enumerate(severities):
            count = self.stats[severity]
            if count == 0:
                continue
            
            bar_x = chart_x + 2 + i * bar_width
            bar_height = int(count * bar_scale)
            bar_y = chart_y + chart_height - 2 - bar_height
            
            # Bar color
            color_map = {
                'critical': ViewColors.BLACK_ON_DANGER,
                'high': ViewColors.BLACK_ON_WARNING,
                'medium': ViewColors.BLACK_ON_INFO,
                'low': ViewColors.BLACK_ON_SUCCESS,
                'info': ViewColors.DARK_GRAY,
            }
            color = color_map.get(severity, ViewColors.DARK_GRAY)
            
            # Draw bar
            for h in range(bar_height):
                self.terminal.draw_text(bar_x, bar_y + h, "█" * (bar_width - 2), color)
            
            # Draw label
            label_y = chart_y + chart_height - 1
            self.terminal.draw_text(bar_x, label_y, severity.upper()[:3], ViewColors.DARK_GRAY)
            
            # Draw count
            if bar_height >= 2:
                count_y = bar_y + bar_height // 2
                self.terminal.draw_text(bar_x, count_y, str(count), ViewColors.BLACK_BOLD)
        
        # Draw pie chart (simplified ASCII)
        pie_x = chart_width + 10
        pie_y = chart_y
        
        self.terminal.draw_text(pie_x, pie_y - 1, "Severity Percentage", ViewColors.BLACK_BOLD)
        
        # Draw pie chart segments
        total = self.stats['total']
        if total > 0:
            angles = {}
            current_angle = 0
            
            for severity in severities:
                count = self.stats[severity]
                if count > 0:
                    percentage = (count / total) * 100
                    angle = (percentage / 100) * 360
                    angles[severity] = (current_angle, current_angle + angle)
                    current_angle += angle
            
            # Draw simplified pie chart
            pie_chars = ["◴", "◷", "◶", "◵", "○", "●", "◐", "◑", "◒", "◓"]
            pie_char = pie_chars[int(time.time()) % len(pie_chars)]
            
            self.terminal.draw_text(pie_x + 5, pie_y + 3, pie_char, ViewColors.BLACK_BOLD)
            
            # Draw legend
            legend_y = pie_y + 8
            for severity in severities:
                count = self.stats[severity]
                if count > 0:
                    percentage = self.stats.get(f'{severity}_percent', 0)
                    
                    color_map = {
                        'critical': ViewColors.BLACK_ON_DANGER,
                        'high': ViewColors.BLACK_ON_WARNING,
                        'medium': ViewColors.BLACK_ON_INFO,
                        'low': ViewColors.BLACK_ON_SUCCESS,
                        'info': ViewColors.DARK_GRAY,
                    }
                    color = color_map.get(severity, ViewColors.DARK_GRAY)
                    
                    legend_text = f"{severity.upper():<10} {percentage:5.1f}% ({count})"
                    self.terminal.draw_text(pie_x, legend_y, legend_text, color)
                    legend_y += 1
    
    def _show_export_view(self):
        """Show export options"""
        self.terminal.draw_box(1, 1, self.terminal.width - 2, self.terminal.height - 2, 
                              "Export Results", "double")
        
        export_options = [
            ("JSON", "Export as JSON format", "F1"),
            ("HTML", "Export as HTML report", "F2"),
            ("PDF", "Export as PDF document", "F3"),
            ("CSV", "Export as CSV spreadsheet", "F4"),
            ("XML", "Export as XML format", "F5"),
            ("Markdown", "Export as Markdown", "F6"),
            ("Console", "Print to console", "F7"),
            ("Custom", "Custom export format", "F8"),
        ]
        
        start_y = 5
        for i, (format_name, description, shortcut) in enumerate(export_options):
            y_pos = start_y + i * 2
            
            # Draw option box
            self.terminal.draw_box(5, y_pos, 30, 2)
            
            # Draw format name
            self.terminal.draw_text(7, y_pos + 1, format_name, ViewColors.BLACK_BOLD)
            
            # Draw shortcut
            self.terminal.draw_text(15, y_pos + 1, shortcut, ViewColors.BLACK_ON_HIGHLIGHT)
            
            # Draw description
            self.terminal.draw_text(37, y_pos + 1, description, ViewColors.DIM_GRAY)
        
        # Draw export settings
        settings_y = start_y + len(export_options) * 2 + 2
        self.terminal.draw_text(5, settings_y, "Export Settings:", ViewColors.BLACK_BOLD)
        
        settings = [
            ("Include Timestamp", "[X]"),
            ("Compress Output", "[ ]"),
            ("Include Evidence", "[X]"),
            ("Anonymize Data", "[ ]"),
            ("Export All Data", "[X]"),
        ]
        
        for i, (setting, value) in enumerate(settings):
            y_pos = settings_y + i + 1
            self.terminal.draw_text(7, y_pos, f"{setting:<20} {value}", ViewColors.DARK_GRAY)
        
        # Draw action buttons
        action_y = self.terminal.height - 4
        actions = [
            ("Enter", "Export Selected"),
            ("Space", "Toggle Setting"),
            ("Esc", "Back"),
        ]
        
        action_x = 5
        for key, label in actions:
            self.terminal.draw_box(action_x, action_y, len(label) + 4, 1)
            self.terminal.draw_text(action_x + 2, action_y, label, ViewColors.BLACK_ON_HIGHLIGHT)
            self.terminal.draw_text(action_x + 1, action_y - 1, key, ViewColors.BLACK_BOLD)
            action_x += len(label) + 8

# ============================================
# VIEW MODULE EXPORTS
# ============================================

__all__ = [
    'AdvancedMenu',
    'ResultsDisplay',
    'TerminalManager',
    'ViewColors',
    'ComponentType',
    'AnimationType',
    'UIComponent',
]

# Example usage
if __name__ == "__main__":
    print(f"{ViewColors.ON_CHARCOAL}{ViewColors.BLACK_BOLD}{' TESTING VIEW MODULES ':{'═'}^80}{ViewColors.RESET}")
    
    # Test Terminal Manager
    print(f"\n{ViewColors.BLACK_BOLD}[*] Testing Terminal Manager...{ViewColors.RESET}")
    term = TerminalManager()
    term.clear()
    
    # Draw some test elements
    term.draw_box(5, 5, 40, 10, "Test Box", "double")
    term.draw_text(10, 7, "Hello, Advanced Scanner!", ViewColors.BLACK_BOLD)
    term.draw_progress_bar(10, 9, 30, 0.65, "Scan Progress")
    
    # Test Menu System
    print(f"\n{ViewColors.BLACK_BOLD}[*] Testing Menu System...{ViewColors.RESET}")
    
    def test_action():
        print(f"{ViewColors.BLACK_ON_SUCCESS}[+] Menu item selected!{ViewColors.RESET}")
    
    menu = AdvancedMenu("Test Menu", 80, 24)
    
    # Add categories
    menu.add_category("Scanning")
    menu.add_item("quick_scan", "Quick Scan", test_action, "⚡", "F1")
    menu.add_item("full_scan", "Full Scan", test_action, "🔍", "F2")
    menu.add_item("custom_scan", "Custom Scan", test_action, "⚙️", "F3")
    
    menu.add_separator()
    menu.add_category("Analysis")
    menu.add_item("view_results", "View Results", test_action, "📊", "F4")
    menu.add_item("export_results", "Export Results", test_action, "💾", "F5")
    
    menu.add_separator("Tools")
    menu.add_item("network_tools", "Network Tools", test_action, "🌐", "F6")
    menu.add_item("security_tools", "Security Tools", test_action, "🛡️", "F7")
    
    # In a real application, you would run menu.display()
    # For testing, just show the structure
    print(f"{ViewColors.DARK_GRAY}[*] Menu created with {len(menu.items)} items{ViewColors.RESET}")
    
    # Test Results Display
    print(f"\n{ViewColors.BLACK_BOLD}[*] Testing Results Display...{ViewColors.RESET}")
    
    # Create sample results
    sample_results = {
        'metadata': {
            'target': 'https://example.com',
            'start_time': '2024-01-18 10:00:00',
            'duration': '00:15:30',
            'scanner_name': 'Advanced Scanner',
            'scanner_version': '4.0.0',
            'total_requests': 1250,
        },
        'vulnerabilities': [
            {
                'type': 'SQL Injection',
                'severity': 'critical',
                'affected_url': 'https://example.com/login.php',
                'affected_parameter': 'username',
                'cvss_score': 9.8,
                'discovery_date': '2024-01-18 10:05:00',
                'status': 'Open',
            },
            {
                'type': 'XSS',
                'severity': 'high',
                'affected_url': 'https://example.com/search.php',
                'affected_parameter': 'q',
                'cvss_score': 7.5,
                'discovery_date': '2024-01-18 10:10:00',
                'status': 'Open',
            },
            {
                'type': 'Information Disclosure',
                'severity': 'medium',
                'affected_url': 'https://example.com/api/users',
                'affected_parameter': None,
                'cvss_score': 5.0,
                'discovery_date': '2024-01-18 10:15:00',
                'status': 'Fixed',
            },
        ]
    }
    
    results_display = ResultsDisplay(term)
    results_display.set_results(sample_results)
    
    # In a real application, you would run results_display.display('summary')
    # For testing, just show that it's ready
    print(f"{ViewColors.DARK_GRAY}[*] Results Display ready with {len(sample_results['vulnerabilities'])} vulnerabilities{ViewColors.RESET}")
    
    print(f"\n{ViewColors.BLACK_ON_CHARCOAL}{' VIEW MODULES READY ':{'═'}^80}{ViewColors.RESET}")