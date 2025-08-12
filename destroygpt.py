#!/usr/bin/env python3
"""
Advanced AI Assistant CLI for Ethical Hackers (Enhanced)

Key Improvements:
1. Enhanced security with multi-layer command validation
2. Improved stream parsing with better error handling
3. More comprehensive safety checks
4. Better user interface with color-coded output
5. Additional utility functions for ethical hacking
6. Improved configuration management
7. More robust command execution
8. Better documentation and type hints
"""

#!/usr/bin/env python3
"""
Advanced DestroyGPT CLI (refactor)
"""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import List, Optional, Tuple

import requests
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

# Setup logging
logger = logging.getLogger(__name__)

# Rest of your code...

# -------------------------
# Configuration / Constants
# -------------------------

class SecurityLevel(Enum):
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()

APP_NAME = "EthicalHackerAI"
VERSION = "2.1.0"
HOME = Path.home()
CONFIG_DIR = HOME / ".config" / APP_NAME
API_KEY_FILE = CONFIG_DIR / "api_key"
HISTORY_FILE = CONFIG_DIR / "history.json"
LOG_FILE = CONFIG_DIR / "hacker_ai.log"
API_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_MODEL = "deepseek/deepseek-r1:free"
STREAM_TIMEOUT = 120
COMMAND_TIMEOUT_SEC = 180
HISTORY_MAX_ENTRIES = 5000
MAX_COMMAND_LENGTH = 1000

# Enhanced command lists with categories
NETWORK_COMMANDS = {
    "nmap", "masscan", "curl", "wget", "nc", "netcat", "ssh", "scp", "rsync",
    "tcpdump", "dig", "host", "traceroute", "tracepath", "mtr", "ping", "arp",
    "netstat", "ss", "telnet", "socat", "openssl", "ncat", "nslookup", "whois"
}

SYSTEM_COMMANDS = {
    "ls", "ps", "top", "htop", "kill", "pkill", "pgrep", "df", "du", "mount",
    "umount", "lsof", "journalctl", "dmesg", "vmstat", "iostat", "mpstat",
    "lscpu", "free", "uname", "whoami", "id", "groups", "last", "lastlog",
    "w", "who", "uptime", "date", "timedatectl", "systemctl", "service",
    "chmod", "chown", "chattr", "lsattr", "getfacl", "setfacl", "ip", "ifconfig"
}

ANALYSIS_COMMANDS = {
    "grep", "awk", "sed", "cut", "sort", "uniq", "wc", "head", "tail", "less",
    "more", "cat", "tac", "rev", "hexdump", "xxd", "objdump", "strings",
    "file", "ldd", "nm", "readelf", "strace", "ltrace", "perf", "stat"
}

DEVELOPMENT_COMMANDS = {
    "python", "python3", "pip", "pip3", "git", "gcc", "g++", "make", "cmake",
    "gdb", "lldb", "valgrind", "javac", "java", "node", "npm", "go", "rustc",
    "cargo", "ruby", "gem", "php", "composer", "perl", "bash", "sh", "zsh",
    "fish", "dash", "sqlite3", "mysql", "psql"
}

CONTAINER_COMMANDS = {
    "docker", "docker-compose", "podman", "kubectl", "helm", "ctr", "nerdctl"
}

SAFE_COMMANDS = NETWORK_COMMANDS | SYSTEM_COMMANDS | ANALYSIS_COMMANDS | DEVELOPMENT_COMMANDS | CONTAINER_COMMANDS

# Enhanced blacklist patterns
BLACKLIST_PATTERNS = [
    r"rm\s+-rf\s+/",  # Recursive delete root
    r"rm\s+-rf\s+.*(/etc|/boot|/dev|/proc|/sys)",  # Critical system dirs
    r":\s*\(\s*\)\s*{\s*:\s*|\s*&\s*};?",  # Fork bomb variants
    r"dd\s+if=.*of=/dev/",  # Disk destruction
    r"mkfs\..*\s+/dev/",  # Filesystem creation on devices
    r"(shutdown|reboot|poweroff|halt)\b",  # System shutdown
    r":>\s*/",  # Truncate root files
    r"chmod\s+0+\s+/",  # Permission destruction
    r"mv\s+/.*\s+/dev/null",  # Moving to null
    r">\s*/dev/sd[a-z]\d*",  # Direct disk writing
    r"echo\s+.+\s+>\s*/proc/sysrq-trigger",  # Kernel triggers
    r"sysctl\s+-w\s+kernel\.",  # Dangerous kernel params
    r"setfacl\s+-R\s+-m\s+u::rwx\s+/",  # Permission escalation
    r"nc\s+-l\s+-p\s+\d+\s+-e\s+/bin/sh",  # Reverse shell
    r"python\s+-c\s+'.*subprocess\.call\(.*\)'"  # Python subprocess abuse
]

BLACKLIST_REGEX = [re.compile(x, re.IGNORECASE) for x in BLACKLIST_PATTERNS]

# Danger keywords that require manual confirmation
DANGER_KEYWORDS = {
    "rm", "dd", "mkfs", "shutdown", "reboot", "poweroff", "format", 
    "forkbomb", "overwrite", "wipe", "zero", "null", "drop", "table",
    "alter", "delete", "update", "insert", "truncate", "kill", "signal"
}

SYSTEM_PROMPT = (
    "You are an advanced CLI assistant for ethical hackers and security professionals.\n"
    "When asked to perform security testing or system operations, reply ONLY with:\n"
    "- Valid, runnable bash commands (one per line)\n"
    "- No explanations or markdown formatting\n"
    "- Use sudo where necessary\n"
    "- Include safety checks where appropriate\n\n"
    "For complex tasks, use multiline commands with backslashes (\\).\n"
    "Always prefer non-destructive operations first."
)

# -------------------------
# Logging & Utilities
# -------------------------

def ensure_config_dir() -> None:
    """Ensure configuration directory exists with proper permissions."""
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_DIR.chmod(0o700)
    except Exception as e:
        logger.error(f"Failed to create config directory: {e}")
        raise

def setup_logging(verbosity: int = 1) -> None:
    """Setup logging with rotation and proper formatting."""
    ensure_config_dir()
    
    logger = logging.getLogger(APP_NAME)
    logger.setLevel(logging.DEBUG)
    
    # File handler with rotation
    fh = RotatingFileHandler(
        str(LOG_FILE), 
        maxBytes=5_000_000, 
        backupCount=3,
        encoding='utf-8'
    )
    fh.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        "%(asctime)s [%(levelname)-8s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    fh.setFormatter(file_formatter)
    logger.addHandler(fh)

    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.WARNING if verbosity < 1 else logging.INFO)
    console_formatter = logging.Formatter("[%(levelname)s] %(message)s")
    ch.setFormatter(console_formatter)
    logger.addHandler(ch)

def save_api_key(api_key: str) -> None:
    """Securely save API key to disk."""
    try:
        API_KEY_FILE.write_text(api_key)
        API_KEY_FILE.chmod(0o600)
        logger.info("API key saved securely")
    except Exception as e:
        logger.error(f"Failed to save API key: {e}")
        raise

def load_api_key() -> Optional[str]:
    """Load API key from environment or secure storage."""
    # Check environment first
    env_key = os.getenv("OPENROUTER_API_KEY")
    if env_key:
        return env_key.strip()
    
    # Check secure file
    if API_KEY_FILE.exists():
        try:
            return API_KEY_FILE.read_text().strip()
        except Exception as e:
            logger.error(f"Failed to read API key: {e}")
    return None

# -------------------------
# Security Validation
# -------------------------

class CommandValidator:
    """Advanced command validation with multiple security layers."""
    
    @staticmethod
    def validate_length(cmd: str) -> bool:
        """Check command length is reasonable."""
        return len(cmd) <= MAX_COMMAND_LENGTH
    
    @staticmethod
    def contains_blacklist(cmd: str) -> bool:
        """Check if command matches any blacklist pattern."""
        cmd_lower = cmd.lower()
        return any(rx.search(cmd_lower) for rx in BLACKLIST_REGEX)
    
    @staticmethod
    def has_danger_keyword(cmd: str) -> bool:
        """Check for danger keywords with context awareness."""
        words = set(re.findall(r'\b\w+\b', cmd.lower()))
        return bool(words & DANGER_KEYWORDS)
    
    @staticmethod
    def extract_base_command(cmd: str) -> Optional[str]:
        """Safely extract base command with shell parsing."""
        try:
            parts = shlex.split(cmd.strip())
            return parts[0].lower() if parts else None
        except ValueError:
            # Fallback for malformed commands
            first_part = cmd.strip().split()[0] if cmd.strip() else None
            return first_part.lower() if first_part else None
    
    @classmethod
    def is_safe_command(cls, cmd: str) -> Tuple[bool, List[str]]:
        """
        Comprehensive safety check with detailed feedback.
        Returns (is_safe, reasons_if_unsafe)
        """
        reasons = []
        
        if not cls.validate_length(cmd):
            reasons.append(f"Command exceeds max length ({MAX_COMMAND_LENGTH} chars)")
        
        if cls.contains_blacklist(cmd):
            reasons.append("Matches blacklist pattern")
        
        base_cmd = cls.extract_base_command(cmd)
        if not base_cmd:
            reasons.append("No valid command detected")
        
        if base_cmd:
            # Check if command exists in PATH (except for absolute paths)
            if not (base_cmd.startswith('/') or base_cmd.startswith('./')):
                if not shutil.which(base_cmd):
                    reasons.append(f"Command not found in PATH: {base_cmd}")
            
            # Check against whitelist
            if base_cmd not in SAFE_COMMANDS:
                reasons.append(f"Command not in whitelist: {base_cmd}")
        
        return (len(reasons) == 0, reasons)

# -------------------------
# Command Processing
# -------------------------

def parse_ai_response(raw: str) -> List[str]:
    """
    Extract commands from AI response with robust parsing.
    Handles various formats including markdown, plain text, and JSON.
    """
    commands = []
    
    # First try to parse as JSON if it looks like JSON
    if raw.strip().startswith('{') or raw.strip().startswith('['):
        try:
            data = json.loads(raw)
            if isinstance(data, dict) and 'commands' in data:
                return data['commands']
            elif isinstance(data, list):
                return [str(item) for item in data]
        except json.JSONDecodeError:
            pass  # Not JSON, continue with text parsing
    
    # Normalize line endings and remove markdown code fences
    lines = raw.replace('\r\n', '\n').split('\n')
    lines = [line for line in lines if not line.strip().startswith('```')]
    
    # Filter and clean lines
    for line in lines:
        line = line.strip()
        
        # Skip empty lines and comments
        if not line or line.startswith('#'):
            continue
            
        # Remove leading prompts/markers
        line = re.sub(r'^\s*[>\-]\s*', '', line)
        
        # Basic command validation
        if re.match(r'^(\w+|\./|/|sudo|python|bash)', line):
            commands.append(line)
    
    return commands

def group_commands(commands: List[str]) -> List[str]:
    """
    Group multiline commands intelligently.
    Handles line continuations and logical command groupings.
    """
    grouped = []
    current_command = []
    
    for line in commands:
        line = line.rstrip()
        
        # Handle line continuation
        if line.endswith('\\'):
            current_command.append(line[:-1].strip())
            continue
        
        # Complete the current command
        if current_command:
            current_command.append(line)
            grouped.append(' '.join(current_command))
            current_command = []
        else:
            grouped.append(line)
    
    # Add any remaining command parts
    if current_command:
        grouped.append(' '.join(current_command))
    
    return grouped

# -------------------------
# API Communication
# -------------------------

class AICommunicator:
    """Handles all AI API communication with robust error handling."""
    
    def __init__(self, api_key: str, model: str = DEFAULT_MODEL):
        self.api_key = api_key
        self.model = model
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "X-Title": f"{APP_NAME}/{VERSION}",
        })
    
    def query_ai(self, prompt: str) -> Optional[str]:
        """
        Send prompt to AI with streaming and proper timeout handling.
        Returns the raw response text or None on failure.
        """
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "stream": True,
            "temperature": 0.7,
            "max_tokens": 2000,
        }
        
        try:
            response = self.session.post(
                API_URL,
                json=payload,
                stream=True,
                timeout=(10, STREAM_TIMEOUT)  # Connect and read timeouts
            )
            response.raise_for_status()
            
            return self._process_stream(response)
        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed: {e}")
            return None
    
    def _process_stream(self, response: requests.Response) -> str:
        """Process streaming response with proper error handling."""
        buffer = []
        last_activity = time.time()
        
        try:
            for line in response.iter_lines():
                if time.time() - last_activity > STREAM_TIMEOUT:
                    logger.warning("Stream timeout reached")
                    break
                    
                if line:
                    last_activity = time.time()
                    content = self._parse_stream_line(line)
                    if content:
                        buffer.append(content)
        
        except requests.exceptions.ChunkedEncodingError as e:
            logger.warning(f"Stream interrupted: {e}")
        
        return ''.join(buffer)
    
    @staticmethod
    def _parse_stream_line(line: Union[bytes, str]) -> Optional[str]:
        """Parse a single line from the streaming response."""
        if isinstance(line, bytes):
            line = line.decode('utf-8', errors='ignore')
        
        line = line.strip()
        if not line or line == "data: [DONE]":
            return None
            
        # Handle both "data: {...}" and raw JSON
        if line.startswith("data:"):
            line = line[5:].strip()
        
        try:
            data = json.loads(line)
            choices = data.get("choices", [])
            for choice in choices:
                if "delta" in choice:
                    return choice["delta"].get("content", "")
                if "message" in choice:
                    return choice["message"].get("content", "")
        except json.JSONDecodeError:
            return line if line else None
        
        return None

# -------------------------
# Command Execution
# -------------------------

class CommandExecutor:
    """Handles command execution with safety and sandboxing options."""
    
    def __init__(self, security_level: SecurityLevel = SecurityLevel.MEDIUM):
        self.security_level = security_level
        self.use_docker = shutil.which("docker") is not None
        self.console = Console()
    
    def execute(self, command: str, confirm: bool = True) -> Tuple[int, str, str]:
        """
        Execute a command with safety checks and optional confirmation.
        Returns (exit_code, stdout, stderr)
        """
        # Validate command first
        is_safe, reasons = CommandValidator.is_safe_command(command)
        
        if not is_safe:
            self.console.print(f"[red]Command blocked: {', '.join(reasons)}[/red]")
            return (-1, "", f"Command blocked: {', '.join(reasons)}")
        
        # Show command details
        self.console.print(Panel(
            command,
            title="Command to Execute",
            style="bright_magenta"
        ))
        
        # Additional warnings for dangerous commands
        if CommandValidator.has_danger_keyword(command):
            self.console.print("[bold red]WARNING: Command contains dangerous operations![/bold red]")
        
        # Require confirmation unless explicitly bypassed
        if confirm and not Confirm.ask("Execute this command?", default=False):
            return (0, "", "Command execution cancelled by user")
        
        # Execute based on security level
        if self.security_level == SecurityLevel.HIGH and self.use_docker:
            return self._execute_in_docker(command)
        else:
            return self._execute_direct(command)
    
    def _execute_direct(self, command: str) -> Tuple[int, str, str]:
        """Execute command directly on host system."""
        try:
            proc = subprocess.Popen(
                command,
                shell=True,
                executable="/bin/bash",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True
            )
            
            try:
                stdout, stderr = proc.communicate(timeout=COMMAND_TIMEOUT_SEC)
                return (proc.returncode, stdout, stderr)
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                return (-2, "", "Command timed out")
                
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return (-3, "", str(e))
    
    def _execute_in_docker(self, command: str) -> Tuple[int, str, str]:
        """Execute command in a disposable Docker container."""
        safe_cmd = shlex.quote(command)
        docker_cmd = (
            "docker run --rm --network none --cap-drop ALL "
            "--security-opt no-new-privileges "
            "-v /tmp:/tmp:ro "  # Read-only temp access
            "ubuntu:22.04 bash -c {}".format(safe_cmd)
        )
        
        return self._execute_direct(docker_cmd)

# -------------------------
# Main Application
# -------------------------

class HackerAICLI:
    """Main application class for the Ethical Hacker AI CLI."""
    
    def __init__(self):
        self.console = Console()
        self.history = []
        self.ai = None
        self.executor = None
        self.running = False
    
    def initialize(self, args) -> bool:
        """Initialize the application with command line args."""
        try:
            setup_logging(args.verbosity)
            logger.info(f"Starting {APP_NAME} v{VERSION}")
            
            # Load or request API key
            api_key = load_api_key()
            if not api_key:
                self.console.print("[bold]OpenRouter API Key required[/bold]")
                api_key = getpass.getpass("API Key: ").strip()
                if not api_key:
                    self.console.print("[red]API key is required[/red]")
                    return False
                
                if not args.no_save_key:
                    save_api_key(api_key)
            
            # Initialize components
            self.ai = AICommunicator(api_key, args.model)
            
            security_level = {
                0: SecurityLevel.LOW,
                1: SecurityLevel.MEDIUM,
                2: SecurityLevel.HIGH
            }.get(args.security, SecurityLevel.MEDIUM)
            
            self.executor = CommandExecutor(security_level)
            
            # Load command history
            self._load_history()
            return True
            
        except Exception as e:
            logger.critical(f"Initialization failed: {e}")
            self.console.print(f"[red]Error: {e}[/red]")
            return False
    
    def run(self):
        """Main application loop."""
        self.running = True
        self._show_banner()
        
        while self.running:
            try:
                user_input = Prompt.ask("[bold cyan]HackerAI>[/bold cyan]").strip()
                
                if not user_input:
                    continue
                    
                if user_input.lower() in ('exit', 'quit'):
                    self.running = False
                    continue
                
                # Process special commands
                if user_input.startswith('!'):
                    self._handle_special_command(user_input)
                    continue
                
                # Query AI and process response
                self._process_user_query(user_input)
                
            except KeyboardInterrupt:
                self.console.print("\n[yellow]Use 'exit' to quit[/yellow]")
            except Exception as e:
                logger.error(f"Unexpected error: {e}")
                self.console.print(f"[red]Error: {e}[/red]")
        
        self.console.print("[bold green]Session ended[/bold green]")
    
    def _show_banner(self):
        """Display application banner."""
        banner = f"""[bold blue]
        ╔══════════════════════════════════════════════╗
        ║  [bold white]Ethical Hacker AI Assistant v{VERSION}[/bold white]  ║
        ║  [bright_black]Type '!help' for special commands[/bright_black]    ║
        ╚══════════════════════════════════════════════╝
        [/bold blue]"""
        self.console.print(banner)
    
    def _load_history(self):
        """Load command history from file."""
        try:
            if HISTORY_FILE.exists():
                with open(HISTORY_FILE, 'r') as f:
                    self.history = json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load history: {e}")
    
    def _save_history(self):
        """Save command history to file."""
        try:
            with open(HISTORY_FILE, 'w') as f:
                json.dump(self.history[-HISTORY_MAX_ENTRIES:], f)
        except Exception as e:
            logger.warning(f"Failed to save history: {e}")
    
    def _handle_special_command(self, cmd: str):
        """Process special commands starting with !"""
        if cmd == '!help':
            self._show_help()
        elif cmd == '!history':
            self._show_history()
        elif cmd == '!clear':
            self.history = []
            self.console.print("[green]History cleared[/green]")
        elif cmd == '!models':
            self._list_models()
        else:
            self.console.print(f"[red]Unknown command: {cmd}[/red]")
    
    def _show_help(self):
        """Display help information."""
        help_text = """[bold]Special Commands:[/bold]
  [cyan]!help[/cyan]       - Show this help
  [cyan]!history[/cyan]    - Show command history
  [cyan]!clear[/cyan]      - Clear history
  [cyan]!models[/cyan]     - List available AI models
  [cyan]exit[/cyan]        - Quit the application

[bold]Usage Tips:[/bold]
- Be specific in your requests
- For complex tasks, break them into steps
- Review commands before execution
"""
        self.console.print(Panel(help_text, title="Help"))
    
    def _process_user_query(self, query: str):
        """Process a user query through the AI and handle the response."""
        self.console.print("[dim]Consulting AI...[/dim]")
        
        response = self.ai.query_ai(query)
        if not response:
            self.console.print("[red]No response from AI[/red]")
            return
        
        # Parse and display commands
        commands = parse_ai_response(response)
        grouped_commands = group_commands(commands)
        
        if not grouped_commands:
            self.console.print("[yellow]No valid commands found in response[/yellow]")
            return
        
        # Add to history
        self.history.append({
            "timestamp": datetime.now().isoformat(),
            "query": query,
            "commands": grouped_commands
        })
        self._save_history()
        
        # Display commands in a table
        table = Table(title="Generated Commands", show_lines=True)
        table.add_column("#", style="cyan")
        table.add_column("Command", style="magenta")
        
        for i, cmd in enumerate(grouped_commands):
            table.add_row(str(i), cmd)
        
        self.console.print(table)
        
        # Prompt for execution
        if Confirm.ask("Execute any commands?", default=False):
            self._execute_commands_interactive(grouped_commands)
    
    def _execute_commands_interactive(self, commands: List[str]):
        """Interactive command execution with selection."""
        selection = Prompt.ask(
            "Enter command numbers (e.g. 0, 1-3)",
            default="all"
        )
        
        selected = set()
        
        # Parse selection
        if selection.lower() == 'all':
            selected = set(range(len(commands)))
        else:
            for part in selection.split(','):
                part = part.strip()
                if '-' in part:
                    start, end = map(int, part.split('-'))
                    selected.update(range(start, end + 1))
                elif part.isdigit():
                    selected.add(int(part))
        
        # Execute selected commands
        for idx in sorted(selected):
            if 0 <= idx < len(commands):
                cmd = commands[idx]
                exit_code, stdout, stderr = self.executor.execute(cmd)
                
                # Display results
                if stdout:
                    self.console.print(Panel(stdout, title="Output", style="green"))
                if stderr:
                    self.console.print(Panel(stderr, title="Error", style="red"))
                
                status = "[green]success[/green]" if exit_code == 0 else f"[red]failed ({exit_code})[/red]"
                self.console.print(f"Command {idx} {status}")
            else:
                self.console.print(f"[yellow]Invalid index: {idx}[/yellow]")

# -------------------------
# CLI Entry Point
# -------------------------

def main():
    parser = argparse.ArgumentParser(
        description=f"{APP_NAME} - AI Assistant for Ethical Hackers",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help="AI model to use"
    )
    parser.add_argument(
        "--no-save-key",
        action="store_true",
        help="Don't save API key to disk"
    )
    parser.add_argument(
        "--security",
        type=int,
        choices=[0, 1, 2],
        default=1,
        help="Security level (0=low, 1=medium, 2=high)"
    )
    parser.add_argument(
        "-v", "--verbosity",
        action="count",
        default=0,
        help="Increase logging verbosity"
    )
    
    args = parser.parse_args()
    
    app = HackerAICLI()
    if app.initialize(args):
        app.run()

if __name__ == "__main__":
    main()
