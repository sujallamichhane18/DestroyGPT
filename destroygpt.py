#!/usr/bin/env python3
"""
Advanced DestroyGPT CLI - Enhanced and Fixed Version

Key Improvements:
1. Fixed logging import and setup
2. Enhanced security checks
3. Better error handling
4. Improved command validation
5. Streamlined execution flow
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
from typing import List, Optional, Tuple, Dict

import requests
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

# -------------------------
# Configuration / Constants
# -------------------------

APP_NAME = "DestroyGPT-Advanced"
VERSION = "2.0"
HOME = Path.home()
CONFIG_DIR = HOME / ".destroygpt"
API_KEY_FILE = CONFIG_DIR / "api_key"
HISTORY_FILE = CONFIG_DIR / "history.json"
LOG_FILE = CONFIG_DIR / "destroygpt.log"
API_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_MODEL = "deepseek/deepseek-r1:free"
STREAM_TIMEOUT = 120
COMMAND_TIMEOUT_SEC = 180
HISTORY_MAX_ENTRIES = 5000
MAX_COMMAND_LENGTH = 2000

# Initialize logging
logger = logging.getLogger(APP_NAME)

# Whitelist of allowed commands
SAFE_COMMANDS = {
    "nmap", "masscan", "curl", "wget", "nc", "netcat", "ssh",
    "python", "python3", "bash", "chmod", "chown", "systemctl", "service",
    "ip", "ifconfig", "tcpdump", "dig", "host", "traceroute", "whoami", "id",
    "uname", "cat", "grep", "awk", "sed", "find", "ls", "ps", "kill", "docker",
    "kubectl", "helm", "git", "java", "node", "pip", "pip3", "jq", "openssl",
}

# Blacklist patterns
BLACKLIST_PATTERNS = [
    r"rm\s+-rf\s+/",
    r"rm\s+-rf\s+",
    r":\s*\(\s*\)\s*{\s*:\s*|\s*&\s*};?",
    r"dd\s+if=",
    r"mkfs\.",
    r"shutdown\b",
    r"reboot\b",
    r":>\s*/",
    r"chmod\s+0+\s+/",
]
BLACKLIST_REGEX = [re.compile(x, re.IGNORECASE) for x in BLACKLIST_PATTERNS]

# Danger keywords
DANGER_KEYWORDS = {
    "rm", "dd", "mkfs", "shutdown", "reboot", "poweroff", "format", "forkbomb"
}

SYSTEM_PROMPT = (
    "You are DestroyGPT, an advanced CLI assistant for ethical hackers.\n"
    "When asked to scan or exploit, reply ONLY with runnable bash commands.\n"
    "Use sudo where necessary. Commands may be multiline with backslashes (\\)."
)

# Initialize console
console = Console()

# -------------------------
# Setup Functions
# -------------------------

def setup_logging(verbosity: int = 1) -> None:
    """Configure logging with rotation and proper formatting."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_DIR.chmod(0o700)

    logger.setLevel(logging.DEBUG)
    
    # File handler with rotation
    fh = RotatingFileHandler(
        LOG_FILE,
        maxBytes=2_000_000,
        backupCount=3,
        encoding='utf-8'
    )
    fh.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s",
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
        logger.info("API key saved successfully")
    except Exception as e:
        logger.error(f"Failed to save API key: {e}")
        raise

def load_api_key() -> Optional[str]:
    """Load API key from environment or file."""
    env_key = os.getenv("OPENROUTER_API_KEY")
    if env_key:
        return env_key.strip()
    
    if API_KEY_FILE.exists():
        try:
            return API_KEY_FILE.read_text().strip()
        except Exception as e:
            logger.error(f"Failed to read API key: {e}")
    return None

# -------------------------
# Security Functions
# -------------------------

def validate_command(cmd: str) -> Tuple[bool, List[str]]:
    """Validate command against security rules."""
    reasons = []
    
    # Length check
    if len(cmd) > MAX_COMMAND_LENGTH:
        reasons.append(f"Command exceeds maximum length ({MAX_COMMAND_LENGTH} chars)")
    
    # Blacklist check
    for rx in BLACKLIST_REGEX:
        if rx.search(cmd):
            reasons.append(f"Matches blacklist pattern: {rx.pattern}")
    
    # Base command extraction
    try:
        parts = shlex.split(cmd.strip())
        base_cmd = parts[0].lower() if parts else None
    except ValueError:
        base_cmd = cmd.strip().split()[0].lower() if cmd.strip() else None
    
    # Whitelist check
    if base_cmd and base_cmd not in SAFE_COMMANDS:
        reasons.append(f"Command not in whitelist: {base_cmd}")
    
    # Executable check
    if base_cmd and not (base_cmd.startswith('/') or base_cmd.startswith('./')):
        if not shutil.which(base_cmd):
            reasons.append(f"Executable not found in PATH: {base_cmd}")
    
    return (len(reasons) == 0, reasons)

def contains_danger_keywords(cmd: str) -> bool:
    """Check if command contains dangerous keywords."""
    cmd_lower = cmd.lower()
    return any(kw in cmd_lower for kw in DANGER_KEYWORDS)

# -------------------------
# Command Processing
# -------------------------

def parse_commands(raw: str) -> List[str]:
    """Parse commands from AI response."""
    commands = []
    current_command = []
    
    for line in raw.splitlines():
        line = line.strip()
        
        # Skip empty lines and code fences
        if not line or line.startswith('```'):
            continue
            
        # Remove leading markers
        line = re.sub(r'^\s*[>-]\s*', '', line)
        
        # Handle line continuations
        if line.endswith('\\'):
            current_command.append(line[:-1].strip())
            continue
        
        # Complete current command
        if current_command:
            current_command.append(line)
            commands.append(' '.join(current_command))
            current_command = []
        else:
            commands.append(line)
    
    # Add any remaining command parts
    if current_command:
        commands.append(' '.join(current_command))
    
    return commands

# -------------------------
# API Communication
# -------------------------

def query_ai(api_key: str, prompt: str, model: str = DEFAULT_MODEL) -> Optional[str]:
    """Query the AI API with streaming support."""
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "X-Title": f"{APP_NAME}/{VERSION}",
    }
    
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "stream": True,
    }
    
    try:
        response = requests.post(
            API_URL,
            headers=headers,
            json=payload,
            stream=True,
            timeout=30
        )
        response.raise_for_status()
        
        buffer = []
        last_activity = time.time()
        
        for line in response.iter_lines():
            if time.time() - last_activity > STREAM_TIMEOUT:
                logger.warning("Stream timeout reached")
                break
                
            if line:
                last_activity = time.time()
                content = parse_stream_line(line)
                if content:
                    buffer.append(content)
                    console.print(content, end="", style="bold green")
        
        console.print()
        return ''.join(buffer)
        
    except requests.exceptions.RequestException as e:
        logger.error(f"API request failed: {e}")
        console.print(f"[red]API Error: {e}[/red]")
        return None

def parse_stream_line(line: bytes) -> Optional[str]:
    """Parse a single line from the streaming response."""
    try:
        line = line.decode('utf-8').strip()
        if not line or line == "data: [DONE]":
            return None
            
        if line.startswith("data:"):
            line = line[5:].strip()
        
        data = json.loads(line)
        choices = data.get("choices", [])
        for choice in choices:
            if "delta" in choice:
                return choice["delta"].get("content", "")
            if "message" in choice:
                return choice["message"].get("content", "")
    except Exception:
        return None
    return None

# -------------------------
# Command Execution
# -------------------------

def execute_command(cmd: str, use_docker: bool = False) -> Tuple[int, str, str]:
    """Execute a command with optional Docker sandboxing."""
    if use_docker and shutil.which("docker"):
        safe_cmd = shlex.quote(cmd)
        docker_cmd = (
            "docker run --rm --network none --security-opt no-new-privileges "
            f"-v /tmp:/tmp ubuntu:22.04 bash -c {safe_cmd}"
        )
        cmd_to_exec = docker_cmd
    else:
        cmd_to_exec = cmd
    
    logger.info(f"Executing: {cmd_to_exec}")
    
    try:
        proc = subprocess.Popen(
            cmd_to_exec,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            executable="/bin/bash",
        )
        
        stdout, stderr = proc.communicate(timeout=COMMAND_TIMEOUT_SEC)
        return proc.returncode, stdout, stderr
        
    except subprocess.TimeoutExpired:
        proc.kill()
        return -1, "", "Command timed out"
    except Exception as e:
        logger.error(f"Command execution failed: {e}")
        return -2, "", str(e)

# -------------------------
# History Management
# -------------------------

def load_history() -> List[Dict]:
    """Load command history from file."""
    if HISTORY_FILE.exists():
        try:
            with open(HISTORY_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load history: {e}")
    return []

def save_history(history: List[Dict]) -> None:
    """Save command history to file."""
    try:
        with open(HISTORY_FILE, 'w') as f:
            json.dump(history[-HISTORY_MAX_ENTRIES:], f)
    except Exception as e:
        logger.error(f"Failed to save history: {e}")

# -------------------------
# Main Application
# -------------------------

def main():
    parser = argparse.ArgumentParser(description=f"{APP_NAME} - Advanced CLI Assistant")
    parser.add_argument("--no-save-key", action="store_true", help="Don't save API key to disk")
    parser.add_argument("--use-docker", action="store_true", help="Use Docker sandbox when available")
    parser.add_argument("--dry-run", action="store_true", help="Show commands without executing")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Model to use")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity")
    args = parser.parse_args()
    
    setup_logging(args.verbose)
    logger.info(f"Starting {APP_NAME} v{VERSION}")
    
    # API Key handling
    api_key = load_api_key()
    if not api_key:
        console.print("[bold]OpenRouter API Key required[/bold]")
        api_key = getpass.getpass("API Key: ").strip()
        if not api_key:
            console.print("[red]API key is required[/red]")
            sys.exit(1)
        if not args.no_save_key:
            save_api_key(api_key)
    
    history = load_history()
    
    console.print(f"[bold green]{APP_NAME} v{VERSION}[/bold green]")
    console.print("Type 'exit' to quit. Commands will be shown for confirmation before execution.")
    
    while True:
        try:
            prompt = Prompt.ask("[bold cyan]>>>[/bold cyan]").strip()
            if not prompt:
                continue
            if prompt.lower() in ('exit', 'quit'):
                break
            
            console.print("[dim]Querying AI...[/dim]")
            response = query_ai(api_key, prompt, args.model)
            if not response:
                continue
            
            commands = parse_commands(response)
            if not commands:
                console.print("[yellow]No valid commands found in response[/yellow]")
                continue
            
            # Add to history
            history.append({
                "timestamp": datetime.now().isoformat(),
                "prompt": prompt,
                "commands": commands
            })
            save_history(history)
            
            # Display commands
            table = Table(title="Generated Commands", show_lines=True)
            table.add_column("#", style="cyan")
            table.add_column("Command", style="magenta")
            for i, cmd in enumerate(commands):
                table.add_row(str(i), cmd)
            console.print(table)
            
            # Command execution
            if args.dry_run:
                console.print("[cyan]Dry run mode - no commands executed[/cyan]")
                continue
                
            if Confirm.ask("Execute these commands?", default=False):
                indices = Prompt.ask(
                    "Which commands? (comma/range, e.g. 0,2 or 0-2)",
                    default="all"
                )
                
                selected = set()
                if indices.lower() == 'all':
                    selected = set(range(len(commands)))
                else:
                    for part in indices.split(','):
                        part = part.strip()
                        if '-' in part:
                            start, end = map(int, part.split('-'))
                            selected.update(range(start, end + 1))
                        elif part.isdigit():
                            selected.add(int(part))
                
                for idx in sorted(selected):
                    if 0 <= idx < len(commands):
                        cmd = commands[idx]
                        
                        # Validate command
                        is_safe, reasons = validate_command(cmd)
                        if not is_safe:
                            console.print(f"[red]Command {idx} blocked: {', '.join(reasons)}[/red]")
                            continue
                            
                        if contains_danger_keywords(cmd):
                            console.print(f"[bold red]DANGER: Command {idx} contains dangerous operations[/bold red]")
                            if not Confirm.ask(f"Really execute command {idx}?", default=False):
                                continue
                        
                        console.print(Panel(cmd, title=f"Executing Command {idx}", style="yellow"))
                        exit_code, stdout, stderr = execute_command(cmd, args.use_docker)
                        
                        if stdout:
                            console.print(Panel(stdout, title="Output", style="green"))
                        if stderr:
                            console.print(Panel(stderr, title="Error", style="red"))
                        
                        if exit_code == 0:
                            console.print(f"[green]Command {idx} completed successfully[/green]")
                        else:
                            console.print(f"[red]Command {idx} failed with code {exit_code}[/red]")
                    else:
                        console.print(f"[yellow]Invalid command index: {idx}[/yellow]")
            
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted - use 'exit' to quit[/yellow]")
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            console.print(f"[red]Error: {e}[/red]")
    
    console.print("[bold green]Session ended[/bold green]")

if __name__ == "__main__":
    main()
