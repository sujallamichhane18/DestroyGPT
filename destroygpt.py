#!/usr/bin/env python3
"""
DestroyGPT v5.0 - Minimal & Functional Shell-based Hacking Assistant
Inspired by ShellGPT - Simple, Fast, Effective
"""

import argparse
import asyncio
import getpass
import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple

import requests
from rich.console import Console

# ─── CONFIG ──────────────────────────────────────────────────────

HOME = Path.home()
API_KEY_FILE = HOME / ".destroygpt_api_key"
HISTORY_FILE = HOME / ".destroygpt_history.json"
LOG_FILE = HOME / ".destroygpt.log"

API_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_MODEL = "openai/gpt-oss-20b"

# Timeout settings
STREAM_TIMEOUT = 60
COMMAND_TIMEOUT = 120
API_TIMEOUT = 30

# ⚠️  WARNING: No restrictions - User can execute ANY command
# Use responsibly and ethically

# ─── SETUP ───────────────────────────────────────────────────────

console = Console()
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(message)s')

# ─── API KEY MANAGEMENT ──────────────────────────────────────────

def get_api_key() -> str:
    """Get API key from file or environment"""
    if os.getenv("OPENROUTER_API_KEY"):
        return os.getenv("OPENROUTER_API_KEY").strip()
    
    if API_KEY_FILE.exists():
        key = API_KEY_FILE.read_text().strip()
        if key:
            return key
    
    console.print("[yellow]🔑 Enter OpenRouter API key (hidden):[/]")
    key = getpass.getpass().strip()
    if key:
        API_KEY_FILE.write_text(key)
        API_KEY_FILE.chmod(0o600)
    return key

# ─── COMMAND SAFETY ──────────────────────────────────────────────

def is_safe(cmd: str) -> bool:
    """No restrictions - allow any command"""
    return True

# ─── LLM CALL ────────────────────────────────────────────────────

def call_llm(api_key: str, prompt: str, model: str = DEFAULT_MODEL) -> Optional[Tuple[str, str]]:
    """Call OpenRouter API with retry logic - returns (command, explanation)"""
    
    system_prompt = """You are an AI Security Assistant that helps with ethical hacking and penetration testing.
For each user request, provide:
1. A practical Linux command to accomplish the task
2. A brief explanation of what it does and why

Format your response EXACTLY as:
COMMAND: <the actual command>
EXPLANATION: <what it does and how it helps>

Examples:

User: scan example.com for open ports
COMMAND: nmap -sV -p- example.com
EXPLANATION: This uses nmap to scan all 65535 ports (-p-) on example.com and identify services (-sV). Helps identify exposed services and vulnerabilities.

User: check ssl certificate
COMMAND: openssl s_client -connect example.com:443 -showcerts
EXPLANATION: This connects to the target on port 443 and displays the SSL certificate chain. Helps check cert validity, expiration, and cipher strength.

User: find subdomains
COMMAND: dnsrecon -d example.com -t std
EXPLANATION: Performs DNS enumeration to discover subdomains. Critical for reconnaissance as subdomains often have weaker security.

User: osint on target
COMMAND: whois example.com && curl -s https://api.shodan.io/shodan/host/1.1.1.1 2>/dev/null
EXPLANATION: Gathers WHOIS data and Shodan info. Useful for finding registered details, IP history, and exposed services.

User: check http headers
COMMAND: curl -I https://example.com
EXPLANATION: Displays HTTP response headers which may reveal server version, security headers, or misconfigurations.

User: enumerate dns records
COMMAND: dig example.com ANY
EXPLANATION: Shows all DNS records (A, MX, TXT, NS). Reveals email servers, name servers, and SPF/DKIM configuration.

User: reverse ip lookup
COMMAND: nslookup -type=PTR 8.8.8.8
EXPLANATION: Performs reverse DNS lookup. Helps identify hostnames associated with IPs.

User: trace network path
COMMAND: traceroute example.com
EXPLANATION: Shows network hops to target. Helps identify infrastructure and potential filtering points.

User: check for sql injection
COMMAND: sqlmap -u "http://example.com/search?q=test" --batch
EXPLANATION: Automated SQL injection detection. Scans parameters for SQL injection vulnerabilities.

Always provide both command AND explanation."""
    
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.1,
        "max_tokens": 300
    }
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.post(API_URL, headers=headers, json=payload, timeout=API_TIMEOUT)
        
        if response.status_code != 200:
            console.print(f"[red]✗ API Error {response.status_code}[/]")
            return None
        
        data = response.json()
        
        # Extract content safely
        if "choices" in data and len(data["choices"]) > 0:
            choice = data["choices"][0]
            if "message" in choice and "content" in choice["message"]:
                content = choice["message"]["content"].strip()
                if content:
                    # Parse COMMAND and EXPLANATION
                    command = ""
                    explanation = ""
                    
                    lines = content.split('\n')
                    for line in lines:
                        if line.startswith("COMMAND:"):
                            command = line.replace("COMMAND:", "").strip()
                        elif line.startswith("EXPLANATION:"):
                            explanation = line.replace("EXPLANATION:", "").strip()
                    
                    if command and explanation:
                        return (command, explanation)
                    elif command:
                        return (command, "")
        
        console.print("[red]✗ Invalid response format[/]")
        return None
    
    except requests.Timeout:
        console.print("[red]✗ Request timeout - try again[/]")
        return None
    except json.JSONDecodeError:
        console.print("[red]✗ Invalid response format[/]")
        return None
    except Exception as e:
        console.print(f"[red]✗ Error: {str(e)[:50]}[/]")
        return None

# ─── COMMAND EXECUTION ───────────────────────────────────────────

def run_cmd(cmd: str, dry_run: bool = False) -> Tuple[str, str, int]:
    """Execute shell command safely"""
    
    if not is_safe(cmd):
        return "", f"⚠ Command blocked: {cmd}", -1
    
    if dry_run:
        return "", f"[DRY RUN] {cmd}", 0
    
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "", f"✗ Timeout after {COMMAND_TIMEOUT}s", -1
    except Exception as e:
        return "", f"✗ Error: {e}", -1

# ─── HISTORY ─────────────────────────────────────────────────────

def load_history() -> list:
    """Load command history"""
    if HISTORY_FILE.exists():
        try:
            return json.loads(HISTORY_FILE.read_text())
        except:
            return []
    return []

def save_history(history: list):
    """Save command history"""
    try:
        HISTORY_FILE.write_text(json.dumps(history, indent=2))
    except:
        pass

# ─── MAIN INTERACTIVE LOOP ──────────────────────────────────────

def main():
    """Main CLI loop"""
    
    parser = argparse.ArgumentParser(description="DestroyGPT v5.0 - Minimal Hacking Assistant")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="LLM model")
    parser.add_argument("--dry-run", action="store_true", help="Preview commands")
    parser.add_argument("-c", "--command", help="Single command mode")
    args = parser.parse_args()
    
    api_key = get_api_key()
    if not api_key:
        console.print("[red]✗ No API key found[/]")
        sys.exit(1)
    
    history = load_history()
    
    # Welcome message with custom banner
    banner = """
    ╔════════════════════════════════════════════════════════════════╗
    ║                                                                ║
    ║   ██████╗  ██████╗ ██████╗ ████████╗                           ║
    ║   ██╔══██╗██╔════╝██╔════╝ ╚══██╔══╝                           ║
    ║   ██║  ██║██║     ██║        ██║                              ║
    ║   ██║  ██║██║     ██║        ██║                              ║
    ║   ██████╔╝╚██████╗╚██████╗   ██║                              ║
    ║   ╚═════╝  ╚═════╝ ╚═════╝   ╚═╝                              ║
    ║                                                                ║
    ║              AI-Powered Ethical Hacking Tool                   ║
    ║                 v5.0 Minimal & Powerful                        ║
    ║                                                                ║
    ║              Author: Sujal Lamichhane                          ║
    ║          GitHub: sujallamichhane18/DestroyGPT                 ║
    ║                                                                ║
    ╚════════════════════════════════════════════════════════════════╝
    """
    console.print(banner)
    console.print("[red bold]⚠️  ETHICAL HACKING WARNING ⚠️[/]\n")
    console.print("[red]This tool is designed for AUTHORIZED penetration testing and security research ONLY.[/]")
    console.print("[red]Unauthorized access to computer systems is ILLEGAL and punishable by law.[/]")
    console.print("[red]You are responsible for your actions. Use responsibly and ethically.[/]\n")
    console.print("[dim]Type 'help' for commands, 'exit' to quit\n[/]")
    
    # Single command mode
    if args.command:
        console.print(f"[yellow]$ {args.command}[/]")
        stdout, stderr, code = run_cmd(args.command, args.dry_run)
        if stdout:
            console.print(stdout)
        if stderr:
            console.print(f"[red]{stderr}[/]")
        return
    
    # Interactive loop
    while True:
        try:
            prompt = console.input("[bold magenta]🔓 hacker[/bold magenta]@[bold cyan]dgpt[/bold cyan] $ ")
            
            if not prompt.strip():
                continue
            
            prompt = prompt.strip()
            
            # Commands
            if prompt.lower() == "exit":
                save_history(history)
                console.print("[yellow]Goodbye![/]")
                break
            
            if prompt.lower() == "help":
                help_text = """
╔════════════════════════════════════════════════════════════════╗
║                    DGPT - HACKING COMMANDS                    ║
╠════════════════════════════════════════════════════════════════╣
║                                                                ║
║  help              Show this help menu                         ║
║  history           Show last 10 commands                       ║
║  clear             Clear screen                               ║
║  exit              Exit program                               ║
║                                                                ║
║  USAGE: Ask anything about hacking/security:                  ║
║                                                                ║
║  Examples:                                                     ║
║    $ scan 192.168.1.1 for open ports                          ║
║    $ check ssl on example.com                                 ║
║    $ enumerate dns for example.com                            ║
║    $ find subdomains of example.com                           ║
║    $ osint sujallamichhane                                    ║
║    $ check http headers for example.com                       ║
║    $ reverse lookup 8.8.8.8                                   ║
║    $ trace route to example.com                               ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
                """
                console.print(help_text)
                continue
            
            if prompt.lower() == "history":
                if history:
                    console.print("\n[bold cyan]═══ COMMAND HISTORY ═══[/bold cyan]\n")
                    for i, h in enumerate(history[-10:], 1):
                        console.print(f"[dim][{i}][/dim] {h}")
                    console.print()
                else:
                    console.print("[dim]No history[/dim]\n")
                continue
            
            if prompt.lower() == "clear":
                console.clear()
                continue
            
            # Add to history
            history.append(prompt)
            
            # Ask LLM for command suggestion
            console.print("[bold cyan]⚙️  Processing...[/bold cyan]")
            
            response = call_llm(api_key, prompt, args.model)
            
            if not response:
                continue
            
            # Clean up response
            cmd = response.strip()
            # Remove markdown code blocks
            cmd = cmd.replace("```bash", "").replace("```sh", "").replace("```", "").strip()
            # Get first line only
            cmd = cmd.split('\n')[0].strip()
            
            if not cmd or cmd.lower() in ("sorry", "i can't", "n/a", "none", "command:"):
                console.print("[red]✗ Unable to generate command[/]")
                continue
            
            # Show the command
            console.print(f"\n[bold green]✓ Suggested Command:[/bold green]")
            console.print(f"[bold yellow]  $ {cmd}[/bold yellow]\n")
            
            # Ask for execution
            try:
                execute = console.input("[bold cyan]Execute this command?[/] [y/N] ").lower().strip()
            except:
                execute = "n"
            
            if execute != "y":
                console.print()
                continue
            
            # Execute command
            console.print("\n[bold cyan]▶ Running...[/bold cyan]\n")
            stdout, stderr, code = run_cmd(cmd, args.dry_run)
            
            if stdout:
                console.print(f"[green]{stdout}[/green]")
            if stderr:
                console.print(f"[red]{stderr}[/red]")
            
            console.print()
        
        except KeyboardInterrupt:
            console.print("\n[yellow]⏹ Interrupted by user[/yellow]")
            break
        except Exception as e:
            console.print(f"[red]Error: {e}[/]")

if __name__ == "__main__":
    main()
