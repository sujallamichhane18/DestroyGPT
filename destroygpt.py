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

def call_llm(api_key: str, prompt: str, model: str = DEFAULT_MODEL) -> Optional[str]:
    """Call OpenRouter API and stream response"""
    
    payload = {
        "model": model,
        "messages": [
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": 0.7,
        "max_tokens": 1000,
        "stream": True
    }
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    response_text = []
    
    try:
        with requests.post(API_URL, headers=headers, json=payload, stream=True, timeout=API_TIMEOUT) as r:
            if r.status_code != 200:
                console.print(f"[red]✗ API Error {r.status_code}[/]")
                return None
            
            for line in r.iter_lines(decode_unicode=True):
                if line.startswith("data:"):
                    chunk = line[5:].strip()
                    if chunk == "[DONE]":
                        break
                    try:
                        delta = json.loads(chunk)["choices"][0]["delta"]
                        content = delta.get("content", "")
                        if content:
                            response_text.append(content)
                            console.print(content, end="", style="cyan")
                    except:
                        pass
        
        console.print()
        return "".join(response_text)
    
    except requests.Timeout:
        console.print("[red]✗ Request timed out[/]")
        return None
    except Exception as e:
        console.print(f"[red]✗ Error: {e}[/]")
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
    
    # Welcome message
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║     ██████╗ ███████╗███████╗████████╗██████╗  ██████╗ ██╗   ║
    ║     ██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗██╔═══██╗██║   ║
    ║     ██║  ██║█████╗  ███████╗   ██║   ██████╔╝██║   ██║██║   ║
    ║     ██║  ██║██╔══╝  ╚════██║   ██║   ██╔══██╗██║   ██║██║   ║
    ║     ██████╔╝███████╗███████║   ██║   ██║  ██║╚██████╔╝██║   ║
    ║     ╚═════╝ ╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝   ║
    ║                                                               ║
    ║              AI-Powered Ethical Hacking Assistant             ║
    ║                      v5.0 Minimal Edition                     ║
    ║                                                               ║
    ║                  Made by: Sujal Lamichhane                    ║
    ║              GitHub: sujallamichhane18/DestroyGPT            ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    console.print(banner)
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
            prompt = console.input("[bold cyan]dgpt>[/] ")
            
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
Commands:
  help              - Show this help
  history           - Show command history
  clear             - Clear screen
  exit              - Exit program

Ask anything:
  dgpt> scan example.com with nmap
  dgpt> check SSL on example.com
  dgpt> enumerate DNS for example.com
                """
                console.print(help_text)
                continue
            
            if prompt.lower() == "history":
                if history:
                    for i, h in enumerate(history[-10:], 1):
                        console.print(f"{i}. {h}")
                else:
                    console.print("[dim]No history[/]")
                continue
            
            if prompt.lower() == "clear":
                console.clear()
                continue
            
            # Add to history
            history.append(prompt)
            
            # Ask LLM for command suggestion
            console.print("[dim]Thinking...[/]")
            
            llm_prompt = f"""You are a cybersecurity assistant. The user asked:
"{prompt}"

Suggest ONE Linux security command to help with this task. 
Reply with ONLY the command, nothing else. No explanation, no markdown.
Make sure the command is safe and uses only common tools like nmap, dig, curl, grep, etc.

Command:"""
            
            response = call_llm(api_key, llm_prompt, args.model)
            
            if not response:
                continue
            
            # Extract command from response
            cmd = response.strip().split('\n')[0].strip()
            
            # Remove markdown code blocks if present
            cmd = cmd.replace("```bash", "").replace("```", "").strip()
            
            if not cmd:
                console.print("[red]✗ No command suggested[/]")
                continue
            
            # Show command
            console.print(f"[yellow]→ {cmd}[/]")
            
            # Safety check
            if not is_safe(cmd):
                console.print("[red]✗ Command blocked (unsafe)[/]")
                continue
            
            # Execute
            if console.input("[bold cyan]Execute?[/] [y/n] ").lower() == 'y':
                console.print()
                stdout, stderr, code = run_cmd(cmd, args.dry_run)
                
                if stdout:
                    console.print(stdout)
                if stderr:
                    console.print(f"[red]{stderr}[/]")
                
                console.print()
        
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted[/]")
            break
        except Exception as e:
            console.print(f"[red]Error: {e}[/]")

if __name__ == "__main__":
    main()
