#!/usr/bin/env python3
"""
DestroyGPT v5.0 - Universal AI Assistant
Works like ChatGPT but for hacking, coding, and everything else

Installation:
    1. Save this file as 'dgpt' (without .py)
    2. Make it executable: chmod +x dgpt
    3. Move to /usr/local/bin: sudo mv dgpt /usr/local/bin/
    4. Now use: dgpt "your question"
"""

import argparse
import json
import logging
import os
import getpass
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import requests
from rich.console import Console
from rich.markdown import Markdown

# ─── CONFIG ──────────────────────────────────────────────────────

HOME = Path.home()
API_KEY_FILE = HOME / ".destroygpt_api_key"
HISTORY_FILE = HOME / ".destroygpt_history.json"
LOG_FILE = HOME / ".destroygpt.log"

API_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_MODEL = "openai/gpt-4o-mini"

STREAM_TIMEOUT = 60
API_TIMEOUT = 120

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

# ─── LLM CALL ────────────────────────────────────────────────────

def call_llm_stream(api_key: str, prompt: str, model: str = DEFAULT_MODEL) -> bool:
    """Call OpenRouter API and stream response"""
    
    # Detect if user is asking for hacking/security commands
    hacking_keywords = ["scan", "port", "nmap", "exploit", "vulnerability", "hack", "security", 
                        "pentest", "osint", "dns", "ssl", "injection", "enum", "brute", "crack",
                        "payload", "shell", "backdoor", "malware", "network", "firewall", "ips",
                        "certificate", "subdomain", "directory", "http", "headers", "ip", "server"]
    
    is_hacking_question = any(keyword in prompt.lower() for keyword in hacking_keywords)
    
    if is_hacking_question:
        system_prompt = """You are DestroyGPT, an advanced ethical hacking assistant. When users ask about security testing, provide practical Linux commands and detailed explanations.

For hacking/security questions, ALWAYS respond in this format:
COMMAND: <the actual command>
EXPLANATION: <what it does and how it helps>
TIPS: <advanced variations or related commands>

Examples:
User: scan my website
COMMAND: nmap -sV -p- example.com && curl -I https://example.com
EXPLANATION: nmap scans all ports and identifies services. curl gets HTTP headers which may reveal server info or misconfigurations.
TIPS: Add -sC for default scripts, -O for OS detection. Use -A for aggressive scan. Combine with whatweb for tech fingerprinting.

User: check ssl
COMMAND: openssl s_client -connect example.com:443 -showcerts
EXPLANATION: Shows SSL certificate details, chain, and cipher strength. Helps identify weak certs or misconfiguration.
TIPS: Use -dates to check expiration, add | grep -i "subject" for quick info.

User: enumerate dns
COMMAND: dig example.com ANY && nslookup -type=MX example.com && dnsrecon -d example.com -t std
EXPLANATION: Gets all DNS records, identifies mail servers, finds subdomains. Critical for reconnaissance.
TIPS: Use fierce for subdomain brute forcing, amass for comprehensive enumeration.

Always provide commands that are practical and educational."""
    else:
        system_prompt = """You are DestroyGPT, a helpful AI assistant created by Sujal Lamichhane. You help with coding, hacking, security, and general knowledge. Be concise and practical."""
    
    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": system_prompt
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": 0.7,
        "max_tokens": 2000,
        "stream": True
    }
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    try:
        with requests.post(API_URL, headers=headers, json=payload, stream=True, timeout=API_TIMEOUT) as r:
            if r.status_code != 200:
                console.print(f"[red]✗ API Error {r.status_code}[/]")
                if r.status_code == 404:
                    console.print("[yellow]⚠️  Model not found. Retrying with fallback...[/]")
                    return call_llm_stream(api_key, prompt, "openai/gpt-4o-mini")
                elif r.status_code == 401:
                    console.print("[red]❌ Invalid API key.[/]")
                return False
            
            response_text = []
            for line in r.iter_lines(decode_unicode=True):
                if line.startswith("data:"):
                    chunk = line[5:].strip()
                    if chunk == "[DONE]":
                        break
                    try:
                        data = json.loads(chunk)
                        delta = data.get("choices", [{}])[0].get("delta", {})
                        content = delta.get("content", "")
                        if content:
                            response_text.append(content)
                            console.print(content, end="", style="cyan")
                    except:
                        pass
            
            console.print("\n")
            return True
    
    except requests.Timeout:
        console.print("[red]✗ Request timed out - try again[/]")
        return False
    except requests.exceptions.ConnectionError:
        console.print("[red]✗ Connection error - check your internet[/]")
        return False
    except Exception as e:
        console.print(f"[red]✗ Error: {str(e)[:100]}[/]")
        return False

# ─── HISTORY MANAGEMENT ──────────────────────────────────────────

def load_history() -> list:
    """Load chat history"""
    if HISTORY_FILE.exists():
        try:
            return json.loads(HISTORY_FILE.read_text())
        except:
            return []
    return []

def save_history(history: list):
    """Save chat history"""
    try:
        HISTORY_FILE.write_text(json.dumps(history, indent=2))
    except:
        pass

def add_to_history(history: list, role: str, content: str):
    """Add message to history"""
    history.append({
        "role": role,
        "content": content,
        "timestamp": datetime.now().isoformat()
    })

# ─── MAIN INTERACTIVE LOOP ──────────────────────────────────────

def main():
    """Main CLI loop"""
    
    parser = argparse.ArgumentParser(description="DestroyGPT v5.0 - Universal AI Assistant")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="LLM model")
    parser.add_argument("-c", "--command", help="Single command mode")
    args = parser.parse_args()
    
    api_key = get_api_key()
    if not api_key:
        console.print("[red]✗ No API key found[/]")
        sys.exit(1)
    
    history = load_history()
    
    # Welcome banner
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
    ║          Universal AI Assistant & Hacking Tool                ║
    ║                    v5.0 Enterprise Edition                    ║
    ║                                                                ║
    ║              Author: Sujal Lamichhane                          ║
    ║          GitHub: sujallamichhane18/DestroyGPT                 ║
    ║                                                                ║
    ╚════════════════════════════════════════════════════════════════╝
    """
    console.print(banner)
    console.print("[red bold]⚠️  ETHICAL HACKING WARNING ⚠️[/]\n")
    console.print("[red]This tool is for AUTHORIZED testing and learning ONLY.[/]")
    console.print("[red]Unauthorized access to systems is ILLEGAL.[/]\n")
    console.print("[dim]Type 'help' for commands, 'exit' to quit\n[/]")
    
    # Single command mode
    if args.command:
        console.print(f"[magenta]🤖 Assistant[/magenta]\n")
        call_llm_stream(api_key, args.command, args.model)
        return
    
    # Interactive loop
    while True:
        try:
            # Get user input
            prompt = console.input("[bold magenta]🤖 You[/bold magenta]: ")
            
            if not prompt.strip():
                continue
            
            prompt = prompt.strip()
            
            # Built-in commands
            if prompt.lower() == "exit":
                save_history(history)
                console.print("[yellow]👋 Goodbye![/]")
                break
            
            if prompt.lower() == "help":
                help_text = """
╔════════════════════════════════════════════════════════════════╗
║                    DGPT - HELP MENU                           ║
╠════════════════════════════════════════════════════════════════╣
║                                                                ║
║  Commands:                                                     ║
║    help              Show this help menu                       ║
║    history           Show last 10 messages                     ║
║    clear             Clear screen                             ║
║    exit              Exit program                             ║
║                                                                ║
║  Usage:                                                        ║
║    Ask ANY question - coding, hacking, general knowledge      ║
║                                                                ║
║  Examples:                                                     ║
║    What is the fibonacci sequence?                            ║
║    How to scan ports with nmap?                               ║
║    Explain machine learning                                   ║
║    Write a Python function to sort arrays                     ║
║    How to find SQL injection vulnerabilities?                 ║
║    What is blockchain?                                        ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
                """
                console.print(help_text)
                continue
            
            if prompt.lower() == "history":
                if history:
                    console.print("\n[bold cyan]═══ CONVERSATION HISTORY ═══[/bold cyan]\n")
                    for i, msg in enumerate(history[-10:], 1):
                        role = msg.get("role", "unknown")
                        content = msg.get("content", "")[:100]
                        timestamp = msg.get("timestamp", "")
                        console.print(f"[dim][{i}][/dim] [{role.upper()}] {content}...")
                    console.print()
                else:
                    console.print("[dim]No history[/dim]\n")
                continue
            
            if prompt.lower() == "clear":
                console.clear()
                continue
            
            # Add to history
            add_to_history(history, "user", prompt)
            
            # Get AI response
            console.print(f"\n[bold magenta]🤖 Assistant[/bold magenta]:\n")
            success = call_llm_stream(api_key, prompt, args.model)
            
            if success:
                add_to_history(history, "assistant", "[response streamed]")
            
            console.print()
        
        except KeyboardInterrupt:
            console.print("\n[yellow]⏹ Interrupted by user[/yellow]")
            break
        except Exception as e:
            console.print(f"[red]Error: {e}[/]")

if __name__ == "__main__":
    main()
