#!/usr/bin/env python3
"""
DestroyGPT v5.0 - Interactive AI Assistant
Simple, Fast, Powerful - Just like ShellGPT but for hacking
"""

import argparse
import json
import os
import sys
import getpass
import subprocess
import shlex
import requests
from pathlib import Path
from typing import Optional

# ─── CONFIG ──────────────────────────────────────────────────────

HOME = Path.home()
API_KEY_FILE = HOME / ".destroygpt_api_key"

API_URL = "https://openrouter.ai/api/v1/chat/completions"

# Available models
MODELS = {
    "1": {"name": "openai/gpt-oss-120b", "label": "GPT-OSS 120B (Fast & Powerful)"},
    "2": {"name": "arcee-ai/trinity-mini", "label": "Trinity Mini (Lightweight)"},
    "3": {"name": "nvidia/nemotron-nano-12b-v2-vl", "label": "Nemotron Nano (Efficient)"},
    "4": {"name": "moonshotai/kimi-k2", "label": "Kimi K2 (Advanced)"},
    "5": {"name": "google/gemma-3-27b-it", "label": "Gemma 3 27B (Powerful)"},
}

API_TIMEOUT = 120

# ─── API KEY MANAGEMENT ──────────────────────────────────────────

def get_api_key(force_new: bool = False) -> str:
    """Get API key from file or environment"""
    if not force_new:
        if os.getenv("OPENROUTER_API_KEY"):
            return os.getenv("OPENROUTER_API_KEY").strip()
        
        if API_KEY_FILE.exists():
            key = API_KEY_FILE.read_text().strip()
            if key:
                return key
    
    print("\n🔑 Enter OpenRouter API key (hidden):")
    key = getpass.getpass().strip()
    if key:
        API_KEY_FILE.write_text(key)
        API_KEY_FILE.chmod(0o600)
        print(f"✓ API key saved to {API_KEY_FILE}\n")
    return key

def select_model() -> str:
    """Let user select a model"""
    print("\n📊 Available Models:\n")
    for key, model in MODELS.items():
        print(f"  [{key}] {model['label']}")
        print(f"      Model: {model['name']}\n")
    
    choice = input("Select model [1-5] (default 1): ").strip()
    selected = MODELS.get(choice, MODELS["1"])
    print(f"\n✓ Using: {selected['label']}\n")
    return selected["name"]

def test_api(api_key: str, model: str) -> bool:
    """Test if API key works with selected model"""
    print(f"🔍 Testing API with {model}...")
    
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": "test"}],
        "temperature": 0.5,
        "max_tokens": 10,
        "stream": False
    }
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.post(API_URL, headers=headers, json=payload, timeout=30)
        
        if response.status_code == 200:
            print("✓ API key is valid!\n")
            return True
        elif response.status_code == 401:
            print("✗ Invalid API key")
            return False
        elif response.status_code == 429:
            print("✗ API rate limit exceeded")
            return False
        elif response.status_code == 503:
            print(f"✗ Model {model} is unavailable or quota exceeded")
            return False
        else:
            print(f"✗ Error {response.status_code}: {response.text[:100]}")
            return False
    
    except requests.Timeout:
        print("✗ API request timed out")
        return False
    except Exception as e:
        print(f"✗ Connection error: {str(e)[:100]}")
        return False

# ─── COMMAND EXECUTION ──────────────────────────────────────────

def run_command(cmd: str, timeout: int = 120) -> Optional[str]:
    """Execute a shell command and return output"""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return f"✗ Command timed out after {timeout}s"
    except Exception as e:
        return f"✗ Error: {str(e)}"

def extract_and_execute_command(response: str, api_key: str, model: str) -> str:
    """Extract command from response and ask user to execute"""
    
    lines = response.split('\n')
    command = ""
    explanation = ""
    tips = ""
    
    for line in lines:
        if line.startswith("COMMAND:"):
            command = line.replace("COMMAND:", "").strip()
        elif line.startswith("EXPLANATION:"):
            explanation = line.replace("EXPLANATION:", "").strip()
        elif line.startswith("TIPS:"):
            tips = line.replace("TIPS:", "").strip()
    
    if command:
        # Clean up the command - remove placeholders
        if "<" in command or ">" in command:
            print(f"\n⚠️  Command has placeholders that need to be filled:")
            print(f"  {command}\n")
            print("Please provide the missing information or modify the command:\n")
            command = input("$ ").strip()
            if not command:
                print()
                return response
        
        print(f"\n📋 Suggested Command:\n  {command}\n")
        
        if explanation:
            print(f"ℹ️  {explanation}\n")
        
        if tips:
            print(f"💡 Tips: {tips}\n")
        
        # Ask for execution
        try:
            execute = input("Execute this command? [y/N]: ").strip().lower()
            if execute == 'y':
                print(f"\n▶ Running: {command}\n")
                output = run_command(command)
                print(output)
                print()
                return output
            else:
                print()
        except KeyboardInterrupt:
            print("\n")
    
    return response

# ─── LLM CALL ────────────────────────────────────────────────────

def call_llm(api_key: str, prompt: str, model: str) -> Optional[str]:
    """Call OpenRouter API and return response"""
    
    # Detect if user is asking for hacking/security commands
    hacking_keywords = ["scan", "port", "nmap", "exploit", "vulnerability", "hack", "security", 
                        "pentest", "osint", "dns", "ssl", "injection", "enum", "brute", "crack",
                        "payload", "shell", "backdoor", "malware", "network", "firewall",
                        "certificate", "subdomain", "directory", "http", "headers", "ip", "server",
                        "website", "web", "site", "domain", "target", "check", "test", "find",
                        "enumerate", "discover", "recon", "fingerprint", "identify", "detect", "query"]
    
    is_hacking_question = any(keyword in prompt.lower() for keyword in hacking_keywords)
    
    if is_hacking_question:
        system_prompt = """You are DestroyGPT, an advanced ethical hacking assistant created by Sujal Lamichhane.
You help with penetration testing, security research, and reconnaissance.

IMPORTANT: For security/hacking questions, respond in this format:

COMMAND: <the exact command to run - NO PLACEHOLDERS>
EXPLANATION: <what it does>
TIPS: <variations and advanced usage>

Be direct and provide COMPLETE, READY-TO-RUN commands. No markdown, no code blocks.
NEVER use placeholders like <target>, <ip>, <domain>, etc. Use example values instead.

Examples:
User: scan my network
COMMAND: nmap -sn 192.168.1.0/24
EXPLANATION: Performs a ping sweep of the 192.168.1.0/24 subnet to find live hosts.
TIPS: Add -sV for service detection, use -O for OS detection. For faster scans use -T4.

User: scan using arp
COMMAND: sudo arp-scan -l
EXPLANATION: Sends ARP probes on the local network segment to list all devices and their MAC addresses.
TIPS: Add --interface=eth0 to specify a network interface, use -r 3 to send 3 requests per address.

User: find subdomains
COMMAND: dig example.com ANY
EXPLANATION: Queries all DNS records for example.com to find subdomains and mail servers.
TIPS: Use dnsrecon -d example.com -t std for more comprehensive enumeration.

CRITICAL: Always provide complete, executable commands with example values. Never use angle brackets or placeholders."""
    else:
        system_prompt = """You are DestroyGPT, a helpful AI assistant created by Sujal Lamichhane. 
Be concise, direct, and practical in your responses.
Keep responses short and to the point."""
    
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.7,
        "max_tokens": 2000,
        "stream": False
    }
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.post(API_URL, headers=headers, json=payload, timeout=API_TIMEOUT)
        
        if response.status_code == 200:
            data = response.json()
            if "choices" in data and len(data["choices"]) > 0:
                content = data["choices"][0].get("message", {}).get("content", "")
                return content.strip()
            return None
        
        elif response.status_code == 401:
            print("\n✗ Invalid API key")
            return None
        
        elif response.status_code == 429:
            print("\n✗ API rate limit exceeded - quota used")
            return None
        
        elif response.status_code == 503:
            print("\n✗ Model unavailable or quota exceeded")
            return None
        
        else:
            print(f"\n✗ API Error {response.status_code}")
            return None
    
    except requests.Timeout:
        print("\n✗ Request timed out")
        return None
    except requests.exceptions.ConnectionError:
        print("\n✗ Connection error")
        return None
    except Exception as e:
        print(f"\n✗ Error: {str(e)[:100]}")
        return None

# ─── MAIN ────────────────────────────────────────────────────────

def main():
    """Main entry point - Interactive mode only"""
    
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-h", "--help", action="store_true", help="Show help")
    parser.add_argument("-k", "--key", action="store_true", help="Update API key")
    args = parser.parse_args()
    
    # Help
    if args.help:
        print("""
DestroyGPT v5.0 - Interactive AI Assistant

Usage:
  python3 destroygpt.py                Start interactive chat
  python3 destroygpt.py -k             Update API key
  python3 destroygpt.py -h, --help    Show this help

Commands in interactive mode:
  exit, quit      Exit the program
  help            Show this help
  clear           Clear screen
  model           Switch model
  key             Update API key
  test            Test API

Just ask any question:
  scan my website example.com
  what is python
  find subdomains
  check ssl certificate

Author: Sujal Lamichhane
GitHub: sujallamichhane18/DestroyGPT
        """)
        return
    
    # Get API key
    if args.key:
        api_key = get_api_key(force_new=True)
        print("✓ API key updated")
        return
    
    api_key = get_api_key()
    if not api_key:
        print("✗ No API key found")
        sys.exit(1)
    
    # Select model
    model = select_model()
    
    # Interactive mode
    print("╔════════════════════════════════════════════════════════════════╗")
    print("║                   DestroyGPT v5.0                             ║")
    print("║              AI Assistant for Hacking & Learning               ║")
    print("║                                                                ║")
    print("║              Author: Sujal Lamichhane                          ║")
    print("║          GitHub: sujallamichhane18/DestroyGPT                 ║")
    print("╚════════════════════════════════════════════════════════════════╝\n")
    print(f"Model: {model}")
    print("Type 'help' for commands, 'exit' to quit\n")
    
    while True:
        try:
            prompt = input("$ ").strip()
            
            if not prompt:
                continue
            
            if prompt.lower() in ("exit", "quit"):
                print("Goodbye!")
                break
            
            if prompt.lower() == "help":
                print("""
Commands:
  exit, quit      Exit the program
  help            Show this help
  clear           Clear screen
  model           Switch model
  key             Update API key
  test            Test API

Just ask any question:
  scan my website example.com
  what is python
  find subdomains
  check ssl certificate
                """)
                continue
            
            if prompt.lower() == "clear":
                os.system("clear" if os.name != "nt" else "cls")
                continue
            
            if prompt.lower() == "model":
                model = select_model()
                continue
            
            if prompt.lower() == "key":
                api_key = get_api_key(force_new=True)
                print("✓ API key updated\n")
                continue
            
            if prompt.lower() == "test":
                print("\n🧪 Testing API key...")
                test_api(api_key, model)
                continue
            
            print()
            response = call_llm(api_key, prompt, model)
            
            if response is None:
                print("✗ Failed to get response")
                print("💡 Your API key or quota may have expired")
                print("💡 Type 'key' to update API key or 'model' to switch model\n")
                continue
            
            if response:
                # Check if response contains a command
                if "COMMAND:" in response:
                    extract_and_execute_command(response, api_key, model)
                else:
                    print(response)
                    print()
        
        except KeyboardInterrupt:
            print("\n\nGoodbye!")
            break
        except Exception as e:
            print(f"✗ Error: {e}\n")

if __name__ == "__main__":
    main()
