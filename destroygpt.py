#!/usr/bin/env python3
"""
DestroyGPT v5.0
Usage: python3 dgpt.py [QUERY]
Simple, Fast, Powerful - Just like ShellGPT but for hacking
"""

import argparse
import json
import os
import sys
import getpass
from pathlib import Path
from typing import Optional

import subprocess
import shlex
import requests

# ─── CONFIG ──────────────────────────────────────────────────────

HOME = Path.home()
API_KEY_FILE = HOME / ".destroygpt_api_key"

API_URL = "https://openrouter.ai/api/v1/chat/completions"

# Available free models
MODELS = {
    "1": {"name": "openai/gpt-oss-120b", "label": "GPT-OSS 120B (Fast & Powerful)"},
    "2": {"name": "arcee-ai/trinity-mini", "label": "Trinity Mini (Lightweight)"},
    "3": {"name": "nvidia/nemotron-nano-12b-v2-vl", "label": "Nemotron Nano (Efficient)"},
    "4": {"name": "moonshotai/kimi-k2", "label": "Kimi K2 (Advanced)"},
    "5": {"name": "google/gemma-3-27b-it", "label": "Gemma 3 27B (Powerful)"},
}

DEFAULT_MODEL = MODELS["1"]["name"]
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
    
    print("🔑 Enter OpenRouter API key (hidden):")
    key = getpass.getpass().strip()
    if key:
        API_KEY_FILE.write_text(key)
        API_KEY_FILE.chmod(0o600)
        print(f"✓ API key saved to {API_KEY_FILE}")
    return key

def select_model() -> str:
    """Let user select a model"""
    print("\n📊 Available Free Models:\n")
    for key, model in MODELS.items():
        print(f"  [{key}] {model['label']}")
        print(f"      Model: {model['name']}\n")
    
    choice = input("Select model [1-5] (default 1): ").strip()
    selected = MODELS.get(choice, MODELS["1"])
    print(f"✓ Using: {selected['label']}\n")
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

def call_llm(api_key: str, prompt: str, model: str = DEFAULT_MODEL) -> Optional[str]:
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

COMMAND: <the exact command to run>
EXPLANATION: <what it does>
TIPS: <variations and advanced usage>

Be direct and provide working commands. No markdown, no code blocks.

Examples:
User: scan my website example.com
COMMAND: nmap -sV -p- example.com && curl -I https://example.com
EXPLANATION: nmap scans all ports and identifies services. curl gets HTTP headers revealing server info.
TIPS: Add -A for aggressive scan, -O for OS detection, combine with whatweb for technology fingerprinting.

User: find subdomains
COMMAND: dnsrecon -d example.com -t std && dig example.com ANY
EXPLANATION: dnsrecon enumerates DNS records to find subdomains. dig shows all DNS records.
TIPS: Use fierce for brute forcing, amass for comprehensive enumeration.

Always provide practical, working commands."""
    else:
        system_prompt = """You are DestroyGPT, a helpful AI assistant. 
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
    """Main entry point"""
    
    parser = argparse.ArgumentParser(
        description="DestroyGPT v5.0 - AI Assistant for Hacking & Learning",
        add_help=False
    )
    parser.add_argument("query", nargs="*", help="Question or query")
    parser.add_argument("-m", "--model", default=DEFAULT_MODEL, help="Model to use")
    parser.add_argument("-h", "--help", action="store_true", help="Show help")
    
    args = parser.parse_args()
    
    # Help
    if args.help or (not args.query and sys.stdin.isatty()):
        print("""
DestroyGPT v5.0 - AI Assistant for Hacking & Security Research

Usage:
  dgpt [QUERY]                  Ask a question or run a command
  dgpt -m MODEL "question"      Use a specific model
  dgpt -h, --help               Show this help

Examples:
  dgpt scan my website example.com
  dgpt what is machine learning
  dgpt find subdomains of example.com
  dgpt check ssl certificate
  dgpt write a python function

Interactive Mode:
  dgpt                          Start interactive chat

Environment Variables:
  OPENROUTER_API_KEY          Your API key (optional)

Author: Sujal Lamichhane
GitHub: sujallamichhane18/DestroyGPT
        """)
        return
    
    # Get API key
    api_key = get_api_key()
    if not api_key:
        print("✗ No API key found")
        sys.exit(1)
    
    # Query mode
    if args.query:
        prompt = " ".join(args.query)
        print(f"\n$ {prompt}\n")
        response = call_llm(api_key, prompt, args.model)
        if response:
            # Check if response contains a command
            if "COMMAND:" in response:
                extract_and_execute_command(response, api_key, args.model)
            else:
                print(response)
            print()
        return
    
    # Interactive mode
    print("\nDestroyGPT v5.0 - Interactive Mode")
    print("Type 'exit' to quit, 'help' for commands\n")
    
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
            
            print()
            response = call_llm(api_key, prompt, args.model)
            if response:
                # Check if response contains a command
                if "COMMAND:" in response:
                    extract_and_execute_command(response, api_key, args.model)
                else:
                    print(response)
            print()
        
        except KeyboardInterrupt:
            print("\n\nGoodbye!")
            break
        except Exception as e:
            print(f"✗ Error: {e}")

if __name__ == "__main__":
    main()
