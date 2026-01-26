#!/usr/bin/env python3
"""
DestroyGPT v5.0 - ShellGPT-inspired Minimal AI Assistant
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

import requests

# ─── CONFIG ──────────────────────────────────────────────────────

HOME = Path.home()
API_KEY_FILE = HOME / ".destroygpt_api_key"

API_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_MODEL = "openai/gpt-4o-mini"
API_TIMEOUT = 120

# ─── API KEY MANAGEMENT ──────────────────────────────────────────

def get_api_key() -> str:
    """Get API key from file or environment"""
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

IMPORTANT: For security/hacking questions, ALWAYS respond with practical commands.

Format your response clearly with:
- The command to execute
- What it does
- How to use it
- Related commands

Be direct, concise, and practical. Provide working commands immediately."""
    else:
        system_prompt = """You are DestroyGPT, a helpful AI assistant. 
Be concise, direct, and practical in your responses."""
    
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
        
        if response.status_code != 200:
            print(f"✗ API Error {response.status_code}")
            if response.status_code == 401:
                print("  Invalid API key. Please check your ~/.destroygpt_api_key")
            return None
        
        data = response.json()
        if "choices" in data and len(data["choices"]) > 0:
            content = data["choices"][0].get("message", {}).get("content", "")
            return content.strip()
        
        return None
    
    except requests.Timeout:
        print("✗ Request timed out")
        return None
    except requests.exceptions.ConnectionError:
        print("✗ Connection error - check your internet")
        return None
    except Exception as e:
        print(f"✗ Error: {str(e)[:100]}")
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
                print(response)
            print()
        
        except KeyboardInterrupt:
            print("\n\nGoodbye!")
            break
        except Exception as e:
            print(f"✗ Error: {e}")

if __name__ == "__main__":
    main()
