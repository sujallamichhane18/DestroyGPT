#!/usr/bin/env python3
"""
DestroyGPT v8.0 - Clean, Fast, Intelligent
No fluff. Just results.
"""

import argparse
import json
import os
import sys
import getpass
import subprocess
import requests
from pathlib import Path
from datetime import datetime

HOME = Path.home()
API_KEY_FILE = HOME / ".destroygpt_api_key"
HISTORY_FILE = HOME / ".destroygpt_history.json"

API_URL = "https://openrouter.ai/api/v1/chat/completions"

MODELS = {
    "1": "openai/gpt-4o",
    "2": "openai/gpt-oss-120b",
    "3": "arcee-ai/trinity-mini",
    "4": "moonshotai/kimi-k2",
    "5": "google/gemma-3-27b-it",
}

# ─── CONVERSATION STATE ──────────────────────────────────────────

class State:
    def __init__(self):
        self.history = []
        self.context = {}
        self.load_history()
    
    def load_history(self):
        if HISTORY_FILE.exists():
            try:
                self.history = json.loads(HISTORY_FILE.read_text())[-10:]
            except:
                self.history = []
    
    def save_history(self):
        with open(HISTORY_FILE, 'w') as f:
            json.dump(self.history, f)
    
    def add(self, role: str, msg: str):
        self.history.append({"role": role, "content": msg})
        self.save_history()
    
    def get_context(self) -> list:
        """Return last 5 messages for context"""
        return self.history[-5:] if self.history else []

# ─── API ────────────────────────────────────────────────────────

def call_ai(api_key: str, prompt: str, model: str, state: State) -> str:
    """Call AI with actual context"""
    
    # Smart system prompt based on question
    if any(x in prompt.lower() for x in ["scan", "nmap", "port", "dns", "network"]):
        system = """You are a hacking expert. Answer questions about penetration testing.

CRITICAL RULES:
1. NEVER use placeholders like <IP>, <target>, <domain>
2. Use REAL example values (192.168.1.0/24, example.com)
3. Be CONCISE - one line command, one line explanation
4. NO unnecessary details
5. NO markdown formatting
6. If command is dangerous, warn first"""
    else:
        system = """You are a helpful AI. Answer concisely and directly.
Use real examples, not placeholders.
Keep responses short."""
    
    messages = [{"role": "system", "content": system}]
    
    # Add context
    for msg in state.get_context():
        messages.append(msg)
    
    messages.append({"role": "user", "content": prompt})
    
    try:
        r = requests.post(
            API_URL,
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"model": model, "messages": messages, "temperature": 0.7, "max_tokens": 1000},
            timeout=60
        )
        
        if r.status_code == 200:
            content = r.json()["choices"][0]["message"]["content"].strip()
            return content
        else:
            return f"API Error {r.status_code}"
    except Exception as e:
        return f"Error: {str(e)[:50]}"

# ─── COMMAND EXECUTION ──────────────────────────────────────────

def run_cmd(cmd: str) -> str:
    """Execute command, return output"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
        return result.stdout.strip() or result.stderr.strip() or "[No output]"
    except subprocess.TimeoutExpired:
        return "[Timeout]"
    except Exception as e:
        return f"[Error: {str(e)[:50]}]"

# ─── MAIN ────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-h", "--help", action="store_true")
    parser.add_argument("-k", "--key", action="store_true")
    args = parser.parse_args()
    
    if args.help:
        print("""
DestroyGPT v8.0 - No Fluff. Just Results.

Commands:
  help, -h        This help
  key, -k         Update API key
  exit, quit      Exit
  history         Show past 5 messages
  
Just ask anything:
  scan my network
  what is nmap
  check if port 80 is open
  find subdomains of example.com

Smart features:
✓ Remembers conversation
✓ Real examples (not placeholders)
✓ Fast & concise
✓ No unnecessary text
        """)
        return
    
    # API Key
    if args.key:
        print("🔑 Enter API key (hidden):")
        key = getpass.getpass().strip()
        if key:
            Path(API_KEY_FILE).write_text(key)
            Path(API_KEY_FILE).chmod(0o600)
            print("✓ Saved")
        return
    
    key = os.getenv("OPENROUTER_API_KEY") or (API_KEY_FILE.read_text().strip() if API_KEY_FILE.exists() else "")
    if not key:
        print("No API key. Run: python3 destroygpt.py -k")
        sys.exit(1)
    
    # Model selection
    print("\n🤖 DestroyGPT v8.0\n")
    print("Models:")
    for k, v in MODELS.items():
        print(f"  [{k}] {v}")
    
    choice = input("\nSelect [1-5] (default 1): ").strip()
    model = MODELS.get(choice, MODELS["1"])
    print(f"✓ Using: {model}\n")
    print("Type 'help' for commands, 'exit' to quit\n")
    
    state = State()
    
    # Main loop
    while True:
        try:
            user_input = input("$ ").strip()
            
            if not user_input:
                continue
            
            if user_input.lower() in ("exit", "quit"):
                print("Goodbye!")
                break
            
            if user_input.lower() == "help":
                print("""
Commands:
  history         Show conversation
  key             Update API key
  exit            Exit
                """)
                continue
            
            if user_input.lower() == "history":
                for msg in state.get_context():
                    role = "You" if msg["role"] == "user" else "AI"
                    content = msg["content"][:60]
                    print(f"{role}: {content}...")
                print()
                continue
            
            # Get AI response
            print()
            response = call_ai(key, user_input, model, state)
            
            # Check for command
            has_cmd = False
            if response and not response.startswith("Error") and not response.startswith("API"):
                # Try to extract command from response
                lines = response.split('\n')
                
                for line in lines:
                    # Look for executable lines
                    if line.strip() and not line.startswith('#') and any(x in line for x in ['nmap', 'dig', 'curl', 'ssh', 'bash', '&&', '|', '$']):
                        # Clean line
                        cmd = line.strip()
                        if '<' in cmd:
                            print(f"Command needs parameters: {cmd}\n")
                            break
                        
                        print(f"💻 {cmd}")
                        has_cmd = True
                        break
            
            # Print response
            print(response)
            print()
            
            # Execute if found command
            if has_cmd and input("Run? [y/N]: ").strip().lower() == 'y':
                print()
                output = run_cmd(cmd)
                print(output)
                print()
            
            # Save to history
            state.add("user", user_input)
            state.add("assistant", response)
        
        except KeyboardInterrupt:
            print("\n\nGoodbye!")
            break
        except Exception as e:
            print(f"Error: {e}\n")

if __name__ == "__main__":
    main()
