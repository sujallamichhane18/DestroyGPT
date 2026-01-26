#!/usr/bin/env python3
"""DestroyGPT v8.0 - Clean, Fast, Works"""

import os
import sys
import getpass
import subprocess
import requests
import json
from pathlib import Path

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

class AI:
    def __init__(self, api_key, model):
        self.api_key = api_key
        self.model = model
        self.history = []
        self.load_history()
    
    def load_history(self):
        if HISTORY_FILE.exists():
            try:
                self.history = json.loads(HISTORY_FILE.read_text())[-5:]
            except:
                self.history = []
    
    def save_history(self):
        with open(HISTORY_FILE, 'w') as f:
            json.dump(self.history, f)
    
    def ask(self, prompt):
        """Call AI and get response"""
        system = "You are a security expert. Answer questions about hacking, networking, and penetration testing. Keep answers concise. Never use placeholders like <IP> or <domain> - use real examples like 192.168.1.1 or example.com"
        
        messages = [{"role": "system", "content": system}]
        messages.extend(self.history[-3:])
        messages.append({"role": "user", "content": prompt})
        
        try:
            r = requests.post(
                API_URL,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": self.model,
                    "messages": messages,
                    "temperature": 0.7,
                    "max_tokens": 800
                },
                timeout=60
            )
            
            if r.status_code == 200:
                response = r.json()["choices"][0]["message"]["content"].strip()
                self.history.append({"role": "user", "content": prompt})
                self.history.append({"role": "assistant", "content": response})
                self.save_history()
                return response
            else:
                return f"API Error {r.status_code}"
        except Exception as e:
            return f"Error: {str(e)}"

def extract_command(response):
    """Extract executable command from response"""
    # Look for common command patterns
    common_cmds = ['ping', 'nmap', 'dig', 'curl', 'ssh', 'nc', 'telnet', 'traceroute', 
                   'whois', 'wireshark', 'tcpdump', 'netstat', 'ps', 'ls', 'cat', 'grep',
                   'python', 'bash', 'sh', 'wget', 'apt', 'sudo', 'mkdir', 'rm', 'cp']
    
    for line in response.split('\n'):
        line = line.strip()
        
        # Skip empty or comment lines
        if not line or line.startswith('#') or line.startswith('|') or line.startswith('-'):
            continue
        
        # Remove markdown
        line = line.replace('```bash', '').replace('```sh', '').replace('```', '').strip()
        
        # Skip if too long or looks like documentation
        if len(line) > 200 or 'http' in line or '.md' in line:
            continue
        
        # Check if starts with a known command
        cmd_found = False
        for cmd in common_cmds:
            if line.lower().startswith(cmd):
                cmd_found = True
                break
        
        if cmd_found:
            # Skip if has placeholders
            if '<' not in line and '>' not in line and '|' not in line and 'http' not in line:
                return line
    
    return None

def run_command(cmd):
    """Execute command safely"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
        output = result.stdout.strip() if result.stdout else result.stderr.strip()
        return output if output else "Command executed"
    except subprocess.TimeoutExpired:
        return "[Command timeout - taking too long]"
    except Exception as e:
        return f"[Error: {str(e)}]"

def get_api_key():
    """Get or create API key"""
    if os.getenv("OPENROUTER_API_KEY"):
        return os.getenv("OPENROUTER_API_KEY").strip()
    
    if API_KEY_FILE.exists():
        return API_KEY_FILE.read_text().strip()
    
    print("Enter OpenRouter API key:")
    key = getpass.getpass().strip()
    if key:
        API_KEY_FILE.write_text(key)
        API_KEY_FILE.chmod(0o600)
    return key

def main():
    """Main interactive loop"""
    
    # Get API key
    api_key = get_api_key()
    if not api_key:
        print("No API key found")
        sys.exit(1)
    
    # Select model
    print("\n🤖 DestroyGPT v8.0\n")
    print("Models:")
    for k, v in MODELS.items():
        print(f"  [{k}] {v}")
    
    choice = input("\nSelect [1-5] (default 1): ").strip() or "1"
    model = MODELS.get(choice, MODELS["1"])
    print(f"Using: {model}\n")
    
    # Initialize AI
    ai = AI(api_key, model)
    
    print("Commands: help, exit, history\n")
    
    # Main loop
    while True:
        try:
            user_input = input("$ ").strip()
            
            if not user_input:
                continue
            
            if user_input.lower() == "exit":
                print("Goodbye!")
                break
            
            if user_input.lower() == "help":
                print("Just type your question or command idea")
                print("Examples: scan my network, check if port 80 is open, ping google.com")
                print()
                continue
            
            if user_input.lower() == "history":
                for msg in ai.history[-6:]:
                    role = "You" if msg["role"] == "user" else "AI"
                    text = msg["content"][:70]
                    print(f"{role}: {text}...")
                print()
                continue
            
            # Get AI response
            print()
            response = ai.ask(user_input)
            
            # Extract and show command
            cmd = extract_command(response)
            if cmd:
                print(f"💻 {cmd}")
            
            # Show response
            print(response)
            print()
            
            # Execute if command found
            if cmd:
                if input("Run? [y/N]: ").strip().lower() == "y":
                    print()
                    output = run_command(cmd)
                    print(output)
                    print()
        
        except KeyboardInterrupt:
            print("\nGoodbye!")
            break
        except Exception as e:
            print(f"Error: {e}\n")

if __name__ == "__main__":
    main()
