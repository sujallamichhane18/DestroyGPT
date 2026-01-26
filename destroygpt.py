#!/usr/bin/env python3
"""
DestroyGPT v9.0 - Enhanced AI Security Assistant
Improved intelligence, safety, and user experience
"""

import os
import sys
import json
import shlex
import subprocess
import re
from pathlib import Path
from datetime import datetime
import requests
from typing import Optional, Dict, List, Tuple

# Configuration
HOME = Path.home()
CONFIG_DIR = HOME / ".destroygpt"
CONFIG_DIR.mkdir(exist_ok=True)

API_KEY_FILE = CONFIG_DIR / "api_key"
HISTORY_FILE = CONFIG_DIR / "history.json"
LOG_FILE = CONFIG_DIR / "session_log.txt"
CONFIG_FILE = CONFIG_DIR / "config.json"

API_URL = "https://openrouter.ai/api/v1/chat/completions"

# Default command timeout
DEFAULT_TIMEOUT = 30

# Simple blocked patterns - basic safety only
BLOCKED_PATTERNS = [
    r'\brm\b', r'\bsudo\b', r'\bsu\b'
]

# AI Models with detailed info
MODELS = {
    "1": {
        "id": "openai/gpt-4o",
        "name": "GPT-4o",
        "speed": "Fast",
        "quality": "Excellent",
        "best_for": "Complex security concepts"
    },
    "2": {
        "id": "google/gemini-2.0-flash-exp:free",
        "name": "Gemini 2.0 Flash",
        "speed": "Very Fast",
        "quality": "Very Good",
        "best_for": "Quick responses, free tier"
    },
    "3": {
        "id": "meta-llama/llama-3.1-8b-instruct:free",
        "name": "Llama 3.1 8B",
        "speed": "Fast",
        "quality": "Good",
        "best_for": "Educational queries, free tier"
    },
    "4": {
        "id": "anthropic/claude-3.5-sonnet",
        "name": "Claude 3.5 Sonnet",
        "speed": "Fast",
        "quality": "Excellent",
        "best_for": "Detailed explanations"
    },
}

# Color codes for terminal
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'


class EnhancedAI:
    """Enhanced AI with better prompting, context, and safety"""
    
    def __init__(self, api_key: str, model_id: str):
        self.api_key = api_key
        self.model_id = model_id
        self.history = []
        self.session_start = datetime.now()
        self.load_history()
    
    def load_history(self):
        """Load conversation history"""
        if HISTORY_FILE.exists():
            try:
                with open(HISTORY_FILE, 'r') as f:
                    data = json.load(f)
                    self.history = data[-20:]  # Keep last 20 messages
            except Exception as e:
                print(f"{Colors.YELLOW}⚠️  Could not load history: {e}{Colors.END}")
                self.history = []
    
    def save_history(self):
        """Save conversation history"""
        try:
            with open(HISTORY_FILE, 'w') as f:
                json.dump(self.history, f, indent=2)
        except Exception as e:
            print(f"{Colors.YELLOW}⚠️  Could not save history: {e}{Colors.END}")
    
    def log_session(self, event: str):
        """Log session events"""
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(LOG_FILE, 'a') as f:
                f.write(f"[{timestamp}] {event}\n")
        except:
            pass
    
    def ask(self, prompt: str, context: Optional[Dict] = None) -> str:
        """Enhanced AI query with better prompting"""
        
        # Build comprehensive system prompt
        system_prompt = self._build_system_prompt(context)
        
        # Build message list with context
        messages = [{"role": "system", "content": system_prompt}]
        
        # Add relevant history (last 3 exchanges)
        messages.extend(self.history[-6:])
        
        # Add current query
        messages.append({"role": "user", "content": prompt})
        
        try:
            response = requests.post(
                API_URL,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "https://github.com/destroygpt",
                    "X-Title": "DestroyGPT"
                },
                json={
                    "model": self.model_id,
                    "messages": messages,
                    "temperature": 0.7,
                    "max_tokens": 1500,
                    "top_p": 0.9,
                },
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                content = data["choices"][0]["message"]["content"].strip()
                
                # Update history
                self.history.append({"role": "user", "content": prompt})
                self.history.append({"role": "assistant", "content": content})
                self.save_history()
                
                # Log query
                self.log_session(f"Query: {prompt[:100]}")
                
                return content
            
            elif response.status_code == 401:
                return f"{Colors.RED}❌ API Error: Invalid API key. Check your credentials.{Colors.END}"
            elif response.status_code == 429:
                return f"{Colors.RED}❌ Rate limited. Please wait a moment and try again.{Colors.END}"
            else:
                error_msg = "Unknown error"
                try:
                    error_data = response.json()
                    if 'error' in error_data:
                        error_msg = error_data['error'].get('message', error_msg)
                except:
                    pass
                return f"{Colors.RED}❌ API Error ({response.status_code}): {error_msg}{Colors.END}"
        
        except requests.exceptions.Timeout:
            return f"{Colors.RED}❌ Request timeout. The API took too long to respond.{Colors.END}"
        except requests.exceptions.ConnectionError:
            return f"{Colors.RED}❌ Connection error. Check your internet connection.{Colors.END}"
        except Exception as e:
            return f"{Colors.RED}❌ Error: {str(e)}{Colors.END}"
    
    def _build_system_prompt(self, context: Optional[Dict] = None) -> str:
        """Build comprehensive system prompt"""
        
        base_prompt = """You are an expert cybersecurity educator and ethical hacking instructor. Your role is to:

1. **Educate**: Explain security concepts clearly, accurately, and in-depth
2. **Guide Safely**: Only suggest safe, read-only commands that won't damage systems
3. **Emphasize Ethics**: Always remind users to only test authorized systems
4. **Be Practical**: Provide real, working examples that users can learn from

## Available Commands
You can suggest any standard Linux/Unix commands for security learning and reconnaissance.
Focus on educational value and practical examples.

Common useful commands include:
- Network: ping, dig, nslookup, whois, traceroute, host, nmap, netstat, ss
- File operations: ls, cat, grep, find, file
- System info: whoami, uname, ps, top
- Web: curl, wget
- And any other standard commands that help with learning

## Prohibited Content
Avoid suggesting:
- Commands that could damage systems (rm -rf /, mkfs, dd to devices)
- Malicious payloads or shellcode
- Commands requiring root without explanation (sudo, su)

## Response Format
When suggesting commands:
1. Explain the concept first
2. Show the command on its own line clearly
3. Explain what the command does
4. Mention what output to expect
5. Add safety/legal reminders when relevant

## Examples to Use
Always use real, safe examples:
- Domains: example.com, google.com, github.com, cloudflare.com
- IPs: 8.8.8.8, 1.1.1.1, 93.184.216.34
- Never use: localhost, 192.168.x.x, 10.x.x.x (unless explicitly asked about local testing)

## Tone
Be friendly, encouraging, and educational. Help users understand WHY things work, not just HOW."""

        # Add context if provided
        if context:
            if context.get('last_command'):
                base_prompt += f"\n\n## Recent Context\nUser just ran: {context['last_command']}"
            if context.get('user_level'):
                base_prompt += f"\nUser skill level: {context['user_level']}"
        
        return base_prompt


class CommandValidator:
    """Enhanced command validation with detailed feedback"""
    
    @staticmethod
    def extract_commands(text: str) -> List[str]:
        """Extract potential commands from AI response"""
        commands = []
        lines = text.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Remove markdown code blocks
            line = re.sub(r'```(?:bash|sh|shell)?', '', line).strip()
            
            # Skip empty or comment lines
            if not line or line.startswith('#') or line.startswith('//'):
                continue
            
            # Look for lines that seem like commands (start with common command words)
            # Simple heuristic: if line has spaces and looks like a command
            if ' ' in line or any(line.startswith(cmd) for cmd in ['ping', 'dig', 'nmap', 'curl', 'wget', 'ls', 'cat', 'grep', 'whoami', 'ssh', 'nc', 'nslookup', 'whois', 'traceroute', 'host', 'netstat', 'ss', 'ps', 'find']):
                if line not in commands:
                    commands.append(line)
        
        return commands
    
    @staticmethod
    def validate_command(cmd_string: str) -> Tuple[bool, str, Optional[Dict]]:
        """
        Validate command with minimal restrictions
        Returns: (is_valid, message, command_info)
        """
        try:
            # Parse command safely
            parts = shlex.split(cmd_string)
            if not parts:
                return False, "Empty command", None
            
            base_cmd = parts[0]
            
            # Check for blocked patterns only (very minimal)
            full_cmd = ' '.join(parts)
            for pattern in BLOCKED_PATTERNS:
                if re.search(pattern, full_cmd, re.IGNORECASE):
                    return False, f"Command contains blocked pattern", None
            
            return True, "Command validated successfully", {'timeout': DEFAULT_TIMEOUT}
            
        except ValueError as e:
            return False, f"Parse error: {str(e)}", None
        except Exception as e:
            return False, f"Validation error: {str(e)}", None
    
    @staticmethod
    def execute_safe(cmd_string: str, timeout: int = 15) -> Tuple[bool, str]:
        """
        Execute validated command safely
        Returns: (success, output)
        """
        try:
            # Double-check validation
            is_valid, msg, cmd_info = CommandValidator.validate_command(cmd_string)
            if not is_valid:
                return False, f"Validation failed: {msg}"
            
            # Use default timeout
            if cmd_info and 'timeout' in cmd_info:
                timeout = cmd_info['timeout']
            
            # Parse and execute with shell=False for security
            parts = shlex.split(cmd_string)
            result = subprocess.run(
                parts,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False  # Critical: Never use shell=True
            )
            
            # Get output
            output = result.stdout.strip() if result.stdout else result.stderr.strip()
            
            if not output:
                output = f"Command executed (exit code: {result.returncode})"
            
            # Log execution
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            try:
                with open(LOG_FILE, 'a') as f:
                    f.write(f"[{timestamp}] EXECUTED: {cmd_string}\n")
                    f.write(f"[{timestamp}] OUTPUT: {output[:200]}\n")
            except:
                pass
            
            return True, output
            
        except subprocess.TimeoutExpired:
            return False, f"{Colors.YELLOW}⏱️  Command timeout ({timeout}s){Colors.END}"
        except FileNotFoundError:
            return False, f"{Colors.RED}❌ Command not found. Is it installed?{Colors.END}"
        except Exception as e:
            return False, f"{Colors.RED}❌ Execution error: {str(e)}{Colors.END}"


def print_banner():
    """Display startup banner"""
    banner = f"""{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════╗
║                                                       ║
║            🛡️  DestroyGPT v9.0                       ║
║     AI-Powered Security Learning Assistant           ║
║                                                       ║
║     ⚠️  FOR AUTHORIZED USE ONLY ⚠️                   ║
║                                                       ║
╚═══════════════════════════════════════════════════════╝
{Colors.END}"""
    print(banner)


def get_api_key() -> Optional[str]:
    """Get API key from file or environment"""
    # Try environment variable first
    if os.getenv("OPENROUTER_API_KEY"):
        return os.getenv("OPENROUTER_API_KEY").strip()
    
    # Try config file
    if API_KEY_FILE.exists():
        try:
            return API_KEY_FILE.read_text().strip()
        except:
            pass
    
    # Prompt user
    print(f"{Colors.YELLOW}No API key found.{Colors.END}")
    print(f"Get one free at: {Colors.CYAN}https://openrouter.ai/keys{Colors.END}")
    
    key = input(f"\n{Colors.BOLD}Enter your OpenRouter API key: {Colors.END}").strip()
    if key:
        try:
            API_KEY_FILE.write_text(key)
            API_KEY_FILE.chmod(0o600)
            print(f"{Colors.GREEN}✓ API key saved securely{Colors.END}\n")
            return key
        except Exception as e:
            print(f"{Colors.YELLOW}⚠️  Could not save key: {e}{Colors.END}")
            return key
    
    return None


def select_model() -> str:
    """Interactive model selection"""
    print(f"\n{Colors.BOLD}Available AI Models:{Colors.END}\n")
    
    for key, model in MODELS.items():
        print(f"{Colors.CYAN}[{key}]{Colors.END} {Colors.BOLD}{model['name']}{Colors.END}")
        print(f"    Speed: {model['speed']} | Quality: {model['quality']}")
        print(f"    Best for: {model['best_for']}\n")
    
    choice = input(f"{Colors.BOLD}Select model [1-{len(MODELS)}] (default: 1): {Colors.END}").strip()
    
    if choice not in MODELS:
        choice = "1"
    
    selected = MODELS[choice]
    print(f"{Colors.GREEN}✓ Using: {selected['name']}{Colors.END}\n")
    
    return selected['id']


def show_help():
    """Display help information"""
    help_text = f"""
{Colors.BOLD}DestroyGPT - Available Commands:{Colors.END}

{Colors.CYAN}help{Colors.END}        Show this help message
{Colors.CYAN}history{Colors.END}     Display recent conversation
{Colors.CYAN}commands{Colors.END}    List all safe commands
{Colors.CYAN}clear{Colors.END}       Clear the screen
{Colors.CYAN}exit/quit{Colors.END}   Exit the program

{Colors.BOLD}How to Use:{Colors.END}
- Ask questions about security concepts
- Request command examples
- Learn about networking and protocols
- Practice safe reconnaissance techniques

{Colors.BOLD}Example Queries:{Colors.END}
{Colors.GREEN}• how do I check DNS records?
• explain what ping does
• show me how to trace a route to google.com
• what is the difference between dig and nslookup?{Colors.END}

{Colors.YELLOW}Remember: Only test systems you own or have permission to test!{Colors.END}
"""
    print(help_text)


def show_commands():
    """Display information about command usage"""
    print(f"\n{Colors.BOLD}Command Usage:{Colors.END}\n")
    print(f"DestroyGPT can suggest and execute various commands for security learning.")
    print(f"All commands require your confirmation before execution.")
    print(f"\nMinimal restrictions applied - use responsibly!\n")


def main():
    """Main application loop"""
    
    # Display banner
    print_banner()
    
    # Get API key
    api_key = get_api_key()
    if not api_key:
        print(f"{Colors.RED}❌ No API key provided. Exiting.{Colors.END}")
        sys.exit(1)
    
    # Select model
    model_id = select_model()
    
    # Initialize AI
    ai = EnhancedAI(api_key, model_id)
    ai.log_session("=== New Session Started ===")
    
    # Show quick help
    print(f"{Colors.BOLD}Quick Start:{Colors.END}")
    print(f"  Type {Colors.CYAN}'help'{Colors.END} for commands")
    print(f"  Type {Colors.CYAN}'exit'{Colors.END} to quit")
    print(f"  Ask any security question to begin!\n")
    
    print(f"{Colors.YELLOW}⚠️  Legal Reminder: Only test authorized systems{Colors.END}\n")
    
    # Main interaction loop
    last_command = None
    
    while True:
        try:
            # Get user input
            user_input = input(f"{Colors.BOLD}{Colors.BLUE}${Colors.END} ").strip()
            
            if not user_input:
                continue
            
            # Handle built-in commands
            if user_input.lower() in ['exit', 'quit']:
                print(f"\n{Colors.GREEN}👋 Goodbye! Stay ethical!{Colors.END}")
                ai.log_session("=== Session Ended ===")
                break
            
            if user_input.lower() == 'help':
                show_help()
                continue
            
            if user_input.lower() == 'commands':
                show_commands()
                continue
            
            if user_input.lower() == 'clear':
                os.system('clear' if os.name != 'nt' else 'cls')
                continue
            
            if user_input.lower() == 'history':
                print(f"\n{Colors.BOLD}Recent Conversation:{Colors.END}\n")
                for msg in ai.history[-10:]:
                    role = f"{Colors.CYAN}You{Colors.END}" if msg["role"] == "user" else f"{Colors.GREEN}AI{Colors.END}"
                    content = msg["content"][:100] + "..." if len(msg["content"]) > 100 else msg["content"]
                    print(f"{role}: {content}\n")
                continue
            
            # Query AI
            print()
            context = {'last_command': last_command}
            response = ai.ask(user_input, context)
            
            # Display response
            print(f"{Colors.GREEN}AI:{Colors.END} {response}\n")
            
            # Extract and validate commands
            commands = CommandValidator.extract_commands(response)
            
            if commands:
                for cmd in commands:
                    # Validate
                    is_valid, msg, cmd_info = CommandValidator.validate_command(cmd)
                    
                    if is_valid:
                        print(f"{Colors.CYAN}💻 Command:{Colors.END} {Colors.BOLD}{cmd}{Colors.END}")
                        
                        # Ask for confirmation
                        confirm = input(f"{Colors.YELLOW}Run this command? [y/N]:{Colors.END} ").strip().lower()
                        
                        if confirm == 'y':
                            print()
                            success, output = CommandValidator.execute_safe(cmd)
                            
                            if success:
                                print(f"{Colors.GREEN}{output}{Colors.END}\n")
                                last_command = cmd
                            else:
                                print(f"{output}\n")
                        else:
                            print(f"{Colors.YELLOW}⊘ Skipped{Colors.END}\n")
                    else:
                        print(f"{Colors.RED}⚠️  Command validation failed: {msg}{Colors.END}\n")
            
        except KeyboardInterrupt:
            print(f"\n\n{Colors.GREEN}👋 Interrupted. Goodbye!{Colors.END}")
            ai.log_session("=== Session Interrupted ===")
            break
        except Exception as e:
            print(f"\n{Colors.RED}❌ Error: {str(e)}{Colors.END}\n")
            continue


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"{Colors.RED}Fatal error: {str(e)}{Colors.END}")
        sys.exit(1)
