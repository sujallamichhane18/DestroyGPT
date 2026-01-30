#!/usr/bin/env python3
"""
DestroyGPT v10.0 - Intelligent & Flexible AI Security Assistant
Major improvements: Plugin system, advanced AI, context awareness, safety profiles
"""

import os
import sys
import json
import shlex
import subprocess
import re
import importlib.util
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, List, Tuple, Any, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import requests
from abc import ABC, abstractmethod

# ============================================================================
# Configuration & Constants
# ============================================================================

HOME = Path.home()
CONFIG_DIR = HOME / ".destroygpt"
PLUGINS_DIR = CONFIG_DIR / "plugins"

# Create directories
CONFIG_DIR.mkdir(exist_ok=True)
PLUGINS_DIR.mkdir(exist_ok=True)

# File paths
API_KEY_FILE = CONFIG_DIR / "api_key"
HISTORY_FILE = CONFIG_DIR / "history.json"
LOG_FILE = CONFIG_DIR / "session_log.txt"
CONFIG_FILE = CONFIG_DIR / "config.json"
CONTEXT_FILE = CONFIG_DIR / "context.json"

API_URL = "https://openrouter.ai/api/v1/chat/completions"

# ============================================================================
# Enums & Data Classes
# ============================================================================

class SafetyLevel(Enum):
    """Safety profile levels"""
    STRICT = "strict"          # Maximum safety, minimal commands
    MODERATE = "moderate"      # Balanced approach
    PERMISSIVE = "permissive"  # Minimal restrictions, user responsibility
    CUSTOM = "custom"          # User-defined rules

class CommandRisk(Enum):
    """Command risk classification"""
    SAFE = "safe"              # Read-only, no side effects
    LOW = "low"                # Minimal impact possible
    MEDIUM = "medium"          # Could affect local system
    HIGH = "high"              # Could affect remote systems
    CRITICAL = "critical"      # Destructive potential

@dataclass
class CommandInfo:
    """Enhanced command metadata"""
    command: str
    risk_level: CommandRisk
    requires_root: bool = False
    requires_network: bool = False
    timeout: int = 30
    description: str = ""
    category: str = "general"
    
@dataclass
class UserContext:
    """Track user context for better AI responses"""
    skill_level: str = "intermediate"  # beginner, intermediate, advanced, expert
    preferred_style: str = "detailed"   # brief, detailed, technical
    last_commands: List[str] = None
    session_goals: List[str] = None
    safety_profile: SafetyLevel = SafetyLevel.MODERATE
    
    def __post_init__(self):
        if self.last_commands is None:
            self.last_commands = []
        if self.session_goals is None:
            self.session_goals = []

# ============================================================================
# Color Scheme
# ============================================================================

class Colors:
    """Extended color palette"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[35m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    DIM = '\033[2m'
    END = '\033[0m'
    
    @staticmethod
    def wrap(text: str, color: str) -> str:
        return f"{color}{text}{Colors.END}"

# ============================================================================
# Configuration Manager
# ============================================================================

class ConfigManager:
    """Manage application configuration with persistence"""
    
    DEFAULT_CONFIG = {
        "safety_level": "moderate",
        "default_model": "openai/gpt-4o",
        "api_timeout": 60,
        "max_history": 50,
        "command_timeout": 30,
        "log_commands": True,
        "auto_save": True,
        "show_thinking": False,
        "colored_output": True,
        "user_context": {
            "skill_level": "intermediate",
            "preferred_style": "detailed"
        }
    }
    
    def __init__(self):
        self.config = self.load()
    
    def load(self) -> Dict:
        """Load configuration from file"""
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE, 'r') as f:
                    loaded = json.load(f)
                    # Merge with defaults to add any new keys
                    return {**self.DEFAULT_CONFIG, **loaded}
            except Exception as e:
                print(f"{Colors.YELLOW}⚠️  Config load error: {e}, using defaults{Colors.END}")
        return self.DEFAULT_CONFIG.copy()
    
    def save(self):
        """Save configuration to file"""
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            print(f"{Colors.YELLOW}⚠️  Could not save config: {e}{Colors.END}")
    
    def get(self, key: str, default=None):
        """Get config value"""
        return self.config.get(key, default)
    
    def set(self, key: str, value):
        """Set config value"""
        self.config[key] = value
        if self.config.get('auto_save', True):
            self.save()
    
    def update(self, updates: Dict):
        """Update multiple config values"""
        self.config.update(updates)
        if self.config.get('auto_save', True):
            self.save()

# ============================================================================
# Plugin System
# ============================================================================

class Plugin(ABC):
    """Base class for plugins"""
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Plugin name"""
        pass
    
    @property
    @abstractmethod
    def version(self) -> str:
        """Plugin version"""
        pass
    
    @abstractmethod
    def on_load(self, config: Dict):
        """Called when plugin is loaded"""
        pass
    
    def on_command_pre_execute(self, command: str) -> Tuple[bool, str]:
        """Called before command execution. Return (continue, message)"""
        return True, ""
    
    def on_command_post_execute(self, command: str, output: str, success: bool):
        """Called after command execution"""
        pass
    
    def on_query(self, query: str) -> Optional[str]:
        """Called on user query. Return response to intercept, None to pass through"""
        return None
    
    def get_commands(self) -> Dict[str, Callable]:
        """Return dict of custom commands: {name: function}"""
        return {}

class PluginManager:
    """Manage plugin loading and execution"""
    
    def __init__(self, config: ConfigManager):
        self.config = config
        self.plugins: List[Plugin] = []
        self.custom_commands: Dict[str, Callable] = {}
    
    def load_plugins(self):
        """Load all plugins from plugins directory"""
        if not PLUGINS_DIR.exists():
            return
        
        for plugin_file in PLUGINS_DIR.glob("*.py"):
            if plugin_file.name.startswith("_"):
                continue
            
            try:
                # Load module dynamically
                spec = importlib.util.spec_from_file_location(
                    plugin_file.stem, plugin_file
                )
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                # Find Plugin subclasses
                for item_name in dir(module):
                    item = getattr(module, item_name)
                    if (isinstance(item, type) and 
                        issubclass(item, Plugin) and 
                        item != Plugin):
                        plugin = item()
                        plugin.on_load(self.config.config)
                        self.plugins.append(plugin)
                        
                        # Register custom commands
                        self.custom_commands.update(plugin.get_commands())
                        
                        print(f"{Colors.GREEN}✓ Loaded plugin: {plugin.name} v{plugin.version}{Colors.END}")
            
            except Exception as e:
                print(f"{Colors.YELLOW}⚠️  Failed to load {plugin_file.name}: {e}{Colors.END}")
    
    def on_command_pre_execute(self, command: str) -> Tuple[bool, str]:
        """Call all plugin pre-execute hooks"""
        for plugin in self.plugins:
            should_continue, message = plugin.on_command_pre_execute(command)
            if not should_continue:
                return False, message
        return True, ""
    
    def on_command_post_execute(self, command: str, output: str, success: bool):
        """Call all plugin post-execute hooks"""
        for plugin in self.plugins:
            plugin.on_command_post_execute(command, output, success)
    
    def on_query(self, query: str) -> Optional[str]:
        """Call plugin query hooks"""
        for plugin in self.plugins:
            response = plugin.on_query(query)
            if response:
                return response
        return None

# ============================================================================
# Enhanced AI System
# ============================================================================

class AIModelProvider:
    """Abstraction for different AI providers"""
    
    MODELS = {
        "openai/gpt-4o": {
            "name": "GPT-4o",
            "provider": "OpenAI",
            "speed": "Fast",
            "quality": "Excellent",
            "cost": "$$",
            "context_window": 128000,
            "best_for": "Complex security analysis, detailed explanations"
        },
        "anthropic/claude-3.5-sonnet": {
            "name": "Claude 3.5 Sonnet",
            "provider": "Anthropic",
            "speed": "Fast",
            "quality": "Excellent",
            "cost": "$$",
            "context_window": 200000,
            "best_for": "Thorough analysis, code review, safety checks"
        },
        "google/gemini-2.0-flash-exp:free": {
            "name": "Gemini 2.0 Flash",
            "provider": "Google",
            "speed": "Very Fast",
            "quality": "Very Good",
            "cost": "Free",
            "context_window": 32000,
            "best_for": "Quick responses, real-time assistance"
        },
        "meta-llama/llama-3.1-8b-instruct:free": {
            "name": "Llama 3.1 8B",
            "provider": "Meta",
            "speed": "Fast",
            "quality": "Good",
            "cost": "Free",
            "context_window": 8000,
            "best_for": "Educational queries, practice"
        },
        "deepseek/deepseek-chat": {
            "name": "DeepSeek Chat",
            "provider": "DeepSeek",
            "speed": "Fast",
            "quality": "Very Good",
            "cost": "$",
            "context_window": 64000,
            "best_for": "Technical analysis, coding tasks"
        }
    }
    
    @classmethod
    def list_models(cls) -> List[Tuple[str, Dict]]:
        """Get list of available models"""
        return list(cls.MODELS.items())
    
    @classmethod
    def get_model_info(cls, model_id: str) -> Optional[Dict]:
        """Get model information"""
        return cls.MODELS.get(model_id)

class IntelligentAI:
    """Enhanced AI with context awareness and intelligent prompting"""
    
    def __init__(self, api_key: str, model_id: str, config: ConfigManager, 
                 user_context: UserContext):
        self.api_key = api_key
        self.model_id = model_id
        self.config = config
        self.user_context = user_context
        self.history = []
        self.session_start = datetime.now()
        self.conversation_topics = []
        self.load_history()
    
    def load_history(self):
        """Load conversation history with size limit"""
        if HISTORY_FILE.exists():
            try:
                with open(HISTORY_FILE, 'r') as f:
                    data = json.load(f)
                    max_history = self.config.get('max_history', 50)
                    self.history = data[-max_history:]
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
    
    def save_context(self):
        """Save user context"""
        try:
            with open(CONTEXT_FILE, 'w') as f:
                json.dump(asdict(self.user_context), f, indent=2)
        except:
            pass
    
    def log_session(self, event: str):
        """Log session events"""
        if not self.config.get('log_commands', True):
            return
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(LOG_FILE, 'a') as f:
                f.write(f"[{timestamp}] {event}\n")
        except:
            pass
    
    def _analyze_query(self, query: str) -> Dict[str, Any]:
        """Analyze user query to extract intent and context"""
        analysis = {
            'is_question': '?' in query,
            'is_command_request': any(word in query.lower() for word in 
                ['how', 'show', 'demonstrate', 'example', 'command', 'syntax']),
            'is_explanation_request': any(word in query.lower() for word in
                ['explain', 'what is', 'why', 'difference', 'describe']),
            'mentions_specific_tool': None,
            'difficulty_indicators': []
        }
        
        # Detect tool mentions
        tools = ['nmap', 'wireshark', 'metasploit', 'burp', 'sqlmap', 
                 'nikto', 'john', 'hashcat', 'hydra', 'aircrack']
        for tool in tools:
            if tool in query.lower():
                analysis['mentions_specific_tool'] = tool
                break
        
        # Detect difficulty level
        if any(word in query.lower() for word in ['basic', 'simple', 'beginner', 'start']):
            analysis['difficulty_indicators'].append('beginner')
        if any(word in query.lower() for word in ['advanced', 'complex', 'detailed', 'deep']):
            analysis['difficulty_indicators'].append('advanced')
        
        return analysis
    
    def _build_system_prompt(self, query_analysis: Dict) -> str:
        """Build context-aware system prompt"""
        
        skill_prompts = {
            'beginner': 'The user is a beginner. Provide clear, step-by-step explanations with context.',
            'intermediate': 'The user has some experience. Balance detail with practical examples.',
            'advanced': 'The user is experienced. Provide technical depth and advanced concepts.',
            'expert': 'The user is an expert. Focus on nuance, edge cases, and optimization.'
        }
        
        style_prompts = {
            'brief': 'Be concise and to-the-point. Provide essential information only.',
            'detailed': 'Provide comprehensive explanations with examples and context.',
            'technical': 'Use precise technical language. Include implementation details.'
        }
        
        base_prompt = f"""You are an expert cybersecurity educator and ethical hacking instructor with deep knowledge of:
- Network security and reconnaissance
- Penetration testing methodologies
- Common vulnerabilities and exploitation techniques
- Defensive security measures
- Security tools and their proper usage

## User Profile
{skill_prompts.get(self.user_context.skill_level, skill_prompts['intermediate'])}
{style_prompts.get(self.user_context.preferred_style, style_prompts['detailed'])}

## Safety Profile: {self.user_context.safety_profile.value}
- ALWAYS emphasize legal and ethical considerations
- Remind users to only test authorized systems
- Explain potential risks and consequences
- Suggest safe alternatives when applicable

## Response Guidelines

### When suggesting commands:
1. **Explain first**: Describe what the command does and why
2. **Show the command**: Present it clearly on its own line
3. **Explain parameters**: Break down each flag/option
4. **Expected output**: Describe what results to expect
5. **Safety notes**: Mention any risks or legal considerations

### Command Format:
When providing a command, format it like this:
```bash
command --flags arguments
```

### Use Real Examples:
- Safe domains: example.com, google.com, cloudflare.com, github.com
- Public DNS: 8.8.8.8, 1.1.1.1
- Avoid private IPs unless explicitly discussing local testing

### Prohibited Content:
- Destructive commands (rm -rf, dd, mkfs)
- Actual exploit code or shellcode
- Malware or backdoor implementations
- Commands targeting real systems without authorization

## Context
"""
        
        # Add query-specific context
        if query_analysis['mentions_specific_tool']:
            base_prompt += f"\nQuery mentions: {query_analysis['mentions_specific_tool']}\n"
        
        if query_analysis['is_command_request']:
            base_prompt += "User wants a practical command example.\n"
        
        if query_analysis['is_explanation_request']:
            base_prompt += "User wants conceptual understanding.\n"
        
        # Add recent command context
        if self.user_context.last_commands:
            recent = self.user_context.last_commands[-3:]
            base_prompt += f"\nRecent commands executed: {', '.join(recent)}\n"
        
        # Add session goals
        if self.user_context.session_goals:
            base_prompt += f"\nSession goals: {', '.join(self.user_context.session_goals)}\n"
        
        return base_prompt
    
    def ask(self, prompt: str, show_thinking: bool = False) -> str:
        """Enhanced query with context awareness"""
        
        # Analyze query
        query_analysis = self._analyze_query(prompt)
        
        # Build context-aware system prompt
        system_prompt = self._build_system_prompt(query_analysis)
        
        # Build messages with relevant history
        messages = [{"role": "system", "content": system_prompt}]
        
        # Add relevant history (smart truncation based on model context window)
        model_info = AIModelProvider.get_model_info(self.model_id)
        context_window = model_info.get('context_window', 8000) if model_info else 8000
        
        # Simple heuristic: keep last 10 exchanges or fewer if context is limited
        history_limit = min(10, context_window // 1000)
        messages.extend(self.history[-(history_limit * 2):])
        
        # Add current query
        messages.append({"role": "user", "content": prompt})
        
        if show_thinking or self.config.get('show_thinking', False):
            print(f"\n{Colors.DIM}[Thinking with {len(messages)} context messages...]{Colors.END}\n")
        
        try:
            response = requests.post(
                API_URL,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "https://github.com/destroygpt",
                    "X-Title": "DestroyGPT Enhanced"
                },
                json={
                    "model": self.model_id,
                    "messages": messages,
                    "temperature": 0.7,
                    "max_tokens": 2000,
                    "top_p": 0.9,
                },
                timeout=self.config.get('api_timeout', 60)
            )
            
            if response.status_code == 200:
                data = response.json()
                content = data["choices"][0]["message"]["content"].strip()
                
                # Update history
                self.history.append({"role": "user", "content": prompt})
                self.history.append({"role": "assistant", "content": content})
                self.save_history()
                
                # Extract topics for better context
                self._extract_topics(prompt, content)
                
                # Log query
                self.log_session(f"Query: {prompt[:100]}")
                
                return content
            
            else:
                return self._handle_api_error(response)
        
        except requests.exceptions.Timeout:
            return f"{Colors.RED}❌ Request timeout. Try a simpler query or check your connection.{Colors.END}"
        except requests.exceptions.ConnectionError:
            return f"{Colors.RED}❌ Connection error. Check your internet connection.{Colors.END}"
        except Exception as e:
            return f"{Colors.RED}❌ Error: {str(e)}{Colors.END}"
    
    def _handle_api_error(self, response) -> str:
        """Handle API errors with helpful messages"""
        if response.status_code == 401:
            return f"{Colors.RED}❌ Invalid API key. Check your credentials at ~/.destroygpt/api_key{Colors.END}"
        elif response.status_code == 429:
            return f"{Colors.RED}❌ Rate limited. Wait a moment or upgrade your plan at openrouter.ai{Colors.END}"
        elif response.status_code == 402:
            return f"{Colors.RED}❌ Insufficient credits. Add credits at openrouter.ai{Colors.END}"
        else:
            error_msg = "Unknown error"
            try:
                error_data = response.json()
                if 'error' in error_data:
                    error_msg = error_data['error'].get('message', error_msg)
            except:
                pass
            return f"{Colors.RED}❌ API Error ({response.status_code}): {error_msg}{Colors.END}"
    
    def _extract_topics(self, query: str, response: str):
        """Extract conversation topics for better context"""
        # Simple keyword extraction (could be enhanced with NLP)
        keywords = ['nmap', 'scan', 'dns', 'port', 'network', 'security', 
                   'vulnerability', 'exploit', 'web', 'sql', 'xss']
        
        text = (query + " " + response).lower()
        for keyword in keywords:
            if keyword in text and keyword not in self.conversation_topics:
                self.conversation_topics.append(keyword)
                if len(self.conversation_topics) > 10:
                    self.conversation_topics.pop(0)

# ============================================================================
# Enhanced Command System
# ============================================================================

class CommandDatabase:
    """Database of known commands with metadata"""
    
    COMMAND_DB = {
        'ping': CommandInfo('ping', CommandRisk.SAFE, requires_network=True,
                          description='Send ICMP echo requests', category='network'),
        'dig': CommandInfo('dig', CommandRisk.SAFE, requires_network=True,
                         description='DNS lookup', category='dns'),
        'nslookup': CommandInfo('nslookup', CommandRisk.SAFE, requires_network=True,
                              description='Query DNS servers', category='dns'),
        'whois': CommandInfo('whois', CommandRisk.SAFE, requires_network=True,
                           description='Domain registration info', category='recon'),
        'traceroute': CommandInfo('traceroute', CommandRisk.SAFE, requires_network=True,
                                description='Trace network path', category='network'),
        'nmap': CommandInfo('nmap', CommandRisk.MEDIUM, requires_network=True,
                          timeout=120, description='Network scanner', category='scan'),
        'curl': CommandInfo('curl', CommandRisk.LOW, requires_network=True,
                          description='Transfer data with URLs', category='web'),
        'wget': CommandInfo('wget', CommandRisk.LOW, requires_network=True,
                          description='Download files', category='web'),
        'netstat': CommandInfo('netstat', CommandRisk.SAFE,
                             description='Network statistics', category='network'),
        'ss': CommandInfo('ss', CommandRisk.SAFE,
                        description='Socket statistics', category='network'),
    }
    
    @classmethod
    def get_command_info(cls, command: str) -> Optional[CommandInfo]:
        """Get command information"""
        return cls.COMMAND_DB.get(command)
    
    @classmethod
    def get_by_category(cls, category: str) -> List[CommandInfo]:
        """Get commands by category"""
        return [cmd for cmd in cls.COMMAND_DB.values() if cmd.category == category]

class SmartCommandValidator:
    """Intelligent command validation with safety profiles"""
    
    def __init__(self, safety_level: SafetyLevel = SafetyLevel.MODERATE):
        self.safety_level = safety_level
        self.blocked_patterns = self._get_blocked_patterns()
    
    def _get_blocked_patterns(self) -> List[str]:
        """Get blocked patterns based on safety level"""
        base_patterns = [
            r'\brm\s+-rf\b',  # Recursive force delete
            r'\bmkfs\b',      # Format filesystem
            r'\bdd\s+if=.*of=/dev/',  # Disk operations
        ]
        
        if self.safety_level == SafetyLevel.STRICT:
            base_patterns.extend([
                r'\bsudo\b', r'\bsu\b',  # Privilege escalation
                r'>\s*/dev/',             # Write to devices
                r'\bchmod\s+777\b',       # Insecure permissions
            ])
        elif self.safety_level == SafetyLevel.MODERATE:
            base_patterns.extend([
                r'\bsudo\s+rm\b',  # Sudo delete
            ])
        # PERMISSIVE and CUSTOM have minimal restrictions
        
        return base_patterns
    
    def extract_commands(self, text: str) -> List[str]:
        """Extract commands from text with improved parsing"""
        commands = []
        lines = text.split('\n')
        
        in_code_block = False
        code_block_lang = None
        
        for line in lines:
            stripped = line.strip()
            
            # Handle code blocks
            if stripped.startswith('```'):
                if not in_code_block:
                    in_code_block = True
                    code_block_lang = stripped[3:].strip()
                else:
                    in_code_block = False
                    code_block_lang = None
                continue
            
            # Only process lines in bash/shell code blocks or that look like commands
            if in_code_block:
                if code_block_lang in ['bash', 'sh', 'shell', '']:
                    if stripped and not stripped.startswith('#'):
                        commands.append(stripped)
            else:
                # Check if line looks like a command (starts with common command or has $)
                if stripped.startswith('$ '):
                    commands.append(stripped[2:])
                elif any(stripped.startswith(cmd) for cmd in 
                        ['ping', 'dig', 'nmap', 'curl', 'wget', 'ls', 'cat', 'grep',
                         'nslookup', 'whois', 'traceroute', 'host', 'netstat', 'ss']):
                    commands.append(stripped)
        
        return list(dict.fromkeys(commands))  # Remove duplicates, preserve order
    
    def validate(self, cmd_string: str) -> Tuple[bool, str, Optional[CommandInfo]]:
        """
        Validate command with risk assessment
        Returns: (is_valid, message, command_info)
        """
        try:
            # Parse command
            parts = shlex.split(cmd_string)
            if not parts:
                return False, "Empty command", None
            
            base_cmd = parts[0]
            
            # Check blocked patterns
            for pattern in self.blocked_patterns:
                if re.search(pattern, cmd_string, re.IGNORECASE):
                    return False, f"Blocked: matches safety pattern '{pattern}'", None
            
            # Get command metadata
            cmd_info = CommandDatabase.get_command_info(base_cmd)
            if not cmd_info:
                # Unknown command - create default info
                cmd_info = CommandInfo(base_cmd, CommandRisk.MEDIUM, timeout=30)
            
            # Risk-based validation
            if self.safety_level == SafetyLevel.STRICT:
                if cmd_info.risk_level.value in ['high', 'critical']:
                    return False, f"Command risk too high for STRICT mode", cmd_info
            
            # Check for root requirement
            if cmd_info.requires_root and 'sudo' not in cmd_string:
                return True, "Note: Command may require root privileges", cmd_info
            
            return True, "Validated", cmd_info
            
        except ValueError as e:
            return False, f"Parse error: {str(e)}", None
        except Exception as e:
            return False, f"Validation error: {str(e)}", None
    
    def execute(self, cmd_string: str, timeout: Optional[int] = None) -> Tuple[bool, str]:
        """
        Execute validated command with safety measures
        Returns: (success, output)
        """
        try:
            # Re-validate
            is_valid, msg, cmd_info = self.validate(cmd_string)
            if not is_valid:
                return False, f"Validation failed: {msg}"
            
            # Use command-specific timeout
            if timeout is None:
                timeout = cmd_info.timeout if cmd_info else 30
            
            # Parse and execute
            parts = shlex.split(cmd_string)
            
            result = subprocess.run(
                parts,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False  # Critical: Never use shell=True
            )
            
            # Process output
            output = result.stdout.strip() if result.stdout else result.stderr.strip()
            
            if not output:
                output = f"Command completed (exit code: {result.returncode})"
            
            success = result.returncode == 0
            
            # Log execution
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            try:
                with open(LOG_FILE, 'a') as f:
                    f.write(f"[{timestamp}] EXECUTED: {cmd_string}\n")
                    f.write(f"[{timestamp}] STATUS: {'SUCCESS' if success else 'FAILED'}\n")
                    f.write(f"[{timestamp}] OUTPUT: {output[:200]}\n\n")
            except:
                pass
            
            return success, output
            
        except subprocess.TimeoutExpired:
            return False, f"{Colors.YELLOW}⏱️  Command timeout ({timeout}s){Colors.END}"
        except FileNotFoundError:
            return False, f"{Colors.RED}❌ Command '{parts[0]}' not found. Is it installed?{Colors.END}"
        except PermissionError:
            return False, f"{Colors.RED}❌ Permission denied. May require elevated privileges.{Colors.END}"
        except Exception as e:
            return False, f"{Colors.RED}❌ Execution error: {str(e)}{Colors.END}"

# ============================================================================
# User Interface
# ============================================================================

class EnhancedUI:
    """Enhanced user interface with better formatting"""
    
    @staticmethod
    def print_banner():
        """Display enhanced startup banner"""
        banner = f"""{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════╗
║  ____            _                  ____ ____ _____       ║
║ |  _ \\ ___  ___ | |_ _ __ ___  _   _ / ___|  _ \\_   _|  ║
║ | | | / _ \\/ __|| __| '__/ _ \\| | | | | _ | |_) || |    ║
║ | |_| |  __/\\__ \\| |_| | | (_) | |_| | |_| |  __/ | |    ║
║ |____/ \\___||___/ \\__|_|  \\___/ \\__, |\\____|_|    |_|    ║
║                                  |___/                     ║
║                                                            ║
║            Enhanced v10.0 - Intelligent & Flexible        ║
╚═══════════════════════════════════════════════════════════╝
{Colors.END}"""
        print(banner)
    
    @staticmethod
    def print_section(title: str, content: str = ""):
        """Print formatted section"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'─' * 60}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.WHITE}{title}{Colors.END}")
        if content:
            print(f"{Colors.CYAN}{'─' * 60}{Colors.END}")
            print(content)
        print(f"{Colors.CYAN}{'─' * 60}{Colors.END}\n")
    
    @staticmethod
    def print_command(cmd: str, risk_level: CommandRisk = None):
        """Print command with risk indicator"""
        risk_colors = {
            CommandRisk.SAFE: Colors.GREEN,
            CommandRisk.LOW: Colors.CYAN,
            CommandRisk.MEDIUM: Colors.YELLOW,
            CommandRisk.HIGH: Colors.RED,
            CommandRisk.CRITICAL: Colors.MAGENTA
        }
        
        risk_color = risk_colors.get(risk_level, Colors.CYAN)
        risk_text = f"[{risk_level.value.upper()}]" if risk_level else ""
        
        print(f"{Colors.BOLD}💻 Command:{Colors.END} {risk_color}{cmd}{Colors.END} {risk_text}")
    
    @staticmethod
    def confirm(prompt: str, default: bool = False) -> bool:
        """Enhanced confirmation prompt"""
        default_text = "[Y/n]" if default else "[y/N]"
        response = input(f"{Colors.YELLOW}{prompt} {default_text}:{Colors.END} ").strip().lower()
        
        if not response:
            return default
        return response in ['y', 'yes']
    
    @staticmethod
    def select_from_list(title: str, items: List[Tuple[str, str]], default: int = 0) -> int:
        """Interactive list selection"""
        print(f"\n{Colors.BOLD}{title}{Colors.END}\n")
        
        for i, (key, description) in enumerate(items, 1):
            print(f"{Colors.CYAN}[{i}]{Colors.END} {key}")
            if description:
                print(f"    {Colors.DIM}{description}{Colors.END}")
        
        while True:
            choice = input(f"\n{Colors.BOLD}Select [1-{len(items)}] (default: {default + 1}): {Colors.END}").strip()
            
            if not choice:
                return default
            
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(items):
                    return idx
            except ValueError:
                pass
            
            print(f"{Colors.RED}Invalid selection. Try again.{Colors.END}")

# ============================================================================
# Main Application
# ============================================================================

class DestroyGPT:
    """Main application class"""
    
    def __init__(self):
        self.config = ConfigManager()
        self.ui = EnhancedUI()
        self.plugin_manager = PluginManager(self.config)
        self.ai: Optional[IntelligentAI] = None
        self.validator: Optional[SmartCommandValidator] = None
        self.user_context: Optional[UserContext] = None
        
    def initialize(self):
        """Initialize application"""
        self.ui.print_banner()
        
        # Load plugins
        print(f"{Colors.BOLD}Loading plugins...{Colors.END}")
        self.plugin_manager.load_plugins()
        
        # Get API key
        api_key = self._get_api_key()
        if not api_key:
            print(f"{Colors.RED}❌ No API key provided. Cannot continue.{Colors.END}")
            sys.exit(1)
        
        # Select model
        model_id = self._select_model()
        
        # Load or create user context
        self.user_context = self._load_user_context()
        
        # Initialize components
        self.ai = IntelligentAI(api_key, model_id, self.config, self.user_context)
        
        safety_level = SafetyLevel(self.config.get('safety_level', 'moderate'))
        self.validator = SmartCommandValidator(safety_level)
        
        # Show welcome message
        self._show_welcome()
    
    def _get_api_key(self) -> Optional[str]:
        """Get API key from various sources"""
        # Environment variable
        if os.getenv("OPENROUTER_API_KEY"):
            return os.getenv("OPENROUTER_API_KEY").strip()
        
        # Config file
        if API_KEY_FILE.exists():
            try:
                return API_KEY_FILE.read_text().strip()
            except:
                pass
        
        # Prompt user
        print(f"\n{Colors.YELLOW}No API key found.{Colors.END}")
        print(f"Get one free at: {Colors.CYAN}https://openrouter.ai/keys{Colors.END}")
        
        key = input(f"\n{Colors.BOLD}Enter your OpenRouter API key (or press Enter to exit): {Colors.END}").strip()
        if not key:
            return None
        
        try:
            API_KEY_FILE.write_text(key)
            API_KEY_FILE.chmod(0o600)
            print(f"{Colors.GREEN}✓ API key saved securely{Colors.END}")
            return key
        except Exception as e:
            print(f"{Colors.YELLOW}⚠️  Could not save key: {e}{Colors.END}")
            return key
    
    def _select_model(self) -> str:
        """Interactive model selection"""
        models = AIModelProvider.list_models()
        items = [
            (info['name'], f"{info['provider']} | {info['best_for']}")
            for _, info in models
        ]
        
        default_model = self.config.get('default_model', 'openai/gpt-4o')
        default_idx = next((i for i, (mid, _) in enumerate(models) if mid == default_model), 0)
        
        selected_idx = self.ui.select_from_list("Available AI Models", items, default_idx)
        model_id = models[selected_idx][0]
        
        print(f"\n{Colors.GREEN}✓ Using: {models[selected_idx][1]['name']}{Colors.END}")
        
        return model_id
    
    def _load_user_context(self) -> UserContext:
        """Load or create user context"""
        if CONTEXT_FILE.exists():
            try:
                with open(CONTEXT_FILE, 'r') as f:
                    data = json.load(f)
                    # Handle safety_profile enum
                    if 'safety_profile' in data:
                        data['safety_profile'] = SafetyLevel(data['safety_profile'])
                    return UserContext(**data)
            except:
                pass
        
        # Create new context
        context = UserContext()
        context.safety_profile = SafetyLevel(self.config.get('safety_level', 'moderate'))
        return context
    
    def _show_welcome(self):
        """Display welcome message and quick start"""
        safety_indicator = {
            SafetyLevel.STRICT: f"{Colors.GREEN}STRICT{Colors.END}",
            SafetyLevel.MODERATE: f"{Colors.YELLOW}MODERATE{Colors.END}",
            SafetyLevel.PERMISSIVE: f"{Colors.RED}PERMISSIVE{Colors.END}"
        }
        
        print(f"\n{Colors.BOLD}Session Information:{Colors.END}")
        print(f"  Safety Level: {safety_indicator.get(self.user_context.safety_profile, 'CUSTOM')}")
        print(f"  Skill Level: {Colors.CYAN}{self.user_context.skill_level.title()}{Colors.END}")
        print(f"  Style: {Colors.CYAN}{self.user_context.preferred_style.title()}{Colors.END}")
        
        print(f"\n{Colors.BOLD}Quick Commands:{Colors.END}")
        print(f"  {Colors.CYAN}help{Colors.END}      - Show all commands")
        print(f"  {Colors.CYAN}config{Colors.END}    - Adjust settings")
        print(f"  {Colors.CYAN}plugins{Colors.END}   - Manage plugins")
        print(f"  {Colors.CYAN}exit{Colors.END}      - Quit program")
        
        print(f"\n{Colors.YELLOW}⚠️  Legal Reminder: Only test authorized systems!{Colors.END}\n")
        
        self.ai.log_session("=== Enhanced Session Started ===")
    
    def _handle_builtin_command(self, cmd: str) -> bool:
        """Handle built-in commands. Returns True if handled."""
        
        if cmd in ['exit', 'quit']:
            print(f"\n{Colors.GREEN}👋 Goodbye! Stay ethical and keep learning!{Colors.END}")
            self.ai.log_session("=== Session Ended ===")
            self.ai.save_context()
            return True
        
        elif cmd == 'help':
            self._show_help()
            return True
        
        elif cmd == 'config':
            self._show_config_menu()
            return True
        
        elif cmd == 'plugins':
            self._show_plugin_info()
            return True
        
        elif cmd == 'history':
            self._show_history()
            return True
        
        elif cmd == 'clear':
            os.system('clear' if os.name != 'nt' else 'cls')
            return True
        
        elif cmd == 'stats':
            self._show_stats()
            return True
        
        elif cmd == 'topics':
            self._show_topics()
            return True
        
        # Check plugin custom commands
        elif cmd in self.plugin_manager.custom_commands:
            self.plugin_manager.custom_commands[cmd]()
            return True
        
        return False
    
    def _show_help(self):
        """Display comprehensive help"""
        help_text = f"""
{Colors.BOLD}DestroyGPT Enhanced - Command Reference{Colors.END}

{Colors.BOLD}Built-in Commands:{Colors.END}
  {Colors.CYAN}help{Colors.END}        Show this help message
  {Colors.CYAN}config{Colors.END}      Configure settings (safety, skill level, etc.)
  {Colors.CYAN}plugins{Colors.END}     View loaded plugins and custom commands
  {Colors.CYAN}history{Colors.END}     Display conversation history
  {Colors.CYAN}topics{Colors.END}      Show conversation topics
  {Colors.CYAN}stats{Colors.END}       Display session statistics
  {Colors.CYAN}clear{Colors.END}       Clear the screen
  {Colors.CYAN}exit/quit{Colors.END}   Exit the program

{Colors.BOLD}How to Use:{Colors.END}
  • Ask questions about security concepts
  • Request command examples for specific tasks
  • Learn about tools and techniques
  • Practice reconnaissance on authorized targets

{Colors.BOLD}Example Queries:{Colors.END}
  {Colors.GREEN}• "How do I enumerate subdomains?"
  • "Show me how to use nmap for service detection"
  • "Explain DNS zone transfers"
  • "What's the difference between TCP and UDP scanning?"{Colors.END}

{Colors.BOLD}Safety Levels:{Colors.END}
  {Colors.GREEN}STRICT{Colors.END}     - Maximum safety, educational focus
  {Colors.YELLOW}MODERATE{Colors.END}   - Balanced (default)
  {Colors.RED}PERMISSIVE{Colors.END} - Minimal restrictions, expert use

{Colors.YELLOW}Always ensure you have authorization before testing any systems!{Colors.END}
"""
        print(help_text)
    
    def _show_config_menu(self):
        """Interactive configuration menu"""
        print(f"\n{Colors.BOLD}Configuration Menu{Colors.END}\n")
        print(f"1. Safety Level: {self.user_context.safety_profile.value}")
        print(f"2. Skill Level: {self.user_context.skill_level}")
        print(f"3. Response Style: {self.user_context.preferred_style}")
        print(f"4. Show AI Thinking: {self.config.get('show_thinking', False)}")
        print(f"5. Command Logging: {self.config.get('log_commands', True)}")
        print(f"6. Back to main")
        
        choice = input(f"\n{Colors.BOLD}Select option [1-6]: {Colors.END}").strip()
        
        if choice == '1':
            levels = [(l.value, "") for l in SafetyLevel]
            idx = self.ui.select_from_list("Select Safety Level", levels)
            self.user_context.safety_profile = list(SafetyLevel)[idx]
            self.config.set('safety_level', self.user_context.safety_profile.value)
            self.validator = SmartCommandValidator(self.user_context.safety_profile)
            print(f"{Colors.GREEN}✓ Safety level updated{Colors.END}")
        
        elif choice == '2':
            levels = [
                ("beginner", "New to security"),
                ("intermediate", "Some experience"),
                ("advanced", "Experienced practitioner"),
                ("expert", "Security professional")
            ]
            idx = self.ui.select_from_list("Select Skill Level", levels)
            self.user_context.skill_level = levels[idx][0]
            print(f"{Colors.GREEN}✓ Skill level updated{Colors.END}")
        
        elif choice == '3':
            styles = [
                ("brief", "Concise responses"),
                ("detailed", "Comprehensive explanations"),
                ("technical", "Technical depth")
            ]
            idx = self.ui.select_from_list("Select Response Style", styles)
            self.user_context.preferred_style = styles[idx][0]
            print(f"{Colors.GREEN}✓ Style updated{Colors.END}")
        
        elif choice == '4':
            current = self.config.get('show_thinking', False)
            self.config.set('show_thinking', not current)
            print(f"{Colors.GREEN}✓ Show thinking: {not current}{Colors.END}")
        
        elif choice == '5':
            current = self.config.get('log_commands', True)
            self.config.set('log_commands', not current)
            print(f"{Colors.GREEN}✓ Command logging: {not current}{Colors.END}")
        
        self.ai.save_context()
    
    def _show_plugin_info(self):
        """Display plugin information"""
        print(f"\n{Colors.BOLD}Loaded Plugins:{Colors.END}\n")
        
        if not self.plugin_manager.plugins:
            print(f"{Colors.YELLOW}No plugins loaded{Colors.END}")
            print(f"\nAdd plugins to: {PLUGINS_DIR}")
        else:
            for plugin in self.plugin_manager.plugins:
                print(f"{Colors.GREEN}✓{Colors.END} {Colors.BOLD}{plugin.name}{Colors.END} v{plugin.version}")
        
        if self.plugin_manager.custom_commands:
            print(f"\n{Colors.BOLD}Custom Commands:{Colors.END}")
            for cmd_name in self.plugin_manager.custom_commands:
                print(f"  {Colors.CYAN}{cmd_name}{Colors.END}")
        
        print()
    
    def _show_history(self):
        """Display conversation history"""
        print(f"\n{Colors.BOLD}Conversation History:{Colors.END}\n")
        
        if not self.ai.history:
            print(f"{Colors.YELLOW}No history yet{Colors.END}")
            return
        
        for i, msg in enumerate(self.ai.history[-10:], 1):
            role = f"{Colors.CYAN}You{Colors.END}" if msg["role"] == "user" else f"{Colors.GREEN}AI{Colors.END}"
            content = msg["content"][:150] + "..." if len(msg["content"]) > 150 else msg["content"]
            print(f"{i}. {role}: {content}\n")
    
    def _show_stats(self):
        """Display session statistics"""
        session_duration = datetime.now() - self.ai.session_start
        
        print(f"\n{Colors.BOLD}Session Statistics:{Colors.END}\n")
        print(f"Duration: {session_duration}")
        print(f"Queries: {len(self.ai.history) // 2}")
        print(f"Commands executed: {len(self.user_context.last_commands)}")
        print(f"Topics discussed: {len(self.ai.conversation_topics)}")
        print()
    
    def _show_topics(self):
        """Show conversation topics"""
        print(f"\n{Colors.BOLD}Conversation Topics:{Colors.END}\n")
        
        if not self.ai.conversation_topics:
            print(f"{Colors.YELLOW}No topics detected yet{Colors.END}")
        else:
            print(", ".join(self.ai.conversation_topics))
        
        print()
    
    def run(self):
        """Main application loop"""
        
        while True:
            try:
                # Get user input
                user_input = input(f"{Colors.BOLD}{Colors.BLUE}❯{Colors.END} ").strip()
                
                if not user_input:
                    continue
                
                # Handle built-in commands
                if self._handle_builtin_command(user_input.lower()):
                    if user_input.lower() in ['exit', 'quit']:
                        break
                    continue
                
                # Check plugin interception
                plugin_response = self.plugin_manager.on_query(user_input)
                if plugin_response:
                    print(f"\n{Colors.GREEN}Plugin:{Colors.END} {plugin_response}\n")
                    continue
                
                # Query AI
                print()
                response = self.ai.ask(user_input, self.config.get('show_thinking', False))
                
                # Display response
                print(f"{Colors.GREEN}AI:{Colors.END} {response}\n")
                
                # Extract and handle commands
                commands = self.validator.extract_commands(response)
                
                for cmd in commands:
                    # Validate
                    is_valid, msg, cmd_info = self.validator.validate(cmd)
                    
                    if is_valid:
                        # Display command with risk level
                        risk = cmd_info.risk_level if cmd_info else None
                        self.ui.print_command(cmd, risk)
                        
                        # Plugin pre-execute hook
                        should_continue, plugin_msg = self.plugin_manager.on_command_pre_execute(cmd)
                        if not should_continue:
                            print(f"{Colors.RED}⊘ Plugin blocked: {plugin_msg}{Colors.END}\n")
                            continue
                        
                        # Ask for confirmation
                        if self.ui.confirm("Run this command?", default=False):
                            print()
                            success, output = self.validator.execute(cmd)
                            
                            # Display output
                            color = Colors.GREEN if success else Colors.RED
                            print(f"{color}{output}{Colors.END}\n")
                            
                            # Update context
                            if success:
                                self.user_context.last_commands.append(cmd)
                                if len(self.user_context.last_commands) > 10:
                                    self.user_context.last_commands.pop(0)
                            
                            # Plugin post-execute hook
                            self.plugin_manager.on_command_post_execute(cmd, output, success)
                        else:
                            print(f"{Colors.YELLOW}⊘ Skipped{Colors.END}\n")
                    else:
                        print(f"{Colors.RED}⚠️  Validation failed: {msg}{Colors.END}\n")
            
            except KeyboardInterrupt:
                print(f"\n\n{Colors.YELLOW}Interrupted. Type 'exit' to quit or press Ctrl+C again.{Colors.END}\n")
                try:
                    # Give them a chance to type exit
                    input()
                except KeyboardInterrupt:
                    print(f"\n{Colors.GREEN}👋 Goodbye!{Colors.END}")
                    self.ai.log_session("=== Session Interrupted ===")
                    break
            
            except Exception as e:
                print(f"\n{Colors.RED}❌ Error: {str(e)}{Colors.END}\n")
                continue

# ============================================================================
# Entry Point
# ============================================================================

def main():
    """Application entry point"""
    try:
        app = DestroyGPT()
        app.initialize()
        app.run()
    except Exception as e:
        print(f"{Colors.RED}Fatal error: {str(e)}{Colors.END}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
