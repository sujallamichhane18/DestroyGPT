# DestroyGPT

AI-Powered CLI for Ethical Hacking with Safe Command Execution

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![OpenRouter API](https://img.shields.io/badge/OpenRouter-Integrated-green.svg)](https://openrouter.ai)

## Overview

DestroyGPT is a secure, AI-assisted terminal tool designed for penetration testers and ethical hackers. It integrates with OpenRouter.ai to leverage advanced language models including DeepSeek-R1, GPT-4o, and Grok for generating security commands, payloads, and exploit strategies. 

The tool enables direct command execution within your terminal while enforcing multiple safety mechanisms—including whitelisting, blacklisting, pattern detection, optional Docker sandboxing, and interactive confirmation—to prevent accidental or malicious system damage.

## ✨ Features

- **Multi-Model LLM Support** – Access GPT-4o, DeepSeek-R1, Grok, and more via OpenRouter.ai
- **Safe Command Execution** – Whitelist enforcement, blacklist patterns, danger keyword detection, and mandatory confirmation
- **Docker Sandbox Mode** – Execute commands in isolated Ubuntu 22.04 containers
- **Streaming AI Responses** – Real-time command suggestions and payload generation
- **Command History** – Persistent storage of up to 5,000 commands in JSON format
- **Rotating Logs** – Comprehensive audit logs for forensic analysis
- **Dry-Run Mode** – Validate commands before execution

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- pip package manager
- (Optional) Docker for sandbox execution

### Installation

```bash
git clone https://github.com/sujallamichhane18/DestroyGPT.git
cd DestroyGPT
pip install -r requirements.txt
```

### API Configuration

Set your OpenRouter.ai API key using one of these methods:

**File-based (Recommended):**
```bash
echo "your_api_key_here" > ~/.destroygpt_api_key
chmod 600 ~/.destroygpt_api_key
```

**Environment Variable:**
```bash
export OPENROUTER_API_KEY="your_api_key_here"
```

### Launch

```bash
python destroygpt_advanced.py
```

## 📖 Usage

### Basic Example

```
DestroyGPT >>> Generate a command to scan open ports on example.com
nmap -sV example.com

Command 1:
nmap -sV example.com

Proceed? (y/N) y
[Command output appears here]
```

### Commands

| Command | Description |
|---------|-------------|
| `cmd: <command>` | Execute a system command (subject to safety checks) |
| `exit` / `quit` | Exit the CLI |

## 🛡️ Security Layers

DestroyGPT implements defense-in-depth security:

| Layer | Description |
|-------|-------------|
| **Whitelist** | Only approved tools permitted (nmap, curl, ssh, dig, etc.) |
| **Blacklist Patterns** | Blocks dangerous operations (rm -rf /, mkfs, fork bombs) |
| **Danger Keywords** | Triggers explicit confirmation for sensitive patterns |
| **Docker Isolation** | Optional sandboxed execution in containers |
| **Timeout Protection** | Auto-terminates long-running or stuck processes |

## ⚠️ Disclaimer

This tool is intended exclusively for **authorized** penetration testing, security research, and educational purposes. 

**Unauthorized access to computer systems is illegal.** Users are solely responsible for ensuring compliance with applicable laws and regulations. The author assumes no liability for misuse or any resulting damages.

## 📜 License

Licensed under the MIT License – see [LICENSE](LICENSE) for details.

## 🔗 Links

- **Repository:** [github.com/sujallamichhane18/DestroyGPT](https://github.com/sujallamichhane18/DestroyGPT)
- **OpenRouter:** [openrouter.ai](https://openrouter.ai)
- **Issue Tracker:** [GitHub Issues](https://github.com/sujallamichhane18/DestroyGPT/issues)

---

**Built for ethical hackers. Use responsibly.**
