# DestroyGPT

<div align="center">

<img src="https://media.giphy.com/media/3o7TKU8FyF4ilS1jUI/giphy.gif" width="200" height="200" alt="AI Animation">

# ⚔️ DestroyGPT

### AI-Powered CLI for Ethical Penetration Testing with Secure Command Execution

![Typing Animation](https://media.giphy.com/media/QaMcXK7nWBfo7EV9Ff/giphy.gif)

<br>

[![License](https://img.shields.io/github/license/sujallamichhane18/DestroyGPT?color=00d4ff&style=flat-square)](LICENSE)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-00d4ff?style=flat-square)](https://www.python.org/)
[![Status](https://img.shields.io/badge/Status-Active-00ff41?style=flat-square)](https://github.com/sujallamichhane18/DestroyGPT)
[![OpenRouter](https://img.shields.io/badge/Powered%20by-OpenRouter.ai-ff006e?style=flat-square)](https://openrouter.ai/)
[![Stars](https://img.shields.io/github/stars/sujallamichhane18/DestroyGPT?color=00d4ff&style=flat-square)](https://github.com/sujallamichhane18/DestroyGPT/stargazers)

<br>

<a href="#-quick-start"><strong>Quick Start</strong></a> • <a href="#-features"><strong>Features</strong></a> • <a href="#-installation"><strong>Installation</strong></a> • <a href="#-security-architecture"><strong>Security</strong></a> • <a href="#-license"><strong>License</strong></a>

</div>

---

## 🎯 Overview

<img align="right" src="https://media.giphy.com/media/l46Cy1rHbQ92uPl3m/giphy.gif" width="300" height="300" alt="Hacking Animation">

**DestroyGPT** is a cutting-edge, AI-assisted penetration testing terminal interface designed for security professionals and ethical hackers. It harnesses the power of advanced language models via [OpenRouter.ai](https://openrouter.ai/)—including **DeepSeek-R1**, **GPT-4o**, and **Grok**—to generate intelligent security commands, payloads, and exploit strategies.

Unlike standard penetration testing tools, DestroyGPT executes commands directly in your terminal while enforcing **multiple security mechanisms**: command whitelisting, blacklist pattern matching, threat detection, optional Docker sandboxing, and interactive confirmation prompts. This combination ensures powerful capabilities without sacrificing system safety.

Whether you're conducting authorized security assessments, performing vulnerability research, or learning cybersecurity concepts, DestroyGPT is your AI-powered companion.

<br clear="right"/>

---

## ✨ Key Features

<table>
  <tr>
    <td width="50%">
      <h3>🧠 Multi-Model LLM Support</h3>
      <p>Access cutting-edge language models (GPT-4o, DeepSeek-R1, Grok) for intelligent command generation and real-time suggestions</p>
      <img src="https://media.giphy.com/media/l0HlNaQ9wTv06XsqXm/giphy.gif" width="100%" height="150" alt="AI Brain">
    </td>
    <td width="50%">
      <h3>🛡️ Layered Security</h3>
      <p>Whitelist-based execution, blacklist patterns, keyword detection, timeout protection, and Docker isolation</p>
      <img src="https://media.giphy.com/media/xULw8MYkghbQXO3okM/giphy.gif" width="100%" height="150" alt="Security Shield">
    </td>
  </tr>
  <tr>
    <td width="50%">
      <h3>⚡ Real-Time Streaming</h3>
      <p>Receive AI-generated suggestions as they're produced for immediate feedback and faster decision-making</p>
      <img src="https://media.giphy.com/media/3o6Zt6KHxJTbXCnSvu/giphy.gif" width="100%" height="150" alt="Lightning">
    </td>
    <td width="50%">
      <h3>📊 Comprehensive Logging</h3>
      <p>Persistent command history (5,000+ records) with rotating logs for compliance and auditing</p>
      <img src="https://media.giphy.com/media/l3q2K6HIQ6playpUQ/giphy.gif" width="100%" height="150" alt="Data Logging">
    </td>
  </tr>
  <tr>
    <td width="50%">
      <h3>🐳 Docker Sandboxing</h3>
      <p>Optional isolated execution in Ubuntu 22.04 containers for maximum safety and isolation</p>
      <img src="https://media.giphy.com/media/3o85xIO33l7RlmLR4I/giphy.gif" width="100%" height="150" alt="Docker Container">
    </td>
    <td width="50%">
      <h3>🔍 Dry-Run Mode</h3>
      <p>Preview and inspect commands before execution to ensure safety and accuracy</p>
      <img src="https://media.giphy.com/media/VgCDAzcKvsR6OM0uWM/giphy.gif" width="100%" height="150" alt="Preview">
    </td>
  </tr>
</table>

---

## 🎬 Demo

<div align="center">

### Interactive CLI Demo

<img src="https://media.giphy.com/media/l0MYt5jPR6QX5pnqM/giphy.gif" width="600" height="400" alt="CLI Demo">

**See DestroyGPT in Action**

```
DestroyGPT >>> Generate a command to scan open ports on example.com

🤖 AI Response:
nmap -sV example.com

Command 1:
nmap -sV example.com
Proceed? (y/N) y

✅ Executing command...
```

</div>

---

## 🚀 Quick Start

### Prerequisites

<img align="right" src="https://media.giphy.com/media/3o6Zt5KVndKFury1sI/giphy.gif" width="250" height="250" alt="Setup">

- **Python** 3.9 or higher
- **pip** package manager
- **Docker** (optional, for sandboxed execution)
- **OpenRouter.ai** API key ([Get one here](https://openrouter.ai/))

### Installation

```bash
# 🔧 Clone the repository
git clone https://github.com/sujallamichhane18/DestroyGPT.git
cd DestroyGPT

# 📦 Install dependencies
pip install -r requirements.txt
```

<br clear="right"/>

### Configure API Key

Store your OpenRouter.ai API key securely:

**Method 1: Local File (Recommended)** 🔒
```bash
echo "your_api_key_here" > ~/.destroygpt_api_key
chmod 600 ~/.destroygpt_api_key
```

**Method 2: Environment Variable** 🌍
```bash
export OPENROUTER_API_KEY="your_api_key_here"
```

### Run DestroyGPT

```bash
python destroygpt_advanced.py
```

<img src="https://media.giphy.com/media/l46CyB1o3A8WJHcjO/giphy.gif" width="100%" height="200" alt="Starting Up">

---

## 📖 Usage Guide

### Interactive CLI Examples

<img align="left" src="https://media.giphy.com/media/l3q2K5jTLw33XS9iM/giphy.gif" width="200" height="200" alt="Typing">

#### Network Reconnaissance
```bash
DestroyGPT >>> Enumerate subdomains for example.com using modern techniques

🤖 AI Response:
subfinder -d example.com -t 40
amass enum -d example.com
```

#### Vulnerability Assessment
```bash
DestroyGPT >>> Generate a command to scan for common web vulnerabilities on localhost:8080

🤖 AI Response:
nikto -h localhost:8080
```

#### Port Scanning & Enumeration
```bash
DestroyGPT >>> Perform comprehensive service enumeration on 192.168.1.0/24

🤖 AI Response:
nmap -sV -p- 192.168.1.0/24
```

<br clear="left"/>

### Built-In Commands

| Command | Description | Icon |
|---------|-------------|------|
| `cmd: <command>` | Execute a system command (subject to safety checks) | ⚙️ |
| `exit` / `quit` | Exit the CLI | 🚪 |
| `help` | Display available commands | ❓ |
| `history` | View command history | 📜 |
| `clear` | Clear the screen | 🗑️ |

---

## 🛡️ Security Architecture

<div align="center">

<img src="https://media.giphy.com/media/l0HlQXnMCVgkOK5vy/giphy.gif" width="400" height="300" alt="Security">

### Defense-in-Depth Approach

</div>

DestroyGPT implements multiple layers of protection to ensure safe operation:

### 1️⃣ Whitelist Layer
Only pre-approved security tools are permitted to execute.

**Default Whitelist:**
- **Network Tools**: `nmap`, `netcat`, `curl`, `wget`, `dig`, `whois`, `traceroute`, `ping`
- **SSH Utilities**: `ssh`, `ssh-keygen`, `scp`, `ssh-copy-id`
- **Cryptography**: `openssl`, `hashcat`, `john`
- **System Analysis**: `netstat`, `ss`, `ps`, `top`, `whoami`

### 2️⃣ Blacklist Pattern Matching
Automatically blocks dangerous patterns and commands.

```
❌ Destructive Operations:
   - rm -rf /
   - mkfs.*
   - dd if=/dev/zero
   
❌ Resource Exhaustion:
   - Fork bombs: :(){ :|: & };
   - Infinite loops
   
❌ Privilege Escalation:
   - Kernel exploits
   - Privilege escalation vectors
```

### 3️⃣ Threat Keyword Detection
Commands containing dangerous keywords trigger explicit user confirmation.

**Monitored Keywords:**
- System Control: `sudo`, `chmod`, `chown`, `passwd`
- Shutdown: `shutdown`, `reboot`, `halt`
- Database: `drop database`, `delete from`
- File Operations: `rm`, `mv`, `cp` (on system directories)

### 4️⃣ Docker Isolation (Optional)

<img align="right" src="https://media.giphy.com/media/iIqmM5tMUEUM8/giphy.gif" width="250" height="200" alt="Docker">

Run commands in isolated Ubuntu 22.04 containers when available:
- ✅ Complete filesystem isolation
- ✅ Network sandboxing
- ✅ Resource limits and quotas
- ✅ Automatic cleanup after execution

<br clear="right"/>

### 5️⃣ Process Management
- ⏱️ Configurable timeout thresholds (default: 30 seconds)
- 🔌 Automatic termination of unresponsive processes
- 📡 Signal handling for clean shutdowns
- 📊 Resource monitoring and limits

---

## ⚙️ Configuration

### Environment Variables

```bash
# 🔑 API Configuration
OPENROUTER_API_KEY=your_key_here
OPENROUTER_MODEL=gpt-4o  # Default model

# 🛡️ Security Settings
ENABLE_DOCKER_SANDBOX=false
COMMAND_TIMEOUT=30
MAX_HISTORY_SIZE=5000

# 📝 Logging
LOG_LEVEL=INFO
LOG_DIR=./logs
```

### Custom Whitelist/Blacklist

Edit `config/security.json`:

```json
{
  "whitelist": [
    "nmap", "curl", "ssh", "dig", "netcat"
  ],
  "blacklist_patterns": [
    "rm -rf /",
    "mkfs",
    ":(){ :|: & };"
  ],
  "danger_keywords": [
    "sudo", "chmod", "shutdown", "reboot"
  ],
  "timeout_seconds": 30,
  "max_output_lines": 1000
}
```

---

## 📊 Performance Benchmarks

<img src="https://media.giphy.com/media/l0HlPy9x8FZo0XO1i/giphy.gif" width="100%" height="150" alt="Performance">

| Model | Response Time | Tokens/Second | Cost | Best For |
|-------|---------------|---------------|------|----------|
| GPT-4o | ~1.2s | 85 | Higher | Complex analysis |
| DeepSeek-R1 | ~0.8s | 95 | Lower | Speed & cost |
| Grok | ~1.5s | 75 | Medium | Humor & context |

---

## 📁 Project Structure

```
DestroyGPT/
├── 🎯 destroygpt_advanced.py      # Main CLI application
├── 📦 requirements.txt             # Python dependencies
├── ⚙️ config/
│   ├── security.json              # Whitelist/blacklist rules
│   ├── models.json                # LLM model configurations
│   └── logging.json               # Logging configuration
├── 📝 logs/                        # Application logs
├── 💾 history/                     # Command history storage
├── 📚 docs/
│   ├── SECURITY.md                # Detailed security documentation
│   ├── API.md                     # API integration guide
│   ├── TROUBLESHOOTING.md         # Common issues & solutions
│   └── CONTRIBUTING.md            # Contribution guidelines
├── 🧪 tests/                       # Unit and integration tests
└── 📄 LICENSE                      # MIT License
```

---

## 🔧 Troubleshooting

<img align="right" src="https://media.giphy.com/media/l0MYt5jPR6QX5pnqM/giphy.gif" width="250" height="200" alt="Debugging">

### ❌ API Key Not Found
```bash
# Verify API key is set
cat ~/.destroygpt_api_key

# Or check environment variable
echo $OPENROUTER_API_KEY
```

### ⚠️ Command Blocked by Safety Checks
- Check whitelist permissions: Run `cmd: help` for allowed commands
- Review blacklist patterns for restrictions
- Use dry-run mode to inspect before execution: `cmd: --dry-run <command>`

### 🐳 Docker Sandbox Issues
```bash
# Verify Docker is running
docker ps

# Check permissions
sudo usermod -aG docker $USER

# Test Docker
docker run --rm ubuntu:22.04 echo "Docker works!"
```

### 🌍 Rate Limiting Issues
```bash
# Check OpenRouter quota
curl -H "Authorization: Bearer $OPENROUTER_API_KEY" \
     https://api.openrouter.ai/api/v1/usage
```

<br clear="right"/>

---

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

<img src="https://media.giphy.com/media/l0HlGdAqKXr7oxjKc/giphy.gif" width="100%" height="150" alt="Contributing">

1. 🔀 Fork the repository
2. 🌿 Create a feature branch: `git checkout -b feature/amazing-feature`
3. 💾 Commit changes: `git commit -m 'Add amazing feature'`
4. 📤 Push to branch: `git push origin feature/amazing-feature`
5. 🔁 Open a Pull Request

**Contribution Areas:**
- 🐛 Bug fixes and issue resolution
- ✨ New features and enhancements
- 📚 Documentation improvements
- 🧪 Test coverage expansion
- 🔒 Security audits and improvements

---

## 🗺️ Roadmap

- [ ] 🎨 Web UI dashboard for command visualization
- [ ] 🗄️ Integration with popular vulnerability databases (CVE, NVD)
- [ ] 🤖 Advanced ML-based threat detection and pattern recognition
- [ ] 👥 Multi-user session management and RBAC
- [ ] 🔄 Real-time collaboration features
- [ ] ☸️ Kubernetes sandbox support
- [ ] 📱 Mobile app companion
- [ ] 🌐 Cloud deployment templates
- [ ] 📊 Advanced reporting and compliance features
- [ ] 🔗 Integration with popular tools (Burp Suite, Metasploit)

---

## 📞 Support & Community

<div align="center">

<img src="https://media.giphy.com/media/l0HlTy9x8FZo7rliw/giphy.gif" width="300" height="200" alt="Support">

</div>

- 📖 **Documentation**: [GitHub Wiki](https://github.com/sujallamichhane18/DestroyGPT/wiki)
- 🐛 **Issues**: [Report a bug](https://github.com/sujallamichhane18/DestroyGPT/issues)
- 💬 **Discussions**: [Ask a question](https://github.com/sujallamichhane18/DestroyGPT/discussions)
- 🔐 **Security Policy**: See [SECURITY.md](SECURITY.md)
- 📧 **Email Support**: sujallamichhane18@gmail.com

---

## ⚖️ Legal & Ethical Disclaimer

<img align="left" src="https://media.giphy.com/media/3o7TKU8FyF4ilS1jUI/giphy.gif" width="200" height="200" alt="Legal">

### ⚠️ IMPORTANT - AUTHORIZED USE ONLY

DestroyGPT is intended **exclusively** for:
- ✅ Authorized penetration testing
- ✅ Security research on authorized systems
- ✅ Educational purposes
- ✅ Systems you own or have written permission to test

### Legal Compliance

- 🚫 Unauthorized access to computer systems is **illegal** in most jurisdictions
- 📝 Obtain **written authorization** before conducting any security assessments
- 📋 Comply with all applicable laws and regulations in your jurisdiction
- 🔒 Respect privacy and data protection regulations (GDPR, CCPA, HIPAA, etc.)

### Responsible Use

- ✔️ Use only on systems you control or have explicit permission to test
- ✔️ Document all testing activities for compliance purposes
- ✔️ Remediate identified vulnerabilities responsibly
- ✔️ Report findings through appropriate disclosure channels

**The author assumes no liability for unauthorized use, illegal activities, or resulting damages.**

<br clear="left"/>

---

## 📜 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2024 Sujal Lamichhane

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software...
```

---

## 🙏 Acknowledgments

<img src="https://media.giphy.com/media/l0HlRnAQ7KLfg6iTm/giphy.gif" width="100%" height="150" alt="Thanks">

Special thanks to:
- 🤖 [OpenRouter.ai](https://openrouter.ai/) for LLM integration
- 🔒 The cybersecurity community for feedback and contributions
- 🚀 All contributors and maintainers
- 💪 Users who help improve DestroyGPT

---

<div align="center">

<img src="https://media.giphy.com/media/3o7TKB3oifq46DDhOE/giphy.gif" width="300" height="200" alt="Success">

### Built with ❤️ for the Security Community

**[⬆ Back to Top](#destroygpt)**

![GitHub followers](https://img.shields.io/github/followers/sujallamichhane18?style=social)
![GitHub watchers](https://img.shields.io/github/watchers/sujallamichhane18/DestroyGPT?style=social)
![GitHub stars](https://img.shields.io/github/stars/sujallamichhane18/DestroyGPT?style=social)

</div>
