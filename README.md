# 🛡️ DestroyGPT

AI-Powered Security Learning CLI with Safe Command Execution

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![OpenRouter API](https://img.shields.io/badge/OpenRouter-Integrated-green.svg)](https://openrouter.ai)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/sujallamichhane18/DestroyGPT/pulls)

---

## 🎯 Overview

DestroyGPT is an AI-powered terminal assistant that helps security professionals and ethical hackers learn and practice cybersecurity concepts. It integrates with OpenRouter.ai to access advanced language models (GPT-4o, DeepSeek, Gemini) for generating security commands, explaining concepts, and assisting with penetration testing workflows.

**Key Features:**
- 🤖 AI-powered command generation and explanation
- 🔒 Multi-layer security validation before execution
- 📝 Comprehensive audit logging
- 💬 Conversational interface with context awareness
- 🎓 Educational focus with detailed explanations
- ⚡ Support for multiple AI models

---

## 📺 Demo

![DestroyGPT Demo](assets/demo.gif)

> **Coming Soon**: Screen recording showing interactive session

---

## 🚨 Legal & Ethical Notice

**READ THIS CAREFULLY BEFORE USE**

This tool is designed **exclusively** for:
- ✅ Authorized penetration testing with written permission
- ✅ Security research in controlled environments
- ✅ Educational purposes on your own systems
- ✅ Practicing for certifications (OSCP, CEH, etc.)

### ⚠️ Prohibited Uses

**DO NOT** use this tool to:
- ❌ Scan or probe networks without explicit authorization
- ❌ Access systems you don't own or have permission to test
- ❌ Perform unauthorized security assessments
- ❌ Attack production systems or infrastructure
- ❌ Violate computer fraud and abuse laws

**Unauthorized access to computer systems is a criminal offense** under laws including:
- Computer Fraud and Abuse Act (CFAA) - United States
- Computer Misuse Act - United Kingdom
- EU Directive on Attacks Against Information Systems
- Similar legislation in most countries worldwide

**The author and contributors assume no liability for misuse. You are solely responsible for ensuring your activities are legal and authorized.**

---

## 🚀 Quick Start

### 📋 Prerequisites

- Python 3.8 or higher
- pip package manager
- Git
- OpenRouter API key ([sign up free](https://openrouter.ai))
- (Optional) Docker for advanced sandboxing

### 💾 Installation

```bash
# Clone the repository
git clone https://github.com/sujallamichhane18/DestroyGPT.git
cd DestroyGPT

# Install required dependencies
pip install -r requirements.txt
```

### 🔑 API Configuration

Get your API key from [OpenRouter.ai](https://openrouter.ai/keys)

**Option 1: Secure File Storage** (Recommended)
```bash
echo "sk-or-v1-your_api_key_here" > ~/.destroygpt_api_key
chmod 600 ~/.destroygpt_api_key
```

**Option 2: Environment Variable**
```bash
export OPENROUTER_API_KEY="sk-or-v1-your_api_key_here"
```

**Option 3: Interactive Setup**
```bash
# The tool will prompt you on first run
python destroygpt.py
```

### ▶️ Launch

```bash
python destroygpt.py
```

---

## 📖 Usage Guide

### 🎮 Interactive Mode

DestroyGPT provides a conversational interface where you can ask questions, request commands, and learn security concepts.

```bash
$ what tools can I use to scan for open ports?

$ generate a ping command to test connectivity to google.com

$ explain how DNS lookup works

$ show me how to use dig to query MX records
```

### 🛠️ Built-in Commands

| Command | Description |
|---------|-------------|
| `help` | Show available commands and usage tips |
| `history` | Display recent conversation history |
| `exit` / `quit` | Exit the program |
| `clear` | Clear the screen |

### 💡 Example Workflows

**Learning Network Diagnostics:**
```
$ how do I test if a host is reachable?

AI: You can use the ping command to test network connectivity...

💻 ping -c 4 google.com

Run? [y/N]: y

PING google.com (142.250.185.46): 56 data bytes
64 bytes from 142.250.185.46: icmp_seq=0 ttl=117 time=12.3 ms
...
```

**Understanding DNS:**
```
$ explain DNS lookup and show me an example

AI: DNS (Domain Name System) translates domain names to IP addresses...
The 'dig' command queries DNS servers for records...

💻 dig example.com

Run? [y/N]: y
```

**Exploring Security Concepts:**
```
$ what is port scanning and how does it work?

AI: Port scanning is a technique to discover open ports on a target...
[Detailed explanation without suggesting active scanning]
```

---

## 🛡️ Security Features

DestroyGPT implements multiple security layers to prevent accidental or malicious damage:

### 🔐 Command Validation
- **Whitelist enforcement**: Only approved safe commands are permitted
- **Pattern blocking**: Dangerous patterns automatically rejected
- **Argument validation**: Command arguments checked for safety
- **Manual confirmation**: All commands require explicit approval

### 📊 Audit & Logging
- **Complete history**: All queries and commands logged
- **Timestamped records**: Full audit trail with timestamps
- **Command tracking**: Separate log of executed commands
- **Session persistence**: History saved between sessions

### ⚙️ Safety Controls
- **Timeout protection**: Commands auto-terminate after timeout
- **Read-only focus**: Emphasis on non-destructive commands
- **Context-aware prompting**: AI instructed to prioritize safety
- **User confirmation**: Explicit approval required before execution

---

## ⚙️ Configuration

### Available Models

DestroyGPT supports multiple AI models with different capabilities:

| Model | Speed | Quality | Cost | Best For |
|-------|-------|---------|------|----------|
| GPT-4o | Fast | Excellent | Medium | General use, complex queries |
| GPT-OSS-120B | Medium | Very Good | Low | Open source alternative |
| Trinity Mini | Very Fast | Good | Free | Quick answers |
| Kimi K2 | Fast | Very Good | Low | Long context tasks |
| Gemma 3 27B | Fast | Good | Free | Educational use |

### Model Selection

Choose your preferred model at startup or modify the `MODELS` dictionary in `destroygpt.py`.

### Advanced Configuration

Create `~/.destroygpt_config.json` for custom settings:

```json
{
  "default_model": "openai/gpt-4o",
  "api_timeout": 60,
  "max_history": 10,
  "auto_save_history": true,
  "command_timeout": 300,
  "log_commands": true
}
```

---

## 🔧 Troubleshooting

### Common Issues

**API Key Not Found**
```bash
Error: No API key found

Solution: 
- Set OPENROUTER_API_KEY environment variable
- Create ~/.destroygpt_api_key file
- Enter key when prompted
```

**API Request Failed**
```bash
API Error 401

Solution:
- Verify your API key is valid
- Check you have credits at openrouter.ai
- Ensure key starts with 'sk-or-v1-'
```

**Command Not Executing**
```bash
Command validation failed

Solution:
- Only basic networking commands are whitelisted
- Check for blocked patterns in command
- Review security restrictions
```

**Module Not Found**
```bash
ModuleNotFoundError: No module named 'requests'

Solution:
pip install -r requirements.txt
```

---

## 📚 Educational Resources

### Learning Path

1. **Network Basics**: Start with ping, traceroute, DNS queries
2. **Information Gathering**: Practice with whois, dig, host
3. **Understanding Protocols**: Learn TCP/IP, HTTP, DNS concepts
4. **Security Fundamentals**: Study common vulnerabilities
5. **Ethical Guidelines**: Understand legal and ethical boundaries

### Recommended Practice Environments

- **HackTheBox**: Legal penetration testing practice
- **TryHackMe**: Guided cybersecurity learning paths  
- **VulnHub**: Vulnerable VMs for offline practice
- **PentesterLab**: Web application security exercises
- **OverTheWire**: Command-line security challenges

### Certifications to Consider

- CompTIA Security+
- Certified Ethical Hacker (CEH)
- Offensive Security Certified Professional (OSCP)
- GIAC Security Essentials (GSEC)

---

## 🤝 Contributing

We welcome contributions that improve safety, education, and functionality!

### How to Contribute

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/amazing-feature`
3. **Commit** your changes: `git commit -m 'Add amazing feature'`
4. **Push** to the branch: `git push origin feature/amazing-feature`
5. **Open** a Pull Request

### Contribution Guidelines

- Prioritize safety and security in all changes
- Add tests for new functionality
- Update documentation as needed
- Follow existing code style
- Include clear commit messages

### Areas for Improvement

- [ ] Additional safe command implementations
- [ ] Enhanced error handling
- [ ] Docker sandbox integration
- [ ] More comprehensive logging
- [ ] Educational tutorial mode
- [ ] Command history search
- [ ] Export/import session data

---

## 📜 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## 🔗 Resources & Links

- 🌐 **OpenRouter.ai**: [https://openrouter.ai](https://openrouter.ai) - AI API platform
- 📖 **Documentation**: [Wiki](https://github.com/sujallamichhane18/DestroyGPT/wiki)
- 🐛 **Bug Reports**: [Issues](https://github.com/sujallamichhane18/DestroyGPT/issues)
- 💬 **Discussions**: [Community](https://github.com/sujallamichhane18/DestroyGPT/discussions)
- 🎓 **Security Learning**: [OWASP](https://owasp.org) | [PortSwigger Academy](https://portswigger.net/web-security)

---

## 🙏 Acknowledgments

- OpenRouter.ai for providing access to multiple AI models
- The open-source security community
- All contributors and users who help improve this tool

---

## 📊 Project Status

**Current Version**: 8.0  
**Status**: Active Development  
**Last Updated**: January 2026

### Roadmap

- ✅ Core AI integration
- ✅ Basic command validation
- ✅ History management
- 🔄 Enhanced safety features (in progress)
- 📋 Docker sandbox mode (planned)
- 📋 Web interface (planned)
- 📋 Plugin system (planned)

---

## ⭐ Support

If you find DestroyGPT helpful, please:
- ⭐ Star this repository
- 🐛 Report bugs and issues
- 💡 Suggest new features
- 📖 Improve documentation
- 🤝 Share with the security community

---

**Built for ethical hackers, security professionals, and cybersecurity students.**  
**Always practice responsible disclosure and obtain proper authorization.**

---

### Disclaimer

This tool is provided "as is" without warranty of any kind. The authors and contributors are not responsible for any misuse or damage caused by this tool. Users are solely responsible for complying with all applicable laws and regulations. Use at your own risk.
