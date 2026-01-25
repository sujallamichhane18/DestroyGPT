# DestroyGPT

<div align="center">

```
    ____           _                   __________ _______ 
   / __ \___  ___| |_ ________  __   / ____/ __ \/_  __/ 
  / / / / _ \/ ___| __/ ___/ / / /  / / __/ /_/ / / /    
 / /_/ /  __(__  ) /_/ /  / /_/ /  / /_/ / ____/ / /     
/_____/\___/____/\__/_/   \__, /   \____/_/    /_/      
                          /____/                         
```

### AI-Powered CLI for Ethical Penetration Testing with Secure Command Execution

<br/>

![Version](https://img.shields.io/badge/Version-2.0.0-00d4ff?style=for-the-badge&logo=github)
![Python](https://img.shields.io/badge/Python-3.9+-00ff41?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-ff006e?style=for-the-badge&logo=open-source-initiative)
![Status](https://img.shields.io/badge/Status-Active-00d4ff?style=for-the-badge)
![Security](https://img.shields.io/badge/Security-Advanced-00ff41?style=for-the-badge&logo=shield)

<br/>

<a href="#quick-start"><strong>Quick Start</strong></a> • 
<a href="#features"><strong>Features</strong></a> • 
<a href="#installation"><strong>Installation</strong></a> • 
<a href="#security-architecture"><strong>Security</strong></a> • 
<a href="#license"><strong>License</strong></a>

<br/>
<br/>

![Banner](https://media.giphy.com/media/l0HlQXnMCVgkOK5vy/giphy.gif)

</div>

---

## 🎯 Overview

<img align="right" src="https://media.giphy.com/media/l46Cy1rHbQ92uPl3m/giphy.gif" width="320" height="320" alt="Hacking Animation">

**DestroyGPT** represents the convergence of artificial intelligence and cybersecurity—a sophisticated, AI-assisted penetration testing terminal interface engineered for security professionals, ethical hackers, and researchers.

Powered by cutting-edge language models via [OpenRouter.ai](https://openrouter.ai/), DestroyGPT leverages **DeepSeek-R1**, **GPT-4o**, and **Grok** to intelligently generate security commands, payloads, and exploit strategies in real-time.

### Why DestroyGPT?

Unlike conventional penetration testing tools, DestroyGPT seamlessly integrates **AI-driven command generation** with **enterprise-grade security mechanisms**:

- 🎯 **Intelligent Execution** — AI understands context and suggests optimal security commands
- 🛡️ **Defense-in-Depth** — Multiple security layers protect your system from accidental damage
- ⚡ **Real-Time Streaming** — See AI responses as they're generated
- 📊 **Compliance Ready** — Comprehensive logging and audit trails
- 🐳 **Sandboxed Execution** — Optional Docker isolation for maximum safety

<br clear="right"/>

---

## ⭐ Features

<table>
<tr>
<td width="50%">

### 🧠 Multi-Model LLM Intelligence
- **GPT-4o** for advanced reasoning
- **DeepSeek-R1** for speed & efficiency  
- **Grok** for contextual understanding
- Automatic model switching
- Custom model configuration

</td>
<td width="50%">

![AI Models](https://media.giphy.com/media/l0HlNaQ9wTv06XsqXm/giphy.gif)

</td>
</tr>
</table>

<table>
<tr>
<td width="50%">

![Security](https://media.giphy.com/media/xULw8MYkghbQXO3okM/giphy.gif)

</td>
<td width="50%">

### 🛡️ Layered Security Framework
- **Whitelist** — Command approval system
- **Blacklist** — Pattern-based threat blocking
- **Keyword Detection** — Real-time threat analysis
- **Docker Sandboxing** — Isolated execution
- **Timeout Protection** — Process safety management

</td>
</tr>
</table>

<table>
<tr>
<td width="50%">

### ⚡ Performance & Reliability
- **Real-Time Streaming** — Instant feedback
- **Command History** — 5,000+ record persistence
- **Rotating Logs** — Automated log management
- **Process Management** — Resource monitoring
- **Error Recovery** — Graceful failure handling

</td>
<td width="50%">

![Performance](https://media.giphy.com/media/3o6Zt6KHxJTbXCnSvu/giphy.gif)

</td>
</tr>
</table>

<table>
<tr>
<td width="50%">

![Logging](https://media.giphy.com/media/l3q2K6HIQ6playpUQ/giphy.gif)

</td>
<td width="50%">

### 📊 Enterprise-Grade Logging
- **Audit Trails** — Complete action history
- **Structured Logs** — JSON-based logging
- **Compliance Ready** — GDPR/SOC 2 compatible
- **Search & Filter** — Easy log analysis
- **Retention Policies** — Configurable archiving

</td>
</tr>
</table>

---

## 🚀 Quick Start

<div align="center">

![Get Started](https://media.giphy.com/media/3o7TKU8FyF4ilS1jUI/giphy.gif)

</div>

### Prerequisites

```bash
✓ Python 3.9 or higher
✓ pip (Python package manager)
✓ Docker (optional, for sandboxing)
✓ OpenRouter.ai API key
```

### Installation & Setup

```bash
# Clone repository
git clone https://github.com/sujallamichhane18/DestroyGPT.git
cd DestroyGPT

# Install dependencies
pip install -r requirements.txt

# Configure API key (recommended: local file)
echo "your_openrouter_api_key" > ~/.destroygpt_api_key
chmod 600 ~/.destroygpt_api_key

# Launch DestroyGPT
python destroygpt_advanced.py
```

### First Command

```
┌─────────────────────────────────────────────────────┐
│ DestroyGPT v2.0.0 - AI Penetration Testing CLI    │
│ Powered by GPT-4o | Mode: Standard                 │
└─────────────────────────────────────────────────────┘

DestroyGPT >>> Scan for open ports on example.com

🤖 AI Analysis:
   Generating optimal nmap command...

📋 Generated Command:
   nmap -sV --script vuln example.com

⚠️  Review before execution:
   ├─ Target: example.com
   ├─ Tool: nmap (whitelisted ✓)
   ├─ Risk Level: LOW
   └─ Execution Mode: Standard

Proceed? (y/N): y

✅ Command executed successfully
```

---

## 💻 Usage Examples

<img align="left" src="https://media.giphy.com/media/l0MYt5jPR6QX5pnqM/giphy.gif" width="240" height="240" alt="CLI">

### Network Reconnaissance

```bash
DestroyGPT >>> Find all subdomains for target.com

# AI generates optimal enumeration command
subfinder -d target.com -o subdomains.txt
amass enum -d target.com -o amass_output.txt
```

### Service Enumeration

```bash
DestroyGPT >>> Enumerate services on 192.168.1.100:22

# AI suggests port-specific fingerprinting
ssh -v 192.168.1.100
nmap -sV -p 22 192.168.1.100
```

### Web Application Testing

```bash
DestroyGPT >>> Scan for common web vulnerabilities on localhost:8080

# AI recommends appropriate scanning tool
nikto -h localhost:8080
curl -I localhost:8080
```

### Credential Auditing

```bash
DestroyGPT >>> Generate a secure password list and test strength

# AI provides safe, non-destructive analysis
openssl rand -base64 32
hashcat --help
```

<br clear="left"/>

---

## 🔐 Security Architecture

<div align="center">

![Security Layers](https://media.giphy.com/media/l0HlGdAqKXr7oxjKc/giphy.gif)

</div>

### Layer 1️⃣ : Command Whitelist

```json
{
  "whitelisted_tools": {
    "network": ["nmap", "netcat", "dig", "whois", "curl", "wget"],
    "ssh": ["ssh", "ssh-keygen", "scp", "ssh-copy-id"],
    "cryptography": ["openssl", "hashcat", "john"],
    "analysis": ["netstat", "ps", "top", "whoami"],
    "dns": ["nslookup", "host", "dig", "drill"]
  }
}
```

**Result**: ✅ Only approved tools execute

---

### Layer 2️⃣ : Blacklist Pattern Blocking

| Category | Blocked Patterns | Impact |
|----------|------------------|--------|
| Destructive | `rm -rf /`, `mkfs`, `dd if=/dev/zero` | ❌ Prevent data loss |
| Resource Exhaustion | Fork bombs, `:(){ \:\|\: & };` | ❌ Protect system stability |
| Privilege Escalation | Kernel exploits, unauthorized sudo | ❌ Block privilege abuse |
| Sensitive Ops | `drop database`, `DELETE FROM` | ❌ Prevent data destruction |

**Result**: 🛑 Dangerous patterns blocked automatically

---

### Layer 3️⃣ : Threat Keyword Detection

```
🔍 Monitored Keywords:
   ├─ System Control: sudo, chmod, chown, passwd
   ├─ Shutdown: shutdown, reboot, halt, poweroff
   ├─ Database: drop database, delete from, truncate
   └─ File Ops: rm, mv, cp (on system directories)

⚠️  Detection Level: Requires explicit user confirmation
✅  Safety Measure: One-time approval per dangerous command
```

---

### Layer 4️⃣ : Docker Sandboxing

```bash
🐳 Sandbox Environment:
   ├─ Image: ubuntu:22.04
   ├─ Isolation: Complete filesystem + network
   ├─ Resource Limits: CPU, Memory, Disk quotas
   ├─ Network: Optional internet access
   └─ Cleanup: Automatic after execution

✨ Benefits:
   ├─ Zero impact on host system
   ├─ Full command execution freedom
   ├─ Forensic capability preservation
   └─ Reproducible testing environment
```

---

### Layer 5️⃣ : Process Safety Management

```
⏱️  Timeout Protection:
   ├─ Default: 30 seconds per command
   ├─ Configurable: Per-command override
   ├─ Auto-Kill: Unresponsive processes
   └─ Graceful: Signal handling (SIGTERM → SIGKILL)

📊 Resource Monitoring:
   ├─ CPU Usage: Real-time tracking
   ├─ Memory: Quota enforcement
   ├─ File Descriptors: Limit management
   └─ Disk I/O: Rate limiting
```

---

## ⚙️ Advanced Configuration

### Environment Setup

```bash
# Core API Configuration
export OPENROUTER_API_KEY="your_key_here"
export OPENROUTER_MODEL="gpt-4o"
export OPENROUTER_BASE_URL="https://openrouter.ai/api/v1"

# Security Settings
export ENABLE_DOCKER_SANDBOX="false"
export COMMAND_TIMEOUT="30"
export MAX_HISTORY_SIZE="5000"

# Logging Configuration
export LOG_LEVEL="INFO"
export LOG_DIR="./logs"
export LOG_MAX_BYTES="10485760"  # 10MB
export LOG_BACKUP_COUNT="5"
```

### Security Configuration

```json
{
  "execution_policy": "strict",
  "whitelist_mode": "enabled",
  "blacklist_patterns": [
    "rm -rf /",
    "mkfs.*",
    ":(){ :|: & };"
  ],
  "danger_keywords": {
    "sudo": "requires_confirmation",
    "chmod": "requires_confirmation",
    "shutdown": "requires_confirmation"
  },
  "timeout_seconds": 30,
  "docker_sandbox": false,
  "interactive_mode": true
}
```

### Model Configuration

```json
{
  "models": {
    "gpt-4o": {
      "max_tokens": 2000,
      "temperature": 0.7,
      "cost_per_1k_input": 0.005,
      "cost_per_1k_output": 0.015
    },
    "deepseek-r1": {
      "max_tokens": 2000,
      "temperature": 0.7,
      "cost_per_1k_input": 0.0005,
      "cost_per_1k_output": 0.002
    }
  }
}
```

---

## 📊 Performance Metrics

<div align="center">

| Metric | GPT-4o | DeepSeek-R1 | Grok |
|--------|--------|------------|------|
| **Avg Response Time** | 1.2s | 0.8s ⚡ | 1.5s |
| **Tokens/Second** | 85 | 95 ⚡ | 75 |
| **Cost/1K Tokens** | $0.015 | $0.002 ⚡ | $0.008 |
| **Best For** | Complex Analysis | Speed | Context |
| **Recommended** | Security Research | Production | Learning |

</div>

---

## 📁 Directory Structure

```
DestroyGPT/
├── 📄 destroygpt_advanced.py          # Main CLI application
├── 📦 requirements.txt                 # Dependencies
│
├── ⚙️ config/
│   ├── security.json                  # Security policies
│   ├── models.json                    # LLM configurations
│   └── logging.json                   # Logging setup
│
├── 📝 logs/
│   ├── application.log                # General logs
│   ├── security.log                   # Security events
│   └── commands.log                   # Command history
│
├── 💾 history/
│   └── command_history.json           # Persistent history
│
├── 📚 docs/
│   ├── SECURITY.md                    # Security documentation
│   ├── API.md                         # API reference
│   ├── TROUBLESHOOTING.md             # Common issues
│   └── CONTRIBUTING.md                # Contribution guide
│
├── 🧪 tests/
│   ├── test_security.py               # Security tests
│   ├── test_execution.py              # Execution tests
│   └── test_api.py                    # API tests
│
└── 📄 LICENSE                          # MIT License
```

---

## 🛠️ Troubleshooting Guide

<img align="right" src="https://media.giphy.com/media/l0MYt5jPR6QX5pnqM/giphy.gif" width="250" height="200" alt="Debugging">

### Issue: API Key Not Recognized

```bash
# ✅ Solution 1: Verify file permissions
ls -la ~/.destroygpt_api_key
chmod 600 ~/.destroygpt_api_key

# ✅ Solution 2: Test environment variable
echo $OPENROUTER_API_KEY

# ✅ Solution 3: Validate API key
curl -H "Authorization: Bearer $OPENROUTER_API_KEY" \
     https://api.openrouter.ai/api/v1/models
```

### Issue: Command Blocked by Security

```bash
# ✅ Check whitelist
DestroyGPT >>> cmd: help  # Shows allowed commands

# ✅ Use dry-run mode
DestroyGPT >>> cmd: --dry-run nmap example.com

# ✅ Check configuration
cat config/security.json | grep whitelist
```

### Issue: Docker Sandbox Not Working

```bash
# ✅ Verify Docker installation
docker --version
docker ps

# ✅ Check user permissions
sudo usermod -aG docker $USER
newgrp docker

# ✅ Test Docker
docker run --rm ubuntu:22.04 echo "Success!"
```

### Issue: Commands Timing Out

```bash
# ✅ Increase timeout in config
export COMMAND_TIMEOUT=60

# ✅ Or set per-command
DestroyGPT >>> cmd: --timeout 120 long-running-command
```

<br clear="right"/>

---

## 🤝 Contributing

We welcome contributions from the security community!

```bash
# 1. Fork repository
git clone https://github.com/YOUR-USERNAME/DestroyGPT.git
cd DestroyGPT

# 2. Create feature branch
git checkout -b feature/amazing-feature

# 3. Make changes and commit
git add .
git commit -m "feat: add amazing feature"

# 4. Push and create PR
git push origin feature/amazing-feature
```

### Contribution Areas

- 🐛 **Bug Fixes** — Fix reported issues
- ✨ **Features** — Implement new capabilities
- 📚 **Documentation** — Improve guides and examples
- 🧪 **Tests** — Expand test coverage
- 🔒 **Security** — Audit and enhance security
- 🎨 **UI/UX** — Improve user experience

---

## 🗺️ Roadmap

```
2024 Q1: MVP Release
├─ Core CLI functionality ✅
├─ Multi-model support ✅
└─ Security framework ✅

2024 Q2: Advanced Features (In Progress)
├─ Web UI dashboard 🔄
├─ Database integrations 🔄
├─ Advanced reporting 🔄
└─ Team collaboration 🔄

2024 Q3: Enterprise Features (Planned)
├─ RBAC & multi-user 📅
├─ API server mode 📅
├─ Cloud deployment 📅
└─ Enterprise integrations 📅

2024 Q4: Ecosystem (Planned)
├─ Mobile companion app 📅
├─ Browser plugin 📅
├─ IDE integrations 📅
└─ Third-party tools 📅
```

---

## 📞 Support & Community

<div align="center">

![Support](https://media.giphy.com/media/l0HlTy9x8FZo7rliw/giphy.gif)

</div>

| Resource | Link |
|----------|------|
| 📖 **Documentation** | [Wiki](https://github.com/sujallamichhane18/DestroyGPT/wiki) |
| 🐛 **Report Issues** | [Issues](https://github.com/sujallamichhane18/DestroyGPT/issues) |
| 💬 **Discussions** | [Discussions](https://github.com/sujallamichhane18/DestroyGPT/discussions) |
| 🔐 **Security Policy** | [SECURITY.md](SECURITY.md) |
| 📧 **Email** | sujallamichhane18@gmail.com |
| 🐦 **Twitter** | [@DestroyGPT](https://twitter.com/destroygpt) |

---

## ⚖️ Legal & Ethical Guidelines

<div align="center">

![Legal](https://media.giphy.com/media/3o7TKU8FyF4ilS1jUI/giphy.gif)

</div>

### ⚠️ AUTHORIZED USE ONLY

```
DestroyGPT is EXCLUSIVELY for:

✅ Authorized penetration testing
✅ Security research on owned systems
✅ Educational learning purposes
✅ Systems with written permission

❌ Unauthorized system access
❌ Data theft or destruction
❌ Illegal activities
❌ Violation of privacy laws
```

### Legal Obligations

- 🔍 **Jurisdiction Compliance** — Follow local laws
- 📝 **Documentation** — Maintain audit trails
- 📋 **Authorization** — Obtain written permission
- 🔐 **Data Protection** — Respect GDPR/CCPA/HIPAA
- 🤝 **Responsible Disclosure** — Report findings ethically

### Liability Disclaimer

> **The author assumes NO liability for:**
> - Unauthorized system access
> - Data loss or corruption
> - Illegal use of this tool
> - Violation of any laws or regulations
> - Any damages resulting from misuse

---

## 📜 License

Licensed under the **MIT License** — free for personal and commercial use.

```
MIT License

Copyright (c) 2024 Sujal Lamichhane

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions...
```

See [LICENSE](LICENSE) for full terms.

---

## 🙏 Acknowledgments

```
Special Thanks To:

🤖 OpenRouter.ai
   For providing unified LLM access

🔒 Security Community
   For feedback and contributions

🚀 Open Source Contributors
   For inspiration and collaboration

💪 Users Like You
   For making DestroyGPT better
```

---

<div align="center">

![Footer](https://media.giphy.com/media/3o7TKB3oifq46DDhOE/giphy.gif)

### Built with ❤️ for the Security Community

<br/>

**[⬆ Back to Top](#destroygpt)**

<br/>

![GitHub Stars](https://img.shields.io/github/stars/sujallamichhane18/DestroyGPT?style=social&label=Star)
![GitHub Forks](https://img.shields.io/github/forks/sujallamichhane18/DestroyGPT?style=social&label=Fork)
![GitHub Watchers](https://img.shields.io/github/watchers/sujallamichhane18/DestroyGPT?style=social&label=Watch)

---

**DestroyGPT v2.0.0** • Made with 🛡️ and 🔐 • 2024

</div>
