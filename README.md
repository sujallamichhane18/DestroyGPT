# DestroyGPT

<div align="center">

![DestroyGPT Banner](https://via.placeholder.com/800x300/1a1a2e/00d4ff?text=DestroyGPT+AI-Powered+Penetration+Testing+CLI)

**AI-Powered CLI for Ethical Penetration Testing with Secure Command Execution**

[![License](https://img.shields.io/github/license/sujallamichhane18/DestroyGPT?color=blue&style=flat-square)](LICENSE)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-blue?style=flat-square)](https://www.python.org/)
[![Status](https://img.shields.io/badge/Status-Active-success?style=flat-square)](https://github.com/sujallamichhane18/DestroyGPT)
[![OpenRouter](https://img.shields.io/badge/Powered%20by-OpenRouter.ai-orange?style=flat-square)](https://openrouter.ai/)

[Quick Start](#-quick-start) • [Features](#-features) • [Installation](#-installation) • [Security](#-security-architecture) • [License](#-license)

</div>

---

## Overview

DestroyGPT is a secure, AI-assisted penetration testing terminal interface designed for security professionals and ethical hackers. It integrates with [OpenRouter.ai](https://openrouter.ai/) to leverage advanced language models—including DeepSeek-R1, GPT-4o, and Grok—for generating security commands, payloads, and exploit strategies.

Unlike standard penetration testing tools, DestroyGPT executes commands directly in your terminal while enforcing multiple safety mechanisms: command whitelisting, blacklist pattern matching, threat detection, optional Docker sandboxing, and interactive confirmation prompts. This combination ensures powerful capabilities without sacrificing system safety.

---

## Key Features

<table>
  <tr>
    <td width="50%">
      <h4>🧠 Multi-Model LLM Support</h4>
      <p>Access cutting-edge language models (GPT-4o, DeepSeek-R1, Grok) for intelligent command generation</p>
    </td>
    <td width="50%">
      <h4>🛡️ Layered Security</h4>
      <p>Whitelist-based execution, blacklist patterns, keyword detection, and Docker isolation</p>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <h4>⚡ Real-Time Streaming</h4>
      <p>Receive AI-generated suggestions as they're produced for immediate feedback</p>
    </td>
    <td width="50%">
      <h4>📊 Comprehensive Logging</h4>
      <p>Persistent command history (5,000+ records) with rotating logs for compliance</p>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <h4>🔒 Docker Sandboxing</h4>
      <p>Optional isolated execution in Ubuntu 22.04 containers for maximum safety</p>
    </td>
    <td width="50%">
      <h4>🔍 Dry-Run Mode</h4>
      <p>Preview and inspect commands before execution</p>
    </td>
  </tr>
</table>

---

## Quick Start

### Prerequisites

- **Python** 3.9 or higher
- **pip** package manager
- **Docker** (optional, for sandboxed execution)
- **OpenRouter.ai** API key

### Installation

```bash
# Clone the repository
git clone https://github.com/sujallamichhane18/DestroyGPT.git
cd DestroyGPT

# Install dependencies
pip install -r requirements.txt
```

### Configure API Key

Store your OpenRouter.ai API key securely:

**Method 1: Local File (Recommended)**
```bash
echo "your_api_key_here" > ~/.destroygpt_api_key
chmod 600 ~/.destroygpt_api_key
```

**Method 2: Environment Variable**
```bash
export OPENROUTER_API_KEY="your_api_key_here"
```

### Run DestroyGPT

```bash
python destroygpt_advanced.py
```

---

## Usage Guide

### Interactive CLI

```
DestroyGPT >>> Generate a command to scan open ports on example.com

nmap -sV example.com

Command 1:
nmap -sV example.com
Proceed? (y/N) y

Starting Nmap 7.92 ( https://nmap.org ) ...
[Output...]
```

### Built-In Commands

| Command | Description |
|---------|-------------|
| `cmd: <command>` | Execute a system command (subject to safety checks) |
| `exit` / `quit` | Exit the CLI |
| `help` | Display available commands |
| `history` | View command history |

### Example Workflows

**Network Reconnaissance**
```bash
DestroyGPT >>> Enumerate subdomains for example.com using subdomain enumeration techniques
```

**Vulnerability Assessment**
```bash
DestroyGPT >>> Generate a command to scan for common web vulnerabilities on localhost:8080
```

**Port Scanning**
```bash
DestroyGPT >>> Perform a comprehensive service enumeration scan on 192.168.1.0/24
```

---

## Security Architecture

DestroyGPT implements a defense-in-depth approach with multiple security layers:

### 1. Whitelist Layer
Only pre-approved security tools are permitted to execute. Default whitelist includes:
- Network tools: `nmap`, `netcat`, `curl`, `wget`, `dig`, `whois`, `traceroute`
- SSH utilities: `ssh`, `ssh-keygen`, `scp`
- Cryptography: `openssl`, `hashcat`
- System analysis: `netstat`, `ss`, `ps`, `top`

### 2. Blacklist Pattern Matching
Automatically blocks dangerous patterns and commands:
- Destructive operations: `rm -rf /`, `mkfs`, `dd if=/dev/zero`
- Resource exhaustion: Fork bombs, infinite loops
- Privilege escalation exploits targeting the host system
- Custom regex patterns for emerging threats

### 3. Threat Keyword Detection
Commands containing dangerous keywords trigger explicit user confirmation:
- Keywords: `sudo`, `chmod`, `chown`, `passwd`, `shutdown`, `reboot`
- Pattern-based detection for common attack vectors
- Customizable threat detection rules

### 4. Docker Isolation (Optional)
Run commands in isolated Ubuntu 22.04 containers when available:
- Complete filesystem isolation
- Network sandboxing
- Resource limits and quotas
- Automatic cleanup after execution

### 5. Process Management
- Configurable timeout thresholds (default: 30 seconds)
- Automatic termination of unresponsive processes
- Signal handling for clean shutdowns
- Resource monitoring and limits

---

## Configuration

### Environment Variables

```bash
# API Configuration
OPENROUTER_API_KEY=your_key_here
OPENROUTER_MODEL=gpt-4o  # Default model

# Security Settings
ENABLE_DOCKER_SANDBOX=false
COMMAND_TIMEOUT=30
MAX_HISTORY_SIZE=5000

# Logging
LOG_LEVEL=INFO
LOG_DIR=./logs
```

### Custom Whitelist/Blacklist

Edit `config/security.json`:

```json
{
  "whitelist": [
    "nmap", "curl", "ssh", "dig"
  ],
  "blacklist_patterns": [
    "rm -rf /",
    "mkfs",
    ":(){ :|: & };"
  ],
  "danger_keywords": [
    "sudo", "chmod", "shutdown"
  ]
}
```

---

## Legal and Ethical Disclaimer

**IMPORTANT:** DestroyGPT is intended exclusively for **authorized** penetration testing, security research, and educational purposes on systems you own or have explicit written permission to test.

### Legal Compliance

- Unauthorized access to computer systems is illegal in most jurisdictions
- Obtain written authorization before conducting any security assessments
- Comply with all applicable laws and regulations in your jurisdiction
- Respect privacy and data protection regulations (GDPR, CCPA, etc.)

### Responsible Use

- Use only on systems you control or have explicit permission to test
- Document all testing activities for compliance purposes
- Remediate identified vulnerabilities responsibly
- Report findings through appropriate disclosure channels

**The author assumes no liability for unauthorized use, illegal activities, or resulting damages.**

---

## Project Structure

```
DestroyGPT/
├── destroygpt_advanced.py     # Main CLI application
├── requirements.txt            # Python dependencies
├── config/
│   ├── security.json          # Whitelist/blacklist rules
│   └── models.json            # LLM model configurations
├── logs/                       # Application logs
├── history/                    # Command history storage
├── docs/
│   ├── SECURITY.md            # Detailed security documentation
│   ├── API.md                 # API integration guide
│   └── CONTRIBUTING.md        # Contribution guidelines
└── LICENSE                     # MIT License
```

---

## Performance Benchmarks

| Model | Avg. Response Time | Tokens/Second | Cost |
|-------|-------------------|---------------|------|
| GPT-4o | 1.2s | 85 | Higher |
| DeepSeek-R1 | 0.8s | 95 | Lower |
| Grok | 1.5s | 75 | Medium |

---

## Troubleshooting

### API Key Not Found
```bash
# Verify API key is set
cat ~/.destroygpt_api_key

# Or check environment variable
echo $OPENROUTER_API_KEY
```

### Command Blocked by Safety Checks
- Check whitelist permissions: Run `cmd: help` for allowed commands
- Review blacklist patterns for restrictions
- Use dry-run mode to inspect before execution

### Docker Sandbox Issues
```bash
# Verify Docker is running
docker ps

# Check permissions
sudo usermod -aG docker $USER
```

---

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

Please ensure all changes maintain security integrity and include appropriate tests.

---

## Roadmap

- [ ] Web UI dashboard for command visualization
- [ ] Integration with popular vulnerability databases
- [ ] Advanced ML-based threat detection
- [ ] Multi-user session management
- [ ] Real-time collaboration features
- [ ] Kubernetes sandbox support

---

## Support & Community

- **Documentation**: [GitHub Wiki](https://github.com/sujallamichhane18/DestroyGPT/wiki)
- **Issues**: [Report a bug](https://github.com/sujallamichhane18/DestroyGPT/issues)
- **Discussions**: [Ask a question](https://github.com/sujallamichhane18/DestroyGPT/discussions)
- **Security Policy**: See [SECURITY.md](SECURITY.md)

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2024 Sujal Lamichhane

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files...
```

---

<div align="center">

**Built with ❤️ for the security community**

[⬆ Back to Top](#destroygpt)

</div>
