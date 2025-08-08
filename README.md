# 🔥 DestroyGPT

**DestroyGPT** is a blazing-fast, terminal-based AI assistant for **ethical hacking** and **pentesting**.  
Built on [OpenRouter](https://openrouter.ai), it helps you generate payloads, perform recon, or analyze exploits — directly from your CLI.

---

![DestroyGPT Status](https://img.shields.io/badge/status-active-success?style=flat-square)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](LICENSE)

---

## ✨ Features

- 🧠 Powered by OpenRouter LLMs (e.g., DeepSeek, GPT-4o, etc.)
- ⚡ Fast & minimal streaming responses
- 🔐 API Key stored securely at `~/.destroygpt_api_key`
- 🧼 Cleans messy Markdown from AI output
- 📟 CLI-based real-time chat with ethical hacking focus
- 🎯 No BS — payloads, tactics, tools, and recon in one-liners

---

## 🚀 Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/sujallamichhane18/DestroyerGPT
cd destroyGPT
2. Install dependencies

pip install -r requirements.txt
Or manually:


pip install requests rich
3. Run DestroyGPT

python destroygpt.py

🔑 First-Time API Key Setup
DestroyGPT uses your OpenRouter API Key to make model requests.

You'll be prompted to paste the key on first launch

It will be stored securely in: ~/.destroygpt_api_key (chmod 600)

You can also export it directly in the terminal:


export OPENROUTER_API_KEY="your_api_key"
🔒 Your API key is hidden and never exposed.

🧪 Example Prompts

DestroyGPT >>> generate metasploit payload for android
DestroyGPT >>> what’s the nmap scan to detect open SMB ports
DestroyGPT >>> bash script to brute force login on FTP
DestroyGPT >>> how to exploit CVE-2021-3156
📁 File Structure

destroygpt/
├── destroygpt.py          # Main CLI code
├── requirements.txt       # Python dependencies
└── README.md              # You're here

⚠️ Disclaimer
This tool is intended for educational and ethical use only.
The author is not responsible for any misuse.
Never use DestroyGPT to target or harm systems without explicit permission.

📄 License
This project is licensed under the MIT License.

👤 Author
Built with ❤️ by Sujal Lamichhane by using AI.
If you like it, give it a ⭐️!
