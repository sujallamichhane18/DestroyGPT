# 🛡️ DestroyGPT  

![License](https://img.shields.io/github/license/sujallamichhane18/DestroyGPT?color=blue)  
![Python](https://img.shields.io/badge/Python-3.8%2B-blue)  
![Status](https://img.shields.io/badge/Status-Active-success)  

**AI-Powered CLI for Ethical Hacking with Safe Command Execution**  

DestroyGPT is a **secure AI-assisted terminal tool** built for **penetration testers** and **ethical hackers**.  
It integrates with **[OpenRouter.ai](https://openrouter.ai/)** to use advanced LLMs like **DeepSeek-R1**, **GPT-4o**, and **Grok** for generating security commands, payloads, and exploit strategies.  

Unlike ordinary tools, it can **execute commands directly** in your terminal — but with **whitelisting, blacklisting, pattern checks, optional Docker sandboxing, and interactive confirmation** to prevent accidental or malicious damage.  

---

## ✨ Features  

- **Multi-model LLM Support** – GPT-4o, DeepSeek-R1, Grok, and more.  
- **Safe Command Execution** – Whitelist, blacklist, danger keyword detection, and manual confirmation.  
- **Optional Docker Sandbox** – Run commands inside isolated containers (Ubuntu 22.04) if available.  
- **Streaming AI Responses** – Get real-time command suggestions from AI.  
- **Command History** – Store up to 5000 past commands in JSON format.  
- **Rotating Logs** – Detailed logs for audits and debugging.  
- **Dry-Run Mode** – Inspect commands without running them.  

---

## ⚙️ Installation  

```bash
# Clone the repository
git clone https://github.com/sujallamichhane18/DestroyGPT.git
cd DestroyGPT

# Install dependencies
pip install -r requirements.txt

🔑 API Key Setup
DestroyGPT-Advanced uses OpenRouter.ai for LLM access.
You can configure your API key in either of these ways:

# Save to file (recommended)
echo "your_api_key_here" > ~/.destroygpt_api_key
chmod 600 ~/.destroygpt_api_key

# OR set as environment variable
export OPENROUTER_API_KEY="your_api_key_here"

🚀 Usage
Run with the default model:

python destroygpt_advanced.py
Example session:

DestroyGPT >>> Generate a command to scan open ports on example.com
nmap -sV example.com

Command 1:
nmap -sV example.com
Proceed? (y/N) y
[Command output appears here]
Special Commands:
cmd: <your_command> → Directly execute a system command (if safe).

exit or quit → Exit the CLI.


```
🛡️ Safety Layers

✅ Whitelist → Only allows predefined safe tools (e.g., nmap, curl, ssh, dig, etc.)

❌ Blacklist Patterns → Blocks dangerous patterns (e.g., rm -rf /, mkfs, forkbomb)

⚠️ Danger Keywords → Prompts explicit confirmation before running

📦 Docker Isolation → Optionally run inside an ubuntu:22.04 sandbox

⏳ Timeouts & Interrupts → Auto-kills long-running or stuck commands

⚠️ Disclaimer

This tool is intended only for authorized penetration testing, research, and educational purposes.
Any misuse for illegal activities is strictly prohibited.
The author assumes no liability for any misuse or damage.

📜 License
Licensed under the MIT License – see LICENSE for details.

