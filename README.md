
---

🛡️ DestroyGPT

AI-Powered CLI for Ethical Hacking with Safe Command Execution

DestroyGPT is a secure AI-assisted terminal tool for penetration testers and ethical hackers.
It integrates with OpenRouter.ai to use models like DeepSeek-R1, GPT-4o, and Grok for generating security commands, payloads, and exploit strategies.

Unlike ordinary tools, it can execute commands directly in your terminal — but with whitelisting, blacklisting, pattern checks, optional Docker sandboxing, and interactive confirmation to prevent damage.


---

✨ Features

Multi-model LLM Support – GPT-4o, DeepSeek-R1, Grok, etc.

Safe Command Execution – Whitelist, blacklist, keyword detection, and manual confirmation.

Optional Docker Sandbox – Runs commands inside isolated containers if available.

Streaming AI Responses – Live output as commands are generated.

Command History – Saves up to 5000 past commands in JSON format.

Logging – Rotating log files for auditing and debugging.

Dry-Run Mode – Review commands before execution.



---

⚙️ Installation

# Clone the repository
git clone https://github.com/sujallamichhane18/DestroyGPT.git
cd DestroyGPT

# Install dependencies
pip install -r requirements.txt


---

🔑 API Key Setup

DestroyGPT-Advanced uses OpenRouter.ai for LLM access.
Set up your API key in one of the following ways:

# Save to file
echo "your_api_key_here" > ~/.destroygpt_api_key
chmod 600 ~/.destroygpt_api_key

# OR set as environment variable
export OPENROUTER_API_KEY="your_api_key_here"


---

🚀 Usage

Run with default model:

python destroygpt_advanced.py

Example interaction:

DestroyGPT >>> Generate a command to scan open ports on example.com
nmap -sV example.com

Command 1:
nmap -sV example.com
Proceed? (y/N) y
[Command output appears here]

Special Commands:

cmd: <your_command> → Directly execute a system command (if safe).

exit or quit → Leave the CLI.



---

🛡️ Safety Layers

Whitelist → Only allows predefined safe tools (e.g., nmap, curl, ssh, dig, etc.).

Blacklist Patterns → Blocks dangerous patterns (e.g., rm -rf /, mkfs, forkbomb).

Danger Keywords → Prompts explicit confirmation before running.

Docker Isolation → Optionally runs commands in a ubuntu:22.04 sandbox.

Timeouts & Interrupts → Auto-kills commands after set duration.



---

⚠️ Disclaimer

> This tool is for authorized penetration testing, research, and educational purposes only.
Any misuse for illegal hacking activities is strictly prohibited.
The author is not responsible for any damage caused by misuse.




---

📜 License

Licensed under the MIT License – see LICENSE for details.


---


