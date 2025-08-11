import os
import sys
import json
import re
import subprocess
import time
from getpass import getpass
import requests
from rich.console import Console
from rich.prompt import Prompt
from rich.panel import Panel
from rich.live import Live
from rich.text import Text

console = Console()

API_KEY_FILE = os.path.expanduser("~/.destroygpt_api_key")
API_URL = "https://openrouter.ai/api/v1/chat/completions"
HISTORY_FILE = os.path.expanduser("~/.destroygpt_cli_history.json")
COMMAND_TIMEOUT_SEC = 300  # 5 minutes

last_output_lines = []
history = []

DAN_PROMPT = """
You are DestroyGPT, an advanced CLI assistant for ethical hackers.
When asked to scan or exploit, reply **ONLY** with runnable bash commands (no explanation, no extra text).
Commands may be multiline with backslashes (\).
Use sudo where necessary.
Never include warnings or explanations.

If you understand, reply with: DestroyGPT ready.
"""

def save_api_key_securely(api_key):
    try:
        with open(API_KEY_FILE, "w") as f:
            f.write(api_key)
        os.chmod(API_KEY_FILE, 0o600)
    except Exception as e:
        console.print(f"[red]Failed to save API key securely: {e}[/red]")

def load_api_key():
    if os.path.isfile(API_KEY_FILE):
        try:
            with open(API_KEY_FILE, "r") as f:
                return f.read().strip()
        except Exception as e:
            console.print(f"[red]Failed to load saved API key: {e}[/red]")
    return None

def get_api_key():
    api_key = os.getenv("OPENROUTER_API_KEY") or load_api_key()
    if api_key:
        return api_key.strip()

    console.print("[bold green]Enter your OpenRouter API Key (hidden):[/bold green]")
    try:
        api_key = getpass("API Key: ").strip()
    except Exception:
        api_key = Prompt.ask("[bold green]Paste API Key[/bold green]").strip()

    if not api_key:
        console.print("[bold red]API Key is required. Exiting.[/bold red]")
        sys.exit(1)

    save_api_key_securely(api_key)
    return api_key

def clean_text(text):
    # remove markdown and URLs for safety
    text = re.sub(r"[#*_`]", "", text)
    text = re.sub(r"http\S+", "", text)
    return text

def filter_command_lines(lines):
    cmd_lines = []
    # Accept only common bash commands to avoid running text/explanations
    command_pattern = re.compile(
        r"^(sudo\s+|bash\s+|\.\/|nmap\b|masscan\b|curl\b|wget\b|nc\b|netcat\b|ssh\b|python\b|perl\b|ruby\b|chmod\b|chown\b|systemctl\b|service\b|ip\b|ifconfig\b|tcpdump\b|dig\b|host\b|traceroute\b|whoami\b|id\b|uname\b|cat\b|grep\b|awk\b|sed\b|find\b|ls\b|ps\b|kill\b|docker\b|kubectl\b|helm\b|git\b|java\b|node\b|ping\b)"
    )
    for line in lines:
        stripped = line.strip()
        if command_pattern.match(stripped):
            cmd_lines.append(line)
    return cmd_lines

def load_history():
    if os.path.isfile(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return []
    return []

def save_history(history_data):
    try:
        with open(HISTORY_FILE, "w") as f:
            json.dump(history_data, f, indent=2)
    except Exception as e:
        console.print(f"[red]Failed to save history: {e}[/red]")

def stream_completion(api_key, user_prompt, dan_mode=True, model="deepseek/deepseek-r1:free"):
    global last_output_lines, history
    last_output_lines = []

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://destroygpt.cli",
        "X-Title": "DestroyGPT CLI Assistant"
    }

    # Always DAN mode here with strict command-only prompt
    system_content = DAN_PROMPT

    # Instruct user prompt to get commands only
    prompt_text = f"{user_prompt}\n\nReply ONLY with runnable shell commands, no explanation."

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_content},
            {"role": "user", "content": prompt_text}
        ],
        "stream": True
    }

    try:
        with requests.post(API_URL, headers=headers, json=payload, stream=True, timeout=60) as response:
            if response.status_code != 200:
                console.print(f"[red]API Error {response.status_code}: {response.text}[/red]")
                return False

            output_buffer = ""
            for line in response.iter_lines(decode_unicode=True):
                if line and line.startswith("data: "):
                    data_str = line[len("data: "):]
                    if data_str == "[DONE]":
                        break
                    try:
                        data_json = json.loads(data_str)
                        delta = data_json.get("choices", [{}])[0].get("delta", {}).get("content", "")
                        output_buffer += delta
                        console.print(delta, end="", style="bold bright_green")
                    except Exception:
                        continue
            console.print()  # newline

            cleaned_output = clean_text(output_buffer)
            all_lines = [line for line in cleaned_output.strip().splitlines() if line.strip()]
            filtered_lines = filter_command_lines(all_lines)

            last_output_lines.clear()
            last_output_lines.extend(filtered_lines)

            history.append({"prompt": user_prompt, "response": filtered_lines, "timestamp": time.time()})
            save_history(history)

            if not filtered_lines:
                console.print("[yellow]Warning: No executable commands found in AI response.[/yellow]")

            return True

    except requests.exceptions.RequestException as e:
        console.print(f"[red]Request error: {e}[/red]")
        return False
    except Exception as e:
        console.print(f"[red]Unexpected error: {e}[/red]")
        return False

def group_multiline_commands(lines):
    grouped = []
    buffer = []
    for line in lines:
        stripped = line.rstrip()
        if stripped.endswith("\\"):
            buffer.append(stripped[:-1].rstrip())
        else:
            buffer.append(stripped)
            grouped.append(" ".join(buffer))
            buffer = []
    if buffer:
        grouped.append(" ".join(buffer))
    return grouped

def is_root():
    return os.geteuid() == 0 if hasattr(os, "geteuid") else False

def run_shell_command(command):
    if command.startswith("sudo") and not is_root():
        console.print("[yellow]Sudo command detected but you are not root. You might be prompted for password.[/yellow]")

    console.print(Panel(f"[bold cyan]Running command:[/bold cyan]\n{command}", style="bright_magenta"))

    try:
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True,
            executable="/bin/bash"
        )

        with Live(console=console, refresh_per_second=4) as live:
            stdout_lines = []
            stderr_lines = []
            while True:
                out_line = process.stdout.readline()
                err_line = process.stderr.readline()

                if out_line:
                    stdout_lines.append(out_line)
                    live.update(Panel(Text("".join(stdout_lines), style="bright_green"), title="STDOUT"))
                if err_line:
                    stderr_lines.append(err_line)
                    live.update(Panel(Text("".join(stderr_lines), style="bright_red"), title="STDERR"))

                if out_line == '' and err_line == '' and process.poll() is not None:
                    break

            process.wait(timeout=COMMAND_TIMEOUT_SEC)
        return_code = process.returncode

        if return_code == 0:
            console.print("[bold green]Command completed successfully.[/bold green]")
        else:
            console.print(f"[bold red]Command exited with code {return_code}.[/bold red]")

    except subprocess.TimeoutExpired:
        process.kill()
        console.print(f"[bold red]Command timed out after {COMMAND_TIMEOUT_SEC} seconds.[/bold red]")
    except Exception as e:
        console.print(f"[bold red]Error running command: {e}[/bold red]")

def parse_execute_commands(cmd_str):
    cmd_str = cmd_str.strip().lower()
    cmd_str = re.sub(r"^(exec|e)\(?|\)?$", "", cmd_str)
    indices = []
    parts = cmd_str.split(',')
    for part in parts:
        part = part.strip()
        if '-' in part:
            start, end = part.split('-', 1)
            if start.isdigit() and end.isdigit():
                indices.extend(range(int(start), int(end)+1))
        elif part.isdigit():
            indices.append(int(part))
    return sorted(set(indices))

def confirm_execute_commands(commands):
    console.print("\n[bold cyan]Commands to execute:[/bold cyan]")
    for i, cmd in enumerate(commands):
        console.print(f"{i}: [bright_magenta]{cmd}[/bright_magenta]")
    confirm = Prompt.ask("Proceed to execute all? (y/n)", default="n")
    return confirm.lower() == "y"

def execute_commands(indices, last_output_lines):
    chosen_lines = []
    for idx in indices:
        if 0 <= idx < len(last_output_lines):
            chosen_lines.append(last_output_lines[idx])
        else:
            console.print(f"[red]Index {idx} out of range. Skipping.[/red]")

    if not chosen_lines:
        console.print("[yellow]No valid commands found to execute.[/yellow]")
        return

    commands_to_run = group_multiline_commands(chosen_lines)

    if not commands_to_run:
        console.print("[yellow]No commands after grouping lines.[/yellow]")
        return

    if not confirm_execute_commands(commands_to_run):
        console.print("[yellow]Execution cancelled.[/yellow]")
        return

    for cmd in commands_to_run:
        run_shell_command(cmd)

def auto_run_prompt(last_output_lines):
    while True:
        inp = Prompt.ask("Run command(s)? (e.g. e0, e1-3, d=describe, s=skip, h=history)", default="s").lower()
        if inp == 's':
            break
        elif inp == 'd':
            console.print("\n--- Last AI Response ---")
            for i, line in enumerate(last_output_lines):
                console.print(f"{i}: {line}")
            console.print("--- End of Response ---\n")
        elif inp == 'h':
            if not history:
                console.print("No history yet.")
                continue
            console.print("\n--- Last 10 History Entries ---")
            for i, entry in enumerate(history[-10:]):
                ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(entry.get("timestamp", 0)))
                prompt = entry.get("prompt", "")[:50]
                console.print(f"{i}: [{ts}] Prompt: {prompt} ...")
            console.print("--- End of History ---\n")
        else:
            indices = parse_execute_commands(inp)
            if not indices:
                console.print("[yellow]No valid command indices found.[/yellow]")
                continue
            execute_commands(indices, last_output_lines)
            break

def main(api_key):
    global history
    history = load_history()
    console.print("[bold bright_green]DestroyGPT CLI - Ethical Hacking Assistant[/bold bright_green]")
    console.print("[bold]Commands:[/bold] activate dan, deactivate dan, exit")
    console.print("After AI response, run commands by entering e0, e1-3, etc.\n")

    dan_mode = True  # forced DAN mode for strict commands only

    while True:
        try:
            user_input = Prompt.ask("DestroyGPT >>>").strip()
            if not user_input:
                continue
            if user_input.lower() == "exit":
                console.print("[bold red]Goodbye.[/bold red]")
                sys.exit(0)

            if user_input.lower() == "activate dan":
                dan_mode = True
                console.print("[bold red]DAN mode activated.[/bold red]")
                continue
            elif user_input.lower() == "deactivate dan":
                dan_mode = False
                console.print("[bold green]DAN mode deactivated.[/bold green]")
                continue

            console.print("[dim]DestroyGPT is typing...[/dim]\n")
            success = stream_completion(api_key, user_input, dan_mode=dan_mode)
            if success and last_output_lines:
                auto_run_prompt(last_output_lines)

        except KeyboardInterrupt:
            console.print("\n[bold red]Session interrupted by user.[/bold red]")
            sys.exit(0)
        except Exception as e:
            console.print(f"[bold red]Unexpected error: {e}[/bold red]")
            sys.exit(1)

if __name__ == "__main__":
    api_key = get_api_key()
    main(api_key)
