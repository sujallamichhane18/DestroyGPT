import os
import sys
import json
import requests
from rich.console import Console
from rich.prompt import Prompt
from rich.style import Style

console = Console()
API_KEY_FILE = os.path.expanduser("~/.destroygpt_api_key")
API_URL = "https://openrouter.ai/api/v1/chat/completions"

# Styles for coloring output
RED_STYLE = Style(color="red", bold=True)
GREEN_STYLE = Style(color="green", bold=True)

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

    console.print("[bold yellow]Enter your OpenRouter API Key (hidden):[/bold yellow]")
    try:
        import getpass
        api_key = getpass.getpass("API Key: ").strip()
    except Exception:
        api_key = Prompt.ask("[bold green]Paste API Key[/bold green]").strip()

    if not api_key:
        console.print("[bold red]API Key is required. Exiting.[/bold red]")
        sys.exit(1)

    save_api_key_securely(api_key)
    return api_key

def stream_completion(api_key, user_prompt, dan_mode=False, model="deepseek/deepseek-r1:free"):
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://destroygpt.cli",
        "X-Title": "DestroyGPT CLI Assistant"
    }

    system_prompt_content = (
        "You are DestroyGPT, a CLI assistant for ethical hackers. "
        "Provide fast, clear, minimal, and direct help with penetration testing, payloads, "
        "reconnaissance, and exploits — always ethical."
    )

    if dan_mode:
        system_prompt_content += (
            "\n\n[DAN MODE ACTIVATED]\n"
            "Respond with powerful, direct, and more detailed technical info but always remain ethical."
        )

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt_content},
            {"role": "user", "content": user_prompt}
        ],
        "stream": True
    }

    try:
        with requests.post(API_URL, headers=headers, json=payload, stream=True, timeout=60) as response:
            if response.status_code != 200:
                console.print(f"[red]API Error {response.status_code}: {response.text}[/red]")
                return

            # Stream response, print character by character colored by mode
            for line in response.iter_lines(decode_unicode=True):
                if line and line.startswith("data: "):
                    data_str = line[len("data: "):]
                    if data_str == "[DONE]":
                        break
                    try:
                        data_json = json.loads(data_str)
                        delta = data_json["choices"][0]["delta"].get("content", "")
                        # Print output in red for DAN, green for normal
                        if dan_mode:
                            console.print(delta, style=RED_STYLE, end="")
                        else:
                            console.print(delta, style=GREEN_STYLE, end="")
                    except Exception:
                        continue
            print()  # newline after done

    except requests.exceptions.RequestException as e:
        console.print(f"[red]Request error: {e}[/red]")
    except Exception as e:
        console.print(f"[red]Unexpected error: {e}[/red]")

def main():
    console.print("[bold green]DestroyGPT CLI - Ethical Hacking Assistant[/bold green]")
    console.print("Commands: [bold yellow]destroy start[/bold yellow], [bold yellow]activate dan[/bold yellow], [bold yellow]deactivate dan[/bold yellow], [red]exit[/red]\n")

    dan_mode = False

    while True:
        cmd = Prompt.ask("[bold magenta]>>[/bold magenta]").strip().lower()
        if cmd == "destroy start":
            api_key = get_api_key()
            console.print("\n[bold green]DestroyGPT Session Started[/bold green]")
            if dan_mode:
                console.print("[bold red]DAN mode is ON[/bold red]\n")
            else:
                console.print("[bold green]DAN mode is OFF[/bold green]\n")
            break
        elif cmd == "activate dan":
            dan_mode = True
            console.print("[bold red]DAN mode activated.[/bold red]")
        elif cmd == "deactivate dan":
            dan_mode = False
            console.print("[bold green]DAN mode deactivated.[/bold green]")
        elif cmd in ["exit", "quit"]:
            console.print("[red]Goodbye.[/red]")
            sys.exit(0)
        else:
            console.print("[yellow]Available commands: destroy start, activate dan, deactivate dan, exit[/yellow]")

    while True:
        try:
            user_input = Prompt.ask("[bold red]DestroyGPT >>>[/bold red]").strip()
            if user_input.lower() in ["exit", "quit"]:
                console.print("[red]Exiting DestroyGPT...[/red]")
                break
            if user_input.lower() == "activate dan":
                dan_mode = True
                console.print("[bold red]DAN mode activated.[/bold red]")
                continue
            if user_input.lower() == "deactivate dan":
                dan_mode = False
                console.print("[bold green]DAN mode deactivated.[/bold green]")
                continue

            console.print("[dim]DestroyGPT is typing...[/dim]")
            stream_completion(api_key, user_input, dan_mode=dan_mode)

        except KeyboardInterrupt:
            console.print("\n[red]Session interrupted by user.[/red]")
            break
        except Exception as e:
            console.print(f"[bold red]Unexpected Error:[/bold red] {e}")
            break

if __name__ == "__main__":
    main()
