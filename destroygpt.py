import os
import sys
import json
import requests
from rich.console import Console
from rich.prompt import Prompt

console = Console()
API_KEY_FILE = os.path.expanduser("~/.destroygpt_api_key")
API_URL = "https://openrouter.ai/api/v1/chat/completions"


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


def stream_completion(api_key, user_prompt, model="deepseek/deepseek-coder:free"):
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://destroygpt.cli",
        "X-Title": "DestroyGPT CLI Assistant"
    }

    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are DestroyGPT, a CLI assistant for ethical hackers. "
                    "Provide fast, minimal, and direct help with payloads, recon, exploits, and penetration testing. "
                    "Always respond ethically and with technical precision."
                )
            },
            {"role": "user", "content": user_prompt}
        ],
        "stream": True
    }

    try:
        with requests.post(API_URL, headers=headers, json=payload, stream=True, timeout=60) as response:
            if response.status_code != 200:
                console.print(f"[red]API Error {response.status_code}: {response.text}[/red]")
                return

            for line in response.iter_lines(decode_unicode=True):
                if line and line.startswith("data: "):
                    data_str = line[len("data: "):]
                    if data_str == "[DONE]":
                        break
                    try:
                        data_json = json.loads(data_str)
                        delta = data_json["choices"][0]["delta"].get("content", "")
                        cleaned = delta.replace("#", "").replace("*", "").replace("`", "").replace("_", "")
                        print(cleaned, end="", flush=True)
                    except Exception:
                        continue
            print()

    except requests.exceptions.RequestException as e:
        console.print(f"[red]Request error: {e}[/red]")
    except Exception as e:
        console.print(f"[red]Unexpected error: {e}[/red]")


def main():
    console.print("[bold green]DestroyGPT CLI - Ethical Hacking Assistant[/bold green]")
    console.print("Type [bold yellow]destroy start[/bold yellow] to begin or [red]exit[/red] to quit.\n")

    while True:
        cmd = Prompt.ask("[bold magenta]>>[/bold magenta]").strip().lower()
        if cmd == "destroy start":
            break
        elif cmd in ["exit", "quit"]:
            console.print("[red]Goodbye.[/red]")
            sys.exit(0)
        else:
            console.print("[yellow]Hint:[/yellow] Type [cyan]destroy start[/cyan] or [red]exit[/red].")

    api_key = get_api_key()

    console.print("\n[bold red]DestroyGPT Session Started — Ask your hacking questions below[/bold red]\n")

    while True:
        try:
            user_input = Prompt.ask("[bold red]DestroyGPT >>>[/bold red]").strip()
            if user_input.lower() in ["exit", "quit"]:
                console.print("[red]Exiting DestroyGPT...[/red]")
                break

            console.print("[dim]DestroyGPT is typing...[/dim]")
            stream_completion(api_key, user_input)

        except KeyboardInterrupt:
            console.print("\n[red]Session interrupted by user.[/red]")
            break
        except Exception as e:
            console.print(f"[bold red]Unexpected Error:[/bold red] {e}")
            break


if __name__ == "__main__":
    main()
