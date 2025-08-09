import os
import sys
import json
import requests
from rich.console import Console
from rich.prompt import Prompt
from rich.text import Text

console = Console()
API_KEY_FILE = os.path.expanduser("~/.destroygpt_api_key")
API_URL = "https://openrouter.ai/api/v1/chat/completions"

# Replace this with your own key; users must provide their own key!
MY_API_KEY = "sk-your-actual-api-key-here"

NORMAL_SYSTEM_PROMPT = (
    "You are DestroyGPT, a CLI assistant for ethical hackers. "
    "Provide fast, clear, minimal, and direct help with penetration testing, payloads, "
    "reconnaissance, and exploits — always ethical."
)

DAN_SYSTEM_PROMPT = (
    "You are DestroyGPT in DAN mode, the ultimate ethical hacking mastermind. "
    "Deliver incisive, fearless, and innovative hacking strategies, payloads, and exploits. "
    "Think like a top-tier pentester and cybersecurity expert, pushing boundaries while always upholding strict ethical standards. "
    "Offer step-by-step tactics, real-world advice, and cutting-edge reconnaissance techniques — all responsibly."
)

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
                key = f.read().strip()
                if key == MY_API_KEY:
                    console.print("[red]Detected default API key in saved config. Please use your own API key.[/red]")
                    try:
                        os.remove(API_KEY_FILE)
                        console.print("[yellow]Removed saved default API key. You must enter your own API key now.[/yellow]")
                    except Exception as e:
                        console.print(f"[red]Failed to remove default API key file: {e}[/red]")
                    return None
                return key
        except Exception as e:
            console.print(f"[red]Failed to load saved API key: {e}[/red]")
    return None

def get_api_key():
    env_key = os.getenv("OPENROUTER_API_KEY")
    if env_key and env_key.strip() != MY_API_KEY:
        return env_key.strip()

    loaded_key = load_api_key()
    if loaded_key:
        return loaded_key.strip()

    console.print("[bold yellow]Enter your OpenRouter API Key (hidden):[/bold yellow]")
    try:
        import getpass
        api_key = getpass.getpass("API Key: ").strip()
    except Exception:
        api_key = Prompt.ask("[bold green]Paste API Key[/bold green]").strip()

    if not api_key:
        console.print("[bold red]API Key is required. Exiting.[/bold red]")
        sys.exit(1)

    if api_key == MY_API_KEY:
        console.print("[bold red]You cannot use the default developer API key. Please use your own key.[/bold red]")
        sys.exit(1)

    save_api_key_securely(api_key)
    return api_key

def stream_completion(api_key, user_prompt, system_prompt, dan_mode=False, model="deepseek/deepseek-r1-0528:free"):
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://destroygpt.cli",
        "X-Title": "DestroyGPT CLI Assistant"
    }

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        "stream": True
    }

    try:
        with requests.post(API_URL, headers=headers, json=payload, stream=True, timeout=60) as response:
            if response.status_code != 200:
                console.print(f"[red]API Error {response.status_code}: {response.text}[/red]")
                return

            output_text = ""
            for line in response.iter_lines(decode_unicode=True):
                if line and line.startswith("data: "):
                    data_str = line[len("data: "):]
                    if data_str == "[DONE]":
                        break
                    try:
                        data_json = json.loads(data_str)
                        delta = data_json["choices"][0]["delta"].get("content", "")
                        cleaned_delta = delta.replace("#", "").replace("*", "").replace("`", "").replace("_", "")
                        output_text += cleaned_delta
                        console.print(cleaned_delta, end="", style="red" if dan_mode else "green", highlight=False)
                    except Exception:
                        continue
            print()

    except requests.exceptions.RequestException as e:
        console.print(f"[red]Request error: {e}[/red]")
    except Exception as e:
        console.print(f"[red]Unexpected error: {e}[/red]")

def main():
    console.print("[bold green]Welcome to DestroyGPT![/bold green]")
    console.print("Type [bold yellow]destroy start[/bold yellow] to begin, [bold cyan]activate dan[/bold cyan] to toggle DAN mode, or [red]exit[/red] to quit.\n")

    dan_mode = False

    while True:
        cmd = Prompt.ask("[bold magenta]>>[/bold magenta]").strip().lower()

        if cmd == "destroy start":
            break
        elif cmd in ["exit", "quit"]:
            console.print("[red]Goodbye.[/red]")
            sys.exit(0)
        elif cmd == "activate dan":
            dan_mode = True
            console.print("[bold red]DAN mode activated — ethical hacking answers with bold style.[/bold red]")
        elif cmd == "deactivate dan":
            dan_mode = False
            console.print("[bold green]DAN mode deactivated — back to normal mode.[/bold green]")
        else:
            console.print("[yellow]Hint:[/yellow] Type [cyan]destroy start[/cyan], [cyan]activate dan[/cyan], [cyan]deactivate dan[/cyan], or [red]exit[/red].")

    api_key = get_api_key()

    console.print(f"\n[bold {'red' if dan_mode else 'green'}]DestroyGPT Session Started — {'DAN mode ON' if dan_mode else 'Normal mode'}[/bold {'red' if dan_mode else 'green'}]\n")

    while True:
        try:
            user_input = Prompt.ask("[bold red]DestroyGPT >>>[/bold red]").strip()
            if user_input.lower() in ["exit", "quit"]:
                console.print("[red]Exiting DestroyGPT...[/red]")
                break

            console.print("[dim]DestroyGPT is typing...[/dim]")
            system_prompt = DAN_SYSTEM_PROMPT if dan_mode else NORMAL_SYSTEM_PROMPT
            stream_completion(api_key, user_input, system_prompt, dan_mode=dan_mode)

        except KeyboardInterrupt:
            console.print("\n[red]Session interrupted by user.[/red]")
            break
        except Exception as e:
            console.print(f"[bold red]Unexpected Error:[/bold red] {e}")
            break

if __name__ == "__main__":
    main()
