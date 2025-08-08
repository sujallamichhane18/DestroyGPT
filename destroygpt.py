import os
import sys
import time
from openai import OpenAI
from rich.console import Console
from rich.prompt import Prompt

console = Console()
API_KEY_FILE = os.path.expanduser("~/.destroygpt_api_key")

def save_api_key_securely(api_key):
    try:
        with open(API_KEY_FILE, "w") as f:
            f.write(api_key)
        os.chmod(API_KEY_FILE, 0o600)  # Owner read/write only
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
    # Try environment variable first
    api_key = os.getenv("OPENROUTER_API_KEY")
    if api_key:
        return api_key.strip()

    # Then try saved file
    api_key = load_api_key()
    if api_key:
        return api_key

    # Otherwise ask user
    console.print("[bold yellow]Enter your OpenRouter API Key (it will be hidden):[/bold yellow]")
    try:
        import getpass
        api_key = getpass.getpass("API Key: ").strip()
    except Exception:
        api_key = Prompt.ask("[bold green]Paste API Key[/bold green]").strip()

    if not api_key:
        console.print("[bold red]API Key is required. Exiting.[/bold red]")
        sys.exit(1)

    # Save key securely for next time
    save_api_key_securely(api_key)
    return api_key

def typewriter(text, delay=0.01):
    for char in text:
        print(char, end='', flush=True)
        time.sleep(delay)
    print()

def init_client(api_key):
    return OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=api_key,
    )

def ask_destroygpt(client, user_prompt):
    try:
        response = client.chat.completions.create(
            model="deepseek/deepseek-r1-0528:free",
            extra_headers={
                "HTTP-Referer": "https://destroygpt.cli",
                "X-Title": "DestroyGPT CLI Assistant"
            },
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are DestroyGPT, a CLI assistant for ethical hackers. "
                        "Assist users with penetration testing, payload generation, reconnaissance, "
                        "and exploit commands in a responsible and ethical manner. "
                        "Provide clear, minimal, and direct answers without markdown or symbols."
                    )
                },
                {
                    "role": "user",
                    "content": user_prompt
                }
            ]
        )
        answer = response.choices[0].message.content.strip()

        # Basic cleanup of markdown-like chars
        for ch in ["#", "*", "-", "`"]:
            answer = answer.replace(ch, "")

        return answer.strip()
    except Exception as e:
        return f"[!] API Error: {e}"

def main():
    console.print("[bold green]Welcome to DestroyGPT![/bold green]")
    console.print("Type [bold yellow]destroy start[/bold yellow] to begin or [red]exit[/red] to quit.\n")

    while True:
        cmd = Prompt.ask("[bold magenta]>>[/bold magenta]").strip().lower()
        if cmd == "destroy start":
            break
        elif cmd in ["exit", "quit"]:
            console.print("[red]Goodbye.[/red]")
            sys.exit(0)
        else:
            console.print("[yellow]Hint:[/yellow] Type [cyan]destroy start[/cyan] to begin or [red]exit[/red] to quit.")

    api_key = get_api_key()
    client = init_client(api_key)

    console.print("\n[bold red]DestroyGPT Session Started — Ask your hacking questions below[/bold red]\n")

    while True:
        try:
            user_input = Prompt.ask("[bold red]DestroyGPT >>>[/bold red]").strip()
            if user_input.lower() in ["exit", "quit"]:
                console.print("[red]Exiting DestroyGPT...[/red]")
                break

            console.print("[dim]DestroyGPT is typing...[/dim]")
            reply = ask_destroygpt(client, user_input)
            typewriter(reply)

        except KeyboardInterrupt:
            console.print("\n[red]Session interrupted by user.[/red]")
            break
        except Exception as ex:
            console.print(f"[bold red]Unexpected Error:[/bold red] {ex}")
            break

if __name__ == "__main__":
    main()
