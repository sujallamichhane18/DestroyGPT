import os
import sys
import time
from openai import OpenAI
from rich.console import Console
from rich.prompt import Prompt

console = Console()

# -------------------------
# Utility: simulate typing
# -------------------------
def typewriter(text, delay=0.015):
    for char in text:
        print(char, end='', flush=True)
        time.sleep(delay)
    print()

# -------------------------
# Ask for OpenRouter API Key
# -------------------------
def get_api_key():
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        console.print("[bold yellow]Enter your OpenRouter API Key (it will be hidden):[/bold yellow]")
        try:
            import getpass
            api_key = getpass.getpass("API Key: ").strip()
        except Exception:
            api_key = Prompt.ask("[bold green]Paste API Key[/bold green]").strip()
    if not api_key:
        console.print("[bold red]API Key is required. Exiting.[/bold red]")
        sys.exit(1)
    return api_key

# -------------------------
# Initialize Client
# -------------------------
def init_client(api_key):
    return OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=api_key,
    )

# -------------------------
# Ask DestroyGPT
# -------------------------
def ask_destroygpt(client, user_prompt):
    try:
        response = client.chat.completions.create(
            model="deepseek/deepseek-r1-0528:free",  # <-- FIX: comma added here
            extra_headers={
                "HTTP-Referer": "https://destroygpt.cli",
                "X-Title": "DestroyGPT CLI Assistant"
            },
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are DestroyGPT, a CLI assistant for ethical hackers. Help the user with VAPT, "
                        "payload generation, reconnaissance techniques, and exploit commands. Always stay ethical."
                    )
                },
                {
                    "role": "user",
                    "content": user_prompt
                }
            ]
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        return f"[!] API Error: {e}"

# -------------------------
# Main Function
# -------------------------
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
            console.print("[yellow]Hint:[/yellow] Type [cyan]destroy start[/cyan] to begin.")

    # Start the session
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

            # Fancy typing output
            console.print("\n[bold magenta]DestroyGPT:[/bold magenta]", end=" ")
            typewriter(reply)

        except KeyboardInterrupt:
            console.print("\n[red]Session interrupted by user.[/red]")
            break
        except Exception as ex:
            console.print(f"[bold red]Unexpected Error:[/bold red] {ex}")
            break

# -------------------------
# Entry Point
# -------------------------
if __name__ == "__main__":
    main()
