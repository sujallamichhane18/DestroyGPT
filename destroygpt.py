from openai import OpenAI
import os
from rich.console import Console
from rich.prompt import Prompt

console = Console()

# Ask for OpenRouter API Key if not in environment
api_key = os.getenv("OPENROUTER_API_KEY")
if not api_key:
    console.print("[bold yellow]Enter your OpenRouter API Key:[/bold yellow]")
    api_key = Prompt.ask("[bold green]Paste API Key[/bold green]").strip()
    if not api_key:
        console.print("[bold red]API Key is required. Exiting.[/bold red]")
        exit(1)

# Initialize OpenAI-compatible client with OpenRouter base
client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=api_key,
)

# System prompt to keep the assistant hacker-focused
system_prompt = {
    "role": "system",
    "content": (
        "You are DestroyGPT, a CLI assistant for ethical hackers. Help the user with VAPT, "
        "payload generation, reconnaissance techniques, and exploit commands. Always stay ethical."
    )
}

def ask_destroygpt(user_prompt):
    try:
        completion = client.chat.completions.create(
            model="deepseek-ai/deepseek-coder",  # You can change to gpt-4o, claude, etc.
            extra_headers={
                "HTTP-Referer": "https://destroygpt.cli",
                "X-Title": "DestroyGPT CLI Assistant"
            },
            messages=[
                system_prompt,
                {
                    "role": "user",
                    "content": user_prompt
                }
            ]
        )
        return completion.choices[0].message.content
    except Exception as e:
        return f"[!] API Error: {e}"

def main():
    console.print("[bold green]Type [bold yellow]destroy start[/bold yellow] to begin your hacking assistant[/bold green]\n")

    # Wait until user types 'destroy start'
    while True:
        cmd = Prompt.ask("[bold magenta]>>[/bold magenta]").strip().lower()
        if cmd == "destroy start":
            break
        elif cmd in ["exit", "quit"]:
            console.print("[red]Goodbye.[/red]")
            return
        else:
            console.print("[yellow]Hint:[/yellow] Type [cyan]destroy start[/cyan] to begin.")

    console.print("\n[bold red]DestroyGPT Session Started — Ask your hacking questions below[/bold red]\n")

    # Main loop for user prompts
    while True:
        try:
            user_input = Prompt.ask("[bold red]DestroyGPT >>>[/bold red]").strip()
            if user_input.lower() in ["exit", "quit"]:
                console.print("[red]Exiting DestroyGPT...[/red]")
                break

            reply = ask_destroygpt(user_input)
            console.print(f"\n[bold magenta]DestroyGPT:[/bold magenta] {reply}\n")

        except KeyboardInterrupt:
            console.print("\n[red]Session interrupted by user.[/red]")
            break

if __name__ == "__main__":
    main()
