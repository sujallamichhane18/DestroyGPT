#!/usr/bin/env python3
import argparse
import getpass
import sys
from pathlib import Path
from rich.console import Console
from rich.prompt import Confirm, Prompt

# Import all your advanced functions from the previous script:
# - stream_completion
# - sanitize_ai_output
# - filter_command_lines
# - group_multiline_commands
# - interactive_execute
# - load_api_key, save_api_key, setup_logging, etc.

console = Console()

def main():
    parser = argparse.ArgumentParser(description="DestroyGPT CLI (sgpt-style)")
    parser.add_argument("prompt", nargs="*", help="Prompt or question to ask AI")
    parser.add_argument("--dry-run", action="store_true", help="Do not execute commands, just show them")
    parser.add_argument("--no-confirm", action="store_true", help="Auto execute without confirmation")
    parser.add_argument("--use-docker", action="store_true", help="Run commands in docker sandbox")
    parser.add_argument("--model", default="deepseek/deepseek-r1:free", help="AI model to use")
    parser.add_argument("--api-key", help="OpenRouter API key")
    args = parser.parse_args()

    if not args.prompt:
        console.print("[red]No prompt provided. Exiting.[/red]")
        sys.exit(1)

    user_prompt = " ".join(args.prompt)

    # load API key
    api_key = args.api_key or load_api_key()
    if not api_key:
        try:
            api_key = getpass.getpass("OpenRouter API Key: ").strip()
        except Exception:
            api_key = Prompt.ask("OpenRouter API Key").strip()
        if not api_key:
            console.print("[red]API key is required. Exiting.[/red]")
            sys.exit(1)

    setup_logging(verbosity=1)
    console.print(f"[bold green]DestroyGPT CLI — Processing prompt:[/bold green] {user_prompt}")

    # call AI
    raw_response = stream_completion(api_key, user_prompt, model=args.model)
    if raw_response is None:
        console.print("[red]No response from AI model.[/red]")
        sys.exit(1)

    # parse and sanitize
    lines = sanitize_ai_output(raw_response)
    cmd_lines = filter_command_lines(lines)
    grouped_cmds = group_multiline_commands(cmd_lines)

    if not grouped_cmds:
        console.print("[yellow]No executable commands detected in AI response.[/yellow]")
        return

    # show commands
    for i, c in enumerate(grouped_cmds):
        console.print(f"[cyan][{i}][/cyan] {c}")

    # execution
    if args.no_confirm:
        interactive_execute(grouped_cmds, use_docker=args.use_docker, dry_run=args.dry_run)
    else:
        if Confirm.ask("Run these commands?", default=False):
            interactive_execute(grouped_cmds, use_docker=args.use_docker, dry_run=args.dry_run)
        else:
            console.print("[cyan]Commands skipped.[/cyan]")

if __name__ == "__main__":
    main()
