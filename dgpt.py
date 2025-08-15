#!/usr/bin/env python3
import argparse
import subprocess
import os
import sys

VERSION = "1.0.0"

HELP_TEXT = """
DestroyGPT — sgpt-like CLI powered by OpenRouter
------------------------------------------------
A command-line AI assistant for chat, shell command generation, and execution.

USAGE:
  dgpt [OPTIONS] [PROMPT]

POSITIONAL ARGUMENTS:
  PROMPT                 Your question, request, or natural language instruction.

OPTIONS:
  -h, --help             Show this help message and exit
  --chat NAME            Start or continue a chat session with the given NAME
  --shell                Generate shell commands from natural language
  --dry-run              Show generated commands without running them
  --no-confirm           Automatically execute generated commands without asking
  --timeout SECONDS      Set a timeout for command execution (default: 60)
  --model MODEL_NAME     Set the model (default: gpt-4o-mini)
  --api-key KEY          Set your OpenRouter API key
  --version              Show version information

EXAMPLES:
  dgpt "What is SQL injection?"
  dgpt --shell "List all listening ports"
  dgpt --chat work "Summarize today's cybersecurity news"
  dgpt --shell --no-confirm "ping -c 4 google.com"

NOTES:
  - By default, API key is read from $OPENROUTER_API_KEY or ~/.destroygpt_api_key
  - Shell mode will prompt before running commands unless --no-confirm is set
"""

def get_api_key():
    key = os.getenv("OPENROUTER_API_KEY")
    if not key:
        key_path = os.path.expanduser("~/.destroygpt_api_key")
        if os.path.exists(key_path):
            with open(key_path) as f:
                key = f.read().strip()
    return key

def stream_completion(prompt, model):
    # Placeholder for API call — implement OpenRouter streaming here
    return "echo 'Mocked command from DestroyGPT'"

def maybe_execute(cmd, no_confirm, timeout):
    if not no_confirm:
        choice = input("[E]xecute, [D]escribe, [A]bort: ").strip().lower()
        if choice != "e":
            if choice == "d":
                print("Description: This is a mocked explanation of the generated command.")
            print("Aborted.")
            return
    try:
        subprocess.run(cmd, shell=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"Command timed out after {timeout} seconds.")

def main():
    parser = argparse.ArgumentParser(description="DestroyGPT CLI — sgpt-like assistant", add_help=False)
    parser.add_argument("prompt", nargs=argparse.REMAINDER, help="Your question or instruction")
    parser.add_argument("--chat", type=str, help="Start or continue a chat session")
    parser.add_argument("--shell", action="store_true", help="Generate shell commands from natural language")
    parser.add_argument("--dry-run", action="store_true", help="Show generated commands without running them")
    parser.add_argument("--no-confirm", action="store_true", help="Auto execute without confirmation")
    parser.add_argument("--timeout", type=int, default=60, help="Command execution timeout")
    parser.add_argument("--model", type=str, default="gpt-4o-mini", help="Model to use")
    parser.add_argument("--api-key", type=str, help="OpenRouter API key")
    parser.add_argument("--version", action="store_true", help="Show version")
    parser.add_argument("-h", "--help", action="store_true", help="Show this help message and exit")

    args = parser.parse_args()

    if args.help:
        print(HELP_TEXT)
        sys.exit(0)

    if args.version:
        print(f"DestroyGPT version {VERSION}")
        sys.exit(0)

    api_key = args.api_key or get_api_key()
    if not api_key:
        print("Error: OpenRouter API key not set.")
        sys.exit(1)

    if not args.prompt and not args.shell:
        print("No prompt provided. Use --help for usage.")
        sys.exit(1)

    prompt_text = " ".join(args.prompt) if args.prompt else input("> ")

    if args.shell:
        print(f"\n[DestroyGPT — Shell Mode]\n> {prompt_text}\n")
        cmd = stream_completion(prompt_text, args.model)
        print(f"Generated command:\n{cmd}\n")
        if not args.dry_run:
            maybe_execute(cmd, args.no_confirm, args.timeout)
    else:
        if args.chat:
            print(f"[DestroyGPT — Chat Session: {args.chat}] Prompt: {prompt_text}")
        else:
            print(f"[DestroyGPT] Prompt: {prompt_text}")
        print("Mocked response from AI model.")

if __name__ == "__main__":
    main()
