#!/usr/bin/env python3
"""
Advanced DestroyGPT CLI (refactor)

- Safer command filtering (whitelist + blacklist + pattern checks)
- Optional Docker sandbox execution (if docker available)
- Stream-resilient OpenRouter streaming parser
- Rotating history and logging
- Dry-run and interactive per-command confirmation
- Command execution watchdog using communicate(timeout=...)
- Configurable via argparse and a small config section
- Keeps compatibility with original features (rich UI, live output)

Notes:
This tool is intended for ethical, authorized testing only.
Running arbitrary commands from an LLM is dangerous even with filters.
"""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import List, Optional, Tuple

import requests
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

# -------------------------
# Configuration / Constants
# -------------------------

APP_NAME = "DestroyGPT-Advanced"
HOME = Path.home()
API_KEY_FILE = HOME / ".destroygpt_api_key"
HISTORY_FILE = HOME / ".destroygpt_cli_history.json"
LOG_FILE = HOME / ".destroygpt_cli.log"
API_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_MODEL = "deepseek/deepseek-r1:free"
STREAM_TIMEOUT = 120  # seconds to wait for stream activity before abort
COMMAND_TIMEOUT_SEC = 180  # per-command timeout (seconds)
HISTORY_MAX_ENTRIES = 5000

# Whitelist of allowed executable base commands (lowercase)
SAFE_COMMANDS = {
    "nmap", "masscan", "curl", "wget", "nc", "netcat", "ssh",
    "python", "python3", "bash", "chmod", "chown", "systemctl", "service",
    "ip", "ifconfig", "tcpdump", "dig", "host", "traceroute", "whoami", "id",
    "uname", "cat", "grep", "awk", "sed", "find", "ls", "ps", "kill", "docker",
    "kubectl", "helm", "git", "java", "node", "pip", "pip3", "jq", "openssl",
}

# Blacklist patterns (dangerous ops)
BLACKLIST_PATTERNS = [
    r"rm\s+-rf\s+/",
    r"rm\s+-rf\s+",
    r":👦👦\s{\s*:|:\s*&\s*};?",  # fork bomb
    r"dd\s+if=",  # destructive disk writes
    r"mkfs.",
    r"shutdown\b",
    r"reboot\b",
    r":>\s*/",  # truncate root
    r"chmod\s+0+\s+/",  # chmod root
]
BLACKLIST_REGEX = [re.compile(x, re.IGNORECASE) for x in BLACKLIST_PATTERNS]

# Danger keywords that require manual confirmation if present
DANGER_KEYWORDS = {
    "rm", "dd", "mkfs", "shutdown", "reboot", "poweroff", "format", "forkbomb"
}

DAN_PROMPT = (
    "You are DestroyGPT, an advanced CLI assistant for ethical hackers.\n"
    "When asked to scan or exploit, reply ONLY with runnable bash commands (no explanation, no extra text).\n"
    "Commands may be multiline with backslashes (\\). Use sudo where necessary."
)

console = Console()
logger = logging.getLogger(APP_NAME)

# -------------------------
# Logging & Utilities
# -------------------------


def setup_logging(verbosity: int = 1) -> None:
    """Setup logging handlers and formatters."""
    logger.setLevel(logging.DEBUG)
    fh = RotatingFileHandler(str(LOG_FILE), maxBytes=2_000_000, backupCount=3)
    fh.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    ch = logging.StreamHandler(sys.stderr)
    ch.setLevel(logging.WARNING if verbosity < 1 else logging.INFO)
    ch.setFormatter(fmt)
    logger.addHandler(ch)


def save_api_key(api_key: str) -> None:
    """Save API key to disk with restrictive permissions."""
    try:
        API_KEY_FILE.write_text(api_key)
        API_KEY_FILE.chmod(0o600)
        logger.info("Saved API key to %s", API_KEY_FILE)
    except Exception as e:
        logger.exception("Failed to save API key: %s", e)


def load_api_key() -> Optional[str]:
    """Load API key from env var or file."""
    env = os.getenv("OPENROUTER_API_KEY")
    if env:
        return env.strip()
    if API_KEY_FILE.exists():
        try:
            return API_KEY_FILE.read_text().strip()
        except Exception:
            return None
    return None


def ensure_history_capacity(hist: List[dict]) -> None:
    """Trim history to max entries."""
    if len(hist) > HISTORY_MAX_ENTRIES:
        excess = len(hist) - HISTORY_MAX_ENTRIES
        del hist[0:excess]


def load_history() -> List[dict]:
    """Load command history from file."""
    if HISTORY_FILE.exists():
        try:
            return json.loads(HISTORY_FILE.read_text())
        except Exception:
            return []
    return []


def save_history(hist: List[dict]) -> None:
    """Save command history to file."""
    try:
        ensure_history_capacity(hist)
        HISTORY_FILE.write_text(json.dumps(hist, indent=2))
    except Exception as e:
        logger.exception("Failed to write history: %s", e)

# -------------------------
# Stream parsing helpers
# -------------------------


def parse_streamed_line(raw_line: str) -> Optional[str]:
    """
    Handle streaming formats like 'data: {...}' or raw json chunks.
    Return the content string if found, else None.
    """
    if not raw_line:
        return None
    line = raw_line.strip()
    if line.startswith("data:"):
        payload = line[len("data:") :].strip()
    else:
        payload = line

    if payload == "[DONE]":
        return None

    try:
        data = json.loads(payload)
        choices = data.get("choices") or []
        for c in choices:
            delta = c.get("delta") or {}
            content = delta.get("content")
            if content:
                return content
            message = c.get("message") or {}
            content = message.get("content") or ""
            if content:
                return content
    except Exception:
        # Not JSON, maybe plain text
        return payload
    return None

# -------------------------
# Safety checks & filtering
# -------------------------


def contains_blacklist(cmd: str) -> bool:
    """Check if command matches any blacklist pattern."""
    for rx in BLACKLIST_REGEX:
        if rx.search(cmd):
            return True
    return False


def has_danger_keyword(cmd: str) -> bool:
    """Check if command contains any danger keyword."""
    lowered = cmd.lower()
    return any(k in lowered for k in DANGER_KEYWORDS)


def extract_base_command(cmd: str) -> Optional[str]:
    """Return the first token (base command) from a shell command string."""
    try:
        tokens = shlex.split(cmd, posix=True)
        if not tokens:
            return None
        return tokens[0].lower()
    except Exception:
        # fallback by whitespace split
        return cmd.strip().split()[0].lower() if cmd.strip() else None


def is_safe_command(cmd: str) -> Tuple[bool, List[str]]:
    """
    Check if command is safe:
    - Does not match blacklist
    - Is in whitelist or allowed by docker
    - Executable exists in PATH (except python inline)
    Returns (is_safe, list_of_reasons_if_not)
    """
    reasons = []

    if contains_blacklist(cmd):
        reasons.append("matches blacklist pattern")

    base = extract_base_command(cmd) or ""

    # If base is an absolute path check it exists
    if base.startswith("/"):
        if not shutil.which(base):
            # maybe it's a script path, check file exists
            if not Path(base).exists():
                reasons.append(f"command path not found: {base}")
    else:
        if base and base not in SAFE_COMMANDS:
            reasons.append(f"'{base}' not in whitelist")
        else:
            # if allowed, ensure executable exists on PATH unless python inline
            if base and not shutil.which(base) and not base.startswith("python"):
                reasons.append(f"executable not found in PATH: {base}")

    return (len(reasons) == 0, reasons)

# -------------------------
# Command grouping / parsing
# -------------------------


def sanitize_ai_output(raw: str) -> List[str]:
    """
    Remove markdown fences and extra characters from AI output.
    Returns list of lines containing command strings.
    """
    lines = []
    for line in raw.splitlines():
        # skip code fences
        if line.strip().startswith("```") or line.strip().startswith("```"):
            continue
        # remove leading markdown markers like > or -
        line = re.sub(r"^\s*[>-]\s*", "", line)
        if line.strip():
            lines.append(line.rstrip())
    return lines


def filter_command_lines(lines: List[str]) -> List[str]:
    """
    Accept only lines that look like commands (basic heuristic).
    Skip lines with backticks or non-ASCII control characters.
    """
    cmd_lines = []
    for line in lines:
        stripped = line.strip()
        if "`" in stripped or any(ord(c) < 32 for c in stripped):
            continue
        # simple heuristic: line starts with sudo, bash, ./, or alphanumeric command
        if re.match(r"^(sudo\s+|bash\s+|./|[A-Za-z0-9_-]+\b)", stripped):
            cmd_lines.append(stripped)
    return cmd_lines


def group_multiline_commands(lines: List[str]) -> List[str]:
    """Group multiline commands ending with backslash into single command strings."""
    grouped = []
    buf: List[str] = []
    for line in lines:
        if line.rstrip().endswith("\\"):
            buf.append(line.rstrip()[:-1].rstrip())
        else:
            if buf:
                buf.append(line)
                grouped.append(" ".join(buf))
                buf = []
            else:
                grouped.append(line)
    if buf:
        grouped.append(" ".join(buf))
    return grouped

# -------------------------
# OpenRouter streaming
# -------------------------


def stream_completion(
    api_key: str, user_prompt: str, model: str = DEFAULT_MODEL, timeout: int = STREAM_TIMEOUT
) -> Optional[str]:
    """Send prompt to OpenRouter API and stream back response content."""
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "X-Title": APP_NAME,
    }

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": DAN_PROMPT},
            {"role": "user", "content": user_prompt + "\n\nReply ONLY with runnable shell commands, no explanation."},
        ],
        "stream": True,
    }

    try:
        with requests.post(API_URL, headers=headers, json=payload, stream=True, timeout=30) as resp:
            if resp.status_code != 200:
                console.print(f"[red]API Error {resp.status_code}: {resp.text}[/red]")
                logger.error("API error %s %s", resp.status_code, resp.text)
                return None

            out = []
            last_activity = time.time()
            for raw in resp.iter_lines(decode_unicode=True):
                if raw:
                    last_activity = time.time()
                    try:
                        content = parse_streamed_line(raw)
                        if content:
                            out.append(content)
                            console.print(content, end="", style="bold bright_green")
                    except Exception:
                        continue
                if time.time() - last_activity > timeout:
                    logger.warning("Stream timed out after %s seconds", timeout)
                    break
            console.print()
            return "".join(out)
    except requests.exceptions.RequestException as e:
        console.print(f"[red]Request error: {e}[/red]")
        logger.exception("Request exception: %s", e)
        return None

# -------------------------
# Execution functions
# -------------------------


def run_in_docker_if_available(cmd: str, use_docker: bool) -> Tuple[int, str, str]:
    """
    Execute command inside docker sandbox if requested and available,
    otherwise run directly on host shell.
    """
    if use_docker and shutil.which("docker"):
        safe_cmd = shlex.quote(cmd)
        docker_cmd = (
            f"docker run --rm --network none --security-opt no-new-privileges "
            f"-v /tmp:/tmp -v /etc/localtime:/etc/localtime:ro ubuntu:22.04 bash -lc {safe_cmd}"
        )
        exec_cmd = docker_cmd
    else:
        exec_cmd = cmd

    logger.info("Executing command: %s", exec_cmd)

    try:
        proc = subprocess.Popen(
            exec_cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            executable="/bin/bash",
        )
        stdout, stderr = proc.communicate(timeout=COMMAND_TIMEOUT_SEC)
        return proc.returncode, stdout, stderr
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()
        logger.warning("Command timed out: %s", cmd)
        return -1, stdout, stderr
    except Exception as e:
        logger.exception("Execution error: %s", e)
        return -2, "", str(e)


def interactive_execute(commands: List[str], use_docker: bool, dry_run: bool) -> None:
    """Interactively confirm and execute commands one by one."""
    for i, cmd in enumerate(commands):
        console.rule(f"Command {i}")
        console.print(Panel(cmd, title=f"Command {i}", style="bright_magenta"))

        if contains_blacklist(cmd):
            console.print("[red]This command matches a blacklist pattern and will NOT be executed.[/red]")
            logger.warning("Blacklisted command blocked: %s", cmd)
            continue

        safe, reasons = is_safe_command(cmd)
        if not safe:
            console.print(f"[yellow]Command flagged: {', '.join(reasons)}[/yellow]")
            if not Confirm.ask("Proceed despite warnings?", default=False):
                console.print("Skipping command.")
                continue

        if has_danger_keyword(cmd):
            console.print("[red]Danger keyword detected — requires explicit confirmation.[/red]")
            if not Confirm.ask("Are you sure you want to run this command?", default=False):
                console.print("Skipping command.")
                continue

        if dry_run:
            console.print("[cyan]Dry-run mode: not executing.\n" + cmd)
            continue

        code, out, err = run_in_docker_if_available(cmd, use_docker)
        if out:
            console.print(Panel(Text(out), title="STDOUT", style="bright_green"))
        if err:
            console.print(Panel(Text(err), title="STDERR", style="bright_red"))
        if code == 0:
            console.print("[bold green]Command completed successfully.[/bold green]")
        elif code > 0:
            console.print(f"[bold red]Command returned non-zero exit code: {code}[/bold red]")
        else:
            console.print(f"[bold red]Command execution error (code {code}). Check logs.[/bold red]")


# -------------------------
# CLI Main
# -------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Advanced DestroyGPT CLI")
    parser.add_argument("--no-save-key", action="store_true", help="Do not save API key to disk")
    parser.add_argument("--use-docker", action="store_true", help="Run commands inside a docker sandbox if available")
    parser.add_argument("--dry-run", action="store_true", help="Do not execute commands, only show them")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Model to use (OpenRouter style)")
    parser.add_argument("--verbosity", type=int, default=1, help="Logging verbosity (0..2)")
    args = parser.parse_args()

    setup_logging(args.verbosity)
    logger.info("Starting %s", APP_NAME)

    api_key = load_api_key()
    if not api_key:
        console.print("[bold green]Enter your OpenRouter API Key (input hidden):[/bold green]")
        try:
            api_key = getpass.getpass("API Key: ").strip()
        except Exception:
            api_key = Prompt.ask("API Key").strip()
        if not api_key:
            console.print("[red]API key is required. Exiting.[/red]")
            sys.exit(1)
        if not args.no_save_key:
            save_api_key(api_key)

    history = load_history()

    console.print(f"[bold bright_green]{APP_NAME} - advanced mode[/bold bright_green]")
    console.print("Type 'exit' to quit. After AI reply you'll be shown parsed commands and invited to run them.")

    while True:
        try:
            user_input = Prompt.ask("DestroyGPT >>>").strip()
            if not user_input:
                continue
            if user_input.lower() in {"exit", "quit"}:
                console.print("[bold red]Goodbye.[/bold red]")
                break

            console.print("[dim]Requesting model...[/dim]")
            raw = stream_completion(api_key, user_input, model=args.model)
            if raw is None:
                console.print("[red]No response from model.[/red]")
                continue

            # sanitize & parse
            lines = sanitize_ai_output(raw)
            cmd_lines = filter_command_lines(lines)
            grouped = group_multiline_commands(cmd_lines)

            if not grouped:
                console.print("[yellow]No executable-looking commands found in model response.[/yellow]")
                history.append({"prompt": user_input, "response_raw": raw, "timestamp": time.time()})
                save_history(history)
                continue

            # show commands summary table
            table = Table(title="Parsed Commands")
            table.add_column("#", style="cyan", width=4)
            table.add_column("Command", style="magenta")
            for i, c in enumerate(grouped):
                table.add_row(str(i), c)
            console.print(table)

            # append to history
            history.append({"prompt": user_input, "response": grouped, "timestamp": time.time()})
            save_history(history)

            # interactive execution
                     # interactive execution
            if Confirm.ask("Would you like to run any of these commands?", default=False):
                indices = Prompt.ask("Enter indices (e.g. 0 or 0-2 or 0,2)")
                # parse indices
                chosen = set()
                for part in indices.split(","):
                    part = part.strip()
                    if not part:
                        continue
                    if "-" in part:
                        a, b = part.split("-", 1)
                        chosen.update(range(int(a), int(b) + 1))
                    else:
                        chosen.add(int(part))
                chosen_cmds = [grouped[i] for i in sorted(chosen) if 0 <= i < len(grouped)]
                if chosen_cmds:
                    interactive_execute(chosen_cmds, use_docker=args.use_docker, dry_run=args.dry_run)
                else:
                    console.print("[yellow]No valid selection.[/yellow]")

        except KeyboardInterrupt:
            console.print("\n[bold red]Interrupted by user. Exiting.[/bold red]")
            break
        except Exception as e:
            logger.exception("Unhandled exception: %s", e)
            console.print(f"[red]Unexpected error: {e}[/red]")

if __name__ == "__main__":
    main()

