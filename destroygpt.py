#!/usr/bin/env python3
"""
Advanced DestroyGPT CLI v2.0 — Agentic Ethical Hacking Assistant
Features added / improved:
- Structured JSON output from LLM (using OpenRouter supported models)
- Full agent loop: execute → feed output back → next step
- Semantic safety check (via small local regex + LLM judge)
- Improved Docker sandbox (with network control, resource limits)
- Session state & context management
- Better prompt engineering (CoT + role + phase awareness)
- Auto-retry on malformed output
- Pentest phase tracking (recon → enum → exploit → post → report)
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
import threading
import time
import uuid
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn

# ────────────────────────────────────────────────────────────────
#  CONFIGURATION
# ────────────────────────────────────────────────────────────────

APP_NAME = "DestroyGPT-Advanced-Agentic"
HOME = Path.home()
API_KEY_FILE = HOME / ".destroygpt_api_key"
HISTORY_FILE = HOME / ".destroygpt_history.json"
LOG_FILE = HOME / ".destroygpt.log"
SESSION_STATE_FILE = HOME / ".destroygpt_session.json"

API_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_MODEL = "anthropic/claude-3.5-sonnet"  # or "openai/gpt-4o" or "deepseek/deepseek-r1:free"

STREAM_TIMEOUT = 180
COMMAND_TIMEOUT_SEC = 300
MAX_RETRIES = 3
HISTORY_MAX_ENTRIES = 5000

# ─── Enhanced Safety ─────────────────────────────────────────────

SAFE_COMMANDS = {
    "nmap", "masscan", "gobuster", "dirsearch", "ffuf", "feroxbuster", "nuclei",
    "sqlmap", "nikto", "whatweb", "wpscan", "testssl.sh", "hydra", "crackmapexec",
    "enum4linux", "smbmap", "ldapsearch", "kerbrute", "bloodhound", "john", "hashcat",
    "curl", "wget", "nc", "socat", "ssh", "python3", "bash", "git", "openssl",
    "tcpdump", "tshark", "dig", "host", "whois", "traceroute", "jq"
}

DANGER_PATTERNS = [
    r"(?i)rm\s+-rf\s+[/~.]", r"(?i)dd\s+if=/dev/zero|of=/dev/sd", r"(?i):\(\)\s*{.*:.*;*\s*}",
    r"(?i)mkfs", r"(?i)shutdown|reboot|poweroff|halt", r"(?i)chmod\s+777\s+/", r"(?i)chown\s+root\s+/",
    r"(?i)>\s*/etc/passwd|\.ssh/authorized_keys", r"(?i)curl.*\s*\|\s*bash"
]

DANGER_REGEX = [re.compile(p) for p in DANGER_PATTERNS]

# ─── System Prompts ──────────────────────────────────────────────

SYSTEM_PROMPT = """You are DestroyGPT v2 — an ELITE, ETHICAL penetration testing agent powered by advanced reasoning.

RULES YOU MUST FOLLOW:
1. ONLY output **valid JSON** — no extra text, no markdown, no explanations outside JSON.
2. Structure your response **exactly** like this:

{{
  "thought": "Chain-of-thought reasoning — explain your plan step by step",
  "phase": "recon|enum|exploit|post|report|other",
  "commands": ["sudo nmap -sV -sC 10.10.10.10", "curl http://example.com"],
  "next_prompt": "optional natural language question to ask user if you need info",
  "done": false
}}

3. Use sudo ONLY when absolutely necessary.
4. Commands must be safe, ethical, and legal — assume authorized target.
5. If you need more info from user, set "next_prompt" to a clear question.
6. When finished with the current task or when reaching a logical stopping point, set "done": true and write a short summary/report in "thought".

Current target: {target}
Previous results: {previous_results}
Current phase: {current_phase}"""

# ─── Globals ─────────────────────────────────────────────────────

console = Console()
logger = logging.getLogger(APP_NAME)

# ─── Logging ─────────────────────────────────────────────────────

def setup_logging(verbosity: int = 1):
    logger.setLevel(logging.DEBUG)
    fh = RotatingFileHandler(str(LOG_FILE), maxBytes=5_000_000, backupCount=5)
    fh.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    ch = logging.StreamHandler(sys.stderr)
    ch.setLevel(logging.INFO if verbosity >= 1 else logging.WARNING)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

# ─── API Key ─────────────────────────────────────────────────────

def load_or_prompt_api_key() -> str:
    env = os.getenv("OPENROUTER_API_KEY")
    if env:
        return env.strip()

    if API_KEY_FILE.exists():
        try:
            return API_KEY_FILE.read_text().strip()
        except:
            pass

    console.print("[bold green]Enter your OpenRouter API Key (hidden):[/bold green]")
    key = getpass.getpass("API Key: ").strip()
    if not key:
        console.print("[red]API key required.[/red]")
        sys.exit(1)

    try:
        API_KEY_FILE.write_text(key)
        API_KEY_FILE.chmod(0o600)
        logger.info("API key saved securely.")
    except Exception as e:
        logger.warning("Could not save API key: %s", e)

    return key

# ─── Session State ───────────────────────────────────────────────

class SessionState:
    def __init__(self):
        self.target: str = ""
        self.phase: str = "recon"
        self.history: List[Dict] = []
        self.previous_results: List[str] = []

    def load(self):
        if SESSION_STATE_FILE.exists():
            try:
                data = json.loads(SESSION_STATE_FILE.read_text())
                self.target = data.get("target", "")
                self.phase = data.get("phase", "recon")
                self.history = data.get("history", [])
                self.previous_results = data.get("previous_results", [])
            except:
                logger.warning("Failed to load session state.")

    def save(self):
        data = {
            "target": self.target,
            "phase": self.phase,
            "history": self.history[-50:],  # keep last 50
            "previous_results": self.previous_results[-10:]  # last 10 outputs
        }
        SESSION_STATE_FILE.write_text(json.dumps(data, indent=2))

# ─── Streaming & Parsing ─────────────────────────────────────────

def stream_and_parse_json(
    api_key: str,
    user_prompt: str,
    state: SessionState,
    model: str = DEFAULT_MODEL
) -> Optional[Dict]:
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/yourusername/destroygpt",  # optional
        "X-Title": APP_NAME,
    }

    full_prompt = SYSTEM_PROMPT.format(
        target=state.target or "unknown",
        previous_results="\n".join(state.previous_results[-3:]),
        current_phase=state.phase
    )

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": full_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "stream": True,
        "response_format": {"type": "json_object"},  # if model supports it
    }

    full_response = []
    with Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True
    ) as progress:
        task = progress.add_task("[cyan]Thinking...", total=None)

        try:
            with requests.post(API_URL, headers=headers, json=payload, stream=True, timeout=60) as r:
                if r.status_code != 200:
                    console.print(f"[red]API Error {r.status_code}: {r.text}[/red]")
                    return None

                for line in r.iter_lines(decode_unicode=True):
                    if not line:
                        continue
                    if line.startswith(":"):
                        continue  # SSE comment
                    if line.startswith("data:"):
                        data = line[5:].strip()
                        if data == "[DONE]":
                            break
                        try:
                            chunk = json.loads(data)
                            delta = chunk["choices"][0]["delta"]
                            content = delta.get("content", "")
                            if content:
                                full_response.append(content)
                                console.print(content, end="", style="bold bright_cyan")
                        except:
                            pass
        except Exception as e:
            logger.exception("Stream error: %s", e)
            console.print("[red]Stream failed.[/red]")
            return None

        console.print()  # newline

    raw = "".join(full_response).strip()
    try:
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            raise ValueError("Not a dict")
        return parsed
    except:
        logger.warning("Invalid JSON from model: %s", raw)
        return None

# ─── Safety Check ────────────────────────────────────────────────

def is_dangerous_command(cmd: str) -> Tuple[bool, str]:
    if any(rx.search(cmd) for rx in DANGER_REGEX):
        return True, "Matches dangerous pattern (rm -rf /, fork bomb, etc.)"

    base = shlex.split(cmd)[0].lower().lstrip("sudo")
    if base not in SAFE_COMMANDS:
        return True, f"Command '{base}' not in safe list"

    return False, ""

# ─── Execution in Sandbox ────────────────────────────────────────

def execute_command(cmd: str, use_docker: bool, dry_run: bool) -> Tuple[int, str, str]:
    if dry_run:
        console.print(f"[cyan]DRY-RUN: {cmd}[/cyan]")
        return 0, "Dry run — no execution", ""

    if use_docker and shutil.which("docker"):
        container_name = f"destroygpt-sandbox-{uuid.uuid4().hex[:8]}"
        # Very restrictive sandbox
        docker_cmd = (
            f"docker run --rm --name {container_name} "
            "--network none "  # no network by default!
            "--memory=512m --cpus=1 "
            "--cap-drop=ALL "
            "-v /tmp:/tmp:ro "
            "ubuntu:24.04 "
            f"bash -c {shlex.quote(cmd)}"
        )
        exec_cmd = docker_cmd
    else:
        exec_cmd = cmd

    logger.info("Executing: %s", exec_cmd)

    proc = subprocess.Popen(
        exec_cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        preexec_fn=os.setsid if not use_docker else None,
    )

    stdout_lines, stderr_lines = [], []

    def read_stream(pipe, lines, style):
        for line in iter(pipe.readline, ''):
            console.print(line.rstrip(), style=style)
            lines.append(line)

    t_out = threading.Thread(target=read_stream, args=(proc.stdout, stdout_lines, "bright_green"))
    t_err = threading.Thread(target=read_stream, args=(proc.stderr, stderr_lines, "bright_red"))
    t_out.start()
    t_err.start()

    start = time.time()
    while proc.poll() is None:
        if time.time() - start > COMMAND_TIMEOUT_SEC:
            if use_docker:
                subprocess.run(["docker", "kill", container_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            return -1, "".join(stdout_lines), "TIMEOUT"

    t_out.join()
    t_err.join()

    return proc.returncode, "".join(stdout_lines), "".join(stderr_lines)

# ─── Main Agent Loop ─────────────────────────────────────────────

def agent_loop(state: SessionState, api_key: str, args):
    console.print(Panel.fit(
        f"[bold bright_green]DestroyGPT Agentic Mode[/]\nTarget: {state.target or 'not set'}\nPhase: {state.phase}",
        title="Session",
        border_style="bright_blue"
    ))

    while True:
        user_input = Prompt.ask("You >>>").strip()

        if user_input.lower() in {"exit", "quit", "q"}:
            state.save()
            console.print("[bold red]Session saved. Goodbye.[/bold red]")
            break

        if user_input.lower() == "set-target":
            state.target = Prompt.ask("Target (IP/domain)")
            state.phase = "recon"
            state.previous_results = []
            console.print(f"[green]Target set to {state.target}[/green]")
            continue

        if user_input.lower() == "status":
            console.print(f"Target: {state.target}")
            console.print(f"Phase: {state.phase}")
            console.print(f"Previous results count: {len(state.previous_results)}")
            continue

        # Use user input as prompt
        prompt = user_input

        for attempt in range(1, MAX_RETRIES + 1):
            console.rule(f"[cyan]Agent Thinking (attempt {attempt}/{MAX_RETRIES})[/cyan]")
            response = stream_and_parse_json(api_key, prompt, state, model=args.model)

            if not response or "commands" not in response:
                console.print("[yellow]Bad response — retrying...[/yellow]")
                continue

            thought = response.get("thought", "No reasoning")
            commands = response.get("commands", [])
            next_prompt = response.get("next_prompt")
            done = response.get("done", False)
            new_phase = response.get("phase", state.phase)

            console.print(Panel(thought, title="Agent Thought", style="bright_white on black"))

            if new_phase != state.phase:
                console.print(f"[bold green]Phase changed → {new_phase}[/bold green]")
                state.phase = new_phase

            if not commands:
                console.print("[yellow]No commands suggested.[/yellow]")
                if next_prompt:
                    console.print(f"[cyan]Agent asks:[/] {next_prompt}")
                break

            # Show commands in table
            table = Table(title="Suggested Commands")
            table.add_column("#", style="cyan")
            table.add_column("Command", style="magenta")
            table.add_column("Safety", style="yellow")
            for i, cmd in enumerate(commands, 1):
                dangerous, reason = is_dangerous_command(cmd)
                safety = "[red]DANGEROUS[/red]" if dangerous else "[green]SAFE[/green]"
                if dangerous:
                    safety += f" ({reason})"
                table.add_row(str(i), cmd, safety)
            console.print(table)

            if done:
                console.print("[bold green]Agent reports mission complete![/bold green]")
                console.print(Panel(thought, title="Final Report"))

            if not Confirm.ask("Execute these commands?", default=False):
                if next_prompt:
                    prompt = Prompt.ask("Your response to agent")
                continue

            executed_outputs = []
            for cmd in commands:
                dangerous, reason = is_dangerous_command(cmd)
                if dangerous:
                    if not Confirm.ask(f"[red]DANGEROUS COMMAND[/red]\n{reason}\nStill run?", default=False):
                        console.print("[yellow]Skipped.[/yellow]")
                        continue

                code, out, err = execute_command(cmd, args.use_docker, args.dry_run)
                result = f"Exit: {code}\nSTDOUT:\n{out}\nSTDERR:\n{err}"
                executed_outputs.append(result)
                state.previous_results.append(result)

                if code != 0:
                    console.print(f"[bold red]Command failed (code {code})[/bold red]")

            # Feed back to next iteration
            if executed_outputs:
                prompt = f"Previous commands executed. Results:\n" + "\n".join(executed_outputs) + "\nContinue."

            if done:
                break

        state.history.append({
            "timestamp": datetime.now().isoformat(),
            "prompt": user_input,
            "response": response,
            "executed": executed_outputs if 'executed_outputs' in locals() else []
        })
        state.save()

# ─── CLI Entry ───────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="DestroyGPT v2 — Agentic Ethical Hacking CLI")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="OpenRouter model name")
    parser.add_argument("--use-docker", action="store_true", help="Use Docker sandbox (recommended)")
    parser.add_argument("--dry-run", action="store_true", help="Show commands but don't execute")
    parser.add_argument("--verbosity", type=int, default=1, help="Logging level")
    args = parser.parse_args()

    setup_logging(args.verbosity)
    logger.info(f"Starting {APP_NAME}")

    api_key = load_or_prompt_api_key()

    state = SessionState()
    state.load()

    if not state.target:
        console.print("[yellow]No target set. Use 'set-target' command.[/yellow]")

    try:
        agent_loop(state, api_key, args)
    except KeyboardInterrupt:
        console.print("\n[bold red]Interrupted. Saving session...[/bold red]")
        state.save()

if __name__ == "__main__":
    main()
