#!/usr/bin/env python3
"""
DestroyGPT CLI v3.2 — Advanced Agentic Ethical Hacking Assistant with Full VAPT Reporting

FIXES & IMPROVEMENTS v3.2:
✅ Subprocess timeouts enforced with asyncio.wait_for()
✅ API key file permissions validated on load
✅ Docker command injection prevention (list-based args)
✅ JSON schema validation for LLM output
✅ Sensitive data filtering in logs
✅ Better error handling with retry logic
✅ Type hints throughout
✅ Command safety regex improvements
"""

import argparse
import asyncio
import getpass
import json
import logging
import os
import re
import shlex
import shutil
import signal
import stat
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

APP_NAME = "DestroyGPT-v3.2"
HOME = Path.home()
CONFIG_FILE      = HOME / ".destroygpt_config.json"
API_KEY_FILE     = HOME / ".destroygpt_api_key"
HISTORY_FILE     = HOME / ".destroygpt_history.json"
LOG_FILE         = HOME / ".destroygpt.log"
SESSION_FILE     = HOME / ".destroygpt_session.json"
REPORT_DIR       = HOME / "destroygpt_reports"
REPORT_DIR.mkdir(exist_ok=True)

API_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_MODEL = "openai/gpt-4o-mini"

STREAM_TIMEOUT    = 180
COMMAND_TIMEOUT   = 420   # 7 minutes
API_TIMEOUT       = 90    # API call timeout
MAX_RETRIES       = 3
PARALLEL_MAX      = 3

SAFE_COMMANDS = {
    "nslookup", "dig", "host", "whois", "dnsrecon", "fierce",
    "curl", "wget", "whatweb", "wafw00f", "nikto", "testssl.sh",
    "nmap", "masscan", "naabu",
    "gobuster", "ffuf", "dirsearch", "feroxbuster",
    "nuclei", "sqlmap", "openssl", "tcpdump", "tshark", "jq",
    "python3", "bash", "git", "echo", "cat", "ls", "ps", "netstat",
    "ss", "iptables", "ufw", "systemctl", "journalctl"
}

DANGER_PATTERNS = [
    r"(?i)rm\s+-rf\s+[/~.]",
    r"(?i)dd\s+if=/dev/zero|of=/dev/sd[a-z]",
    r"(?i):\(\)\s*{.*:.*;*\s*}",
    r"(?i)mkfs",
    r"(?i)shutdown\b|reboot\b|poweroff\b|halt\b",
    r"(?i)chmod\s+777\s+/",
    r"(?i)chown\s+root\s+/",
    r"(?i)>\s*/etc/passwd",
    r"(?i)curl.*\s*\|\s*bash",
    r"(?i)wget.*\s*-O\s*-\s*\|\s*bash",
    r"(?i)eval\s*\(",
    r"(?i)exec\s*<"
]
DANGER_REGEX = [re.compile(p) for p in DANGER_PATTERNS]

# ─── Required JSON Schema ────────────────────────────────────────

REQUIRED_JSON_FIELDS = {"thought", "commands", "next_agent", "next_prompt", "done"}

# ─── Agent Prompts ───────────────────────────────────────────────

AGENT_PROMPTS = {
    "recon": """You are ReconAgent. Perform safe reconnaissance: DNS, WHOIS, headers, light port scans.
Prefer targeted nmap on CDNs (80,443,8080,...). Avoid -p- on Cloudflare/Akamai.
Output ONLY valid JSON (no markdown, no preamble):
{
  "thought": "reasoning here",
  "commands": ["cmd1", "cmd2"],
  "next_agent": "enum" or null,
  "next_prompt": "question for user or null",
  "done": false
}""",

    "enum": """You are EnumAgent. Enumerate services, directories, versions, users, shares.
Use gobuster, nikto, nuclei, etc. Output ONLY valid JSON with same structure.""",

    "exploit": """You are ExploitAgent. Suggest ONLY safe, authorized, ethical checks.
NEVER run real exploits without explicit user confirmation.
Output ONLY valid JSON with same structure.""",

    "post": """You are PostAgent. Suggest post-exploitation steps (pivoting, credential reuse simulation, etc.)
Only if previous phase succeeded. Output ONLY valid JSON with same structure.""",

    "report": """You are ReportAgent. Produce final VAPT report in markdown.
Use previous results to write: Executive Summary, Performed Actions, Raw Outputs, Findings Table, Recommendations.
Output:
{
  "thought": "full markdown report here (escaped newlines as \\n)",
  "commands": [],
  "next_agent": null,
  "next_prompt": null,
  "done": true
}"""
}

BASE_SYSTEM_PROMPT = """You are {agent_name} — part of an ethical multi-agent pentest system.
Current target: {target}
Previous results: {previous_results}
Current phase: {phase}

Follow RULES strictly:
1. Output ONLY valid JSON — no markdown, no preamble, nothing else.
2. Commands MUST be safe, ethical, legal.
3. Ensure all JSON fields present: thought, commands, next_agent, next_prompt, done.
4. Use sudo only when necessary.
5. For CDNs limit aggressive scanning.
"""

# ─── Globals ─────────────────────────────────────────────────────

console = Console()
logger = logging.getLogger(APP_NAME)

# ─── Logging Setup with Sensitive Data Filtering ──────────────────

class SensitiveDataFilter(logging.Filter):
    """Filter to prevent API keys and sensitive data from being logged"""
    SENSITIVE_PATTERNS = [
        r"sk_[a-zA-Z0-9_-]+",  # API keys
        r"Bearer\s+[a-zA-Z0-9_-]+",  # Bearer tokens
        r"Authorization:\s*[^\s]+",  # Auth headers
    ]
    
    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        for pattern in self.SENSITIVE_PATTERNS:
            message = re.sub(pattern, "***REDACTED***", message)
        record.msg = message
        return True

def setup_logging(verbosity: int) -> None:
    """Setup logging with rotating file handler and sensitive data filtering"""
    logger.setLevel(logging.DEBUG)
    
    fh = RotatingFileHandler(LOG_FILE, maxBytes=5_000_000, backupCount=5)
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    fh.addFilter(SensitiveDataFilter())
    logger.addHandler(fh)

    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO if verbosity >= 1 else logging.WARNING)
    ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    ch.addFilter(SensitiveDataFilter())
    logger.addHandler(ch)

# ─── Config & Keys with Security Checks ──────────────────────────

class Config:
    """Configuration management with secure key handling"""
    
    def __init__(self) -> None:
        self.api_key = self._load_key(API_KEY_FILE, "OPENROUTER_API_KEY", "OpenRouter")
        self.model = DEFAULT_MODEL
        if not self.api_key:
            raise ValueError("No API key found. Set OPENROUTER_API_KEY or create ~/.destroygpt_api_key")

    def _load_key(self, path: Path, env: str, name: str) -> str:
        """Load API key with security checks"""
        
        # Try environment variable first
        if os.getenv(env):
            key = os.getenv(env).strip()
            if key:
                logger.info(f"Loaded {name} API key from environment variable")
                return key

        # Try file with permission check
        if path.exists():
            try:
                # Check file permissions (should be 0o600 or more restrictive)
                stat_info = os.stat(path)
                mode = stat_info.st_mode
                
                # Check if group/other have any permissions
                if mode & 0o077:
                    raise PermissionError(
                        f"API key file {path} has unsafe permissions: {oct(mode)}. "
                        f"Run: chmod 600 {path}"
                    )
                
                key = path.read_text().strip()
                if key:
                    logger.info(f"Loaded {name} API key from file")
                    return key
            except PermissionError as e:
                console.print(f"[red]Security Error: {e}[/]")
                raise

        # Prompt user
        console.print(f"[bold yellow]{name} API Key (hidden input):[/]")
        key = getpass.getpass().strip()
        
        if key:
            path.write_text(key)
            path.chmod(0o600)  # Secure permissions
            logger.info(f"Saved {name} API key to {path} with secure permissions")
            return key
        
        return ""

# ─── Session State ───────────────────────────────────────────────

class Session:
    """Session state management with persistence"""
    
    def __init__(self) -> None:
        self.target: str = ""
        self.phase: str = "recon"
        self.current_agent: str = "recon"
        self.history: List[Dict] = []
        self.raw_outputs: List[Dict] = []
        self.thoughts_per_phase: Dict[str, List[str]] = {}
        self.load()

    def load(self) -> None:
        """Load session from file"""
        if SESSION_FILE.exists():
            try:
                data = json.loads(SESSION_FILE.read_text())
                self.target = data.get("target", "")
                self.phase = data.get("phase", "recon")
                self.current_agent = data.get("current_agent", "recon")
                self.thoughts_per_phase = data.get("thoughts", {})
                logger.info(f"Loaded session for target: {self.target}")
            except Exception as e:
                logger.warning(f"Failed to load session: {e}")

    def save(self) -> None:
        """Save session to file"""
        try:
            data = {
                "target": self.target,
                "phase": self.phase,
                "current_agent": self.current_agent,
                "thoughts": self.thoughts_per_phase
            }
            SESSION_FILE.write_text(json.dumps(data, indent=2))
            logger.debug("Session saved")
        except Exception as e:
            logger.error(f"Failed to save session: {e}")

# ─── LLM Interaction with Timeout & Validation ───────────────────

def validate_json_schema(data: Dict) -> Tuple[bool, str]:
    """Validate LLM output has required fields"""
    missing = REQUIRED_JSON_FIELDS - set(data.keys())
    if missing:
        return False, f"Missing fields: {missing}"
    
    if not isinstance(data.get("commands"), list):
        return False, "'commands' must be a list"
    
    if not isinstance(data.get("thought"), str):
        return False, "'thought' must be a string"
    
    return True, "Valid"

def extract_json_from_response(raw: str) -> Optional[Dict]:
    """Extract JSON from LLM response, handling markdown blocks"""
    raw = raw.strip()
    
    # Try direct JSON parse first
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    
    # Try to extract JSON from markdown code blocks
    json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', raw, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group(1))
        except json.JSONDecodeError:
            pass
    
    # Try to find JSON object pattern
    json_match = re.search(r'\{.*\}', raw, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group())
        except json.JSONDecodeError:
            pass
    
    return None

def call_llm(config: Config, session: Session, user_input: str) -> Optional[Dict]:
    """Call LLM with timeout and response validation"""
    
    system = BASE_SYSTEM_PROMPT.format(
        agent_name=session.current_agent.upper(),
        target=session.target or "unknown",
        previous_results="\n".join([
            o["command"] + "\n" + o.get("stdout","")[:300] 
            for o in session.raw_outputs[-4:]
        ]),
        phase=session.phase
    ) + "\n" + AGENT_PROMPTS.get(session.current_agent, "")

    payload = {
        "model": config.model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user",   "content": user_input},
        ],
        "temperature": 0.15,
        "max_tokens": 1800,
        "stream": True
    }

    headers = {
        "Authorization": f"Bearer {config.api_key}",
        "Content-Type": "application/json"
    }

    full = []
    try:
        with requests.post(
            API_URL, 
            headers=headers, 
            json=payload, 
            stream=True, 
            timeout=API_TIMEOUT
        ) as r:
            if r.status_code != 200:
                logger.error(f"API error {r.status_code}")
                console.print(f"[red]API error {r.status_code}[/]")
                return None
            
            for line in r.iter_lines(decode_unicode=True):
                if line.startswith("data:"):
                    chunk = line[5:].strip()
                    if chunk == "[DONE]":
                        break
                    try:
                        delta = json.loads(chunk)["choices"][0]["delta"]
                        content = delta.get("content", "")
                        if content:
                            full.append(content)
                            console.print(content, end="", style="cyan")
                    except (json.JSONDecodeError, KeyError):
                        pass
        console.print()
    except requests.Timeout:
        logger.error("API request timeout")
        console.print("[red]API request timed out[/]")
        return None
    except Exception as e:
        logger.error(f"API request failed: {e}")
        console.print(f"[red]API request failed: {e}[/]")
        return None

    raw = "".join(full).strip()
    
    # Extract and validate JSON
    response = extract_json_from_response(raw)
    if not response:
        logger.warning(f"Failed to extract JSON from response: {raw[:200]}...")
        return None
    
    valid, msg = validate_json_schema(response)
    if not valid:
        logger.warning(f"Invalid JSON schema: {msg}")
        return None
    
    logger.debug(f"Valid response from {session.current_agent}")
    return response

# ─── Command Safety & Execution ──────────────────────────────────

def is_safe_command(cmd: str) -> Tuple[bool, str]:
    """Check if command is safe to execute"""
    
    # Check danger patterns first
    if any(rx.search(cmd) for rx in DANGER_REGEX):
        return False, "Dangerous pattern detected"
    
    # Extract base command
    try:
        parts = shlex.split(cmd.lstrip("sudo ").lstrip("sudo"))
        if not parts:
            return False, "Empty command"
        base = parts[0].lower()
        base = Path(base).name
    except ValueError:
        return False, "Invalid shell syntax"
    
    # Check whitelist
    if base not in SAFE_COMMANDS:
        return False, f"'{base}' not in safe list"
    
    return True, ""

async def run_command(cmd: str, use_docker: bool, dry_run: bool) -> Dict:
    """Execute command with timeout and error handling"""
    
    if dry_run:
        logger.info(f"DRY RUN: {cmd}")
        return {"command": cmd, "stdout": "[DRY RUN - No execution]", "stderr": "", "exit": 0}

    exec_str = cmd
    
    # Use Docker if requested
    if use_docker and shutil.which("docker"):
        container_name = f"dgpt-{uuid.uuid4().hex[:8]}"
        # Use list-based command construction to prevent injection
        docker_cmd = [
            "docker", "run", "--rm",
            "--name", container_name,
            "--network", "none",
            "--memory=512m",
            "--cpus=1",
            "-v", "/tmp:/tmp:ro",
            "ubuntu:24.04",
            "bash", "-c", cmd
        ]
        exec_str = " ".join(shlex.quote(str(arg)) for arg in docker_cmd)
        logger.info(f"Using Docker sandbox")

    try:
        # Create subprocess with timeout enforcement
        proc = await asyncio.create_subprocess_shell(
            exec_str,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        # Execute with timeout
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), 
                timeout=COMMAND_TIMEOUT
            )
        except asyncio.TimeoutError:
            proc.kill()
            logger.warning(f"Command timeout after {COMMAND_TIMEOUT}s: {cmd}")
            return {
                "command": cmd,
                "stdout": "",
                "stderr": f"TIMEOUT: Command exceeded {COMMAND_TIMEOUT} seconds",
                "exit": 124  # Standard timeout exit code
            }

        out = stdout.decode(errors="replace").strip()
        err = stderr.decode(errors="replace").strip()
        code = proc.returncode

        if out:
            console.print(Panel(out[:1000], title="stdout", style="green"))
        if err:
            console.print(Panel(err[:500], title="stderr", style="red"))

        logger.info(f"Command executed: {cmd[:100]} (exit={code})")
        return {"command": cmd, "stdout": out, "stderr": err, "exit": code}

    except Exception as e:
        logger.error(f"Command execution failed: {e}")
        return {
            "command": cmd,
            "stdout": "",
            "stderr": f"Execution error: {str(e)}",
            "exit": -1
        }

async def execute_commands(commands: List[str], use_docker: bool, dry_run: bool) -> List[Dict]:
    """Execute multiple commands with concurrency limit"""
    
    sem = asyncio.Semaphore(PARALLEL_MAX)
    
    async def limited_run(cmd: str) -> Dict:
        async with sem:
            return await run_command(cmd, use_docker, dry_run)
    
    tasks = [limited_run(c) for c in commands]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Convert exceptions to error dicts
    processed = []
    for r in results:
        if isinstance(r, Exception):
            processed.append({
                "command": "unknown",
                "stdout": "",
                "stderr": str(r),
                "exit": -1
            })
        else:
            processed.append(r)
    
    return processed

# ─── Report Generation ───────────────────────────────────────────

def generate_vapt_report(session: Session) -> str:
    """Generate professional VAPT report"""
    
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
    md = f"""# VAPT Report – DestroyGPT Assisted Pentest

**Target:** {session.target}
**Date:** {ts}
**Tool Version:** DestroyGPT v3.2
**Tester:** Ethical AI Agent

## 1. Executive Summary

External reconnaissance and enumeration performed on {session.target}.
This assessment was conducted using automated tooling with manual oversight.

## 2. Performed Actions & Reasoning

"""
    
    for phase, thoughts in session.thoughts_per_phase.items():
        md += f"### {phase.upper()} Phase\n\n"
        for i, t in enumerate(thoughts, 1):
            md += f"{i}. {t[:200]}\n\n"

    md += "## 3. Raw Command Outputs\n\n"

    for i, res in enumerate(session.raw_outputs, 1):
        md += f"### Command {i}: `{res['command']}`\n"
        md += f"**Exit Code:** {res['exit']}\n\n"
        
        if res['stdout']:
            output = res['stdout'][:2000]
            md += "**STDOUT**\n```text\n" + output + "\n```\n\n"
        
        if res['stderr']:
            error = res['stderr'][:1000]
            md += "**STDERR**\n```text\n" + error + "\n```\n\n"

    md += """## 4. Findings & Analysis

| # | Finding | Severity | Details |
|---|---------|----------|---------|
| 1 | Assessment Completed | Info | Automated reconnaissance completed |
| 2 | See Raw Outputs | Variable | Review command outputs above |

## 5. Recommendations

- Review tool output for security insights
- Conduct authenticated testing if authorized
- Implement findings recommendations
- Schedule regular security assessments

---

**Report Generated:** {ts}
**End of Report**
""".format(ts=ts)
    
    return md

# ─── Main Loop ───────────────────────────────────────────────────

async def main_loop(session: Session, config: Config, args) -> None:
    """Main interactive/autonomous loop"""
    
    console.print(Panel(
        f"[bold green]DestroyGPT v3.2[/]\nTarget: {session.target or '<not set>'}\nPhase: {session.phase} | Agent: {session.current_agent}",
        title="Session",
        border_style="blue"
    ))

    autonomous = Confirm.ask("Autonomous mode? (fewer prompts)", default=False)

    while True:
        if not session.target:
            session.target = Prompt.ask("Set target (domain/IP)").strip()
            session.save()
            continue

        user_msg = "Continue." if autonomous else Prompt.ask("You >>> ").strip()

        if user_msg.lower() in ("exit", "quit", "q"):
            if session.raw_outputs:
                report = generate_vapt_report(session)
                report_path = REPORT_DIR / f"report_{session.target.replace('.', '_')}_{datetime.now():%Y%m%d_%H%M}.md"
                report_path.write_text(report)
                console.print(f"\n[green]✓ Report saved → {report_path}[/]")
                console.print(Panel(report[:1500] + "...", title="Report Preview"))
            session.save()
            break

        if user_msg.lower() == "report":
            report = generate_vapt_report(session)
            console.print(Panel(report[:2000], title="VAPT Report", expand=True))
            continue

        # Get response from LLM with retries
        response = None
        for attempt in range(1, MAX_RETRIES + 1):
            console.rule(f"[cyan]{session.current_agent.upper()} Thinking (attempt {attempt}/{MAX_RETRIES})[/cyan]")
            response = call_llm(config, session, user_msg)
            if response:
                break
            if attempt < MAX_RETRIES:
                console.print("[yellow]⚠ Invalid response, retrying...[/yellow]")
                await asyncio.sleep(1)

        if not response:
            console.print("[red]✗ Failed to get valid response from model.[/]")
            continue

        # Parse response
        thought = response.get("thought", "")
        commands = response.get("commands", [])
        next_agent = response.get("next_agent")
        next_prompt = response.get("next_prompt")
        done = response.get("done", False)

        if thought:
            console.print(Panel(thought, title=f"{session.current_agent} Thought", style="white on black"))

        session.thoughts_per_phase.setdefault(session.phase, []).append(thought)

        # Switch agent if needed
        if next_agent and next_agent in AGENT_PROMPTS:
            console.print(f"[bold green]→ Switching to {next_agent.upper()}[/]")
            session.current_agent = next_agent
            session.phase = next_agent

        # Show proposed commands
        if commands:
            table = Table(title="Proposed Commands")
            table.add_column("#", style="cyan")
            table.add_column("Command", style="white")
            table.add_column("Safety", style="magenta")
            
            for i, cmd in enumerate(commands, 1):
                safe, reason = is_safe_command(cmd)
                safety = "[green]✓ SAFE[/]" if safe else f"[red]✗ BLOCKED[/] ({reason})"
                table.add_row(str(i), cmd, safety)
            
            console.print(table)

            if not autonomous and not Confirm.ask("Execute safe commands?", default=True):
                continue

            # Filter safe commands and execute
            safe_cmds = [c for c in commands if is_safe_command(c)[0]]
            if safe_cmds:
                console.print(f"[cyan]Executing {len(safe_cmds)} safe command(s)...[/]")
                results = await execute_commands(safe_cmds, args.use_docker, args.dry_run)
                for r in results:
                    if isinstance(r, dict):
                        session.raw_outputs.append(r)

        # Check if phase is complete
        if done:
            console.print("[bold bright_green]✓ Phase complete. Generating report...[/]")
            report = generate_vapt_report(session)
            report_path = REPORT_DIR / f"vapt_{session.target.replace('.', '_')}_{datetime.now():%Y%m%d_%H%M}.md"
            report_path.write_text(report)
            console.print(f"[green]✓ Full report saved → {report_path}[/]")
            console.print(Panel(report[:2000] + "\n...", title="Report Preview", expand=True))
            
            if Confirm.ask("Exit now?", default=True):
                break

        session.save()

# ─── Entry Point ─────────────────────────────────────────────────

def main() -> None:
    """Main entry point"""
    
    parser = argparse.ArgumentParser(
        description="DestroyGPT v3.2 - AI-Powered Ethical Hacking Assistant"
    )
    parser.add_argument("--model", default=DEFAULT_MODEL, help="LLM model to use")
    parser.add_argument("--use-docker", action="store_true", help="Use Docker sandbox")
    parser.add_argument("--dry-run", action="store_true", help="Preview commands without execution")
    parser.add_argument("-v", "--verbose", action="count", default=1, help="Verbosity level")
    args = parser.parse_args()

    setup_logging(args.verbose)

    try:
        config = Config()
        session = Session()
        asyncio.run(main_loop(session, config, args))
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/]")
        sys.exit(0)
    except Exception as e:
        logger.exception("Fatal error")
        console.print(f"[red]Fatal error: {e}[/]")
        sys.exit(1)

if __name__ == "__main__":
    main()
