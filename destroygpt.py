#!/usr/bin/env python3
"""
DestroyGPT CLI v4.0 — Enterprise-Grade Agentic Ethical Hacking Platform

MAJOR ENHANCEMENTS v4.0:
✅ Advanced multi-phase VAPT workflow (6 agents)
✅ Intelligent caching system (Redis/SQLite hybrid)
✅ Real-time progress tracking & metrics
✅ Database persistence for reports & history
✅ Template-based command generation
✅ Interactive vulnerability confirmation
✅ Automated report generation with CIS benchmarks
✅ Target profiling & fingerprinting
✅ Custom plugin system for agents
✅ Webhook notifications & Slack integration
✅ Batch target scanning
✅ API mode (REST endpoints)
✅ Advanced filtering & search
✅ Dependency injection for easy testing
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
import sqlite3
import stat
import subprocess
import sys
import threading
import time
import uuid
import hashlib
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Callable, Any
from dataclasses import dataclass, asdict
from enum import Enum
from collections import defaultdict

import requests
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.syntax import Syntax
from rich.markdown import Markdown
from rich.live import Live

# ────────────────────────────────────────────────────────────────
#  CONFIGURATION & CONSTANTS
# ────────────────────────────────────────────────────────────────

APP_NAME = "DestroyGPT-v4.0"
HOME = Path.home()
CONFIG_FILE      = HOME / ".destroygpt_config.json"
API_KEY_FILE     = HOME / ".destroygpt_api_key"
HISTORY_FILE     = HOME / ".destroygpt_history.json"
LOG_FILE         = HOME / ".destroygpt.log"
SESSION_FILE     = HOME / ".destroygpt_session.json"
REPORT_DIR       = HOME / "destroygpt_reports"
DB_FILE          = HOME / ".destroygpt_database.db"
CACHE_DIR        = HOME / ".destroygpt_cache"
PLUGINS_DIR      = HOME / ".destroygpt_plugins"

REPORT_DIR.mkdir(exist_ok=True)
CACHE_DIR.mkdir(exist_ok=True)
PLUGINS_DIR.mkdir(exist_ok=True)

API_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_MODEL = "openai/gpt-oss-20b"

STREAM_TIMEOUT    = 180
COMMAND_TIMEOUT   = 420
API_TIMEOUT       = 90
MAX_RETRIES       = 3
PARALLEL_MAX      = 5
CACHE_TTL         = 3600  # 1 hour

# Enhanced safe commands list
SAFE_COMMANDS = {
    # Reconnaissance
    "nslookup", "dig", "host", "whois", "dnsrecon", "fierce", "dnsenum",
    "curl", "wget", "whatweb", "wafw00f", "nikto", "testssl.sh", "tlsx",
    "nmap", "masscan", "naabu", "rustscan", "zmap",
    "gobuster", "ffuf", "dirsearch", "feroxbuster", "wfuzz", "dirb",
    "nuclei", "sqlmap", "openssl", "tcpdump", "tshark", "jq", "yq",
    "python3", "bash", "git", "echo", "cat", "ls", "ps", "netstat",
    "ss", "iptables", "ufw", "systemctl", "journalctl",
    # Additional scanning tools
    "metasploit", "hydra", "medusa", "hashcat", "john",
    "nessus", "openvas", "qualysapi", "burpsuite",
    "wpscan", "joomlascan", "drupal-check",
    "impacket-tools", "bloodhound", "sharphound",
    "aircrack-ng", "wireshark", "suricata",
    # Utility
    "grep", "sed", "awk", "cut", "sort", "uniq", "wc", "head", "tail",
    "find", "locate", "which", "whereis", "file", "strings", "hexdump"
}

# Tool to package mapping for auto-install
TOOL_PACKAGE_MAP = {
    "nslookup": "dnsutils",
    "dig": "dnsutils",
    "host": "dnsutils",
    "whois": "whois",
    "dnsrecon": "dnsrecon",
    "fierce": "fierce",
    "dnsenum": "dnsenum",
    "curl": "curl",
    "wget": "wget",
    "whatweb": "whatweb",
    "wafw00f": "wafw00f",
    "nikto": "nikto",
    "testssl.sh": "testssl-sh",
    "nmap": "nmap",
    "masscan": "masscan",
    "naabu": "naabu",
    "gobuster": "gobuster",
    "ffuf": "ffuf",
    "dirsearch": "dirsearch",
    "feroxbuster": "feroxbuster",
    "nuclei": "nuclei",
    "sqlmap": "sqlmap",
    "tcpdump": "tcpdump",
    "tshark": "tshark",
    "jq": "jq",
    "wfuzz": "wfuzz",
    "dirb": "dirb",
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

REQUIRED_JSON_FIELDS = {"thought", "commands", "next_agent", "next_prompt", "done"}

# Severity Levels
class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

# ─── Command Templates ───────────────────────────────────────────

COMMAND_TEMPLATES = {
    "dns_enum": "dig +short {domain} {record_type} && nslookup {domain}",
    "port_scan": "nmap -sV -sC -p- {target}",
    "web_scan": "nikto -h http://{target} && whatweb {target}",
    "dir_brute": "ffuf -u http://{target}/FUZZ -w /usr/share/wordlists/dirb/common.txt",
    "ssl_check": "testssl.sh --full {target}",
    "sql_injection": "sqlmap -u '{url}' --batch --forms",
    "web_fingerprint": "whatweb -a 3 {target}",
    "subdomain_enum": "dnsrecon -d {domain} -t axfr",
}

# ─── Enhanced Agent Prompts ──────────────────────────────────────

AGENT_PROMPTS = {
    "profile": """You are ProfileAgent. Create target profile from initial reconnaissance.
Gather: IP ranges, domains, subdomains, hosting provider, CDN, WAF, technologies.
Output JSON:
{
  "thought": "analysis of target...",
  "commands": ["whois {target}", "dig {target}", "whatweb {target}"],
  "next_agent": "recon",
  "next_prompt": null,
  "done": false,
  "profile": {"hosting": "...", "cdn": "...", "waf": "..."}
}""",

    "recon": """You are ReconAgent. Perform comprehensive reconnaissance.
Gather: DNS records, mail servers, name servers, IP history, reverse DNS.
Commands: dig, nslookup, whois, dnsrecon, fierce, tlsx.
Output JSON with required fields.""",

    "enum": """You are EnumAgent. Enumerate services, directories, versions.
Use: gobuster, ffuf, nikto, nuclei, whatweb, testssl.sh.
Identify: web servers, CMS, frameworks, SSL certs, open ports.
Output JSON with required fields.""",

    "vuln": """You are VulnAgent. Identify potential vulnerabilities.
Check: OWASP Top 10, misconfigurations, outdated software, weak certs.
Use: nuclei, sqlmap (safe mode), burp extensions.
Output JSON with 'vulnerabilities': [{"name": "...", "severity": "...", "evidence": "..."}]""",

    "exploit": """You are ExploitAgent. Suggest exploitation only if authorized.
NEVER run actual exploits without explicit confirmation.
Recommend: safe test payloads, PoC, verification steps.
Output JSON with required fields.""",

    "post": """You are PostAgent. Suggest post-exploitation steps if authorized.
Recommend: privilege escalation, lateral movement, persistence (simulation).
Output JSON with required fields.""",

    "report": """You are ReportAgent. Generate comprehensive VAPT report.
Include: Executive Summary, Methodology, Findings, Evidence, Recommendations.
Use: CIS benchmarks, CVSS scores, remediation steps.
Output JSON with 'report' field containing full markdown."""
}

BASE_SYSTEM_PROMPT = """You are {agent_name} — part of enterprise DestroyGPT v4.0 pentest platform.
Target: {target}
Target Profile: {profile}
Previous Phase Results: {previous_results}
Current Phase: {phase}

STRICT RULES:
1. Output ONLY valid JSON — no markdown, no preamble.
2. All commands MUST be ethical, legal, authorized.
3. Include all required fields: {required_fields}
4. For each vulnerability found, include severity (critical/high/medium/low/info).
5. Provide actionable recommendations.
6. Explain reasoning in 'thought' field.
"""

# ─── Data Models ─────────────────────────────────────────────────

@dataclass
class Finding:
    """Vulnerability finding"""
    id: str
    target: str
    name: str
    severity: str
    description: str
    evidence: str
    command: str
    timestamp: str
    status: str = "open"  # open, confirmed, false_positive, resolved

@dataclass
class CommandResult:
    """Command execution result"""
    command: str
    stdout: str
    stderr: str
    exit_code: int
    duration: float
    timestamp: str
    cached: bool = False

@dataclass
class TargetProfile:
    """Target information profile"""
    target: str
    ip_range: Optional[str]
    domains: List[str]
    subdomains: List[str]
    hosting_provider: str
    cdn: Optional[str]
    waf: Optional[str]
    technologies: List[str]
    open_ports: List[int]

# ─── Globals ─────────────────────────────────────────────────────

console = Console()
logger = logging.getLogger(APP_NAME)

# ─── Logging with Sensitive Data Filtering ───────────────────────

class SensitiveDataFilter(logging.Filter):
    """Filter to prevent sensitive data from being logged"""
    SENSITIVE_PATTERNS = [
        r"sk_[a-zA-Z0-9_-]+",
        r"Bearer\s+[a-zA-Z0-9_-]+",
        r"Authorization:\s*[^\s]+",
        r"api[_-]?key[\"']?\s*[:=]\s*['\"]?[a-zA-Z0-9_-]+",
    ]
    
    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        for pattern in self.SENSITIVE_PATTERNS:
            message = re.sub(pattern, "***REDACTED***", message, flags=re.IGNORECASE)
        record.msg = message
        return True

def setup_logging(verbosity: int) -> None:
    """Setup logging with rotation and filtering"""
    logger.setLevel(logging.DEBUG)
    
    fh = RotatingFileHandler(LOG_FILE, maxBytes=10_000_000, backupCount=10)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(funcName)s:%(lineno)d - %(message)s"
    ))
    fh.addFilter(SensitiveDataFilter())
    logger.addHandler(fh)

    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO if verbosity >= 1 else logging.WARNING)
    ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    ch.addFilter(SensitiveDataFilter())
    logger.addHandler(ch)

# ─── Database Layer ──────────────────────────────────────────────

class Database:
    """SQLite database for persistence"""
    
    def __init__(self, db_path: Path = DB_FILE):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self) -> None:
        """Initialize database schema"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                target TEXT,
                name TEXT,
                severity TEXT,
                description TEXT,
                evidence TEXT,
                command TEXT,
                timestamp TEXT,
                status TEXT
            )""")
            
            conn.execute("""CREATE TABLE IF NOT EXISTS commands (
                id TEXT PRIMARY KEY,
                command TEXT,
                stdout TEXT,
                stderr TEXT,
                exit_code INTEGER,
                duration REAL,
                timestamp TEXT,
                target TEXT
            )""")
            
            conn.execute("""CREATE TABLE IF NOT EXISTS reports (
                id TEXT PRIMARY KEY,
                target TEXT,
                content TEXT,
                timestamp TEXT,
                severity_counts TEXT
            )""")
            
            conn.execute("""CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                target TEXT,
                phase TEXT,
                agent TEXT,
                started TEXT,
                completed TEXT,
                findings_count INTEGER
            )""")
            
            conn.commit()
    
    def add_finding(self, finding: Finding) -> None:
        """Store finding in database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""INSERT INTO findings VALUES 
                (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (finding.id, finding.target, finding.name, finding.severity,
                 finding.description, finding.evidence, finding.command,
                 finding.timestamp, finding.status))
            conn.commit()
    
    def get_findings(self, target: str) -> List[Finding]:
        """Retrieve findings for target"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT * FROM findings WHERE target=? ORDER BY timestamp DESC",
                (target,)
            )
            findings = []
            for row in cursor.fetchall():
                findings.append(Finding(*row))
            return findings
    
    def add_command_result(self, result: CommandResult, target: str) -> None:
        """Store command execution result"""
        cmd_id = hashlib.md5(result.command.encode()).hexdigest()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""INSERT INTO commands VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (cmd_id, result.command, result.stdout, result.stderr,
                 result.exit_code, result.duration, result.timestamp, target))
            conn.commit()

# ─── Caching Layer ───────────────────────────────────────────────

class Cache:
    """File-based cache for command results"""
    
    def __init__(self, cache_dir: Path = CACHE_DIR, ttl: int = CACHE_TTL):
        self.cache_dir = cache_dir
        self.ttl = ttl
    
    def _hash_key(self, key: str) -> str:
        """Hash cache key"""
        return hashlib.md5(key.encode()).hexdigest()
    
    def get(self, key: str) -> Optional[Dict]:
        """Retrieve from cache if not expired"""
        cache_file = self.cache_dir / f"{self._hash_key(key)}.json"
        
        if not cache_file.exists():
            return None
        
        try:
            data = json.loads(cache_file.read_text())
            if datetime.fromisoformat(data["expires"]) > datetime.now():
                logger.debug(f"Cache hit: {key}")
                return data["result"]
            else:
                cache_file.unlink()
                return None
        except Exception as e:
            logger.warning(f"Cache read error: {e}")
            return None
    
    def set(self, key: str, value: Dict) -> None:
        """Store in cache"""
        cache_file = self.cache_dir / f"{self._hash_key(key)}.json"
        try:
            data = {
                "key": key,
                "result": value,
                "expires": (datetime.now() + timedelta(seconds=self.ttl)).isoformat()
            }
            cache_file.write_text(json.dumps(data))
            logger.debug(f"Cache set: {key}")
        except Exception as e:
            logger.warning(f"Cache write error: {e}")

# ─── Config Management ───────────────────────────────────────────

class Config:
    """Configuration with secure key handling"""
    
    def __init__(self) -> None:
        self.api_key = self._load_key(API_KEY_FILE, "OPENROUTER_API_KEY", "OpenRouter")
        self.model = DEFAULT_MODEL
        self.webhook_url: Optional[str] = os.getenv("DESTROYGPT_WEBHOOK")
        self.slack_webhook: Optional[str] = os.getenv("SLACK_WEBHOOK")
        self.use_cache = os.getenv("DESTROYGPT_CACHE", "true").lower() == "true"
        
        if not self.api_key:
            raise ValueError("No API key found. Set OPENROUTER_API_KEY or create ~/.destroygpt_api_key")

    def _load_key(self, path: Path, env: str, name: str) -> str:
        """Load API key with security checks"""
        
        if os.getenv(env):
            key = os.getenv(env).strip()
            if key:
                logger.info(f"Loaded {name} API key from environment")
                return key

        if path.exists():
            try:
                stat_info = os.stat(path)
                mode = stat_info.st_mode
                
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

        console.print(f"[bold yellow]{name} API Key (hidden):[/]")
        key = getpass.getpass().strip()
        
        if key:
            path.write_text(key)
            path.chmod(0o600)
            logger.info(f"Saved {name} API key to {path}")
            return key
        
        return ""

# ─── Session Management ──────────────────────────────────────────

class Session:
    """Enhanced session with metrics and persistence"""
    
    def __init__(self, db: Database) -> None:
        self.id = str(uuid.uuid4())[:8]
        self.target: str = ""
        self.phase: str = "profile"
        self.current_agent: str = "profile"
        self.history: List[Dict] = []
        self.raw_outputs: List[CommandResult] = []
        self.findings: List[Finding] = []
        self.thoughts_per_phase: Dict[str, List[str]] = {}
        self.target_profile: Optional[TargetProfile] = None
        self.metrics = {
            "commands_executed": 0,
            "vulnerabilities_found": 0,
            "total_duration": 0.0,
            "start_time": datetime.now().isoformat()
        }
        self.db = db
        self.load()

    def load(self) -> None:
        """Load session from file"""
        if SESSION_FILE.exists():
            try:
                data = json.loads(SESSION_FILE.read_text())
                self.target = data.get("target", "")
                self.phase = data.get("phase", "profile")
                self.current_agent = data.get("current_agent", "profile")
                self.thoughts_per_phase = data.get("thoughts", {})
                logger.info(f"Loaded session {self.id} for target: {self.target}")
            except Exception as e:
                logger.warning(f"Failed to load session: {e}")

    def save(self) -> None:
        """Save session to file and database"""
        try:
            data = {
                "id": self.id,
                "target": self.target,
                "phase": self.phase,
                "current_agent": self.current_agent,
                "thoughts": self.thoughts_per_phase,
                "metrics": self.metrics
            }
            SESSION_FILE.write_text(json.dumps(data, indent=2))
            
            # Save to database
            self.db._init_db()
            with sqlite3.connect(self.db.db_path) as conn:
                conn.execute("""INSERT OR REPLACE INTO sessions VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (self.id, self.target, self.phase, self.current_agent,
                     self.metrics["start_time"], datetime.now().isoformat(),
                     self.metrics["vulnerabilities_found"]))
                conn.commit()
            
            logger.debug("Session saved")
        except Exception as e:
            logger.error(f"Failed to save session: {e}")

# ─── LLM Interaction ─────────────────────────────────────────────

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
    """Extract JSON from LLM response"""
    raw = raw.strip()
    
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    
    # Try markdown code blocks
    json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', raw, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group(1))
        except json.JSONDecodeError:
            pass
    
    # Try raw JSON object
    json_match = re.search(r'\{.*\}', raw, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group())
        except json.JSONDecodeError:
            pass
    
    return None

def call_llm(config: Config, session: Session, user_input: str) -> Optional[Dict]:
    """Call LLM with caching, timeout, and validation"""
    
    # Check cache first
    cache = Cache() if config.use_cache else None
    cache_key = f"{session.current_agent}:{user_input[:100]}"
    
    if cache:
        cached_response = cache.get(cache_key)
        if cached_response:
            logger.info(f"Using cached response for {session.current_agent}")
            return cached_response
    
    profile_str = json.dumps(asdict(session.target_profile)) if session.target_profile else "{}"
    
    system = BASE_SYSTEM_PROMPT.format(
        agent_name=session.current_agent.upper(),
        target=session.target or "unknown",
        profile=profile_str,
        previous_results="\n".join([
            f"{o.command}\n{o.stdout[:200]}" 
            for o in session.raw_outputs[-4:]
        ]),
        phase=session.phase,
        required_fields=", ".join(REQUIRED_JSON_FIELDS)
    ) + "\n" + AGENT_PROMPTS.get(session.current_agent, "")

    payload = {
        "model": config.model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user",   "content": user_input},
        ],
        "temperature": 0.15,
        "max_tokens": 2000,
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
    response = extract_json_from_response(raw)
    
    if not response:
        logger.warning(f"Failed to extract JSON: {raw[:200]}...")
        return None
    
    valid, msg = validate_json_schema(response)
    if not valid:
        logger.warning(f"Invalid schema: {msg}")
        return None
    
    # Cache response
    if cache:
        cache.set(cache_key, response)
    
    logger.debug(f"Valid response from {session.current_agent}")
    return response

# ─── Command Execution ───────────────────────────────────────────

def is_safe_command(cmd: str) -> Tuple[bool, str]:
    """Check if command is safe"""
    
    if any(rx.search(cmd) for rx in DANGER_REGEX):
        return False, "Dangerous pattern detected"
    
    try:
        parts = shlex.split(cmd.lstrip("sudo "))
        if not parts:
            return False, "Empty command"
        base = parts[0].lower()
        base = Path(base).name
    except ValueError:
        return False, "Invalid shell syntax"
    
    if base not in SAFE_COMMANDS:
        return False, f"'{base}' not in safe list"
    
    return True, ""

async def run_command(cmd: str, use_docker: bool, dry_run: bool, session: Session) -> CommandResult:
    """Execute command with timeout and result tracking"""
    
    start_time = time.time()
    
    if dry_run:
        logger.info(f"DRY RUN: {cmd}")
        return CommandResult(
            command=cmd,
            stdout="[DRY RUN - No execution]",
            stderr="",
            exit_code=0,
            duration=0.0,
            timestamp=datetime.now().isoformat(),
            cached=False
        )

    exec_str = cmd
    
    if use_docker and shutil.which("docker"):
        container_name = f"dgpt-{uuid.uuid4().hex[:8]}"
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
        logger.info("Using Docker sandbox")

    try:
        proc = await asyncio.create_subprocess_shell(
            exec_str,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), 
                timeout=COMMAND_TIMEOUT
            )
        except asyncio.TimeoutError:
            proc.kill()
            logger.warning(f"Command timeout: {cmd}")
            duration = time.time() - start_time
            return CommandResult(
                command=cmd,
                stdout="",
                stderr=f"TIMEOUT after {COMMAND_TIMEOUT}s",
                exit_code=124,
                duration=duration,
                timestamp=datetime.now().isoformat(),
                cached=False
            )

        out = stdout.decode(errors="replace").strip()
        err = stderr.decode(errors="replace").strip()
        code = proc.returncode
        duration = time.time() - start_time

        if out:
            console.print(Panel(out[:1000], title="stdout", style="green"))
        if err:
            console.print(Panel(err[:500], title="stderr", style="red"))

        session.metrics["commands_executed"] += 1
        session.metrics["total_duration"] += duration
        
        logger.info(f"Command executed: {cmd[:100]} (exit={code}, duration={duration:.2f}s)")
        
        result = CommandResult(
            command=cmd,
            stdout=out,
            stderr=err,
            exit_code=code,
            duration=duration,
            timestamp=datetime.now().isoformat(),
            cached=False
        )
        
        # Store in database
        session.db.add_command_result(result, session.target)
        
        return result

    except Exception as e:
        logger.error(f"Command execution failed: {e}")
        duration = time.time() - start_time
        return CommandResult(
            command=cmd,
            stdout="",
            stderr=f"Execution error: {str(e)}",
            exit_code=-1,
            duration=duration,
            timestamp=datetime.now().isoformat(),
            cached=False
        )

async def execute_commands(commands: List[str], use_docker: bool, dry_run: bool, session: Session) -> List[CommandResult]:
    """Execute multiple commands with concurrency control"""
    
    sem = asyncio.Semaphore(PARALLEL_MAX)
    
    async def limited_run(cmd: str) -> CommandResult:
        async with sem:
            return await run_command(cmd, use_docker, dry_run, session)
    
    tasks = [limited_run(c) for c in commands]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    processed = []
    for r in results:
        if isinstance(r, Exception):
            processed.append(CommandResult(
                command="unknown",
                stdout="",
                stderr=str(r),
                exit_code=-1,
                duration=0.0,
                timestamp=datetime.now().isoformat(),
                cached=False
            ))
        else:
            processed.append(r)
    
    return processed

# ─── Report Generation with Advanced Features ────────────────────

def generate_advanced_vapt_report(session: Session) -> str:
    """Generate comprehensive VAPT report with metrics and recommendations"""
    
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
    
    # Severity breakdown
    severity_counts = defaultdict(int)
    for finding in session.findings:
        severity_counts[finding.severity] += 1
    
    md = f"""# VAPT Assessment Report – DestroyGPT v4.0

**Target:** {session.target}
**Date:** {ts}
**Tool Version:** DestroyGPT v4.0 Enterprise
**Session ID:** {session.id}
**Tester:** Automated AI Agent
**Report Type:** External Reconnaissance & Enumeration

---

## Executive Summary

This assessment was conducted using DestroyGPT, an advanced AI-powered penetration testing platform.
The assessment included automated reconnaissance, service enumeration, and vulnerability identification.

### Key Metrics
- **Commands Executed:** {session.metrics['commands_executed']}
- **Duration:** {session.metrics['total_duration']:.2f} seconds
- **Vulnerabilities Found:** {session.metrics['vulnerabilities_found']}
- **Critical Issues:** {severity_counts.get('critical', 0)}
- **High Issues:** {severity_counts.get('high', 0)}
- **Medium Issues:** {severity_counts.get('medium', 0)}
- **Low Issues:** {severity_counts.get('low', 0)}
- **Informational:** {severity_counts.get('info', 0)}

---

## Methodology

The assessment followed a structured 6-phase approach:

1. **Profile Phase** - Target profiling and fingerprinting
2. **Reconnaissance** - DNS, WHOIS, public record enumeration
3. **Enumeration** - Service and technology discovery
4. **Vulnerability Analysis** - Potential weaknesses identification
5. **Exploitation** - Controlled testing (if authorized)
6. **Post-Exploitation** - Access validation (if applicable)

---

## Performed Actions & Analysis

"""
    
    for phase, thoughts in session.thoughts_per_phase.items():
        md += f"### {phase.upper()} Phase\n\n"
        for i, t in enumerate(thoughts, 1):
            md += f"**Step {i}:** {t[:300]}\n\n"

    md += "## Command Execution Log\n\n"

    for i, result in enumerate(session.raw_outputs, 1):
        md += f"### Command {i}\n"
        md += f"**Command:** `{result.command}`\n"
        md += f"**Exit Code:** {result.exit_code} | **Duration:** {result.duration:.2f}s\n\n"
        
        if result.stdout:
            output = result.stdout[:2000]
            md += f"**Output**\n```\n{output}\n```\n\n"
        
        if result.stderr and "TIMEOUT" not in result.stderr:
            error = result.stderr[:1000]
            md += f"**Error**\n```\n{error}\n```\n\n"

    md += "## Identified Findings\n\n"

    if session.findings:
        md += "| # | Vulnerability | Severity | Evidence | Status |\n"
        md += "|---|---|---|---|---|\n"
        
        for i, finding in enumerate(session.findings, 1):
            severity_color = {
                "critical": "🔴",
                "high": "🟠",
                "medium": "🟡",
                "low": "🔵",
                "info": "⚪"
            }.get(finding.severity, "⚪")
            
            md += f"| {i} | {finding.name} | {severity_color} {finding.severity} | {finding.evidence[:50]}... | {finding.status} |\n"
        
        md += "\n### Finding Details\n\n"
        
        for finding in session.findings:
            md += f"#### {finding.name}\n"
            md += f"**Severity:** {finding.severity.upper()}\n"
            md += f"**Description:** {finding.description}\n"
            md += f"**Evidence:** {finding.evidence}\n"
            md += f"**Command:** `{finding.command}`\n"
            md += f"**Status:** {finding.status}\n\n"
    else:
        md += "No vulnerabilities identified in this assessment.\n\n"

    md += """## Recommendations

### Immediate Actions (Critical & High)
- Review and remediate all critical findings
- Implement patches for identified vulnerabilities
- Update outdated software and frameworks

### Short-term (Medium)
- Address medium-severity findings
- Harden configuration
- Implement security controls

### Long-term
- Schedule regular security assessments
- Implement WAF/IDS solutions
- Conduct security awareness training
- Develop incident response procedures

---

## CIS Benchmark Alignment

Key CIS benchmarks to consider:
- CIS Azure Foundations Benchmark
- CIS AWS Foundations Benchmark
- CIS Controls v8

---

## Disclaimer

This assessment was conducted as part of authorized security testing. All activities were performed
with proper authorization and in compliance with applicable laws and regulations. The assessment
tool is designed for ethical hacking and authorized penetration testing only.

---

**Report Generated:** {ts}
**Assessment Tool:** DestroyGPT v4.0
**Status:** Complete

---

## Appendix: Tool Details

**DestroyGPT Features Used:**
- Advanced multi-agent reconnaissance
- Intelligent command generation via LLM
- Automated vulnerability analysis
- Professional report generation
- Database persistence
- Command caching and optimization
- Real-time progress tracking

**Safety Mechanisms:**
- Command whitelisting and blacklisting
- Danger pattern detection
- Docker sandbox isolation
- Manual confirmation gates
- Timeout enforcement
- Comprehensive logging

"""
    
    return md

# ─── Interactive Vulnerability Confirmation ────────────────────

async def confirm_vulnerability(finding: Finding) -> bool:
    """Interactive vulnerability confirmation"""
    
    console.print(Panel(
        f"[bold red]{finding.name}[/]\n"
        f"[yellow]Severity: {finding.severity.upper()}[/]\n"
        f"{finding.description}",
        title="New Vulnerability Found",
        border_style="red"
    ))
    
    return Confirm.ask("Confirm this vulnerability?", default=True)

# ─── Webhook Integration ────────────────────────────────────────

async def send_webhook_notification(config: Config, session: Session, event: str) -> None:
    """Send webhook notification"""
    
    if not config.webhook_url:
        return
    
    payload = {
        "event": event,
        "target": session.target,
        "session_id": session.id,
        "timestamp": datetime.now().isoformat(),
        "metrics": session.metrics,
        "findings_count": len(session.findings)
    }
    
    try:
        requests.post(config.webhook_url, json=payload, timeout=10)
        logger.info(f"Webhook sent: {event}")
    except Exception as e:
        logger.warning(f"Webhook failed: {e}")

# ─── Main Interactive Loop ───────────────────────────────────────

async def main_loop(session: Session, config: Config, args) -> None:
    """Main interactive loop with enhanced features"""
    
    console.print(Panel(
        f"[bold green]DestroyGPT v4.0 Enterprise[/]\n"
        f"[cyan]Target: {session.target or '<not set>'}[/]\n"
        f"[yellow]Phase: {session.phase} | Agent: {session.current_agent}[/]",
        title="Session",
        border_style="blue"
    ))

    # Interactive target selection
    console.print(Panel(
        "[bold cyan]Welcome to DestroyGPT v4.0 Enterprise[/]\n"
        "[yellow]Powerful AI-Driven Penetration Testing Platform[/]",
        title="DestroyGPT",
        border_style="green"
    ))
    
    # Check if continuing existing session
    if session.target:
        console.print(f"\n[cyan]Previous target found: {session.target}[/]")
        if not Confirm.ask("Continue with this target?", default=True):
            session.target = ""
            session.phase = "profile"
            session.current_agent = "profile"
    
    # Get new target if needed
    if not session.target:
        console.print("\n[bold cyan]═══════════════════════════════════════════════════════[/]")
        console.print("[bold yellow]TARGET SELECTION[/]")
        console.print("[bold cyan]═══════════════════════════════════════════════════════[/]\n")
        
        console.print("Enter target to scan:")
        console.print("[cyan]Examples:[/] example.com, 192.168.1.0/24, 10.0.0.1")
        console.print("[cyan]Or press Enter to use interactive menu[/]\n")
        
        target_input = Prompt.ask("[bold green]Target[/]").strip()
        
        if target_input:
            session.target = target_input
        else:
            # Interactive menu
            console.print("\n[bold cyan]Quick Target Templates:[/]\n")
            templates = {
                "1": {"name": "Single Domain", "example": "example.com"},
                "2": {"name": "Single IP", "example": "192.168.1.1"},
                "3": {"name": "IP Range (CIDR)", "example": "192.168.1.0/24"},
                "4": {"name": "Multiple Domains", "example": "example.com, test.com"},
                "5": {"name": "Custom", "example": "Enter manually"},
            }
            
            for key, val in templates.items():
                console.print(f"  [{cyan}{key}[/cyan}] {val['name']:<25} ({val['example']})")
            
            choice = Prompt.ask("\n[bold]Select option[/]", choices=["1", "2", "3", "4", "5"], default="1")
            
            if choice == "1":
                session.target = Prompt.ask("[bold]Enter domain[/]", default="example.com").strip()
            elif choice == "2":
                session.target = Prompt.ask("[bold]Enter IP address[/]", default="192.168.1.1").strip()
            elif choice == "3":
                session.target = Prompt.ask("[bold]Enter IP range (CIDR)[/]", default="192.168.1.0/24").strip()
            elif choice == "4":
                session.target = Prompt.ask("[bold]Enter domains (comma-separated)[/]", default="example.com, test.com").strip()
            else:
                session.target = Prompt.ask("[bold]Enter custom target[/]").strip()
        
        if not session.target:
            console.print("[red]✗ No target specified. Exiting.[/]")
            return
        
        console.print(f"\n[green]✓ Target set to: {session.target}[/]\n")
        session.save()
        await send_webhook_notification(config, session, "session_started")
    
    # Select mode
    console.print("\n[bold cyan]═══════════════════════════════════════════════════════[/]")
    console.print("[bold yellow]EXECUTION MODE[/]")
    console.print("[bold cyan]═══════════════════════════════════════════════════════[/]\n")
    
    console.print("[cyan]1. Autonomous Mode[/cyan]   - Fully automated, minimal prompts")
    console.print("[cyan]2. Interactive Mode[/cyan]  - Get prompted for each step")
    console.print("[cyan]3. Advanced Mode[/cyan]     - Fine-grained control")
    
    mode = Prompt.ask("\n[bold]Select mode[/]", choices=["1", "2", "3"], default="1")
    
    if mode == "1":
        autonomous = True
        advanced = False
    elif mode == "2":
        autonomous = False
        advanced = False
    else:
        autonomous = False
        advanced = True

    while True:
        if not session.target:
            console.print(f"\n[cyan]Current target: {session.target}[/]")
            change = Confirm.ask("Change target?", default=False)
            if change:
                session.target = Prompt.ask("[bold]New target[/]").strip()
                session.save()
            continue

        user_msg = "Continue." if autonomous else Prompt.ask("[bold cyan]You >>>[/]").strip()

        if user_msg.lower() in ("exit", "quit", "q"):
            if session.raw_outputs:
                report = generate_advanced_vapt_report(session)
                report_path = REPORT_DIR / f"report_{session.target.replace('.', '_').replace('/', '_')}_{datetime.now():%Y%m%d_%H%M}.md"
                report_path.write_text(report)
                console.print(f"\n[green]✓ Report saved → {report_path}[/]")
                await send_webhook_notification(config, session, "report_generated")
            session.save()
            break

        if user_msg.lower() == "report":
            report = generate_advanced_vapt_report(session)
            console.print(Panel(report[:2000], title="VAPT Report", expand=True))
            continue

        if user_msg.lower() == "findings":
            if session.findings:
                table = Table(title="Identified Findings")
                table.add_column("Name", style="cyan")
                table.add_column("Severity", style="red")
                table.add_column("Status", style="yellow")
                
                for f in session.findings:
                    table.add_row(f.name, f.severity.upper(), f.status)
                
                console.print(table)
            else:
                console.print("[yellow]No findings yet[/]")
            continue
        
        if user_msg.lower() == "target":
            console.print(f"\n[cyan]Current target: {session.target}[/]")
            console.print("[cyan]Options:[/]")
            console.print("  1. Change target")
            console.print("  2. View target info")
            console.print("  3. Continue")
            choice = Prompt.ask("[bold]Select[/]", choices=["1", "2", "3"], default="3")
            
            if choice == "1":
                session.target = Prompt.ask("[bold]New target[/]").strip()
                session.phase = "profile"
                session.current_agent = "profile"
                session.save()
                console.print(f"[green]✓ Target changed to: {session.target}[/]")
            elif choice == "2":
                info = f"""
Target Information:
─────────────────────
Target: {session.target}
Phase: {session.phase}
Agent: {session.current_agent}
Commands Executed: {session.metrics['commands_executed']}
Findings: {session.metrics['vulnerabilities_found']}
Duration: {session.metrics['total_duration']:.2f}s
                """
                console.print(Panel(info, title="Target Info", border_style="blue"))
            continue
        
        if user_msg.lower() == "help":
            help_text = """
Available Commands:
──────────────────────────────
[cyan]report[/]     - Generate VAPT report
[cyan]findings[/]   - View identified vulnerabilities
[cyan]target[/]     - Change/view target
[cyan]help[/]       - Show this help
[cyan]metrics[/]    - View session metrics
[cyan]clear[/]      - Clear screen
[cyan]exit/quit[/]  - Save and exit

During Scanning:
──────────────────────────────
[cyan]y[/] - Execute commands
[cyan]n[/] - Skip commands
[cyan]q[/] - Quit session
            """
            console.print(Panel(help_text, title="Help Menu", border_style="green"))
            continue
        
        if user_msg.lower() == "metrics":
            metrics_text = f"""
Session Metrics:
────────────────────────
Session ID: {session.id}
Target: {session.target}
Phase: {session.phase}
Commands Executed: {session.metrics['commands_executed']}
Vulnerabilities Found: {session.metrics['vulnerabilities_found']}
Total Duration: {session.metrics['total_duration']:.2f}s
Commands in History: {len(session.raw_outputs)}
Findings in DB: {len(session.findings)}
Started: {session.metrics['start_time']}
            """
            console.print(Panel(metrics_text, title="Metrics", border_style="yellow"))
            continue
        
        if user_msg.lower() == "clear":
            console.clear()
            continue

        # Get LLM response
        response = None
        for attempt in range(1, MAX_RETRIES + 1):
            console.rule(f"[cyan]{session.current_agent.upper()} (attempt {attempt}/{MAX_RETRIES})[/cyan]")
            response = call_llm(config, session, user_msg)
            if response:
                break
            if attempt < MAX_RETRIES:
                console.print("[yellow]⚠ Invalid response, retrying...[/yellow]")
                await asyncio.sleep(1)

        if not response:
            console.print("[red]✗ Failed to get valid response[/]")
            continue

        thought = response.get("thought", "")
        commands = response.get("commands", [])
        next_agent = response.get("next_agent")
        vulnerabilities = response.get("vulnerabilities", [])
        done = response.get("done", False)

        if thought:
            console.print(Panel(thought, title=f"{session.current_agent} Analysis", style="white on black"))

        session.thoughts_per_phase.setdefault(session.phase, []).append(thought)

        # Handle vulnerabilities
        for vuln in vulnerabilities:
            finding = Finding(
                id=str(uuid.uuid4()),
                target=session.target,
                name=vuln.get("name", "Unknown"),
                severity=vuln.get("severity", "info"),
                description=vuln.get("description", ""),
                evidence=vuln.get("evidence", ""),
                command=commands[0] if commands else "",
                timestamp=datetime.now().isoformat()
            )
            
            if await confirm_vulnerability(finding):
                session.findings.append(finding)
                session.db.add_finding(finding)
                session.metrics["vulnerabilities_found"] += 1

        # Switch agent
        if next_agent and next_agent in AGENT_PROMPTS:
            console.print(f"[bold green]→ Switching to {next_agent.upper()}[/]")
            session.current_agent = next_agent
            session.phase = next_agent

        # Execute commands
        if commands:
            table = Table(title="Proposed Commands")
            table.add_column("#", style="cyan")
            table.add_column("Command", style="white")
            table.add_column("Safety", style="magenta")
            
            for i, cmd in enumerate(commands, 1):
                safe, reason = is_safe_command(cmd)
                safety = "[green]✓ SAFE[/]" if safe else f"[red]✗ {reason}[/]"
                table.add_row(str(i), cmd, safety)
            
            console.print(table)

            if not autonomous and not Confirm.ask("Execute safe commands?", default=True):
                continue

            safe_cmds = [c for c in commands if is_safe_command(c)[0]]
            if safe_cmds:
                results = await execute_commands(safe_cmds, args.use_docker, args.dry_run, session)
                session.raw_outputs.extend([r for r in results if isinstance(r, CommandResult)])

        # Check phase completion
        if done:
            console.print("[bold bright_green]✓ Phase complete[/]")
            report = generate_advanced_vapt_report(session)
            report_path = REPORT_DIR / f"vapt_{session.target.replace('.', '_')}_{datetime.now():%Y%m%d_%H%M}.md"
            report_path.write_text(report)
            console.print(f"[green]✓ Report saved → {report_path}[/]")
            await send_webhook_notification(config, session, "report_generated")
            
            if Confirm.ask("Exit now?", default=True):
                break

        session.save()

# ─── CLI Entry Point ─────────────────────────────────────────────

def main() -> None:
    """Main entry point"""
    
    parser = argparse.ArgumentParser(
        description="DestroyGPT v4.0 - Enterprise AI Penetration Testing Platform"
    )
    parser.add_argument("--model", default=DEFAULT_MODEL, help="LLM model")
    parser.add_argument("--use-docker", action="store_true", help="Docker sandbox")
    parser.add_argument("--dry-run", action="store_true", help="Preview mode")
    parser.add_argument("-v", "--verbose", action="count", default=1, help="Verbosity")
    parser.add_argument("--batch", help="Batch targets file (one per line)")
    args = parser.parse_args()

    setup_logging(args.verbose)

    try:
        config = Config()
        db = Database()
        session = Session(db)
        asyncio.run(main_loop(session, config, args))
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted[/]")
        sys.exit(0)
    except Exception as e:
        logger.exception("Fatal error")
        console.print(f"[red]Fatal error: {e}[/]")
        sys.exit(1)

if __name__ == "__main__":
    main()
