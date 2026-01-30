#!/usr/bin/env python3
"""
DestroyGPT v10.0 - Intelligent & Flexible AI Security Assistant
FIXED VERSION: Safe command extraction
"""

import os
import sys
import json
import shlex
import subprocess
import re
import importlib.util
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, List, Tuple, Any, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import requests
from abc import ABC, abstractmethod

# ============================================================================
# Configuration
# ============================================================================

HOME = Path.home()
CONFIG_DIR = HOME / ".destroygpt"
PLUGINS_DIR = CONFIG_DIR / "plugins"

CONFIG_DIR.mkdir(exist_ok=True)
PLUGINS_DIR.mkdir(exist_ok=True)

API_KEY_FILE = CONFIG_DIR / "api_key"
HISTORY_FILE = CONFIG_DIR / "history.json"
LOG_FILE = CONFIG_DIR / "session_log.txt"
CONFIG_FILE = CONFIG_DIR / "config.json"
CONTEXT_FILE = CONFIG_DIR / "context.json"

API_URL = "https://openrouter.ai/api/v1/chat/completions"

# ============================================================================
# Enums & Dataclasses
# ============================================================================

class SafetyLevel(Enum):
    STRICT = "strict"
    MODERATE = "moderate"
    PERMISSIVE = "permissive"

class CommandRisk(Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class CommandInfo:
    command: str
    risk_level: CommandRisk
    timeout: int = 30

@dataclass
class UserContext:
    skill_level: str = "intermediate"
    preferred_style: str = "detailed"
    last_commands: List[str] = None
    safety_profile: SafetyLevel = SafetyLevel.MODERATE

    def __post_init__(self):
        self.last_commands = self.last_commands or []

# ============================================================================
# Colors
# ============================================================================

class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BLUE = "\033[94m"
    BOLD = "\033[1m"
    END = "\033[0m"

# ============================================================================
# Command Database
# ============================================================================

class CommandDatabase:
    DB = {
        "nmap": CommandInfo("nmap", CommandRisk.MEDIUM, 120),
        "ping": CommandInfo("ping", CommandRisk.SAFE),
        "dig": CommandInfo("dig", CommandRisk.SAFE),
        "curl": CommandInfo("curl", CommandRisk.LOW),
        "wget": CommandInfo("wget", CommandRisk.LOW),
        "whois": CommandInfo("whois", CommandRisk.SAFE),
        "traceroute": CommandInfo("traceroute", CommandRisk.SAFE),
    }

    @classmethod
    def get(cls, name):
        return cls.DB.get(name)

# ============================================================================
# ✅ FIXED Command Validator
# ============================================================================

class SmartCommandValidator:
    def __init__(self, safety: SafetyLevel):
        self.safety = safety
        self.blocked = [
            r"\brm\s+-rf\b",
            r"\bmkfs\b",
            r"\bdd\s+if=.*of=/dev/",
        ]

    # 🔒 FIX: ONLY extract commands from fenced bash/sh blocks
    def extract_commands(self, text: str) -> List[str]:
        commands = []
        in_block = False
        lang = None

        for line in text.splitlines():
            stripped = line.strip()

            if stripped.startswith("```"):
                if not in_block:
                    in_block = True
                    lang = stripped[3:].strip().lower()
                else:
                    in_block = False
                    lang = None
                continue

            if in_block and lang in ("bash", "sh", "shell", ""):
                if stripped and not stripped.startswith("#"):
                    commands.append(stripped)

        return list(dict.fromkeys(commands))

    def validate(self, cmd: str):
        for p in self.blocked:
            if re.search(p, cmd):
                return False, "Blocked dangerous pattern", None

        parts = shlex.split(cmd)
        info = CommandDatabase.get(parts[0]) or CommandInfo(parts[0], CommandRisk.MEDIUM)

        if self.safety == SafetyLevel.STRICT and info.risk_level in (
            CommandRisk.HIGH,
            CommandRisk.CRITICAL,
        ):
            return False, "Command too risky for STRICT mode", info

        return True, "OK", info

    def execute(self, cmd: str, timeout: int):
        try:
            proc = subprocess.run(
                shlex.split(cmd),
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False,
            )
            out = proc.stdout.strip() or proc.stderr.strip()
            return proc.returncode == 0, out or "Done"
        except Exception as e:
            return False, str(e)

# ============================================================================
# AI Engine (unchanged logic)
# ============================================================================

class IntelligentAI:
    def __init__(self, api_key: str):
        self.api_key = api_key

    def ask(self, prompt: str) -> str:
        r = requests.post(
            API_URL,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": "openai/gpt-4o",
                "messages": [
                    {"role": "system", "content": "You are an ethical cybersecurity tutor."},
                    {"role": "user", "content": prompt},
                ],
            },
            timeout=60,
        )

        if r.status_code == 401:
            return "❌ Invalid API key. Check ~/.destroygpt/api_key"

        return r.json()["choices"][0]["message"]["content"]

# ============================================================================
# Main App
# ============================================================================

class DestroyGPT:
    def __init__(self):
        self.api_key = API_KEY_FILE.read_text().strip()
        self.ai = IntelligentAI(self.api_key)
        self.ctx = UserContext()
        self.validator = SmartCommandValidator(self.ctx.safety_profile)

    def run(self):
        while True:
            try:
                q = input(f"{Colors.BLUE}❯{Colors.END} ").strip()
                if q in ("exit", "quit"):
                    break

                answer = self.ai.ask(q)
                print(f"\n{Colors.GREEN}AI:{Colors.END} {answer}\n")

                cmds = self.validator.extract_commands(answer)
                for cmd in cmds:
                    ok, msg, info = self.validator.validate(cmd)
                    if not ok:
                        print(f"{Colors.RED}Blocked:{Colors.END} {msg}")
                        continue

                    if input(f"Run `{cmd}`? [y/N]: ").lower() == "y":
                        success, out = self.validator.execute(cmd, info.timeout)
                        color = Colors.GREEN if success else Colors.RED
                        print(f"{color}{out}{Colors.END}\n")

            except KeyboardInterrupt:
                print("\nInterrupted. Type exit to quit.\n")

# ============================================================================
# Entry Point
# ============================================================================

if __name__ == "__main__":
    DestroyGPT().run()
