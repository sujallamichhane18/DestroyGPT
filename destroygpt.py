#!/usr/bin/env python3
"""
DestroyGPT v6.0 - Enterprise AI Hacking Assistant
Advanced features: Multi-target scanning, report generation, automation, threat analysis
"""

import argparse
import json
import os
import sys
import getpass
import subprocess
import shlex
import requests
import sqlite3
from pathlib import Path
from typing import Optional, List, Dict
from datetime import datetime
import hashlib

# ─── CONFIG ──────────────────────────────────────────────────────

HOME = Path.home()
API_KEY_FILE = HOME / ".destroygpt_api_key"
DB_FILE = HOME / ".destroygpt_database.db"
REPORTS_DIR = HOME / "destroygpt_reports"
REPORTS_DIR.mkdir(exist_ok=True)

API_URL = "https://openrouter.ai/api/v1/chat/completions"

# Advanced models
MODELS = {
    "1": {"name": "openai/gpt-4o", "label": "GPT-4o (Most Powerful)", "tokens": 128000},
    "2": {"name": "openai/gpt-oss-120b", "label": "GPT-OSS 120B (Fast & Powerful)", "tokens": 8000},
    "3": {"name": "arcee-ai/trinity-mini", "label": "Trinity Mini (Lightweight)", "tokens": 4096},
    "4": {"name": "moonshotai/kimi-k2", "label": "Kimi K2 (Advanced)", "tokens": 8000},
    "5": {"name": "google/gemma-3-27b-it", "label": "Gemma 3 27B (Powerful)", "tokens": 8000},
    "6": {"name": "nvidia/nemotron-nano-12b-v2-vl", "label": "Nemotron (Efficient)", "tokens": 4096},
}

API_TIMEOUT = 180

# ─── DATABASE SETUP ──────────────────────────────────────────────

class Database:
    """Enhanced database for scans, reports, and history"""
    
    def __init__(self):
        self.db_file = DB_FILE
        self.init_db()
    
    def init_db(self):
        """Initialize database with tables"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Scans table
        cursor.execute("""CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            target TEXT,
            timestamp TEXT,
            model TEXT,
            commands_executed INTEGER,
            results TEXT
        )""")
        
        # Commands table
        cursor.execute("""CREATE TABLE IF NOT EXISTS commands (
            id TEXT PRIMARY KEY,
            scan_id TEXT,
            command TEXT,
            output TEXT,
            timestamp TEXT,
            exit_code INTEGER
        )""")
        
        # Vulnerabilities table
        cursor.execute("""CREATE TABLE IF NOT EXISTS vulnerabilities (
            id TEXT PRIMARY KEY,
            scan_id TEXT,
            target TEXT,
            name TEXT,
            severity TEXT,
            description TEXT,
            timestamp TEXT
        )""")
        
        # Reports table
        cursor.execute("""CREATE TABLE IF NOT EXISTS reports (
            id TEXT PRIMARY KEY,
            scan_id TEXT,
            target TEXT,
            report_path TEXT,
            timestamp TEXT,
            findings_count INTEGER
        )""")
        
        conn.commit()
        conn.close()
    
    def add_scan(self, target: str, model: str):
        """Log a new scan"""
        scan_id = hashlib.md5(f"{target}{datetime.now()}".encode()).hexdigest()[:12]
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?)",
                      (scan_id, target, datetime.now().isoformat(), model, 0, ""))
        conn.commit()
        conn.close()
        return scan_id
    
    def add_vulnerability(self, scan_id: str, target: str, name: str, severity: str, desc: str):
        """Log a vulnerability"""
        vuln_id = hashlib.md5(f"{scan_id}{name}".encode()).hexdigest()[:12]
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO vulnerabilities VALUES (?, ?, ?, ?, ?, ?, ?)",
                      (vuln_id, scan_id, target, name, severity, desc, datetime.now().isoformat()))
        conn.commit()
        conn.close()

# ─── API KEY MANAGEMENT ──────────────────────────────────────────

def get_api_key(force_new: bool = False) -> str:
    """Get API key with validation"""
    if not force_new:
        if os.getenv("OPENROUTER_API_KEY"):
            return os.getenv("OPENROUTER_API_KEY").strip()
        
        if API_KEY_FILE.exists():
            key = API_KEY_FILE.read_text().strip()
            if key:
                return key
    
    print("\n🔑 Enter OpenRouter API key (hidden):")
    key = getpass.getpass().strip()
    if key:
        API_KEY_FILE.write_text(key)
        API_KEY_FILE.chmod(0o600)
        print(f"✓ API key saved to {API_KEY_FILE}\n")
    return key

def select_model() -> tuple:
    """Select model with detailed info"""
    print("\n📊 Advanced Model Selection:\n")
    for key, model in MODELS.items():
        print(f"  [{key}] {model['label']}")
        print(f"      Max tokens: {model['tokens']}\n")
    
    choice = input("Select model [1-6] (default 2): ").strip()
    selected = MODELS.get(choice, MODELS["2"])
    print(f"\n✓ Using: {selected['label']}\n")
    return selected["name"], selected["label"]

def test_api(api_key: str, model: str) -> bool:
    """Test API with model"""
    print(f"🔍 Testing API with {model.split('/')[-1]}...")
    
    try:
        response = requests.post(
            API_URL,
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"model": model, "messages": [{"role": "user", "content": "test"}], 
                  "temperature": 0.5, "max_tokens": 10},
            timeout=30
        )
        
        if response.status_code == 200:
            print("✓ API key is valid!\n")
            return True
        else:
            print(f"✗ Error {response.status_code}\n")
            return False
    except Exception as e:
        print(f"✗ Connection error: {str(e)[:50]}\n")
        return False

# ─── ADVANCED COMMAND EXECUTION ──────────────────────────────────

class CommandExecutor:
    """Advanced command execution with logging and analysis"""
    
    def __init__(self, db: Database):
        self.db = db
        self.timeout = 120
    
    def execute(self, cmd: str, scan_id: str = None) -> Dict:
        """Execute command with detailed logging"""
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            output = {
                "command": cmd,
                "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip(),
                "exit_code": result.returncode,
                "status": "success" if result.returncode == 0 else "warning"
            }
            
            return output
        except subprocess.TimeoutExpired:
            return {"command": cmd, "stdout": "", "stderr": f"Timeout after {self.timeout}s", "exit_code": -1, "status": "error"}
        except Exception as e:
            return {"command": cmd, "stdout": "", "stderr": str(e), "exit_code": -1, "status": "error"}

# ─── LLM WITH ADVANCED FEATURES ──────────────────────────────────

def call_llm_advanced(api_key: str, prompt: str, model: str, context: str = "") -> Optional[str]:
    """Advanced LLM call with context and threat analysis"""
    
    hacking_keywords = ["scan", "port", "nmap", "exploit", "vulnerability", "hack", "security", 
                        "pentest", "osint", "dns", "ssl", "injection", "enum", "brute", "crack",
                        "payload", "shell", "backdoor", "malware", "network", "firewall",
                        "certificate", "subdomain", "directory", "http", "headers", "ip", "server",
                        "website", "web", "site", "domain", "target", "check", "test", "find",
                        "enumerate", "discover", "recon", "fingerprint", "identify", "detect", "threat"]
    
    is_hacking = any(keyword in prompt.lower() for keyword in hacking_keywords)
    
    if is_hacking:
        system_prompt = f"""You are DestroyGPT v6.0 - Enterprise AI Hacking Assistant
Created by Sujal Lamichhane | Advanced Penetration Testing Platform

Role: Advanced penetration tester with expertise in:
- Network reconnaissance & enumeration
- Vulnerability assessment & exploitation
- Threat analysis & reporting
- Security hardening

CRITICAL: For hacking/security questions:

COMMAND: <complete, executable command - NO PLACEHOLDERS>
EXPLANATION: <detailed what & why>
SEVERITY: <LOW/MEDIUM/HIGH/CRITICAL>
TIPS: <advanced techniques>
THREAT_ANALYSIS: <potential impact if exploited>

Examples:
User: scan network for vulnerabilities
COMMAND: nmap -sV -sC -O -p- --script=vuln 192.168.1.1
EXPLANATION: Comprehensive scan with service detection, default scripts, and vulnerability checking
SEVERITY: MEDIUM
TIPS: Use -T4 for speed, -A for aggressive detection, combine with nuclei for advanced scanning
THREAT_ANALYSIS: Identifies open services, weak configurations, and known CVEs that could be exploited

{context}

Always provide complete, production-ready commands. Use real IPs/domains, not placeholders."""
    else:
        system_prompt = """You are DestroyGPT v6.0 - Advanced AI Assistant
Be expert, concise, and practical."""
    
    try:
        response = requests.post(
            API_URL,
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"model": model, "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ], "temperature": 0.7, "max_tokens": 2000},
            timeout=API_TIMEOUT
        )
        
        if response.status_code == 200:
            return response.json()["choices"][0]["message"]["content"].strip()
        else:
            print(f"\n✗ API Error {response.status_code}\n")
            return None
    except Exception as e:
        print(f"\n✗ Error: {str(e)[:100]}\n")
        return None

# ─── ADVANCED REPORT GENERATION ──────────────────────────────────

def generate_report(scan_id: str, target: str, model: str, commands: List[Dict], vulns: List[Dict]) -> str:
    """Generate professional security report"""
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report = f"""
╔════════════════════════════════════════════════════════════════╗
║                  SECURITY ASSESSMENT REPORT                   ║
║                      DestroyGPT v6.0                          ║
╚════════════════════════════════════════════════════════════════╝

Target: {target}
Scan ID: {scan_id}
Timestamp: {timestamp}
Model: {model}
Author: Sujal Lamichhane

EXECUTIVE SUMMARY
─────────────────────────────────────────────────────────────────
Total Commands Executed: {len(commands)}
Vulnerabilities Found: {len(vulns)}

COMMANDS EXECUTED
─────────────────────────────────────────────────────────────────
"""
    
    for i, cmd in enumerate(commands, 1):
        report += f"\n[{i}] {cmd['command']}\nStatus: {cmd.get('status', 'unknown')}\n"
        if cmd['stdout']:
            report += f"Output: {cmd['stdout'][:500]}...\n"
    
    report += "\n\nVULNERABILITIES FOUND\n─────────────────────────────────────────────────────────────────\n"
    
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_vulns = sorted(vulns, key=lambda x: severity_order.get(x.get('severity', 'LOW'), 999))
    
    for vuln in sorted_vulns:
        report += f"\n[{vuln.get('severity', 'UNKNOWN')}] {vuln.get('name', 'Unknown')}\n"
        report += f"Description: {vuln.get('description', 'N/A')}\n"
    
    report += f"\n\nREPORT GENERATED: {timestamp}\nTool: DestroyGPT v6.0\nGitHub: sujallamichhane18/DestroyGPT\n"
    
    return report

# ─── MAIN INTERACTIVE LOOP ──────────────────────────────────────

def main():
    """Advanced interactive session"""
    
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-h", "--help", action="store_true")
    parser.add_argument("-k", "--key", action="store_true")
    args = parser.parse_args()
    
    if args.help:
        print("""
DestroyGPT v6.0 - Enterprise AI Hacking Assistant

Commands:
  exit, quit      Exit program
  help            Show help
  clear           Clear screen
  model           Switch model
  key             Update API key
  test            Test API
  report          Generate report
  scans           View scan history
  threats         Analyze threats
  
Ask anything:
  scan my network
  find vulnerabilities
  check ssl certificate
  enumerate subdomains

Author: Sujal Lamichhane
GitHub: sujallamichhane18/DestroyGPT
        """)
        return
    
    if args.key:
        get_api_key(force_new=True)
        return
    
    # Initialize
    api_key = get_api_key()
    if not api_key:
        print("✗ No API key")
        sys.exit(1)
    
    model, model_label = select_model()
    db = Database()
    executor = CommandExecutor(db)
    
    scan_id = db.add_scan("interactive", model_label)
    commands_log = []
    vulnerabilities = []
    
    # Banner
    print("╔════════════════════════════════════════════════════════════════╗")
    print("║              DestroyGPT v6.0 - Enterprise Edition              ║")
    print("║          Advanced AI Penetration Testing Platform               ║")
    print("║                                                                ║")
    print("║              Author: Sujal Lamichhane                          ║")
    print("║          GitHub: sujallamichhane18/DestroyGPT                 ║")
    print("╚════════════════════════════════════════════════════════════════╝\n")
    print(f"Model: {model_label}")
    print("Type 'help' for advanced commands\n")
    
    while True:
        try:
            prompt = input("$ ").strip()
            
            if not prompt:
                continue
            
            if prompt.lower() in ("exit", "quit"):
                print("\nGenerating final report...")
                break
            
            if prompt.lower() == "help":
                print("""
Commands:
  exit              Exit & generate report
  help              This help menu
  clear             Clear screen
  model             Switch model
  key               Update API key
  test              Test API
  report            Generate report
  scans             View history
  
Ask for hacking/security help!
                """)
                continue
            
            if prompt.lower() == "clear":
                os.system("clear" if os.name != "nt" else "cls")
                continue
            
            if prompt.lower() == "model":
                model, model_label = select_model()
                continue
            
            if prompt.lower() == "key":
                api_key = get_api_key(force_new=True)
                continue
            
            if prompt.lower() == "test":
                print()
                test_api(api_key, model)
                continue
            
            if prompt.lower() == "report":
                if commands_log or vulnerabilities:
                    report = generate_report(scan_id, "interactive-session", model_label, commands_log, vulnerabilities)
                    print("\n" + report)
                else:
                    print("\n✗ No data to report yet\n")
                continue
            
            # Get AI response
            print()
            response = call_llm_advanced(api_key, prompt, model)
            
            if not response:
                print("✗ Failed to get response\n")
                continue
            
            # Extract command
            if "COMMAND:" in response:
                lines = response.split('\n')
                command = ""
                severity = "MEDIUM"
                threat_analysis = ""
                
                for line in lines:
                    if line.startswith("COMMAND:"):
                        command = line.replace("COMMAND:", "").strip()
                    elif line.startswith("SEVERITY:"):
                        severity = line.replace("SEVERITY:", "").strip()
                    elif line.startswith("THREAT_ANALYSIS:"):
                        threat_analysis = line.replace("THREAT_ANALYSIS:", "").strip()
                
                if command:
                    # Check for placeholders
                    if "<" in command or ">" in command:
                        print(f"⚠️  Command needs parameters:\n  {command}\n")
                        command = input("Enter command: ").strip()
                        if not command:
                            print()
                            continue
                    
                    print(f"📋 Command:\n  {command}\n")
                    
                    # Show threat analysis
                    if threat_analysis:
                        print(f"🚨 Threat Analysis: {threat_analysis}\n")
                    
                    try:
                        execute = input("Execute? [y/N]: ").strip().lower()
                        if execute == 'y':
                            print(f"\n▶ Executing...\n")
                            result = executor.execute(command, scan_id)
                            commands_log.append(result)
                            print(result['stdout'])
                            if result['stderr']:
                                print(f"[Error] {result['stderr']}")
                            print()
                        else:
                            print()
                    except KeyboardInterrupt:
                        print("\n")
                else:
                    print(response)
                    print()
            else:
                print(response)
                print()
        
        except KeyboardInterrupt:
            print("\n")
            break
        except Exception as e:
            print(f"✗ Error: {e}\n")

if __name__ == "__main__":
    main()
