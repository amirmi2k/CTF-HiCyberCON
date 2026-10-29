#!/usr/bin/env python3
"""
CTF Quick-Start Helper
Run this first to verify your environment and API keys are set up.
"""
import sys
import io
import importlib
import os

# Force UTF-8 output on Windows
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

REQUIRED_PACKAGES = [
    "anthropic", "google.generativeai", "Crypto", "gmpy2",
    "sympy", "pwn", "requests", "aiohttp", "rich"
]

REQUIRED_ENV_VARS = [
    ("ANTHROPIC_API_KEY", "Claude/Sonnet models"),
    ("GOOGLE_API_KEY", "Gemini models"),
]

print("🚩 CTF AI Pipeline — Environment Check\n")

# Check Python version
if sys.version_info < (3, 11):
    print(f"❌ Python 3.11+ required (found {sys.version})")
    sys.exit(1)
print(f"✅ Python {sys.version.split()[0]}")

# Check packages
print("\nPackage Check:")
missing = []
for pkg in REQUIRED_PACKAGES:
    try:
        importlib.import_module(pkg.split(".")[0])
        print(f"  ✅ {pkg}")
    except ImportError:
        print(f"  ❌ {pkg} — run: pip install -r requirements.txt")
        missing.append(pkg)

# Check API keys
print("\nAPI Key Check:")
for var, desc in REQUIRED_ENV_VARS:
    val = os.environ.get(var, "")
    if val:
        print(f"  ✅ {var} ({desc}) — {'*' * (len(val) - 8)}{val[-4:]}")
    else:
        print(f"  ⚠️  {var} not set — {desc} will be unavailable")
        print(f"     Set with: set {var}=<your_key>  (Windows)")

# Check CTF tools
import subprocess
print("\nCTF Tool Check:")
CTF_TOOLS = ["nmap", "gobuster", "sqlmap", "ffuf", "binwalk", "exiftool",
             "strings", "steghide", "hashcat", "john"]
for tool in CTF_TOOLS:
    try:
        result = subprocess.run([tool, "--version"], capture_output=True, timeout=5)
        print(f"  ✅ {tool}")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        print(f"  ⚠️  {tool} not found (install via apt/brew/winget or WSL)")

print("\n" + "─" * 50)
if missing:
    print(f"Run: pip install -r requirements.txt")
else:
    print("✅ All Python packages OK!")
    print("\nQuick start:")
    print('  python pipeline/orchestrator.py --challenge "TestChallenge" --target "http://10.0.0.1" --category auto')
