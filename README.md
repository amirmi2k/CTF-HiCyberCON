# CTF-HiCyberCON

> **Autonomous Multi-Agent AI Pipeline for CTF Competitions**  
> Designed for **HI CyberCon CTF 2026** — Agentic AI Division.

---

## 📌 Overview

**CTF-HiCyberCON** is an advanced, parallel multi-agent AI pipeline designed to solve Capture The Flag (CTF) challenges autonomously and collaboratively. Built for the **Agentic AI Division** of HI CyberCon CTF 2026, the framework leverages specialized AI models and domain-specific skills to enumerate targets, identify vulnerabilities, execute exploits, and extract flags across diverse categories.

---

## 🚀 Key Features

- **Multi-Model Orchestration**: Concurrently runs multiple LLM backends (Anthropic Claude, Google Gemini, GonkaRouter DeepSeek/GLM/MiniMax) to hypothesize, cross-verify, and exploit targets.
- **10+ Specialized Agent Skills**: Modular skills equipped with domain knowledge, methodology, tools, and attack vectors.
- **Dynamic Category Routing**: Automatically classifies challenge targets or accepts direct category flags to dispatch appropriate specialist agents.
- **Automated Tool Integration**: Native command execution and tool wrappers for essential CTF utilities (`nmap`, `gobuster`, `sqlmap`, `pwntools`, `binwalk`, `steghide`, `exiftool`, `john`, `hashcat`).
- **Structured Findings & Flag Aggregation**: Real-time pattern matching for flag formats (`FLAG{...}`, `CTF{...}`, etc.) and structured JSON session logging.

---

## 🤖 Specialized Skills & Categories

| Skill | Category / Domain | Description & Capabilities |
|-------|-------------------|-----------------------------|
| `ctf-recon` | **Reconnaissance & OSINT** | Network enumeration, service discovery, port scanning, subdomains, and directory busting. |
| `ctf-web` | **Web Exploitation** | SQL injection, XSS, SSRF, SSTI, LFI/RFI, XXE, deserialization, IDOR, and OAuth/JWT flaws. |
| `ctf-pwn` | **Binary Exploitation** | Buffer overflows, ROP chains, format strings, heap exploitation, and ret2libc. |
| `ctf-crypto` | **Cryptography** | Classical ciphers, RSA attacks (Wiener, Hastad, factordb), AES flaws, and elliptic curves. |
| `ctf-forensics` | **Forensics & Stego** | Memory dumps, PCAP network captures, file carvings, metadata, and steganography. |
| `ctf-rev` | **Reverse Engineering** | Static & dynamic disassembly, Ghidra/radare2 integration, license check cracking. |
| `ctf-ai-llm` | **AI & LLM Security** | Prompt injection, jailbreaking, model extraction, memory leaks, and agent tool abuse. |
| `ctf-blockchain`| **Blockchain & Web3** | Smart contract analysis, reentrancy, flash loan attacks, and EVM exploitation. |
| `ctf-osint` | **OSINT & GeoINT** | Public intelligence gathering, geolocation, identity mapping, and social investigation. |
| `ctf-pipeline`| **Master Orchestrator** | Multi-agent coordination, findings synthesis, and parallel execution. |

---

## 📂 Project Structure

```text
CTF-HiCyberCON/
├── .agents/
│   ├── rules/
│   │   └── ctf-global.md          # Global agent rules & operational boundaries
│   └── skills/                    # Domain-specific skill modules
│       ├── ctf-ai-llm/
│       ├── ctf-blockchain/
│       ├── ctf-crypto/
│       ├── ctf-forensics/
│       ├── ctf-osint/
│       ├── ctf-pipeline/
│       ├── ctf-pwn/
│       ├── ctf-recon/
│       ├── ctf-rev/
│       └── ctf-web/
├── pipeline/
│   ├── orchestrator.py            # Primary multi-agent coordinator
│   └── tools/
│       └── tool_wrappers.py       # CTF tool execution wrappers
├── docs/                          # Documentation and challenge writeups
├── check_env.py                   # Environment verification script
├── test_api.py                    # Multi-model API connectivity check
├── requirements.txt               # Python dependencies
└── README.md                      # Project documentation
```

---

## ⚙️ Installation & Setup

### 1. Clone Repository & Setup Virtual Environment
```bash
git clone https://github.com/amirmi2k/CTF-HiCyberCON.git
cd CTF-HiCyberCON

# Create and activate virtual environment
python -m venv venv
# Linux / macOS:
source venv/bin/activate
# Windows:
venv\Scripts\activate
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Environment Variables
Create a `.env` file in the project root:
```env
# Multi-Model API Keys
GONKAROUTER_API_KEY=your_gonkarouter_api_key_here
ANTHROPIC_API_KEY=your_anthropic_api_key_here
GOOGLE_API_KEY=your_gemini_api_key_here
```

### 4. Verify Environment
Run the built-in diagnostic scripts to ensure your dependencies and API endpoints are working:
```bash
# Check Python version, libraries, and external tools
python check_env.py

# Test LLM API connectivity
python test_api.py
```

---

## 🎮 Usage

### Automatic Category Detection
Run the pipeline in auto mode against a target or challenge:
```bash
python pipeline/orchestrator.py --challenge "MysteryBox" --target "http://10.10.10.50" --category auto
```

### Category-Specific Solvers
```bash
# Web application challenge
python pipeline/orchestrator.py --challenge "SecureLogin" --target "http://10.10.10.50/admin" --category web

# Binary exploitation
python pipeline/orchestrator.py --challenge "OverFlow1" --target "./vuln_binary" --category pwn

# Cryptographic puzzle
python pipeline/orchestrator.py --challenge "RSA-Oracle" --target "./cipher.txt" --category crypto

# Memory or disk forensics
python pipeline/orchestrator.py --challenge "DumpAnalysis" --target "./memory.raw" --category forensics

# AI / Prompt injection challenge
python pipeline/orchestrator.py --challenge "AIBot" --target "http://10.10.10.50:8000/chat" --category ai
```

---

## 🛡️ Responsible Use & Ethics

This framework is built strictly for **Capture The Flag (CTF) competitions**, academic research, and authorized educational security testing. Users must ensure they have explicit authorization before scanning, testing, or attacking any target.
