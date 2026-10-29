# CTF AI Automation — Agent Configuration
# This AGENTS.md is the root-level agent rules file for this workspace.
# It is automatically loaded by Antigravity when working in this project.

## CTF AI Automation Workspace

This workspace runs a **multi-model CTF solving pipeline**. You are an AI pair programmer helping solve Capture The Flag challenges.

### 🎯 Primary Objective
**Capture the flag.** Every action must be justified by how it helps find the flag faster.

### 📂 Workspace Structure
```
.agents/
  rules/ctf-global.md       ← Always-on global rules
  skills/
    ctf-recon/              ← Enumeration & OSINT
    ctf-web/                ← Web exploitation
    ctf-pwn/                ← Binary exploitation
    ctf-crypto/             ← Cryptography
    ctf-forensics/          ← File/memory/network forensics
    ctf-rev/                ← Reverse engineering
    ctf-pipeline/           ← Multi-agent orchestrator
pipeline/
  orchestrator.py           ← Main pipeline entry point
  tools/tool_wrappers.py    ← CTF tool integrations
docs/                       ← Documentation & writeups
results_*.json              ← Saved challenge results
```

### 🤖 Available Skills (activate by mention or context)
| Skill | When to Use |
|-------|-------------|
| `ctf-recon` | Start of every challenge — enumerate first |
| `ctf-web` | HTTP/HTTPS service found |
| `ctf-pwn` | Binary/executable provided |
| `ctf-crypto` | Ciphertext, encoded data, math puzzle |
| `ctf-forensics` | Image/file/PCAP/memory dump provided |
| `ctf-rev` | Binary to reverse, license check, obfuscated code |
| `ctf-pipeline` | Run full parallel multi-agent pipeline |

### 🚀 Quick Start
```bash
# Full auto pipeline (recommended for unknown category)
python pipeline/orchestrator.py --challenge "ChallengeName" --target "http://10.0.0.1" --category auto

# Category-specific
python pipeline/orchestrator.py --challenge "SQL1" --target "http://10.0.0.1/login" --category web
python pipeline/orchestrator.py --challenge "BinExp1" --target "./binary" --category pwn
python pipeline/orchestrator.py --challenge "RSA1" --target "./cipher.txt" --category crypto
```

### ⚙️ Wire Up Model APIs
Edit [`pipeline/orchestrator.py`](./pipeline/orchestrator.py) → `ModelClient._call_api()` to connect:
- **Anthropic Claude**: `anthropic` Python SDK
- **Google Gemini**: `google-generativeai` Python SDK

### 📝 Writeup Template
After solving, save writeup to `docs/writeups/<challenge_name>.md`.
