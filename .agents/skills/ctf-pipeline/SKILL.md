---
name: ctf-pipeline
description: >-
  Activate this skill when the user wants to run the full CTF multi-model AI
  pipeline, orchestrate multiple specialist agents in parallel, aggregate
  findings from all specialist skills, or when the challenge category is unknown.
  This is the entry point that coordinates ctf-recon, ctf-web, ctf-pwn,
  ctf-crypto, ctf-forensics, and ctf-rev agents.
---

# CTF Multi-Model AI Pipeline Orchestrator

## Architecture Overview

```
User Challenge Input
        │
        ▼
┌──────────────────┐
│  ORCHESTRATOR    │  ← Triage + Route
│  (this skill)    │
└────────┬─────────┘
         │ spawns parallel agents
    ┌────┴────────────────────────────────┐
    │         │          │        │       │
    ▼         ▼          ▼        ▼       ▼
 ctf-recon  ctf-web   ctf-pwn  ctf-crypto ctf-forensics
              │                            │
              ▼                            ▼
           ctf-rev    ← cross-feeds ────────
              │
              ▼
    ┌─────────────────┐
    │  AGGREGATOR     │  ← Merge findings, rank flags
    └─────────────────┘
              │
              ▼
         FINAL FLAG
```

## Pipeline Execution Steps

### Step 1 — Challenge Intake
Collect from the user:
- Challenge name and category (if known)
- Target IP/URL/file(s)
- Flag format (e.g., `FLAG{...}`)
- Time remaining
- Hints already unlocked

### Step 2 — Parallel Triage (run ALL simultaneously)
```python
# See pipeline/orchestrator.py for full implementation
agents_to_run = ["ctf-recon"]  # always run recon

# Category routing
if category in ["web", "unknown"]: agents_to_run.append("ctf-web")
if category in ["pwn", "binary", "unknown"]: agents_to_run.append("ctf-pwn")
if category in ["crypto", "unknown"]: agents_to_run.append("ctf-crypto")
if category in ["forensics", "misc", "stego", "unknown"]: agents_to_run.append("ctf-forensics")
if category in ["rev", "reversing", "unknown"]: agents_to_run.append("ctf-rev")
```

### Step 3 — Cross-Feed Intelligence
After each agent completes Phase 1:
- Recon findings → feed into all exploitation agents
- Web discoveries (hidden endpoints) → feed into pwn if services found
- Crypto artifacts in forensics → feed into crypto agent
- Binary in web response → feed into rev/pwn

### Step 4 — Aggregation & Ranking
```python
# See pipeline/aggregator.py
all_findings = collect_all_agent_outputs()
flag_candidates = rank_by_confidence(all_findings["flag_candidates"])
if flag_candidates[0]["confidence"] > 0.9:
    return flag_candidates[0]["value"]
else:
    # Request deeper analysis from highest-confidence agent
    escalate(flag_candidates[0]["agent"])
```

### Step 5 — Flag Validation
```python
import re
FLAG_PATTERNS = [
    r'FLAG\{[^}]+\}',
    r'CTF\{[^}]+\}',
    r'picoCTF\{[^}]+\}',
    r'HTB\{[^}]+\}',
    r'flag\{[^}]+\}',
    # Add custom pattern at challenge start
]
```

## Model Assignment Strategy

| Agent | Recommended Model | Reasoning |
|-------|------------------|-----------|
| Orchestrator | Claude Sonnet (Thinking) | Complex routing decisions |
| ctf-recon | Flash/Gemini Pro | Fast, broad enumeration |
| ctf-web | Claude Sonnet | Nuanced vuln identification |
| ctf-pwn | Claude/Gemini Pro | Deep binary reasoning |
| ctf-crypto | Gemini Pro (math) | Math-heavy tasks |
| ctf-forensics | Flash | Pattern matching |
| ctf-rev | Claude Sonnet | Code understanding |
| Aggregator | Claude Sonnet (Thinking) | Critical synthesis |

## Resilience Features
1. **Model Redundancy**: If one model fails → fallback to next in list
2. **Timeout Handling**: 5-min timeout per phase → continue with partial results
3. **Cross-Validation**: Two agents independently validate candidate flags
4. **Confidence Scoring**: All outputs ranked 0.0–1.0; threshold 0.85 to submit

## Run the Pipeline
```bash
python pipeline/orchestrator.py --challenge "challenge_name" --target "<IP_or_URL_or_file>" --category auto
```

## References
- [Pipeline Code](../../pipeline/orchestrator.py)
- [Agent Configs](../../pipeline/configs/)
- [Tool Registry](../../pipeline/tools/)
