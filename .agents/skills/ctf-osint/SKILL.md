---
name: ctf-osint
description: >-
  Activate this skill when a CTF challenge involves OSINT (open-source
  intelligence), social media investigation, domain/IP research, metadata
  analysis, geolocation from images, or any intelligence-gathering from
  publicly available sources. HI CyberCon CTF 2026 has an OSINT category.
---

# CTF OSINT Skill

## Phase 1 — Challenge Triage
Identify what you've been given:
- **Username** → social media pivot
- **Email** → domain lookup, breach databases
- **Domain/IP** → WHOIS, Shodan, passive DNS
- **Image** → EXIF, reverse image search, geolocation
- **Name** → LinkedIn, GitHub, social media
- **File** → metadata, hidden strings, creation dates

## Phase 2 — Person / Username OSINT
```bash
# Username enumeration
sherlock <username>          # checks 300+ sites
maigret <username>           # deeper than sherlock

# Email → identity
holehe <email>               # check email registration
h8mail -t <email>            # breach lookup

# Social platforms (manual + automated)
# Twitter/X: site:twitter.com "<target>"
# LinkedIn: site:linkedin.com/in/ "<name>"
# GitHub: https://github.com/<username>
# Instagram, Reddit, TikTok, Telegram
```

## Phase 3 — Domain / IP Intelligence
```bash
# WHOIS
whois <domain>
whois <ip>

# DNS enumeration
dig <domain> ANY
dig <domain> TXT   # TXT records often hide data
nslookup -type=TXT <domain>
subfinder -d <domain>
amass enum -passive -d <domain>

# Passive recon (no direct contact)
# Shodan: https://www.shodan.io/search?query=<ip>
# Censys: https://search.censys.io/
# Netlas: https://app.netlas.io/      ← HI CyberCon sponsor!
# Criminal IP: https://www.criminalip.io/

# Wayback Machine / historical content
waybackurls <domain>
# Or manually: https://web.archive.org/web/*/<domain>/*
```

## Phase 4 — Image OSINT / Geolocation
```bash
# Extract metadata
exiftool <image>
# Look for: GPS coords, device make, timestamps, software

# Reverse image search
# Google Images → drag & drop
# TinEye: https://tineye.com/
# Yandex Images (best for real-world locations)
# Bing Visual Search

# Geolocation from image content
# Look for: signage, license plates, building style, vegetation, shadows (sun angle)
# Google Street View + Maps to confirm
# GeoGuessr trained eye: phone poles, road markings, car driving side
```

## Phase 5 — GitHub / Code OSINT
```bash
# Search GitHub for sensitive info
# https://github.com/search?q=<target>&type=code

# Find commits with secrets
git log --all --oneline
git diff <old_commit> <new_commit>

# GitHub dork patterns
"<target>" filename:.env
"<target>" password
"<target>" api_key
"<target>" secret

# truffleHog for secret scanning
trufflehog git https://github.com/<user>/<repo>
```

## Phase 6 — Metadata & Document OSINT
```bash
# Office/PDF metadata
exiftool <file.pdf>
exiftool <file.docx>
# Look for: author name, company, creation date, revision history

# Cached versions
# Google: cache:<url>
# Bing: cache:<url>
```

## Useful OSINT Frameworks
- **Maltego** — graphical link analysis
- **SpiderFoot** — automated OSINT
- **theHarvester** — email/domain gathering
- **Recon-ng** — modular framework

## OSINT Databases
- `https://haveibeenpwned.com/` — breach check
- `https://dehashed.com/` — credential search
- `https://hunter.io/` — email discovery
- `https://intelx.io/` — data search engine
- `https://builtwith.com/` — tech stack

## Structured Output
```json
{
  "agent": "ctf-osint",
  "target_type": "username|email|domain|image|person",
  "intel_gathered": {},
  "pivot_points": [],
  "flag_candidates": [],
  "confidence": 0.0
}
```
