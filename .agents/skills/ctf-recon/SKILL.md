---
name: ctf-recon
description: >-
  Activate this skill when starting a CTF challenge or when the user asks to
  enumerate, scan, fingerprint, or gather information about a target. Covers
  port scanning, service detection, OS fingerprinting, directory busting, DNS
  enumeration, and OSINT. Use as the first step before any exploitation attempt.
---

# CTF Reconnaissance Skill

## Purpose
Systematically enumerate a target to discover all attack surfaces before exploitation. Good recon = good flags.

## Phase 1 — Network Discovery
```bash
# Quick TCP scan
nmap -sV -sC -T4 -oN nmap_initial.txt <TARGET_IP>

# Full port scan (background)
nmap -p- -T4 --min-rate 5000 -oN nmap_full.txt <TARGET_IP>

# UDP top ports
nmap -sU --top-ports 100 -T4 -oN nmap_udp.txt <TARGET_IP>
```

## Phase 2 — Web Enumeration (if HTTP found)
```bash
# Directory busting
gobuster dir -u http://<TARGET_IP> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o gobuster.txt -x php,html,txt,js,json

# Subdomain enum
gobuster dns -d <DOMAIN> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Tech fingerprinting
whatweb http://<TARGET_IP>
nikto -h http://<TARGET_IP> -o nikto.txt
```

## Phase 3 — Service-Specific Enum
```bash
# SMB
enum4linux -a <TARGET_IP>
smbclient -L //<TARGET_IP>/ -N

# FTP
ftp <TARGET_IP>  # try anonymous login

# SSH
ssh-audit <TARGET_IP>

# SNMP
snmpwalk -v2c -c public <TARGET_IP>
```

## Phase 4 — OSINT (web/crypto/misc challenges)
- Check challenge description for hidden clues (author names, URLs, hex strings)
- Google challenge title + CTF name
- Check GitHub, Pastebin, Wayback Machine
- Inspect image metadata: `exiftool <file>`
- Check file headers: `file <file>` and `xxd <file> | head`

## Structured Output
After recon, emit:
```json
{
  "agent": "ctf-recon",
  "open_ports": [],
  "services": {},
  "web_paths": [],
  "interesting_files": [],
  "attack_vectors": [],
  "flag_candidates": [],
  "recommended_next_skills": ["ctf-web", "ctf-pwn", "ctf-crypto", "ctf-rev", "ctf-forensics"]
}
```

## References
- [Full Tool Reference](./references/tools.md)
- [Wordlists Guide](./references/wordlists.md)
