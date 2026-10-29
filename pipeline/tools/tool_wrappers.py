#!/usr/bin/env python3
"""
CTF AI Pipeline — Tool Wrappers
Thin Python wrappers around common CTF tools, returning structured JSON.
"""
import asyncio
import json
import subprocess
import tempfile
from pathlib import Path
from dataclasses import dataclass


@dataclass
class ToolResult:
    tool: str
    success: bool
    stdout: str
    stderr: str
    parsed: dict

    def to_dict(self):
        return {"tool": self.tool, "success": self.success,
                "parsed": self.parsed, "stdout": self.stdout[:2000]}


async def run_cmd(cmd: list[str], timeout: int = 60) -> tuple[str, str, int]:
    """Run a system command asynchronously."""
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return stdout.decode(errors="replace"), stderr.decode(errors="replace"), proc.returncode
    except asyncio.TimeoutError:
        proc.kill()
        return "", "TIMEOUT", -1


# ─── Recon Tools ─────────────────────────────────────────────────────────────

async def nmap_scan(target: str, ports: str = "top1000", flags: list[str] | None = None) -> ToolResult:
    """Run nmap and return structured results."""
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
        xml_path = f.name

    cmd = ["nmap", "-sV", "-sC", f"-{ports}", "-oX", xml_path, target]
    if flags:
        cmd.extend(flags)

    stdout, stderr, rc = await run_cmd(cmd, timeout=120)
    parsed = {"ports": [], "os_guess": ""}

    # Parse nmap XML (simplified)
    import xml.etree.ElementTree as ET
    try:
        tree = ET.parse(xml_path)
        for port in tree.findall(".//port"):
            state = port.find("state")
            service = port.find("service")
            if state is not None and state.get("state") == "open":
                parsed["ports"].append({
                    "port": port.get("portid"),
                    "protocol": port.get("protocol"),
                    "service": service.get("name") if service is not None else "unknown",
                    "version": service.get("version", "") if service is not None else "",
                })
    except Exception:
        pass

    return ToolResult("nmap", rc == 0, stdout, stderr, parsed)


async def gobuster_dir(url: str, wordlist: str = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
                       extensions: str = "php,html,txt,js") -> ToolResult:
    """Run gobuster dir and return discovered paths."""
    cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-x", extensions, "--no-error", "-q"]
    stdout, stderr, rc = await run_cmd(cmd, timeout=180)
    paths = [line.split()[0] for line in stdout.splitlines() if line.startswith("/")]
    return ToolResult("gobuster", rc == 0, stdout, stderr, {"paths": paths})


async def whatweb(url: str) -> ToolResult:
    """Fingerprint web technologies."""
    stdout, stderr, rc = await run_cmd(["whatweb", "--log-json", "-", url], timeout=30)
    try:
        parsed = json.loads(stdout)
    except Exception:
        parsed = {"raw": stdout[:500]}
    return ToolResult("whatweb", rc == 0, stdout, stderr, parsed)


# ─── Web Tools ────────────────────────────────────────────────────────────────

async def sqlmap_test(url: str, data: str | None = None, level: int = 3) -> ToolResult:
    """Test for SQL injection with sqlmap."""
    cmd = ["sqlmap", "-u", url, "--batch", "--dbs", f"--level={level}", "--risk=2", "--output-dir=/tmp/sqlmap"]
    if data:
        cmd.extend(["--data", data])
    stdout, stderr, rc = await run_cmd(cmd, timeout=300)
    dbs = [l.split("[*]")[-1].strip() for l in stdout.splitlines() if "[*]" in l and "available" not in l]
    return ToolResult("sqlmap", rc == 0, stdout, stderr, {"databases": dbs, "injectable": len(dbs) > 0})


async def ffuf_fuzz(url: str, wordlist: str, fuzz_keyword: str = "FUZZ",
                    match_codes: str = "200,301,302,403") -> ToolResult:
    """Fast web fuzzer."""
    target_url = url.replace("FUZZ", fuzz_keyword) if "FUZZ" in url else f"{url}/FUZZ"
    cmd = ["ffuf", "-u", target_url, "-w", wordlist, "-mc", match_codes, "-o", "/tmp/ffuf_out.json", "-of", "json"]
    stdout, stderr, rc = await run_cmd(cmd, timeout=120)
    try:
        results = json.loads(Path("/tmp/ffuf_out.json").read_text())
        hits = [r["url"] for r in results.get("results", [])]
    except Exception:
        hits = []
    return ToolResult("ffuf", rc == 0, stdout, stderr, {"hits": hits})


# ─── Crypto Tools ─────────────────────────────────────────────────────────────

def crack_xor_single_byte(ciphertext_hex: str) -> dict:
    """Brute-force single-byte XOR and find printable result."""
    ct = bytes.fromhex(ciphertext_hex)
    results = []
    for key in range(256):
        plain = bytes(b ^ key for b in ct)
        printable_ratio = sum(32 <= b < 127 for b in plain) / len(plain)
        if printable_ratio > 0.85:
            results.append({"key": key, "plain": plain.decode(errors="replace"), "score": printable_ratio})
    return {"candidates": sorted(results, key=lambda x: -x["score"])[:5]}


def base_decode_chain(data: str) -> dict:
    """Try common encodings on data."""
    import base64
    results = {}
    encodings = {
        "base64": lambda x: base64.b64decode(x + "==").decode(errors="replace"),
        "base32": lambda x: base64.b32decode(x + "=" * (8 - len(x) % 8) % 8).decode(errors="replace"),
        "hex":    lambda x: bytes.fromhex(x).decode(errors="replace"),
        "rot13":  lambda x: x.translate(str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
        )),
    }
    for name, fn in encodings.items():
        try:
            results[name] = fn(data.strip())
        except Exception as e:
            results[name] = f"ERROR: {e}"
    return results


# ─── Forensics Tools ──────────────────────────────────────────────────────────

async def binwalk_extract(filepath: str) -> ToolResult:
    """Extract embedded files with binwalk."""
    out_dir = f"/tmp/binwalk_{Path(filepath).stem}"
    stdout, stderr, rc = await run_cmd(["binwalk", "-e", "--directory", out_dir, filepath], timeout=60)
    extracted = list(Path(out_dir).rglob("*")) if Path(out_dir).exists() else []
    return ToolResult("binwalk", rc == 0, stdout, stderr,
                      {"extracted_files": [str(f) for f in extracted if f.is_file()]})


async def exiftool_meta(filepath: str) -> ToolResult:
    """Extract metadata with exiftool."""
    stdout, stderr, rc = await run_cmd(["exiftool", "-json", filepath], timeout=30)
    try:
        parsed = json.loads(stdout)[0]
    except Exception:
        parsed = {"raw": stdout[:500]}
    return ToolResult("exiftool", rc == 0, stdout, stderr, parsed)


async def strings_search(filepath: str, min_len: int = 8, grep_pattern: str = "flag") -> ToolResult:
    """Extract strings and search for flags."""
    stdout, stderr, rc = await run_cmd(["strings", f"-n{min_len}", filepath], timeout=30)
    matches = [l for l in stdout.splitlines() if grep_pattern.lower() in l.lower()]
    return ToolResult("strings", rc == 0, stdout[:5000], stderr,
                      {"flag_strings": matches, "total_strings": stdout.count("\n")})


if __name__ == "__main__":
    # Quick self-test
    print(crack_xor_single_byte("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))
    print(base_decode_chain("SGVsbG8gV29ybGQ="))
