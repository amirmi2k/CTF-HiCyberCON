#!/usr/bin/env python3
"""
test_pipeline.py — HI CyberCon CTF 2026 Pre-Competition Test Suite
===================================================================
Tests every agent/skill with realistic mock challenge inputs.
Run this BEFORE the competition to verify the full system works.

Usage:
    python test_pipeline.py               # run all tests
    python test_pipeline.py --category web
    python test_pipeline.py --category ai
    python test_pipeline.py --quick       # API ping only (fastest)
    python test_pipeline.py --list        # show all test cases
"""

import io
import sys
import asyncio
import argparse
import json
import time
from pathlib import Path
from dataclasses import dataclass

# ── Windows UTF-8 fix ─────────────────────────────────────────────────────────
if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "buffer"):
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# ── Path setup ────────────────────────────────────────────────────────────────
ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

# ── Colours ───────────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def ok(msg):    print(f"  {GREEN}[PASS]{RESET} {msg}")
def fail(msg):  print(f"  {RED}[FAIL]{RESET} {msg}")
def warn(msg):  print(f"  {YELLOW}[WARN]{RESET} {msg}")
def info(msg):  print(f"  {CYAN}[INFO]{RESET} {msg}")
def header(msg):print(f"\n{BOLD}{CYAN}{'='*60}{RESET}\n{BOLD}  {msg}{RESET}\n{BOLD}{CYAN}{'='*60}{RESET}")
def section(msg):print(f"\n{BOLD}── {msg} ──{RESET}")


# ── Mock challenge definitions ─────────────────────────────────────────────────
# Each test gives the agent a realistic challenge description.
# The agent won't solve it (no real target), but it WILL produce
# a structured analysis — verifying the skill is loaded and the
# model API responds correctly.

MOCK_CHALLENGES = [
    {
        "category": "web",
        "name":     "LoginBypass",
        "target":   "http://mock-ctf.local/login",
        "prompt":   (
            "Challenge: LoginBypass\n"
            "A login page at /login accepts username and password.\n"
            "Source hint: SELECT * FROM users WHERE username='[INPUT]'\n"
            "Find the flag hidden behind authentication."
        ),
        # Broad OR-style: any 2 of these phrases count as a pass
        "expect_keywords": ["sql injection", "sqlmap", "login bypass", "' or", "union select"],
    },
    {
        "category": "crypto",
        "name":     "WeakRSA",
        "target":   "ciphertext.txt",
        "prompt":   (
            "Challenge: WeakRSA\n"
            "You are given RSA parameters:\n"
            "  n = 77  (p=7, q=11)\n"
            "  e = 13\n"
            "  ciphertext = 20\n"
            "Decrypt the message. Flag format: FLAG{<plaintext>}\n"
            "Show your working step by step."
        ),
        # Match terms that appear in the FIRST few lines of any RSA walkthrough:
        # "rsa", "cipher", "phi"/"φ", "mod", "euclidean" all appear before max_tokens cutoff
        "expect_keywords": ["rsa", "cipher", "phi", "mod", "euclidean"],
    },
    {
        "category": "forensics",
        "name":     "HiddenInPNG",
        "target":   "suspicious.png",
        "prompt":   (
            "Challenge: HiddenInPNG\n"
            "A PNG file has been provided. The flag is hidden inside.\n"
            "Hints: check file magic bytes, EXIF metadata, LSB steganography,\n"
            "appended data after IEND chunk, and strings output."
        ),
        "expect_keywords": ["exiftool", "strings", "steganograph", "lsb", "metadata"],
    },
    {
        "category": "ai",
        "name":     "JailbreakBot",
        "target":   "http://mock-ctf.local/ai-chat",
        "prompt":   (
            "Challenge: JailbreakBot\n"
            "There is an AI chatbot at /ai-chat. Its system prompt contains the flag.\n"
            "The bot refuses to reveal its instructions directly.\n"
            "Extract the flag using prompt injection or jailbreak techniques.\n"
            "The bot appears to be a customer support assistant."
        ),
        "expect_keywords": ["prompt injection", "system prompt", "jailbreak", "ignore", "instruction"],
    },
    {
        "category": "osint",
        "name":     "FindTheDev",
        "target":   "username: h4ck3r_joe",
        "prompt":   (
            "Challenge: FindTheDev\n"
            "The username 'h4ck3r_joe' is linked to this CTF challenge.\n"
            "Find their real identity, GitHub account, or any accounts\n"
            "that reveal the flag. The flag may be in a commit, a bio,\n"
            "a tweet, or a public paste."
        ),
        "expect_keywords": ["github", "username", "profile", "social", "search"],
    },
    {
        "category": "pwn",
        "name":     "BufferBomb",
        "target":   "./vulnerable_binary",
        "prompt":   (
            "Challenge: BufferBomb\n"
            "A 32-bit ELF binary is provided. Running it asks for input.\n"
            "Disassembly shows:\n"
            "  char buf[64];\n"
            "  gets(buf);   // <-- no bounds check\n"
            "  if (authenticated) { system('/bin/sh'); }\n"
            "Overflow the buffer to set authenticated=1 and get a shell."
        ),
        "expect_keywords": ["overflow", "gets", "payload", "offset", "shell"],
    },
    {
        "category": "rev",
        "name":     "CrackMe",
        "target":   "./crackme",
        "prompt":   (
            "Challenge: CrackMe\n"
            "A binary asks for a password. Wrong input prints 'Access Denied'.\n"
            "Strings output shows: 's3cr3t_k3y_2026'\n"
            "IDA pseudo-code:\n"
            "  if strcmp(input, xor_decode(encoded_pass)) == 0:\n"
            "      print_flag()\n"
            "Find the correct password or patch the binary."
        ),
        "expect_keywords": ["strcmp", "xor", "strings", "patch", "disassembl"],
    },
    {
        "category": "blockchain",
        "name":     "VaultBreaker",
        "target":   "0xDEAD...BEEF (Sepolia testnet)",
        "prompt":   (
            "Challenge: VaultBreaker\n"
            "A Solidity contract on Sepolia testnet stores the flag.\n"
            "Contract snippet:\n"
            "  uint256 public balance;\n"
            "  function withdraw(uint amount) external {\n"
            "      require(balance >= amount);\n"
            "      (bool ok,) = msg.sender.call{value: amount}(\"\");\n"
            "      balance -= amount;   // state update AFTER external call!\n"
            "  }\n"
            "Exploit the vulnerability to drain the contract and reveal the flag."
        ),
        "expect_keywords": ["reentrancy", "fallback", "external call", "exploit", "solidity"],
    },
    {
        "category": "network",
        "name":     "PacketSniffer",
        "target":   "capture.pcap",
        "prompt":   (
            "Challenge: PacketSniffer\n"
            "A PCAP file contains network traffic from a compromised machine.\n"
            "Find the flag exfiltrated in DNS queries, HTTP headers,\n"
            "or encoded in packet timing. Tools: Wireshark, tshark, scapy."
        ),
        "expect_keywords": ["wireshark", "tshark", "dns", "http", "packet"],
    },
    {
        "category": "stego",
        "name":     "InvisibleInk",
        "target":   "image.jpg",
        "prompt":   (
            "Challenge: InvisibleInk\n"
            "A JPEG image is provided. The flag is hidden using steganography.\n"
            "Try: steghide, zsteg, stegsolve, LSB analysis, colour channel\n"
            "manipulation. Password hint: 'ctf2026'"
        ),
        "expect_keywords": ["steghide", "lsb", "stegsolve", "steganograph", "hidden"],
    },
    {
        "category": "misc",
        "name":     "WildCard",
        "target":   "challenge_files.zip",
        "prompt":   (
            "Challenge: WildCard — Miscellaneous\n"
            "A ZIP file contains: data.bin, notes.txt, image.bmp\n"
            "notes.txt says: 'The answer is where you least expect it.'\n"
            "data.bin has unknown format. image.bmp looks normal.\n"
            "Find the flag using any technique."
        ),
        "expect_keywords": ["strings", "hex", "binwalk", "file", "extract"],
    },
]


# ── Test runner ───────────────────────────────────────────────────────────────
@dataclass
class TestResult:
    name: str
    category: str
    model: str
    passed: bool
    response_chars: int
    elapsed_s: float
    keywords_found: list
    keywords_missing: list
    error: str = ""
    raw_response: str = ""   # first 400 chars of model output for debug


async def run_one_test(challenge: dict, api_key: str, stagger_s: float = 0.0) -> TestResult:
    """Call the assigned model for this category and validate the response.
    stagger_s: seconds to sleep before sending (avoids 429 on parallel launch).
    Auto-retries once on 429 with a 10-second back-off.
    """
    import httpx

    MODELS = {
        "web":        "deepseek-ai/DeepSeek-V4-Flash-0731",
        "crypto":     "zai-org/GLM-5.3-Flash",            # GLM faster on math prompts
        "forensics":  "zai-org/GLM-5.3-Flash",
        "stego":      "zai-org/GLM-5.3-Flash",
        "network":    "zai-org/GLM-5.3-Flash",
        "ai":         "MiniMaxAI/MiniMax-M2.7",
        "osint":      "deepseek-ai/DeepSeek-V4-Flash-0731",
        "pwn":        "MiniMaxAI/MiniMax-M2.7",
        "rev":        "MiniMaxAI/MiniMax-M2.7",
        "blockchain": "deepseek-ai/DeepSeek-V4-Flash-0731",
        "misc":       "zai-org/GLM-5.3-Flash",
        "hardware":   "MiniMaxAI/MiniMax-M2.7",
    }
    model = MODELS.get(challenge["category"], "zai-org/GLM-5.3-Flash")

    # Stagger launch to avoid concurrent 429s
    if stagger_s:
        await asyncio.sleep(stagger_s)

    # Load skill context for this agent
    skill_path = ROOT / ".agents" / "skills" / f"ctf-{challenge['category']}" / "SKILL.md"
    if not skill_path.exists():
        skill_path = ROOT / ".agents" / "skills" / "ctf-forensics" / "SKILL.md"
    skill_text = skill_path.read_text(encoding="utf-8") if skill_path.exists() else ""

    system_prompt = (
        f"You are a CTF specialist for the '{challenge['category']}' category "
        f"competing in HI CyberCon CTF 2026 (Agentic AI Division).\n\n"
        f"{'--- SKILL GUIDE ---' + chr(10) + skill_text[:2000] if skill_text else ''}\n\n"
        "Analyse the challenge and produce a structured plan with:\n"
        "1. Most likely vulnerability / technique\n"
        "2. Exact tools/commands to run\n"
        "3. Step-by-step exploitation plan\n"
        "4. What the flag might look like\n"
        "Keep your response focused and technical."
    )

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": challenge["prompt"]},
        ],
        "max_tokens": 800,
        "temperature": 0.2,
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type":  "application/json",
    }

    t0 = time.time()
    last_error = ""
    for attempt in range(3):  # up to 3 attempts (0, 1, 2)
        try:
            async with httpx.AsyncClient(timeout=90) as client:
                resp = await client.post(
                    "https://api.gonkarouter.io/v1/chat/completions",
                    headers=headers,
                    json=payload,
                )
            if resp.status_code == 429:
                wait = 12 * (attempt + 1)
                last_error = f"429 Rate limited (attempt {attempt+1}) — retrying in {wait}s"
                await asyncio.sleep(wait)
                continue
            resp.raise_for_status()
            msg = resp.json()["choices"][0]["message"]
            # Some models (DeepSeek-R1, GLM thinking variants) return
            # content="" with reasoning="…" — fall back to reasoning if needed
            content = msg.get("content") or msg.get("reasoning") or ""
            elapsed = time.time() - t0

            # Keyword check (substring, case-insensitive)
            content_lower = content.lower()
            found   = [k for k in challenge["expect_keywords"] if k.lower() in content_lower]
            missing = [k for k in challenge["expect_keywords"] if k.lower() not in content_lower]
            # Pass if ≥ half the keywords are found
            passed  = len(found) >= max(1, len(challenge["expect_keywords"]) // 2)

            return TestResult(
                name=challenge["name"], category=challenge["category"],
                model=model, passed=passed,
                response_chars=len(content), elapsed_s=round(elapsed, 1),
                keywords_found=found, keywords_missing=missing,
                raw_response=content[:600],  # save first 600 chars for debug
            )

        except Exception as e:
            last_error = str(e)
            if "429" not in str(e):
                break  # non-rate-limit error — don't retry
            await asyncio.sleep(12 * (attempt + 1))

    return TestResult(
        name=challenge["name"], category=challenge["category"],
        model=model, passed=False,
        response_chars=0, elapsed_s=round(time.time() - t0, 1),
        keywords_found=[], keywords_missing=challenge["expect_keywords"],
        error=last_error,
    )


async def run_api_ping(api_key: str) -> dict:
    """Quick connectivity check — call all 3 models with a one-liner."""
    import httpx
    MODELS = [
        ("DeepSeek", "deepseek-ai/DeepSeek-V4-Flash-0731"),
        ("GLM",      "zai-org/GLM-5.3-Flash"),
        ("MiniMax",  "MiniMaxAI/MiniMax-M2.7"),
    ]
    results = {}
    async with httpx.AsyncClient(timeout=30) as client:
        tasks = []
        for name, model in MODELS:
            async def ping(n=name, m=model):
                t0 = time.time()
                try:
                    r = await client.post(
                        "https://api.gonkarouter.io/v1/chat/completions",
                        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                        json={"model": m, "messages": [{"role": "user", "content": "Reply with OK"}], "max_tokens": 5},
                    )
                    r.raise_for_status()
                    return n, True, round(time.time()-t0, 2), ""
                except Exception as e:
                    return n, False, round(time.time()-t0, 2), str(e)
            tasks.append(ping())
        pings = await asyncio.gather(*tasks)
    return {name: {"ok": ok, "ms": int(t*1000), "err": err} for name, ok, t, err in pings}


def load_api_key() -> str:
    env_file = ROOT / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            # Accept either key name used in .env
            if line.startswith("GONKA_API_KEY=") or line.startswith("GONKAROUTER_API_KEY="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    # Also check environment variable
    return (
        __import__("os").environ.get("GONKA_API_KEY") or
        __import__("os").environ.get("GONKAROUTER_API_KEY") or
        ""
    )


# ── Main ──────────────────────────────────────────────────────────────────────
async def main():
    parser = argparse.ArgumentParser(description="CTF Pipeline Test Suite")
    parser.add_argument("--category", help="Test only this category (e.g. web, ai, crypto)")
    parser.add_argument("--quick",  action="store_true", help="API ping only — no skill tests")
    parser.add_argument("--list",   action="store_true", help="List all test cases and exit")
    parser.add_argument("--serial", action="store_true", help="Run tests one-by-one (slower but clearer output)")
    parser.add_argument("--debug",  action="store_true", help="Print raw model responses for ALL tests")
    args = parser.parse_args()

    # ── List mode ─────────────────────────────────────────────────────────────
    if args.list:
        header("All Test Cases")
        for i, c in enumerate(MOCK_CHALLENGES, 1):
            print(f"  {i:2}. [{c['category']:12}] {c['name']}  →  {c['target']}")
        print()
        return

    api_key = load_api_key()
    if not api_key:
        fail("API key not found in .env — run: echo GONKA_API_KEY=sk-... > .env")
        sys.exit(1)

    header("HI CyberCon CTF 2026 — Pipeline Test Suite")
    info(f"API key loaded from .env  ({api_key[:8]}...)")
    print()

    # ── Step 1: API ping ───────────────────────────────────────────────────────
    section("Step 1 — API Connectivity (all 3 models)")
    print("  Pinging GonkaRouter... ", end="", flush=True)
    pings = await run_api_ping(api_key)
    all_up = True
    for model_name, result in pings.items():
        if result["ok"]:
            ok(f"{model_name:10}  {result['ms']:>4}ms")
        else:
            fail(f"{model_name:10}  ERROR: {result['err'][:60]}")
            all_up = False

    if not all_up:
        fail("One or more models unreachable — check your API key and connection.")
        sys.exit(1)

    if args.quick:
        ok("Quick mode done. All 3 models online.")
        return

    # ── Step 2: Skill file check ───────────────────────────────────────────────
    section("Step 2 — Skill Files Present")
    skills = [
        "ctf-recon", "ctf-web", "ctf-pwn", "ctf-crypto",
        "ctf-forensics", "ctf-rev", "ctf-ai-llm",
        "ctf-osint", "ctf-blockchain", "ctf-pipeline",
    ]
    skills_ok = True
    for skill in skills:
        path = ROOT / ".agents" / "skills" / skill / "SKILL.md"
        if path.exists():
            size = path.stat().st_size
            ok(f"{skill:20}  ({size:,} bytes)")
        else:
            fail(f"{skill:20}  MISSING at {path}")
            skills_ok = False
    if not skills_ok:
        warn("Some skills missing — run setup to recreate them.")

    # ── Step 3: Per-agent skill tests ──────────────────────────────────────────
    section("Step 3 — Agent Response Tests")

    challenges = MOCK_CHALLENGES
    if args.category:
        challenges = [c for c in MOCK_CHALLENGES if c["category"] == args.category]
        if not challenges:
            fail(f"No test case for category '{args.category}'. Use --list to see all.")
            sys.exit(1)

    print(f"  Running {len(challenges)} test(s){'in serial' if args.serial else ' in parallel'}...\n")

    if args.serial:
        results = []
        for c in challenges:
            print(f"  Testing [{c['category']:12}] {c['name']}... ", end="", flush=True)
            r = await run_one_test(c, api_key, stagger_s=0)
            results.append(r)
            status = f"{GREEN}PASS{RESET}" if r.passed else f"{RED}FAIL{RESET}"
            print(f"[{status}] {r.response_chars} chars in {r.elapsed_s}s")
    else:
        # Stagger launches by 3s each to avoid 429 rate limits
        STAGGER = 3.0
        info(f"Staggering {len(challenges)} requests by {STAGGER}s each to avoid rate limits...")
        tasks = [run_one_test(c, api_key, stagger_s=i * STAGGER) for i, c in enumerate(challenges)]
        results = await asyncio.gather(*tasks)

    # ── Step 4: Results summary ────────────────────────────────────────────────
    section("Step 4 — Results Summary")
    passed_count = 0
    for r in results:
        if r.passed:
            passed_count += 1
            ok(f"[{r.category:12}] {r.name:20}  {r.response_chars:>5} chars  {r.elapsed_s:>5}s  via {r.model.split('/')[0]}")
            if r.keywords_found:
                print(f"           keywords: {', '.join(r.keywords_found)}")
            if args.debug and r.raw_response:
                print(f"\n{CYAN}           --- response preview ---{RESET}")
                print(f"           {r.raw_response[:400].replace(chr(10), chr(10)+'           ')}")
                print()
        else:
            fail(f"[{r.category:12}] {r.name:20}  {r.elapsed_s:>5}s  via {r.model.split('/')[0]}")
            if r.error:
                print(f"           error: {r.error[:100]}")
            if r.keywords_missing:
                warn(f"           missing : {', '.join(r.keywords_missing)}")
            if r.keywords_found:
                print(f"           found   : {', '.join(r.keywords_found)}")
            # Always show response preview on failure so user can tune keywords
            if r.raw_response:
                print(f"\n{YELLOW}           --- model said (first 400 chars) ---{RESET}")
                preview = r.raw_response[:400].replace("\n", "\n           ")
                print(f"           {preview}")
                print()

    # ── Final verdict ─────────────────────────────────────────────────────────
    total = len(results)
    print()
    print(f"  {BOLD}Result: {passed_count}/{total} tests passed{RESET}")
    avg_time = sum(r.elapsed_s for r in results) / total if total else 0
    print(f"  Avg response time: {avg_time:.1f}s")

    if passed_count == total:
        print(f"\n  {GREEN}{BOLD}ALL SYSTEMS GO. Pipeline is ready for HI CyberCon CTF 2026!{RESET}")
        print(f"  Competition starts: 30 Oct 2026 14:00 UTC\n")
    elif passed_count >= total * 0.7:
        print(f"\n  {YELLOW}{BOLD}MOSTLY READY — {total-passed_count} test(s) need attention.{RESET}\n")
    else:
        print(f"\n  {RED}{BOLD}ISSUES DETECTED — review failures before competition.{RESET}\n")

    # ── Save test report ───────────────────────────────────────────────────────
    report = {
        "timestamp": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        "summary": {"passed": passed_count, "total": total, "avg_time_s": round(avg_time, 2)},
        "model_pings": pings,
        "tests": [
            {
                "name": r.name, "category": r.category, "model": r.model,
                "passed": r.passed, "chars": r.response_chars,
                "elapsed_s": r.elapsed_s, "keywords_found": r.keywords_found,
                "keywords_missing": r.keywords_missing, "error": r.error,
            }
            for r in results
        ],
    }
    report_path = ROOT / f"test_report_{__import__('datetime').datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    info(f"Report saved: {report_path.name}")


if __name__ == "__main__":
    asyncio.run(main())
