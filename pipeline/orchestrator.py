#!/usr/bin/env python3
"""
CTF AI Pipeline — Multi-Model Orchestrator
==========================================
Coordinates multiple specialist AI agents in parallel to solve CTF challenges.
Each agent runs independently and feeds findings to an aggregator.
"""

import asyncio
import io
import json
import os
import re
import sys
import time
import argparse
import logging
from dataclasses import dataclass, field, asdict
from typing import Any
from pathlib import Path
from datetime import datetime

# ─── Windows UTF-8 fix ───────────────────────────────────────────────────────
# Reconfigure stdout/stderr to UTF-8 so emoji in log messages don't crash
if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "buffer"):
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# ─── Logging ─────────────────────────────────────────────────────────────────
_stream_handler = logging.StreamHandler(sys.stdout)
_stream_handler.setFormatter(logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s"))
_file_handler = logging.FileHandler(
    f"pipeline_run_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
    encoding="utf-8",
)
_file_handler.setFormatter(logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s"))
logging.basicConfig(level=logging.INFO, handlers=[_stream_handler, _file_handler])
log = logging.getLogger("orchestrator")


# ─── Constants ────────────────────────────────────────────────────────────────
FLAG_PATTERNS = [
    r"FLAG\{[^}]+\}",
    r"CTF\{[^}]+\}",
    r"picoCTF\{[^}]+\}",
    r"HTB\{[^}]+\}",
    r"flag\{[^}]+\}",
    r"DUCTF\{[^}]+\}",
    r"UIUCTF\{[^}]+\}",
]

AGENT_TIMEOUT = 300  # 5 minutes per agent phase

# ─── HI CyberCon CTF 2026 — 12 Challenge Categories ─────────────────────────
# https://ctf.hiddeninvestigations.net/
# Starts: 30 Oct 2026 14:00 UTC | Ends: 01 Nov 2026 14:00 UTC
# Division: Agentic AI (AI pipeline use is ALLOWED and ENCOURAGED)
# Flag format: TBD at launch — check platform when live
CATEGORY_ROUTING = {
    # ── Core categories ───────────────────────────────────────────────────────
    "web":         ["ctf-recon", "ctf-web"],
    "forensics":   ["ctf-forensics"],
    "stego":       ["ctf-forensics"],
    "steganography": ["ctf-forensics"],
    "network":     ["ctf-recon", "ctf-forensics"],       # pcap + traffic analysis
    "crypto":      ["ctf-crypto"],
    "cryptography": ["ctf-crypto"],
    "pwn":         ["ctf-recon", "ctf-pwn"],
    "rev":         ["ctf-rev"],
    "reversing":   ["ctf-rev"],
    "reverse":     ["ctf-rev"],
    # ── HI CyberCon-specific categories ─────────────────────────────────────
    "ai":          ["ctf-ai-llm"],                       # AI/LLM prompt injection
    "llm":         ["ctf-ai-llm"],
    "ai/llm":      ["ctf-ai-llm"],
    "hardware":    ["ctf-rev", "ctf-forensics"],         # firmware, IoT, embedded
    "blockchain":  ["ctf-blockchain"],                   # smart contracts
    "osint":       ["ctf-osint", "ctf-recon"],           # open-source intelligence
    # ── Multi-category & fallback ─────────────────────────────────────────────
    "misc":        ["ctf-recon", "ctf-forensics", "ctf-crypto", "ctf-ai-llm"],
    "miscellaneous": ["ctf-recon", "ctf-forensics", "ctf-crypto"],
    # ── Full auto — all 12 categories, all agents ─────────────────────────────
    "auto":        [
        "ctf-recon", "ctf-web", "ctf-pwn", "ctf-crypto",
        "ctf-forensics", "ctf-rev", "ctf-ai-llm",
        "ctf-osint", "ctf-blockchain",
    ],
}


# ─── GonkaRouter Models ───────────────────────────────────────────────────────
# All served via OpenAI-compatible API at https://api.gonkarouter.io/v1
GONKA_DEEPSEEK  = "deepseek-ai/DeepSeek-V4-Flash-0731"   # Fast, broad reasoning
GONKA_GLM       = "zai-org/GLM-5.3-Flash"                 # Efficient analysis
GONKA_MINIMAX   = "MiniMaxAI/MiniMax-M2.7"                # Deep synthesis

MODEL_ASSIGNMENT = {
    # Fast enumeration → GLM (quick, efficient)
    "ctf-recon":      GONKA_GLM,
    # Web vuln analysis → DeepSeek (broad web knowledge)
    "ctf-web":        GONKA_DEEPSEEK,
    # Binary exploitation → MiniMax (deep reasoning)
    "ctf-pwn":        GONKA_MINIMAX,
    # Crypto math → DeepSeek (strong math)
    "ctf-crypto":     GONKA_DEEPSEEK,
    # Forensics pattern matching → GLM (fast)
    "ctf-forensics":  GONKA_GLM,
    # Reverse engineering → MiniMax (code understanding)
    "ctf-rev":        GONKA_MINIMAX,
    # AI/LLM prompt injection → MiniMax (understands LLM internals best)
    "ctf-ai-llm":     GONKA_MINIMAX,
    # OSINT intelligence → DeepSeek (broad internet knowledge)
    "ctf-osint":      GONKA_DEEPSEEK,
    # Blockchain/smart contracts → DeepSeek (Solidity knowledge)
    "ctf-blockchain": GONKA_DEEPSEEK,
    # Final aggregation → MiniMax (synthesis)
    "aggregator":     GONKA_MINIMAX,
}


FALLBACK_MODELS = {
    GONKA_DEEPSEEK: [GONKA_MINIMAX, GONKA_GLM],
    GONKA_GLM:      [GONKA_DEEPSEEK, GONKA_MINIMAX],
    GONKA_MINIMAX:  [GONKA_DEEPSEEK, GONKA_GLM],
}



# ─── Data Models ─────────────────────────────────────────────────────────────
@dataclass
class AgentFinding:
    agent: str
    task: str
    status: str  # "success" | "partial" | "failed"
    findings: dict[str, Any] = field(default_factory=dict)
    flag_candidates: list[dict] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)
    confidence: float = 0.0
    elapsed_s: float = 0.0
    model_used: str = ""
    raw_output: str = ""


@dataclass
class ChallengeContext:
    name: str
    target: str
    category: str
    flag_format: str
    time_limit_s: int
    hints: list[str] = field(default_factory=list)
    custom_flag_pattern: str | None = None

    @property
    def flag_patterns(self) -> list[str]:
        base = FLAG_PATTERNS.copy()
        if self.custom_flag_pattern:
            base.insert(0, self.custom_flag_pattern)
        return base


# ─── Tool Registry ────────────────────────────────────────────────────────────
class ToolRegistry:
    """Loads available tools from pipeline/tools/ directory."""

    def __init__(self, tools_dir: Path = Path("pipeline/tools")):
        self.tools_dir = tools_dir
        self._tools: dict[str, dict] = {}
        self._load()

    def _load(self):
        if not self.tools_dir.exists():
            return
        for f in self.tools_dir.glob("*.json"):
            try:
                data = json.loads(f.read_text())
                self._tools[data["name"]] = data
                log.debug(f"Loaded tool: {data['name']}")
            except Exception as e:
                log.warning(f"Failed to load tool {f}: {e}")

    def get(self, name: str) -> dict | None:
        return self._tools.get(name)

    def list_for_agent(self, agent: str) -> list[str]:
        return [n for n, t in self._tools.items() if agent in t.get("agents", [])]



# ─── GonkaRouter API Client ───────────────────────────────────────────────────
def _load_gonka_key() -> str:
    """Load API key from .env or environment variable."""
    # Try environment variable first
    key = os.environ.get("GONKAROUTER_API_KEY", "")
    if key:
        return key
    # Try .env file next
    env_path = Path(__file__).parent.parent / ".env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if line.startswith("GONKAROUTER_API_KEY="):
                return line.split("=", 1)[1].strip()
    raise RuntimeError(
        "GONKAROUTER_API_KEY not found. "
        "Set it in .env or as an environment variable."
    )

GONKA_BASE_URL = "https://api.gonkarouter.io/v1"
GONKA_API_KEY  = None   # lazy-loaded on first call


# ─── Model Client ─────────────────────────────────────────────────────────────
class ModelClient:
    """
    Async OpenAI-compatible client for GonkaRouter.
    Supports DeepSeek-V4-Flash, GLM-5.3-Flash, and MiniMax-M2.7.
    Falls back to next model in chain on any error.
    """

    def __init__(self, model: str, fallbacks: list[str] | None = None):
        self.model = model
        self.fallbacks = fallbacks or FALLBACK_MODELS.get(model, [])

    async def run(self, system_prompt: str, user_prompt: str, **kwargs) -> str:
        """Send prompt to model with automatic fallback on failure."""
        for attempt_model in [self.model] + self.fallbacks:
            try:
                log.info(f"[GonkaRouter] Calling: {attempt_model}")
                response = await self._call_api(attempt_model, system_prompt, user_prompt, **kwargs)
                log.info(f"[GonkaRouter] {attempt_model} → {len(response)} chars")
                return response
            except Exception as e:
                log.warning(f"[GonkaRouter] {attempt_model} failed: {e}. Trying fallback...")
        raise RuntimeError(f"All GonkaRouter models failed for task: {user_prompt[:80]!r}")

    async def _call_api(
        self,
        model: str,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 4096,
        temperature: float = 0.2,
        **kwargs,
    ) -> str:
        """
        Async call to GonkaRouter (OpenAI-compatible endpoint).
        Uses httpx for true async HTTP — no blocking thread required.
        """
        global GONKA_API_KEY
        if GONKA_API_KEY is None:
            GONKA_API_KEY = _load_gonka_key()

        import httpx

        headers = {
            "Authorization": f"Bearer {GONKA_API_KEY}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt},
            ],
            "max_tokens": max_tokens,
            "temperature": temperature,
            "stream": False,
        }

        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(
                f"{GONKA_BASE_URL}/chat/completions",
                headers=headers,
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()

        content = data["choices"][0]["message"]["content"]
        return content




# ─── Specialist Agents ────────────────────────────────────────────────────────
class SpecialistAgent:
    """Base class for all specialist agents."""

    def __init__(self, name: str, skill_path: Path, tool_registry: ToolRegistry):
        self.name = name
        self.skill_path = skill_path
        self.tool_registry = tool_registry
        self.model = ModelClient(MODEL_ASSIGNMENT.get(name, "gemini-2.0-flash"))
        self._skill_content = self._load_skill()

    def _load_skill(self) -> str:
        if self.skill_path.exists():
            return self.skill_path.read_text(encoding="utf-8")
        return f"# {self.name}\nNo SKILL.md found."

    def _build_system_prompt(self, ctx: ChallengeContext) -> str:
        return f"""You are the {self.name} specialist agent in a CTF AI pipeline.
Challenge: {ctx.name}
Target: {ctx.target}
Category: {ctx.category}
Flag format: {ctx.flag_format}

Your skill instructions:
{self._skill_content}

Always respond with valid JSON matching the output schema in your skill.
"""

    async def run(self, ctx: ChallengeContext, extra_context: str = "") -> AgentFinding:
        start = time.time()
        user_prompt = f"""Analyze this CTF challenge and execute your skill procedures.

Challenge: {ctx.name}
Target: {ctx.target}
Additional context from other agents:
{extra_context if extra_context else "None yet — you are running in parallel triage phase."}

Provide your structured findings JSON.
"""
        try:
            raw = await asyncio.wait_for(
                self.model.run(self._build_system_prompt(ctx), user_prompt),
                timeout=AGENT_TIMEOUT,
            )
            parsed = self._parse_output(raw)
            parsed.elapsed_s = time.time() - start
            parsed.model_used = self.model.model
            parsed.raw_output = raw
            return parsed
        except asyncio.TimeoutError:
            log.warning(f"{self.name} timed out after {AGENT_TIMEOUT}s")
            return AgentFinding(
                agent=self.name, task="timed_out", status="failed",
                confidence=0.0, elapsed_s=time.time() - start,
            )
        except Exception as e:
            log.error(f"{self.name} error: {e}")
            return AgentFinding(
                agent=self.name, task=str(e)[:100], status="failed",
                confidence=0.0, elapsed_s=time.time() - start,
            )

    def _parse_output(self, raw: str) -> AgentFinding:
        """Extract JSON from model output, with graceful fallback."""
        # Try to find JSON block
        json_match = re.search(r"\{[\s\S]*\}", raw)
        if json_match:
            try:
                data = json.loads(json_match.group())
                return AgentFinding(
                    agent=data.get("agent", self.name),
                    task=data.get("task", "analysis"),
                    status=data.get("status", "partial"),
                    findings=data.get("findings", {}),
                    flag_candidates=data.get("flag_candidates", []),
                    next_steps=data.get("next_steps", []),
                    confidence=float(data.get("confidence", 0.0)),
                )
            except json.JSONDecodeError:
                pass
        # Fallback: scan raw text for flags
        flags = self._extract_flags_from_text(raw)
        return AgentFinding(
            agent=self.name,
            task="raw_parse",
            status="partial",
            flag_candidates=[{"value": f, "source": "raw_text"} for f in flags],
            confidence=0.5 if flags else 0.0,
        )

    def _extract_flags_from_text(self, text: str) -> list[str]:
        found = []
        for pattern in FLAG_PATTERNS:
            found.extend(re.findall(pattern, text, re.IGNORECASE))
        return list(set(found))


# ─── Aggregator ───────────────────────────────────────────────────────────────
class Aggregator:
    """Merges findings from all agents, ranks flag candidates, decides next steps."""

    def __init__(self):
        self.model = ModelClient(MODEL_ASSIGNMENT["aggregator"])

    async def aggregate(self, ctx: ChallengeContext, findings: list[AgentFinding]) -> dict:
        all_flags: dict[str, float] = {}

        # Collect all flag candidates and average confidence
        for finding in findings:
            for fc in finding.flag_candidates:
                val = fc.get("value", "")
                conf = fc.get("confidence", finding.confidence)
                if val:
                    if val in all_flags:
                        all_flags[val] = max(all_flags[val], conf)
                    else:
                        all_flags[val] = conf

        # Also scan all raw outputs
        for finding in findings:
            for pattern in ctx.flag_patterns:
                for match in re.findall(pattern, finding.raw_output, re.IGNORECASE):
                    if match not in all_flags:
                        all_flags[match] = 0.7  # reasonable confidence for direct match

        ranked = sorted(all_flags.items(), key=lambda x: x[1], reverse=True)

        result = {
            "challenge": ctx.name,
            "target": ctx.target,
            "agents_ran": [f.agent for f in findings],
            "agent_statuses": {f.agent: f.status for f in findings},
            "flag_candidates_ranked": [{"flag": f, "confidence": c} for f, c in ranked],
            "top_flag": ranked[0][0] if ranked else None,
            "top_confidence": ranked[0][1] if ranked else 0.0,
            "all_next_steps": list({s for f in findings for s in f.next_steps}),
            "summary": self._build_summary(findings),
        }

        log.info(f"Aggregation complete. Top flag: {result['top_flag']} (conf={result['top_confidence']:.2f})")
        return result

    def _build_summary(self, findings: list[AgentFinding]) -> str:
        lines = []
        for f in findings:
            status_icon = "✅" if f.status == "success" else "⚠️" if f.status == "partial" else "❌"
            lines.append(f"{status_icon} {f.agent} [{f.elapsed_s:.1f}s] — conf={f.confidence:.2f}")
        return "\n".join(lines)


# ─── Orchestrator ─────────────────────────────────────────────────────────────
class CTFOrchestrator:
    """Main pipeline orchestrator."""

    SKILLS_DIR = Path(".agents/skills")

    def __init__(self):
        self.tool_registry = ToolRegistry()
        self.aggregator = Aggregator()

    def _make_agent(self, name: str) -> SpecialistAgent:
        skill_path = self.SKILLS_DIR / name / "SKILL.md"
        return SpecialistAgent(name, skill_path, self.tool_registry)

    def _get_agents_for_category(self, category: str) -> list[str]:
        return CATEGORY_ROUTING.get(category.lower(), CATEGORY_ROUTING["auto"])

    async def run(self, ctx: ChallengeContext) -> dict:
        log.info(f"🚩 Starting CTF Pipeline for: {ctx.name}")
        log.info(f"   Target: {ctx.target} | Category: {ctx.category}")

        agent_names = self._get_agents_for_category(ctx.category)
        log.info(f"   Spawning agents: {agent_names}")

        agents = [self._make_agent(name) for name in agent_names]

        # Phase 1: Parallel triage
        log.info("⚡ Phase 1: Parallel triage...")
        phase1_tasks = [agent.run(ctx) for agent in agents]
        phase1_results: list[AgentFinding] = await asyncio.gather(*phase1_tasks)

        # Phase 2: Cross-feed — high-confidence agents share context
        log.info("🔄 Phase 2: Cross-feeding intelligence...")
        recon_context = self._extract_recon_context(phase1_results)
        phase2_results = list(phase1_results)

        if recon_context:
            cross_feed_agents = [a for a in agents if a.name != "ctf-recon"]
            phase2_tasks = [agent.run(ctx, extra_context=recon_context) for agent in cross_feed_agents]
            phase2_new: list[AgentFinding] = await asyncio.gather(*phase2_tasks)
            # Merge: take the higher-confidence result per agent
            agent_best: dict[str, AgentFinding] = {f.agent: f for f in phase1_results}
            for f in phase2_new:
                if f.confidence > agent_best.get(f.agent, AgentFinding("", "", "", confidence=0.0)).confidence:
                    agent_best[f.agent] = f
            phase2_results = list(agent_best.values())

        # Phase 3: Aggregation
        log.info("🏁 Phase 3: Aggregating findings...")
        final = await self.aggregator.aggregate(ctx, phase2_results)

        # Save results
        out_path = Path(f"results_{ctx.name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        out_path.write_text(json.dumps(final, indent=2))
        log.info(f"💾 Results saved to: {out_path}")

        # Print summary
        print("\n" + "═" * 60)
        print(f"  🚩 CTF PIPELINE RESULTS — {ctx.name}")
        print("═" * 60)
        print(final["summary"])
        print()
        if final["top_flag"]:
            print(f"  🎯 TOP FLAG: {final['top_flag']}")
            print(f"  📊 Confidence: {final['top_confidence']*100:.1f}%")
        else:
            print("  ❌ No flag found. Check next_steps for manual actions.")
        print()
        if final["all_next_steps"]:
            print("  📋 Recommended next steps:")
            for step in final["all_next_steps"][:5]:
                print(f"     → {step}")
        print("═" * 60 + "\n")

        return final

    def _extract_recon_context(self, findings: list[AgentFinding]) -> str:
        recon = next((f for f in findings if f.agent == "ctf-recon" and f.status != "failed"), None)
        if not recon:
            return ""
        return json.dumps({
            "source": "ctf-recon",
            "open_ports": recon.findings.get("open_ports", []),
            "services": recon.findings.get("services", {}),
            "web_paths": recon.findings.get("web_paths", []),
            "attack_vectors": recon.findings.get("attack_vectors", []),
        }, indent=2)


# ─── Entry Point ──────────────────────────────────────────────────────────────
async def main():
    parser = argparse.ArgumentParser(description="CTF AI Multi-Model Pipeline")
    parser.add_argument("--challenge", required=True, help="Challenge name")
    parser.add_argument("--target", required=True, help="Target IP, URL, or file path")
    parser.add_argument("--category", default="auto",
                        choices=list(CATEGORY_ROUTING.keys()),
                        help="Challenge category (default: auto = run all)")
    parser.add_argument("--flag-format", default="FLAG{...}",
                        help="Expected flag format hint")
    parser.add_argument("--time-limit", type=int, default=3600,
                        help="Time limit in seconds (default: 1h)")
    parser.add_argument("--hint", action="append", default=[],
                        help="Add a hint (can specify multiple times)")
    parser.add_argument("--custom-flag-pattern", default=None,
                        help="Custom regex for flag extraction")
    args = parser.parse_args()

    ctx = ChallengeContext(
        name=args.challenge,
        target=args.target,
        category=args.category,
        flag_format=args.flag_format,
        time_limit_s=args.time_limit,
        hints=args.hint,
        custom_flag_pattern=args.custom_flag_pattern,
    )

    orchestrator = CTFOrchestrator()
    await orchestrator.run(ctx)


if __name__ == "__main__":
    asyncio.run(main())
