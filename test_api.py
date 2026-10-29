#!/usr/bin/env python3
"""
GonkaRouter API Connectivity Test
Tests all 3 models with a simple CTF-flavored prompt.
"""
import io, sys, asyncio
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

import httpx
from pathlib import Path

BASE_URL = "https://api.gonkarouter.io/v1"
MODELS = [
    "deepseek-ai/DeepSeek-V4-Flash-0731",
    "zai-org/GLM-5.3-Flash",
    "MiniMaxAI/MiniMax-M2.7",
]

def load_key() -> str:
    env = Path(__file__).parent / ".env"
    for line in env.read_text().splitlines():
        if line.startswith("GONKAROUTER_API_KEY="):
            return line.split("=", 1)[1].strip()
    raise ValueError("Key not found in .env")

async def test_model(client: httpx.AsyncClient, api_key: str, model: str) -> None:
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a CTF AI assistant. Reply in JSON."},
            {"role": "user",   "content": 'Say: {"status":"ok","model":"<your model name>","ready":true}'},
        ],
        "max_tokens": 100,
        "temperature": 0.0,
    }
    try:
        resp = await client.post(
            f"{BASE_URL}/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json=payload,
            timeout=30.0,
        )
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"]
        print(f"  [OK] {model}")
        print(f"       -> {content[:120]}")
    except Exception as e:
        print(f"  [FAIL] {model}: {e}")

async def main():
    api_key = load_key()
    print(f"\nGonkaRouter API Test")
    print(f"Base URL : {BASE_URL}")
    print(f"Key      : {api_key[:8]}...{api_key[-4:]}\n")
    async with httpx.AsyncClient() as client:
        tasks = [test_model(client, api_key, m) for m in MODELS]
        await asyncio.gather(*tasks)
    print("\nDone.")

asyncio.run(main())
