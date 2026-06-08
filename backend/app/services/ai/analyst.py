"""AI Analyst — local LLM analysis of a scan's findings, via Ollama.

Runs entirely on the user's machine (no API key, no cost, data never leaves the
host). Streams an executive summary, prioritized risks, and a remediation plan,
and answers follow-up questions.
"""
import os
import json
import httpx
from typing import AsyncGenerator
from app.models.scan import Scan

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
MODEL = os.environ.get("VAULTSCAN_AI_MODEL", "llama3.1:8b")

SEV_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

ROLE_PROMPT = """You are a senior offensive-security analyst writing for VaultScan, \
a web security scanner. You receive the raw findings of an authorized security \
assessment and turn them into clear, actionable guidance for the engineer who ran the scan.

Be precise, technical, and concise. Prioritize by real-world exploitability and business \
impact, not just raw severity. Never invent findings that aren't in the data. When you \
reference a finding, use its exact title. Reply in the same language the user writes in \
(default to English). Format your answer in clean Markdown."""

ANALYSIS_REQUEST = """Produce a security assessment briefing in Markdown with these sections:

## Executive Summary
2-4 sentences a non-technical manager can understand: overall posture, the single most \
important risk, and the headline grade.

## Top Priorities
A numbered list of the 3-6 findings that matter most, hardest-first. For each: the finding \
title, why it matters here, and a one-line fix.

## Remediation Plan
Concrete, ordered steps the team should take this week vs. later.

## Notes
Any caveats, likely false positives to verify, or gaps the scan couldn't cover.

Keep it tight — this is a briefing, not a textbook."""


def is_available() -> bool:
    """True if the Ollama service is up and the configured model is pulled."""
    try:
        r = httpx.get(f"{OLLAMA_URL}/api/tags", timeout=2.0)
        if r.status_code != 200:
            return False
        names = [m.get("name", "") for m in r.json().get("models", [])]
        base = MODEL.split(":")[0]
        return any(n == MODEL or n.startswith(base) for n in names)
    except Exception:
        return False


def snapshot(scan: Scan) -> dict:
    """Materialize everything the analyst needs *while the DB session is alive*.

    The SSE generator runs after FastAPI closes the request's DB session, so
    touching scan.findings there raises DetachedInstanceError. Build a plain
    dict up front instead.
    """
    findings = sorted(scan.findings, key=lambda f: (-SEV_ORDER.get(f.severity, 0), -f.cvss))
    return {
        "target": scan.target,
        "mode": scan.mode,
        "risk_score": scan.risk_score,
        "risk_grade": scan.risk_grade,
        "findings": [
            {
                "severity": f.severity, "cvss": f.cvss, "title": f.title,
                "category": f.category, "url": f.url,
                "description": f.description, "evidence": f.evidence,
                "recommendation": f.recommendation,
            }
            for f in findings
        ],
    }


def _build_context(snap: dict) -> str:
    counts = {k: 0 for k in SEV_ORDER}
    for f in snap["findings"]:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    lines = [
        f"TARGET: {snap['target']}",
        f"SCAN MODE: {snap['mode']}",
        f"RISK SCORE: {snap['risk_score']}/100 (grade {snap['risk_grade']})",
        "FINDING COUNTS: " + ", ".join(f"{s}={counts[s]}" for s in
                                       ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']),
        "",
        "FINDINGS:",
    ]
    for i, f in enumerate(snap["findings"], 1):
        lines.append(f"\n[{i}] ({f['severity']}, CVSS {f['cvss']}) {f['title']}  —  category: {f['category']}")
        if f["url"]:
            lines.append(f"    url: {f['url']}")
        lines.append(f"    description: {f['description']}")
        if f["evidence"]:
            lines.append(f"    evidence: {f['evidence'].replace(chr(10), ' ')[:300]}")
        lines.append(f"    recommendation: {f['recommendation']}")
    return "\n".join(lines)


def _system_message(snap: dict) -> dict:
    return {
        "role": "system",
        "content": ROLE_PROMPT + "\n\nHere are the findings for the current scan:\n\n" + _build_context(snap),
    }


async def stream_analysis(snap: dict) -> AsyncGenerator[dict, None]:
    async for ev in _stream(snap, [{"role": "user", "content": ANALYSIS_REQUEST}]):
        yield ev


async def stream_chat(snap: dict, question: str, history: list[dict]) -> AsyncGenerator[dict, None]:
    messages = []
    for turn in history[-8:]:
        role = "assistant" if turn.get("role") == "assistant" else "user"
        messages.append({"role": role, "content": str(turn.get("content", ""))[:4000]})
    messages.append({"role": "user", "content": question})
    async for ev in _stream(snap, messages):
        yield ev


async def _stream(snap: dict, messages: list[dict]) -> AsyncGenerator[dict, None]:
    """Bridge Ollama's stream through a queue so we can emit keepalives.

    A local model has a long time-to-first-token (it loads into RAM and processes
    the prompt). Without periodic pings the browser/proxy drops the SSE connection
    mid-wait. We run the Ollama read in a background task and send a keepalive
    every few seconds while waiting.
    """
    import asyncio

    if not is_available():
        yield {"type": "error",
               "message": f"Ollama is not running or model '{MODEL}' is not installed."}
        return

    # Immediate first byte so the connection is established right away.
    yield {"type": "status", "message": "Loading model & analyzing findings…"}

    payload = {
        "model": MODEL,
        "messages": [_system_message(snap)] + messages,
        "stream": True,
        "options": {"temperature": 0.3, "num_ctx": 8192},
        "keep_alive": "30m",  # keep the model warm between requests
    }
    queue: asyncio.Queue = asyncio.Queue()

    async def producer():
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(600.0, connect=5.0)) as client:
                async with client.stream("POST", f"{OLLAMA_URL}/api/chat", json=payload) as resp:
                    if resp.status_code != 200:
                        body = (await resp.aread()).decode(errors="ignore")[:200]
                        await queue.put({"type": "error", "message": f"Ollama HTTP {resp.status_code}: {body}"})
                        return
                    async for line in resp.aiter_lines():
                        if not line.strip():
                            continue
                        try:
                            data = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        chunk = (data.get("message") or {}).get("content", "")
                        if chunk:
                            await queue.put({"type": "text", "delta": chunk})
                        if data.get("done"):
                            await queue.put({"type": "done", "usage": {
                                "eval_count": data.get("eval_count", 0),
                                "prompt_eval_count": data.get("prompt_eval_count", 0),
                            }})
                            return
        except Exception as e:
            await queue.put({"type": "error", "message": f"{type(e).__name__}: {e}"})
        finally:
            await queue.put(None)  # sentinel: producer finished

    task = asyncio.create_task(producer())
    try:
        while True:
            try:
                item = await asyncio.wait_for(queue.get(), timeout=4.0)
            except asyncio.TimeoutError:
                yield {"type": "ping"}  # keepalive while the model warms up
                continue
            if item is None:
                break
            yield item
            if item.get("type") in ("done", "error"):
                break
    finally:
        task.cancel()
