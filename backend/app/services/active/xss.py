"""Reflected XSS detection (aggressive mode only).

Injects a uniquely-marked payload into discovered parameters and checks
whether it is reflected unescaped in the response.
"""
import asyncio
from urllib.parse import urlencode, urlparse, parse_qs
from app.core.context import ScanContext
from app.core.finding import Finding
from app.core.severity import Severity

MARKER = "vsx9z3"
# Payloads carry the marker so reflection is unambiguous.
PAYLOADS = [
    f'"><svg/onload=alert({MARKER})>',
    f"'><script>alert({MARKER})</script>",
    f"{MARKER}<img src=x onerror=alert(1)>",
]
MAX_TESTS = 25


async def run(ctx: ScanContext) -> list[Finding]:
    findings = []
    targets = ctx.param_targets()
    if not targets:
        return findings

    sem = asyncio.Semaphore(6)
    tested = 0
    seen_urls = set()
    tasks = []
    for url, param in targets:
        if tested >= MAX_TESTS:
            break
        tested += 1
        tasks.append(_test_param(ctx, url, param, sem))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, Finding):
            key = (r.url, r.title)
            if key not in seen_urls:
                seen_urls.add(key)
                findings.append(r)
    return findings


async def _test_param(ctx: ScanContext, url: str, param: str, sem: asyncio.Semaphore) -> Finding | None:
    base = url.split("?")[0]
    existing = parse_qs(urlparse(url).query)
    for payload in PAYLOADS:
        params = {k: v[0] for k, v in existing.items()}
        params[param] = payload
        test_url = f"{base}?{urlencode(params)}"
        try:
            async with sem:
                r = await ctx.client.get(test_url)
        except Exception:
            continue
        # Reflected unescaped?
        if payload in r.text:
            return Finding(
                title=f"Reflected XSS in '{param}'",
                description=f"The '{param}' parameter reflects input without sanitisation, allowing arbitrary "
                            "JavaScript execution in a victim's browser.",
                severity=Severity.HIGH,
                category="Active / XSS",
                evidence=f"Payload reflected unescaped at:\n{test_url}",
                recommendation="Context-aware output encoding (HTML/JS/attribute). Deploy a strict Content-Security-Policy.",
                url=test_url,
                cvss=7.2,
            )
    return None
