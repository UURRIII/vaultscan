"""Heuristic IDOR probing (aggressive mode only).

Looks for numeric object-reference parameters and checks whether adjacent IDs
return different, valid-looking content. This is a heuristic — findings are
low-confidence and must be manually verified.
"""
import asyncio
from urllib.parse import urlencode, urlparse, parse_qs
from app.core.context import ScanContext
from app.core.finding import Finding
from app.core.severity import Severity

ID_PARAMS = ["id", "user", "user_id", "userid", "account", "account_id", "uid",
             "order", "order_id", "invoice", "doc", "document", "file", "pid",
             "profile", "customer", "number", "no", "num", "record"]
MAX_TESTS = 12


async def run(ctx: ScanContext) -> list[Finding]:
    findings = []
    targets = ctx.param_targets()
    if not targets:
        return findings

    # Only numeric values on id-like parameters.
    candidates = []
    for url, param in targets:
        if not any(k == param.lower() or k in param.lower() for k in ID_PARAMS):
            continue
        val = parse_qs(urlparse(url).query).get(param, [""])[0]
        if val.isdigit():
            candidates.append((url, param, int(val)))

    sem = asyncio.Semaphore(5)
    tasks = [_test(ctx, url, param, val, sem) for (url, param, val) in candidates[:MAX_TESTS]]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    seen = set()
    for r in results:
        if isinstance(r, Finding) and (r.url, r.title) not in seen:
            seen.add((r.url, r.title))
            findings.append(r)
    return findings


async def _test(ctx, url, param, val, sem) -> Finding | None:
    base = url.split("?")[0]
    existing = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}

    async def fetch(v):
        q = {**existing, param: str(v)}
        try:
            async with sem:
                r = await ctx.client.get(f"{base}?{urlencode(q)}")
            return r
        except Exception:
            return None

    orig = await fetch(val)
    if not orig or orig.status_code != 200:
        return None
    neighbor = await fetch(val - 1 if val > 1 else val + 1)
    if not neighbor or neighbor.status_code != 200:
        return None

    # Both IDs return 200 with non-trivial, differing bodies of similar size → possible IDOR.
    lo, ln = len(orig.text), len(neighbor.text)
    if lo > 200 and ln > 200 and orig.text != neighbor.text and abs(lo - ln) < max(lo, ln) * 0.3:
        return Finding(
            title=f"Possible IDOR via '{param}'",
            description=f"Changing the numeric '{param}' parameter returns different valid content for another "
                        "object, with no apparent authorization check. This may be an Insecure Direct Object "
                        "Reference exposing other users' data. Manual verification required.",
            severity=Severity.MEDIUM,
            category="Active / IDOR",
            evidence=f"{base}?{param}={val} (HTTP 200, {lo} bytes) vs "
                     f"{param}={val-1 if val>1 else val+1} (HTTP 200, {ln} bytes) — different content.",
            recommendation="Enforce per-object authorization server-side. Use unpredictable identifiers (UUIDs) "
                           "and verify the requesting user owns the referenced object.",
            url=f"{base}?{param}={val}",
            cvss=6.5,
        )
    return None
