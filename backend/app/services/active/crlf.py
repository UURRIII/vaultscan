"""CRLF injection / HTTP response splitting (aggressive mode only)."""
import asyncio
from urllib.parse import urlencode, urlparse, parse_qs
from app.core.context import ScanContext
from app.core.finding import Finding
from app.core.severity import Severity

MARKER = "vaultscan-crlf"
# Various encodings of CRLF + an injected header.
PAYLOADS = [
    f"%0d%0a{MARKER}: injected",
    f"%0D%0A{MARKER}: injected",
    f"%E5%98%8D%E5%98%8A{MARKER}: injected",  # unicode CRLF bypass
]
MAX_TESTS = 15


async def run(ctx: ScanContext) -> list[Finding]:
    findings = []
    targets = ctx.param_targets()
    if not targets:
        return findings

    sem = asyncio.Semaphore(5)
    tasks = []
    for i, (url, param) in enumerate(targets):
        if i >= MAX_TESTS:
            break
        tasks.append(_test(ctx, url, param, sem))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    seen = set()
    for r in results:
        if isinstance(r, Finding) and (r.url, r.title) not in seen:
            seen.add((r.url, r.title))
            findings.append(r)
    return findings


async def _test(ctx: ScanContext, url: str, param: str, sem: asyncio.Semaphore) -> Finding | None:
    base = url.split("?")[0]
    existing = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}

    for payload in PAYLOADS:
        inj = {**existing, param: payload}
        test_url = f"{base}?{urlencode(inj, safe='%:')}"
        try:
            async with sem:
                r = await ctx.client.get(test_url)
        except Exception:
            continue
        # If our injected header made it into the response headers, splitting works.
        if MARKER in {k.lower() for k in r.headers.keys()}:
            return Finding(
                title=f"CRLF Injection in '{param}'",
                description=f"The '{param}' parameter allows injecting CRLF sequences into the HTTP response, "
                            "enabling header injection / response splitting (and often reflected XSS or cache poisoning).",
                severity=Severity.HIGH,
                category="Active / CRLF",
                evidence=f"Request: {test_url}\nInjected response header '{MARKER}' was returned.",
                recommendation="Strip CR/LF characters from any user input used in response headers. Use the "
                               "framework's header API rather than string concatenation.",
                url=test_url,
                cvss=6.1,
            )
    return None
