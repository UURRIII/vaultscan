"""Server-Side Request Forgery detection (aggressive mode only).

Targets URL-like parameters and tries to make the server fetch internal
resources (cloud metadata, localhost). Reports a confirmed hit when the
response leaks fingerprints of those internal services.
"""
import asyncio
from urllib.parse import urlencode, urlparse, parse_qs
from app.core.context import ScanContext
from app.core.finding import Finding
from app.core.severity import Severity

# Parameters most likely to be passed to a server-side fetch.
LIKELY = ["url", "uri", "link", "src", "dest", "destination", "redirect", "fetch",
          "callback", "webhook", "proxy", "image", "img", "load", "host", "domain",
          "site", "target", "feed", "next", "data", "reference", "ref"]

PROBES = [
    ("http://169.254.169.254/latest/meta-data/", ["ami-id", "instance-id", "iam/", "hostname", "local-ipv4"]),
    ("http://metadata.google.internal/computeMetadata/v1/", ["computeMetadata", "project-id", "instance/"]),
    ("http://127.0.0.1:80/", ["<html", "server:", "<!doctype"]),
]
MAX_TESTS = 18


async def run(ctx: ScanContext) -> list[Finding]:
    findings = []
    targets = ctx.param_targets()
    if not targets:
        return findings

    targets.sort(key=lambda t: 0 if any(k == t[1].lower() or k in t[1].lower() for k in LIKELY) else 1)

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

    for probe, signatures in PROBES:
        inj = {**existing, param: probe}
        test_url = f"{base}?{urlencode(inj)}"
        try:
            async with sem:
                r = await ctx.client.get(test_url)
        except Exception:
            continue
        low = r.text.lower()
        if any(sig.lower() in low for sig in signatures):
            internal = "cloud metadata" if "169.254" in probe or "metadata" in probe else "an internal service"
            return Finding(
                title=f"SSRF in '{param}' (reached {internal})",
                description=f"The '{param}' parameter caused the server to fetch an attacker-controlled URL and "
                            f"return content from {internal}. SSRF can expose cloud credentials and internal systems.",
                severity=Severity.CRITICAL,
                category="Active / SSRF",
                evidence=f"Request: {test_url}\nLeaked fingerprint of {internal}.",
                recommendation="Validate and allowlist outbound URLs. Block requests to link-local (169.254.0.0/16) "
                               "and loopback ranges. Require IMDSv2 on AWS.",
                url=test_url,
                cvss=9.1,
            )
    return None
