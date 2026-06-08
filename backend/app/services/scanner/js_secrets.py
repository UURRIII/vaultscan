import asyncio
import re
import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from app.core.finding import Finding
from app.core.severity import Severity

# Regex patterns for secrets commonly leaked in client-side JavaScript.
SECRET_PATTERNS = [
    ("AWS Access Key",      r"AKIA[0-9A-Z]{16}",                                    Severity.CRITICAL),
    ("AWS Secret Key",      r"(?i)aws_secret_access_key\s*[:=]\s*['\"][0-9a-zA-Z/+]{40}['\"]", Severity.CRITICAL),
    ("Google API Key",      r"AIza[0-9A-Za-z\-_]{35}",                              Severity.HIGH),
    ("Firebase URL",        r"https://[a-z0-9.-]+\.firebaseio\.com",               Severity.MEDIUM),
    ("Slack Token",         r"xox[baprs]-[0-9a-zA-Z\-]{10,48}",                     Severity.CRITICAL),
    ("Stripe Live Key",     r"sk_live_[0-9a-zA-Z]{24}",                             Severity.CRITICAL),
    ("Stripe Publishable",  r"pk_live_[0-9a-zA-Z]{24}",                             Severity.LOW),
    ("GitHub Token",        r"gh[pousr]_[0-9a-zA-Z]{36}",                           Severity.CRITICAL),
    ("Generic API Key",     r"(?i)api[_-]?key['\"]?\s*[:=]\s*['\"][0-9a-zA-Z\-_]{16,}['\"]", Severity.MEDIUM),
    ("Bearer Token",        r"(?i)bearer\s+[a-z0-9\-._~+/]{20,}",                   Severity.MEDIUM),
    ("Private Key",         r"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----", Severity.CRITICAL),
    ("JWT",                 r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", Severity.LOW),
    ("Mailgun Key",         r"key-[0-9a-zA-Z]{32}",                                 Severity.HIGH),
    ("Twilio SID",          r"AC[a-z0-9]{32}",                                      Severity.MEDIUM),
]

# Patterns that produce too much noise to be useful as standalone findings.
NOISE = re.compile(r"(example|sample|dummy|test|xxx|your[_-]?key|placeholder)", re.IGNORECASE)


async def run(ctx) -> list[Finding]:
    target = ctx.target
    base = target if target.startswith("http") else f"https://{target}"
    findings = []

    async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False,
                                  headers={"User-Agent": "Mozilla/5.0 VaultScan/1.0"}) as client:
        try:
            r = await client.get(base)
        except Exception:
            return findings

        # Collect JS file URLs from the HTML
        soup = BeautifulSoup(r.text, "html.parser")
        js_urls = []
        for script in soup.find_all("script", src=True):
            js_urls.append(urljoin(base, script["src"]))
        js_urls = list(dict.fromkeys(js_urls))[:15]  # cap to 15 files

        # Scan inline HTML + each JS file
        sources = {base: r.text}
        fetch_results = await asyncio.gather(
            *[_fetch(client, u) for u in js_urls], return_exceptions=True
        )
        for u, content in zip(js_urls, fetch_results):
            if isinstance(content, str):
                sources[u] = content

        seen = set()
        for src_url, content in sources.items():
            for name, pattern, severity in SECRET_PATTERNS:
                for match in re.finditer(pattern, content):
                    snippet = match.group(0)
                    if NOISE.search(snippet):
                        continue
                    key = (name, snippet[:40])
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(Finding(
                        title=f"Potential Secret Leaked: {name}",
                        description=f"A {name} was found in client-side code. Anyone can read this by viewing the page source.",
                        severity=severity,
                        category="Scanner / JS Secrets",
                        evidence=f"Source: {src_url}\nMatch: {_mask(snippet)}",
                        recommendation=f"Revoke this {name} immediately and move secrets to the server side. "
                                       "Never embed credentials in client-side JavaScript.",
                        url=src_url,
                    ))

    return findings


async def _fetch(client: httpx.AsyncClient, url: str) -> str:
    r = await client.get(url)
    return r.text[:200000]  # cap file size


def _mask(s: str) -> str:
    if len(s) <= 12:
        return s[:4] + "…"
    return s[:8] + "…" + s[-4:]
