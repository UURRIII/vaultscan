import asyncio
import httpx
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
from app.core.finding import Finding
from app.core.severity import Severity

# Common parameter names used for redirects.
REDIRECT_PARAMS = ["next", "url", "redirect", "redirect_uri", "redirect_url",
                   "return", "return_url", "returnUrl", "goto", "dest",
                   "destination", "continue", "r", "u", "link", "to"]

CANARY = "https://vaultscan-canary.example.com"


async def run(ctx) -> list[Finding]:
    target = ctx.target
    base = target if target.startswith("http") else f"https://{target}"
    findings = []

    async with httpx.AsyncClient(timeout=8, follow_redirects=False, verify=False,
                                  headers={"User-Agent": "Mozilla/5.0 VaultScan/1.0"}) as client:
        # Gather candidate endpoints: homepage + links that already use redirect-style params.
        candidates = await _gather_candidates(client, base)

        tested = 0
        for endpoint in candidates:
            if tested >= 12:
                break
            for param in REDIRECT_PARAMS:
                if tested >= 12:
                    break
                test_url = _inject(endpoint, param, CANARY)
                if not test_url:
                    continue
                tested += 1
                try:
                    r = await client.get(test_url)
                except Exception:
                    continue
                location = r.headers.get("location", "")
                if r.status_code in (301, 302, 303, 307, 308) and CANARY in location:
                    findings.append(Finding(
                        title=f"Open Redirect via '{param}' parameter",
                        description=f"The '{param}' parameter redirects to an externally supplied URL without validation. "
                                    "Attackers can use this for phishing or to bypass redirect-based security checks.",
                        severity=Severity.MEDIUM,
                        category="Scanner / Open Redirect",
                        evidence=f"Request: {test_url}\nResponse: HTTP {r.status_code} → Location: {location}",
                        recommendation="Validate redirect targets against an allowlist of permitted destinations.",
                        url=test_url,
                        cvss=6.1,
                    )
                    )
                    return findings  # one confirmed finding is enough to flag the issue

    return findings


async def _gather_candidates(client: httpx.AsyncClient, base: str) -> list[str]:
    candidates = [base]
    try:
        r = await client.get(base)
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.find_all("a", href=True):
            href = a["href"]
            qs = parse_qs(urlparse(href).query)
            if any(p in qs for p in REDIRECT_PARAMS):
                full = href if href.startswith("http") else base.rstrip("/") + "/" + href.lstrip("/")
                candidates.append(full)
    except Exception:
        pass
    return list(dict.fromkeys(candidates))[:5]


def _inject(url: str, param: str, value: str) -> str | None:
    parsed = urlparse(url)
    sep = "&" if parsed.query else "?"
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}{sep}{param}={value}"
