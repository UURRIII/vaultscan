import httpx
import re
from bs4 import BeautifulSoup
from app.core.finding import Finding
from app.core.severity import Severity

SENSITIVE_COMMENT_PATTERNS = [
    r"password\s*[:=]",
    r"api[_-]?key\s*[:=]",
    r"secret\s*[:=]",
    r"token\s*[:=]",
    r"todo\s*:\s*(fix|remove|hack|temp)",
    r"private\s*key",
    r"aws[_-]access",
]

SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning.*mysql",
    r"unclosed quotation mark",
    r"pg::syntaxerror",
    r"sqlite3::exception",
    r"odbc.*driver.*error",
    r"microsoft ole db provider",
    r"ora-\d{5}",
]


async def run(ctx) -> list[Finding]:
    target = ctx.target
    base = target if target.startswith("http") else f"https://{target}"
    base = base.rstrip("/")
    findings = []

    async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False,
                                  headers={"User-Agent": "Mozilla/5.0 VaultScan/1.0"}) as client:
        # Robots.txt — look for sensitive disallowed paths
        try:
            r = await client.get(f"{base}/robots.txt")
            if r.status_code == 200:
                sensitive_paths = [
                    line.replace("Disallow:", "").strip()
                    for line in r.text.splitlines()
                    if line.lower().startswith("disallow:")
                    and any(k in line.lower() for k in ("admin", "backup", "private", "secret", "config", "db", "api"))
                ]
                if sensitive_paths:
                    findings.append(Finding(
                        title="Sensitive Paths in robots.txt",
                        description="robots.txt disallows crawling of sensitive paths, inadvertently revealing them.",
                        severity=Severity.LOW,
                        category="Scanner / Info Disclosure",
                        evidence="Sensitive Disallow entries:\n" + "\n".join(sensitive_paths),
                        recommendation="Do not list sensitive paths in robots.txt. Security by obscurity is not security.",
                        url=f"{base}/robots.txt",
                    ))
        except Exception:
            pass

        # HTML comments with sensitive content
        try:
            r = await client.get(base)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "html.parser")
                comments = [str(c) for c in soup.find_all(string=lambda t: isinstance(t, __import__("bs4").Comment))]
                sensitive = []
                for comment in comments:
                    for pattern in SENSITIVE_COMMENT_PATTERNS:
                        if re.search(pattern, comment, re.IGNORECASE):
                            sensitive.append(comment[:200])
                            break

                if sensitive:
                    findings.append(Finding(
                        title="Sensitive Data in HTML Comments",
                        description="HTML comments contain potentially sensitive information visible to anyone who views the page source.",
                        severity=Severity.MEDIUM,
                        category="Scanner / Info Disclosure",
                        evidence="\n---\n".join(sensitive[:5]),
                        recommendation="Remove all sensitive information from HTML comments before deploying to production.",
                        url=base,
                    ))

                # SQL errors in normal page load
                body_lower = r.text.lower()
                for pattern in SQL_ERROR_PATTERNS:
                    if re.search(pattern, body_lower):
                        findings.append(Finding(
                            title="SQL Error Exposed in Response",
                            description="The application returns SQL error messages. This confirms a database is in use and leaks schema info.",
                            severity=Severity.HIGH,
                            category="Scanner / Info Disclosure",
                            evidence=re.search(pattern, r.text, re.IGNORECASE).group(0)[:300],
                            recommendation="Disable verbose error output in production. Use a generic error page.",
                            url=base,
                        ))
                        break
        except Exception:
            pass

        # Error page info disclosure
        try:
            r = await client.get(f"{base}/this-page-definitely-does-not-exist-vaultscan")
            if r.status_code == 404:
                tech_leaks = []
                for pattern in [r"nginx/[\d.]+", r"apache/[\d.]+", r"php/[\d.]+", r"express", r"django", r"laravel"]:
                    m = re.search(pattern, r.text, re.IGNORECASE)
                    if m:
                        tech_leaks.append(m.group(0))
                if tech_leaks:
                    findings.append(Finding(
                        title="Technology Leak in Error Page",
                        description="The 404 error page reveals server/framework version information.",
                        severity=Severity.LOW,
                        category="Scanner / Info Disclosure",
                        evidence=f"Detected in 404 response: {', '.join(tech_leaks)}",
                        recommendation="Configure custom error pages that don't reveal technology details.",
                        url=f"{base}/404",
                    ))
        except Exception:
            pass

    return findings
