import httpx
import re
from bs4 import BeautifulSoup
from app.core.finding import Finding
from app.core.severity import Severity

FINGERPRINTS = {
    "WordPress": [r"wp-content", r"wp-includes", r"WordPress"],
    "Drupal": [r"Drupal", r"/sites/default/", r"drupal.js"],
    "Joomla": [r"Joomla!", r"/components/com_"],
    "Laravel": [r"laravel_session", r"Laravel"],
    "Django": [r"csrfmiddlewaretoken", r"Django"],
    "React": [r"__REACT_DEVTOOLS", r"react-root", r"_reactFiber"],
    "Vue.js": [r"__vue__", r"data-v-"],
    "Angular": [r"ng-version", r"angular"],
    "jQuery": [r"jquery", r"jQuery"],
    "Bootstrap": [r"bootstrap.min.css", r"bootstrap.min.js"],
    "Next.js": [r"__NEXT_DATA__", r"_next/static"],
    "Nginx": [r"nginx"],
    "Apache": [r"Apache"],
    "PHP": [r"X-Powered-By: PHP", r"\.php"],
    "ASP.NET": [r"ASP.NET", r"__VIEWSTATE"],
}


async def run(ctx) -> list[Finding]:
    target = ctx.target
    url = target if target.startswith("http") else f"https://{target}"
    findings = []

    try:
        async with httpx.AsyncClient(timeout=12, follow_redirects=True) as client:
            r = await client.get(url, headers={"User-Agent": "Mozilla/5.0 VaultScan/1.0"})
    except Exception as e:
        findings.append(Finding(
            title="HTTP Fetch Failed",
            description=f"Could not fetch {url}.",
            severity=Severity.INFO,
            category="OSINT / Technologies",
            evidence=str(e),
            recommendation="Verify the target is reachable and serves HTTP/HTTPS.",
        ))
        return findings

    headers_str = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
    body = r.text[:50000]
    combined = headers_str + "\n" + body

    detected = []
    for tech, patterns in FINGERPRINTS.items():
        if any(re.search(p, combined, re.IGNORECASE) for p in patterns):
            detected.append(tech)

    if detected:
        findings.append(Finding(
            title=f"Technologies Detected ({len(detected)})",
            description="Technologies identified via HTTP headers and HTML fingerprinting.",
            severity=Severity.INFO,
            category="OSINT / Technologies",
            evidence=", ".join(detected),
            recommendation="Avoid disclosing specific version numbers. Remove unnecessary headers.",
            url=url,
        ))

    # Version disclosure in headers
    version_headers = ["Server", "X-Powered-By", "X-Generator", "X-AspNet-Version"]
    for h in version_headers:
        val = r.headers.get(h)
        if val and any(c.isdigit() for c in val):
            findings.append(Finding(
                title=f"Version Disclosure: {h}",
                description=f"The '{h}' header reveals software version information.",
                severity=Severity.LOW,
                category="OSINT / Technologies",
                evidence=f"{h}: {val}",
                recommendation=f"Remove or obscure the '{h}' header in your server configuration.",
                url=url,
            ))

    return findings
