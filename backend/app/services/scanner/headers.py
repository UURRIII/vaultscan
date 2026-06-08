import httpx
from app.core.finding import Finding
from app.core.severity import Severity

SECURITY_HEADERS = [
    (
        "Content-Security-Policy",
        Severity.HIGH,
        "CSP prevents XSS attacks by restricting which resources the browser can load.",
        "Add a Content-Security-Policy header: Content-Security-Policy: default-src 'self'",
    ),
    (
        "Strict-Transport-Security",
        Severity.HIGH,
        "HSTS forces browsers to use HTTPS, preventing downgrade attacks.",
        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    ),
    (
        "X-Frame-Options",
        Severity.MEDIUM,
        "Missing X-Frame-Options allows clickjacking attacks via iframes.",
        "Add: X-Frame-Options: DENY (or use CSP frame-ancestors directive)",
    ),
    (
        "X-Content-Type-Options",
        Severity.MEDIUM,
        "Missing header allows MIME-type sniffing, which can lead to XSS.",
        "Add: X-Content-Type-Options: nosniff",
    ),
    (
        "Referrer-Policy",
        Severity.LOW,
        "Without Referrer-Policy, sensitive URL data may leak to third parties.",
        "Add: Referrer-Policy: strict-origin-when-cross-origin",
    ),
    (
        "Permissions-Policy",
        Severity.LOW,
        "Without Permissions-Policy, the page can access sensitive browser APIs unnecessarily.",
        "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
    ),
]


async def run(ctx) -> list[Finding]:
    target = ctx.target
    url = target if target.startswith("http") else f"https://{target}"
    findings = []

    try:
        async with httpx.AsyncClient(timeout=12, follow_redirects=True) as client:
            r = await client.get(url, headers={"User-Agent": "Mozilla/5.0 VaultScan/1.0"})
    except Exception as e:
        findings.append(Finding(
            title="Headers Check Failed",
            description=f"Could not reach {url} to inspect headers.",
            severity=Severity.INFO,
            category="Scanner / Headers",
            evidence=str(e),
            recommendation="Verify the target is reachable.",
        ))
        return findings

    for header_name, severity, description, recommendation in SECURITY_HEADERS:
        if header_name.lower() not in {k.lower() for k in r.headers}:
            findings.append(Finding(
                title=f"Missing Header: {header_name}",
                description=description,
                severity=severity,
                category="Scanner / Headers",
                evidence=f"Header '{header_name}' not present in response.",
                recommendation=recommendation,
                url=url,
            ))

    # Check for insecure cookie flags
    for set_cookie in r.headers.get_list("set-cookie") if hasattr(r.headers, "get_list") else []:
        lower = set_cookie.lower()
        if "httponly" not in lower:
            findings.append(Finding(
                title="Cookie Missing HttpOnly Flag",
                description="A cookie without HttpOnly can be accessed by JavaScript, enabling session theft via XSS.",
                severity=Severity.MEDIUM,
                category="Scanner / Headers",
                evidence=f"Set-Cookie: {set_cookie[:120]}",
                recommendation="Add the HttpOnly flag to all sensitive cookies.",
                url=url,
            ))
            break
        if "secure" not in lower:
            findings.append(Finding(
                title="Cookie Missing Secure Flag",
                description="A cookie without the Secure flag can be transmitted over HTTP.",
                severity=Severity.MEDIUM,
                category="Scanner / Headers",
                evidence=f"Set-Cookie: {set_cookie[:120]}",
                recommendation="Add the Secure flag to all cookies.",
                url=url,
            ))
            break

    return findings
