import httpx
from app.core.finding import Finding
from app.core.severity import Severity

RISKY_METHODS = {
    "PUT":    (Severity.HIGH,   "PUT may allow uploading arbitrary files to the server."),
    "DELETE": (Severity.HIGH,   "DELETE may allow removing resources from the server."),
    "TRACE":  (Severity.MEDIUM, "TRACE enables Cross-Site Tracing (XST) attacks."),
    "TRACK":  (Severity.MEDIUM, "TRACK (IIS) enables Cross-Site Tracing attacks."),
    "CONNECT":(Severity.MEDIUM, "CONNECT may allow the server to be used as a proxy."),
    "PATCH":  (Severity.LOW,    "PATCH allows partial resource modification."),
}


async def run(ctx) -> list[Finding]:
    target = ctx.target
    url = target if target.startswith("http") else f"https://{target}"
    findings = []

    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as client:
            r = await client.request("OPTIONS", url, headers={"User-Agent": "Mozilla/5.0 VaultScan/1.0"})
    except Exception:
        return findings

    allow = r.headers.get("Allow", "") or r.headers.get("Access-Control-Allow-Methods", "")
    if not allow:
        return findings

    methods = {m.strip().upper() for m in allow.split(",") if m.strip()}

    findings.append(Finding(
        title="Allowed HTTP Methods",
        description="HTTP methods advertised by the server via OPTIONS.",
        severity=Severity.INFO,
        category="Scanner / HTTP Methods",
        evidence=f"Allow: {', '.join(sorted(methods))}",
        recommendation="Disable any HTTP method that is not strictly required.",
        url=url,
    ))

    for method in methods:
        if method in RISKY_METHODS:
            severity, desc = RISKY_METHODS[method]
            findings.append(Finding(
                title=f"Risky HTTP Method Enabled: {method}",
                description=desc,
                severity=severity,
                category="Scanner / HTTP Methods",
                evidence=f"Server advertises '{method}' in Allow header.",
                recommendation=f"Disable the {method} method unless explicitly needed by your application.",
                url=url,
            ))

    return findings
