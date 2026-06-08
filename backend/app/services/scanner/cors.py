import httpx
from app.core.finding import Finding
from app.core.severity import Severity

EVIL_ORIGIN = "https://evil-attacker.com"


async def run(ctx) -> list[Finding]:
    target = ctx.target
    url = target if target.startswith("http") else f"https://{target}"
    findings = []

    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as client:
            r = await client.get(url, headers={
                "Origin": EVIL_ORIGIN,
                "User-Agent": "Mozilla/5.0 VaultScan/1.0",
            })
    except Exception:
        return findings

    acao = r.headers.get("access-control-allow-origin", "")
    acac = r.headers.get("access-control-allow-credentials", "").lower()

    if acao == "*" and acac == "true":
        findings.append(Finding(
            title="CORS: Wildcard with Credentials",
            description="CRITICAL misconfiguration: Access-Control-Allow-Origin: * combined with Allow-Credentials: true. "
                        "Browsers block this, but it indicates a fundamentally broken CORS policy.",
            severity=Severity.HIGH,
            category="Scanner / CORS",
            evidence=f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
            recommendation="Never use wildcard origin with credentials. Use specific trusted origins.",
            url=url,
        ))
    elif acao == EVIL_ORIGIN:
        if acac == "true":
            findings.append(Finding(
                title="CORS: Arbitrary Origin Reflected with Credentials",
                description="The server reflects arbitrary Origin headers and allows credentials. "
                            "Attackers can make authenticated cross-origin requests from any domain.",
                severity=Severity.CRITICAL,
                category="Scanner / CORS",
                evidence=f"Sent Origin: {EVIL_ORIGIN}\nResponse ACAO: {acao}\nACCC: {acac}",
                recommendation="Validate Origin against an explicit allowlist. Never reflect arbitrary origins.",
                url=url,
            ))
        else:
            findings.append(Finding(
                title="CORS: Arbitrary Origin Reflected",
                description="The server reflects arbitrary Origin headers, allowing cross-origin reads of non-credentialed responses.",
                severity=Severity.MEDIUM,
                category="Scanner / CORS",
                evidence=f"Sent Origin: {EVIL_ORIGIN}\nResponse ACAO: {acao}",
                recommendation="Validate Origin against an explicit allowlist.",
                url=url,
            ))
    elif acao == "*":
        findings.append(Finding(
            title="CORS: Wildcard Origin",
            description="Access-Control-Allow-Origin: * allows any website to read responses. "
                        "Acceptable for public APIs, but dangerous for authenticated endpoints.",
            severity=Severity.LOW,
            category="Scanner / CORS",
            evidence=f"Access-Control-Allow-Origin: *",
            recommendation="If the endpoint handles sensitive data, restrict to specific origins.",
            url=url,
        ))

    return findings
