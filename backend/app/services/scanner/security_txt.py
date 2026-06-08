import httpx
from app.core.finding import Finding
from app.core.severity import Severity


async def run(ctx) -> list[Finding]:
    target = ctx.target
    base = target if target.startswith("http") else f"https://{target}"
    base = base.rstrip("/")
    findings = []

    locations = [f"{base}/.well-known/security.txt", f"{base}/security.txt"]

    async with httpx.AsyncClient(timeout=8, follow_redirects=True, verify=False,
                                  headers={"User-Agent": "Mozilla/5.0 VaultScan/1.0"}) as client:
        found = False
        for loc in locations:
            try:
                r = await client.get(loc)
            except Exception:
                continue
            if r.status_code == 200 and ("contact:" in r.text.lower() or "-----begin" in r.text.lower()):
                found = True
                fields = [line for line in r.text.splitlines()
                          if line.strip() and not line.strip().startswith("#")][:8]
                findings.append(Finding(
                    title="security.txt Present",
                    description="The site publishes a security.txt file, signalling a responsible disclosure process.",
                    severity=Severity.INFO,
                    category="Scanner / security.txt",
                    evidence=f"Location: {loc}\n" + "\n".join(fields),
                    recommendation="Ensure the contact and expiry fields are kept up to date.",
                    url=loc,
                ))
                break

        if not found:
            findings.append(Finding(
                title="Missing security.txt",
                description="No security.txt file was found. Security researchers have no standard channel to report vulnerabilities.",
                severity=Severity.LOW,
                category="Scanner / security.txt",
                evidence="Checked /.well-known/security.txt and /security.txt — not found.",
                recommendation="Publish a security.txt file at /.well-known/security.txt with a Contact field. See https://securitytxt.org",
            ))

    return findings
