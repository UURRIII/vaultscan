"""Host header injection detection (aggressive mode only)."""
from app.core.context import ScanContext
from app.core.finding import Finding
from app.core.severity import Severity

CANARY = "vaultscan-hhi.attacker.test"


async def run(ctx: ScanContext) -> list[Finding]:
    findings = []

    for header in ("Host", "X-Forwarded-Host"):
        try:
            r = await ctx.client.get(ctx.base_url, headers={header: CANARY},
                                     follow_redirects=False)
        except Exception:
            continue

        location = r.headers.get("location", "")
        reflected_in_redirect = CANARY in location
        reflected_in_body = CANARY in r.text[:50000]

        if reflected_in_redirect or reflected_in_body:
            where = "redirect Location header" if reflected_in_redirect else "response body"
            findings.append(Finding(
                title=f"Host Header Injection via {header}",
                description=f"A poisoned '{header}' value was reflected in the {where}. This can enable "
                            "password-reset poisoning, cache poisoning, and routing to attacker infrastructure.",
                severity=Severity.MEDIUM,
                category="Active / Host Header",
                evidence=f"Sent {header}: {CANARY}\nReflected in {where}: "
                         + (location if reflected_in_redirect else "(body)"),
                recommendation="Validate the Host header against an allowlist of expected domains. Build absolute "
                               "URLs from a fixed configured base, not from the request Host.",
                url=ctx.base_url,
                cvss=6.1,
            ))
            break  # one confirmation is enough

    return findings
