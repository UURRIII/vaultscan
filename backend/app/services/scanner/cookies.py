"""Analyze cookie security attributes."""
from app.core.context import ScanContext
from app.core.finding import Finding
from app.core.severity import Severity


async def run(ctx: ScanContext) -> list[Finding]:
    findings = []
    try:
        r = await ctx.client.get(ctx.base_url)
    except Exception:
        return findings

    set_cookies = r.headers.get_list("set-cookie") if hasattr(r.headers, "get_list") else []
    if not set_cookies:
        raw = r.headers.get("set-cookie")
        set_cookies = [raw] if raw else []

    if not set_cookies:
        return findings

    for cookie in set_cookies:
        name = cookie.split("=")[0].strip()
        low = cookie.lower()
        issues = []
        if "secure" not in low:
            issues.append("missing Secure")
        if "httponly" not in low:
            issues.append("missing HttpOnly")
        if "samesite" not in low:
            issues.append("missing SameSite")

        if issues:
            sensitive = any(k in name.lower() for k in ["sess", "auth", "token", "login", "sid"])
            severity = Severity.MEDIUM if sensitive else Severity.LOW
            findings.append(Finding(
                title=f"Insecure Cookie: {name}",
                description=f"Cookie '{name}' is set without important security flags ({', '.join(issues)}). "
                            "This increases the risk of session hijacking and CSRF.",
                severity=severity,
                category="Scanner / Cookies",
                evidence=cookie[:200],
                recommendation="Set Secure, HttpOnly and SameSite=Lax/Strict on session cookies.",
                url=ctx.base_url,
            ))

    return findings
