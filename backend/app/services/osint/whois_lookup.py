import asyncio
from datetime import datetime, timezone
from app.core.finding import Finding
from app.core.severity import Severity


async def run(ctx) -> list[Finding]:
    target = ctx.target
    domain = _strip_scheme(target)
    findings = []

    try:
        import whois
        data = await asyncio.wait_for(asyncio.to_thread(whois.whois, domain), timeout=15)
    except Exception as e:
        findings.append(Finding(
            title="WHOIS Lookup Failed",
            description="Could not retrieve WHOIS data.",
            severity=Severity.INFO,
            category="OSINT / WHOIS",
            evidence=str(e),
            recommendation="Manual WHOIS lookup may be required.",
        ))
        return findings

    if not data or not data.domain_name:
        return findings

    registrar = data.registrar or "Unknown"
    creation = _normalize_date(data.creation_date)
    expiry = _normalize_date(data.expiration_date)
    emails = data.emails if isinstance(data.emails, list) else ([data.emails] if data.emails else [])

    lines = [f"Registrar: {registrar}"]
    if creation:
        lines.append(f"Created: {creation.strftime('%Y-%m-%d')}")
    if expiry:
        lines.append(f"Expires: {expiry.strftime('%Y-%m-%d')}")
    if emails:
        lines.append(f"Contacts: {', '.join(set(emails))}")

    findings.append(Finding(
        title="WHOIS Information",
        description=f"WHOIS record for {domain}.",
        severity=Severity.INFO,
        category="OSINT / WHOIS",
        evidence="\n".join(lines),
        recommendation="Ensure registrant contact details are accurate. Consider enabling WHOIS privacy.",
    ))

    if expiry:
        now = datetime.now(timezone.utc)
        exp = expiry.replace(tzinfo=timezone.utc) if expiry.tzinfo is None else expiry
        days_left = (exp - now).days
        if days_left < 0:
            findings.append(Finding(
                title="Domain Expired",
                description="The domain registration has expired.",
                severity=Severity.CRITICAL,
                category="OSINT / WHOIS",
                evidence=f"Expiry date: {expiry.strftime('%Y-%m-%d')}",
                recommendation="Renew the domain immediately to prevent takeover.",
            ))
        elif days_left < 30:
            findings.append(Finding(
                title="Domain Expiring Soon",
                description=f"Domain expires in {days_left} days.",
                severity=Severity.HIGH,
                category="OSINT / WHOIS",
                evidence=f"Expiry date: {expiry.strftime('%Y-%m-%d')}",
                recommendation="Renew the domain before expiry.",
            ))

    if emails:
        findings.append(Finding(
            title="WHOIS Email Addresses Exposed",
            description="Registrant email addresses are publicly visible in WHOIS records.",
            severity=Severity.LOW,
            category="OSINT / WHOIS",
            evidence="\n".join(set(emails)),
            recommendation="Enable WHOIS privacy protection with your registrar.",
        ))

    return findings


def _strip_scheme(target: str) -> str:
    return target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]


def _normalize_date(val) -> datetime | None:
    if isinstance(val, list):
        val = val[0]
    if isinstance(val, datetime):
        return val
    return None
