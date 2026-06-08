import asyncio
import ssl
import socket
from datetime import datetime, timezone
from app.core.finding import Finding
from app.core.severity import Severity


async def run(ctx) -> list[Finding]:
    target = ctx.target
    domain = _strip_scheme(target)
    findings = []

    try:
        cert_info = await asyncio.wait_for(asyncio.to_thread(_get_cert, domain), timeout=10)
    except Exception as e:
        findings.append(Finding(
            title="SSL/TLS Check Failed",
            description=f"Could not connect via HTTPS to {domain}.",
            severity=Severity.MEDIUM,
            category="OSINT / SSL",
            evidence=str(e),
            recommendation="Ensure HTTPS is configured and the certificate is valid.",
        ))
        return findings

    subject = dict(x[0] for x in cert_info.get("subject", []))
    issuer = dict(x[0] for x in cert_info.get("issuer", []))
    not_after = cert_info.get("notAfter", "")
    sans = [v for t, v in cert_info.get("subjectAltName", []) if t == "DNS"]
    protocol = cert_info.get("protocol", "")

    expiry = None
    if not_after:
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        except ValueError:
            pass

    lines = [
        f"Subject: {subject.get('commonName', 'N/A')}",
        f"Issuer: {issuer.get('organizationName', issuer.get('commonName', 'N/A'))}",
        f"Expires: {not_after}",
        f"Protocol: {protocol}",
    ]
    if sans:
        lines.append(f"SANs: {', '.join(sans[:8])}")

    findings.append(Finding(
        title="SSL Certificate Information",
        description=f"TLS certificate details for {domain}.",
        severity=Severity.INFO,
        category="OSINT / SSL",
        evidence="\n".join(lines),
        recommendation="Ensure certificate is renewed before expiry and uses a trusted CA.",
    ))

    if expiry:
        now = datetime.now(timezone.utc)
        days_left = (expiry - now).days
        if days_left < 0:
            findings.append(Finding(
                title="SSL Certificate Expired",
                description="The TLS certificate has expired. Browsers will show security warnings.",
                severity=Severity.CRITICAL,
                category="OSINT / SSL",
                evidence=f"Expired: {not_after}",
                recommendation="Renew the SSL certificate immediately.",
            ))
        elif days_left < 30:
            findings.append(Finding(
                title="SSL Certificate Expiring Soon",
                description=f"Certificate expires in {days_left} days.",
                severity=Severity.HIGH,
                category="OSINT / SSL",
                evidence=f"Expiry: {not_after}",
                recommendation="Renew the certificate before it expires.",
            ))

    if protocol and ("TLSv1 " in protocol or "TLSv1.1" in protocol):
        findings.append(Finding(
            title="Deprecated TLS Version",
            description=f"Server supports {protocol}, which is deprecated and vulnerable.",
            severity=Severity.HIGH,
            category="OSINT / SSL",
            evidence=f"Protocol: {protocol}",
            recommendation="Disable TLS 1.0 and 1.1. Use TLS 1.2 minimum, preferably TLS 1.3.",
        ))

    return findings


def _get_cert(domain: str) -> dict:
    ctx = ssl.create_default_context()
    with socket.create_connection((domain, 443), timeout=8) as sock:
        with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
            cert = ssock.getpeercert()
            cert["protocol"] = ssock.version()
            return cert


def _strip_scheme(target: str) -> str:
    return target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
