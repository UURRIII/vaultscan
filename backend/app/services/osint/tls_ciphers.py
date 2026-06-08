"""Probe supported TLS protocol versions and detect weak ones."""
import asyncio
import socket
import ssl
from app.core.context import ScanContext
from app.core.finding import Finding
from app.core.severity import Severity

# (label, ssl protocol constant or None for context-based)
PROTOCOLS = [
    ("TLSv1.0", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
]

WEAK = {"TLSv1.0", "TLSv1.1"}


async def run(ctx: ScanContext) -> list[Finding]:
    findings = []
    host = ctx.host

    supported = []
    for label, version in PROTOCOLS:
        ok = await asyncio.to_thread(_test_protocol, host, version)
        if ok:
            supported.append(label)

    if not supported:
        return findings

    findings.append(Finding(
        title=f"Supported TLS Versions: {', '.join(supported)}",
        description="TLS protocol versions the server negotiated.",
        severity=Severity.INFO,
        category="OSINT / TLS",
        evidence=", ".join(supported),
        recommendation="Support only TLS 1.2 and 1.3.",
    ))

    weak_supported = [p for p in supported if p in WEAK]
    if weak_supported:
        findings.append(Finding(
            title=f"Weak TLS Version Enabled: {', '.join(weak_supported)}",
            description=f"The server accepts {', '.join(weak_supported)}, which are deprecated and vulnerable "
                        "to attacks like BEAST and POODLE.",
            severity=Severity.MEDIUM,
            category="OSINT / TLS",
            evidence=f"Negotiated: {', '.join(weak_supported)}",
            recommendation="Disable TLS 1.0 and 1.1 in the server configuration.",
            cvss=5.9,
        ))

    if "TLSv1.3" not in supported:
        findings.append(Finding(
            title="TLS 1.3 Not Supported",
            description="The server does not support TLS 1.3, the most secure and performant TLS version.",
            severity=Severity.LOW,
            category="OSINT / TLS",
            evidence=f"Supported: {', '.join(supported)}",
            recommendation="Enable TLS 1.3 for stronger security and better performance.",
        ))

    return findings


def _test_protocol(host: str, version) -> bool:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = version
        ctx.maximum_version = version
    except ValueError:
        return False
    try:
        with socket.create_connection((host, 443), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:
        return False
