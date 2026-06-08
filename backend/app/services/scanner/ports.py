import asyncio
import random
import socket
from app.core.finding import Finding
from app.core.severity import Severity

# Random high ports used as a sanity check. If these "respond", a tarpit /
# firewall / proxy is accepting every connection and results are unreliable.
CONTROL_PORTS = [random.randint(50000, 65000) for _ in range(3)]

# port: (service name, severity if exposed to the internet)
COMMON_PORTS = {
    21:    ("FTP",            Severity.MEDIUM),
    22:    ("SSH",            Severity.INFO),
    23:    ("Telnet",         Severity.HIGH),
    25:    ("SMTP",           Severity.INFO),
    53:    ("DNS",            Severity.INFO),
    80:    ("HTTP",           Severity.INFO),
    110:   ("POP3",           Severity.LOW),
    135:   ("MSRPC",          Severity.MEDIUM),
    139:   ("NetBIOS",        Severity.MEDIUM),
    143:   ("IMAP",           Severity.LOW),
    443:   ("HTTPS",          Severity.INFO),
    445:   ("SMB",            Severity.HIGH),
    1433:  ("MSSQL",          Severity.HIGH),
    1521:  ("Oracle DB",      Severity.HIGH),
    3306:  ("MySQL",          Severity.HIGH),
    3389:  ("RDP",            Severity.HIGH),
    5432:  ("PostgreSQL",     Severity.HIGH),
    5900:  ("VNC",            Severity.HIGH),
    6379:  ("Redis",          Severity.CRITICAL),
    8080:  ("HTTP-alt",       Severity.INFO),
    8443:  ("HTTPS-alt",      Severity.INFO),
    9200:  ("Elasticsearch",  Severity.CRITICAL),
    11211: ("Memcached",      Severity.HIGH),
    27017: ("MongoDB",        Severity.CRITICAL),
}

# Ports that should essentially never face the public internet.
DB_PORTS = {1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017, 5900}


async def run(ctx) -> list[Finding]:
    target = ctx.target
    host = _strip_scheme(target)
    findings = []

    try:
        ip = await asyncio.to_thread(socket.gethostbyname, host)
    except Exception:
        return findings

    sem = asyncio.Semaphore(100)

    # Sanity check: probe random high ports that should be closed.
    control_results = await asyncio.gather(*[_scan_port(ip, p, sem) for p in CONTROL_PORTS])
    control_open = [p for p in control_results if p is not None]
    if len(control_open) >= 2:
        # A device is accepting all connections — port results can't be trusted.
        return [Finding(
            title="Port Scan Inconclusive (filtering device detected)",
            description="Control ports that should be closed responded as open. A firewall, load balancer, "
                        "tarpit, or proxy appears to accept all TCP connections, so individual port results "
                        "would be unreliable and have been suppressed.",
            severity=Severity.INFO,
            category="Scanner / Ports",
            evidence=f"Control ports {CONTROL_PORTS} all responded as open on {ip}.",
            recommendation="Scan from a network with direct access, or use SYN/banner-grab techniques to confirm real open ports.",
        )]

    tasks = [_scan_port(ip, port, sem) for port in COMMON_PORTS]
    results = await asyncio.gather(*tasks)
    open_ports = [p for p in results if p is not None]

    if not open_ports:
        return findings

    open_ports.sort()
    port_lines = [f"{p}/tcp  {COMMON_PORTS[p][0]}" for p in open_ports]
    findings.append(Finding(
        title=f"Open Ports Detected ({len(open_ports)})",
        description=f"Discovered {len(open_ports)} open TCP ports on {host} ({ip}).",
        severity=Severity.INFO,
        category="Scanner / Ports",
        evidence="\n".join(port_lines),
        recommendation="Close or firewall any port that does not need public exposure.",
    ))

    for port in open_ports:
        service, severity = COMMON_PORTS[port]
        if port in DB_PORTS:
            findings.append(Finding(
                title=f"Exposed Database/Service Port: {port} ({service})",
                description=f"{service} is directly reachable on port {port}. Databases and caches should never be exposed to the internet.",
                severity=severity,
                category="Scanner / Ports",
                evidence=f"{ip}:{port} ({service}) is open",
                recommendation=f"Block port {port} at the firewall. Bind {service} to localhost or a private network only.",
            ))
        elif port == 23:
            findings.append(Finding(
                title="Telnet Service Exposed",
                description="Telnet transmits credentials in cleartext and is obsolete.",
                severity=Severity.HIGH,
                category="Scanner / Ports",
                evidence=f"{ip}:23 (Telnet) is open",
                recommendation="Disable Telnet entirely and use SSH instead.",
            ))
        elif port in (445, 139, 135):
            findings.append(Finding(
                title=f"SMB/NetBIOS Port Exposed: {port} ({service})",
                description=f"{service} on port {port} is exposed. SMB has a long history of critical vulnerabilities (e.g. EternalBlue).",
                severity=severity,
                category="Scanner / Ports",
                evidence=f"{ip}:{port} ({service}) is open",
                recommendation=f"Never expose {service} to the internet. Restrict to internal networks via VPN.",
            ))

    return findings


async def _scan_port(ip: str, port: int, sem: asyncio.Semaphore) -> int | None:
    async with sem:
        try:
            fut = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(fut, timeout=2.0)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return port
        except Exception:
            return None


def _strip_scheme(target: str) -> str:
    return target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
