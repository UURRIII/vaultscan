import asyncio
import dns.asyncresolver
import dns.resolver
import dns.query
import dns.zone
from app.core.finding import Finding
from app.core.severity import Severity

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]


async def run(ctx) -> list[Finding]:
    target = ctx.target
    findings = []
    domain = _strip_scheme(target)
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 8

    records: dict[str, list[str]] = {}
    for rtype in RECORD_TYPES:
        try:
            answers = await resolver.resolve(domain, rtype)
            records[rtype] = [str(r) for r in answers]
        except Exception:
            records[rtype] = []

    # Compile DNS map as INFO finding
    lines = []
    for rtype, vals in records.items():
        if vals:
            lines.append(f"{rtype}: {', '.join(vals[:5])}")

    if lines:
        findings.append(Finding(
            title="DNS Records Enumeration",
            description=f"DNS records found for {domain}.",
            severity=Severity.INFO,
            category="OSINT / DNS",
            evidence="\n".join(lines),
            recommendation="Review exposed records. Avoid leaking internal infrastructure names.",
        ))

    # CAA records — restrict which CAs may issue certs for the domain.
    try:
        caa = await resolver.resolve(domain, "CAA")
        caa_vals = [str(r) for r in caa]
    except Exception:
        caa_vals = []
    if not caa_vals:
        findings.append(Finding(
            title="Missing CAA Record",
            description="No CAA record found. CAA records restrict which Certificate Authorities can issue "
                        "certificates for your domain, mitigating mis-issuance.",
            severity=Severity.LOW,
            category="OSINT / DNS",
            evidence=f"No CAA record on {domain}",
            recommendation='Add a CAA record, e.g. 0 issue "letsencrypt.org"',
        ))

    # DNSSEC — is the zone signed?
    try:
        dnskey = await resolver.resolve(domain, "DNSKEY")
        has_dnssec = len(dnskey) > 0
    except Exception:
        has_dnssec = False
    if not has_dnssec:
        findings.append(Finding(
            title="DNSSEC Not Enabled",
            description="The zone is not DNSSEC-signed, leaving it more exposed to DNS spoofing and cache poisoning.",
            severity=Severity.LOW,
            category="OSINT / DNS",
            evidence=f"No DNSKEY record on {domain}",
            recommendation="Enable DNSSEC at your DNS provider to cryptographically sign DNS responses.",
        ))

    # SPF check
    txt_records = records.get("TXT", [])
    has_spf = any("v=spf1" in r for r in txt_records)
    has_dmarc = False
    try:
        dmarc = await resolver.resolve(f"_dmarc.{domain}", "TXT")
        has_dmarc = any("v=DMARC1" in str(r) for r in dmarc)
    except Exception:
        pass

    if not has_spf:
        findings.append(Finding(
            title="Missing SPF Record",
            description="No SPF (Sender Policy Framework) record found. Attackers can send emails impersonating this domain.",
            severity=Severity.MEDIUM,
            category="OSINT / DNS",
            evidence=f"No TXT record with 'v=spf1' found on {domain}",
            recommendation="Add an SPF record: v=spf1 include:_spf.yourmailprovider.com ~all",
        ))

    if not has_dmarc:
        findings.append(Finding(
            title="Missing DMARC Record",
            description="No DMARC record found. Without DMARC, email spoofing attacks are more effective.",
            severity=Severity.MEDIUM,
            category="OSINT / DNS",
            evidence=f"No TXT record found at _dmarc.{domain}",
            recommendation="Add a DMARC record: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com",
        ))

    # Zone transfer attempt — actually try an AXFR against each nameserver.
    ns_records = records.get("NS", [])
    for ns in ns_records[:3]:
        ns_host = ns.rstrip(".")
        try:
            zone = await asyncio.wait_for(
                asyncio.to_thread(_try_axfr, ns_host, domain),
                timeout=6,
            )
        except Exception:
            zone = None

        if zone:
            record_count = len(zone)
            findings.append(Finding(
                title="DNS Zone Transfer Allowed (AXFR)",
                description=f"The nameserver {ns_host} allowed a full zone transfer, leaking every DNS record "
                            f"for {domain}. This exposes the complete internal infrastructure map.",
                severity=Severity.HIGH,
                category="OSINT / DNS",
                evidence=f"Nameserver: {ns_host}\nRecords transferred: {record_count}",
                recommendation="Restrict zone transfers (allow-transfer) to trusted secondary nameservers only.",
                cvss=7.5,
            ))
            break

    return findings


def _try_axfr(nameserver: str, domain: str):
    """Attempt a real AXFR. Returns the zone on success, None otherwise."""
    try:
        ns_ip = dns.resolver.resolve(nameserver, "A")[0].to_text()
        xfr = dns.query.xfr(ns_ip, domain, lifetime=5)
        zone = dns.zone.from_xfr(xfr)
        return zone
    except Exception:
        return None


def _strip_scheme(target: str) -> str:
    return target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
