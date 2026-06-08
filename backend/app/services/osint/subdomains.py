import asyncio
import httpx
import dns.asyncresolver
from app.core.finding import Finding
from app.core.severity import Severity

WORDLIST = [
    "www", "mail", "smtp", "pop", "imap", "ftp", "api", "dev", "staging",
    "test", "admin", "portal", "vpn", "remote", "ns1", "ns2", "mx", "blog",
    "shop", "store", "app", "mobile", "cdn", "static", "assets", "media",
    "backup", "db", "database", "internal", "intranet", "git", "gitlab",
    "jenkins", "jira", "confluence", "monitor", "dashboard", "panel",
]

SENSITIVE = {"dev", "staging", "test", "admin", "internal", "intranet",
             "backup", "db", "database", "git", "gitlab", "jenkins", "panel"}


async def run(ctx) -> list[Finding]:
    target = ctx.target
    domain = _strip_scheme(target)
    findings = []
    found: dict[str, str] = {}

    # Passive: certificate transparency via crt.sh
    ct_subs = await _crtsh(domain)
    for sub in ct_subs:
        found[sub] = "crt.sh"

    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 4

    # Wildcard DNS detection: if random nonsense hostnames resolve, *.domain is
    # a catch-all and brute-force results would be meaningless.
    wildcard_ips = await _detect_wildcard(domain, resolver)

    # Active: DNS brute force
    tasks = [_resolve(f"{w}.{domain}", resolver) for w in WORDLIST]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    brute_found: dict[str, str] = {}
    for w, result in zip(WORDLIST, results):
        if isinstance(result, str) and result not in wildcard_ips:
            brute_found[f"{w}.{domain}"] = result
            found[f"{w}.{domain}"] = result

    if wildcard_ips:
        findings.append(Finding(
            title="Wildcard DNS Detected",
            description=f"*.{domain} resolves to a catch-all address, so brute-forced subdomain names "
                        "cannot be confirmed as real services. Only certificate-transparency results are reported.",
            severity=Severity.INFO,
            category="OSINT / Subdomains",
            evidence=f"Wildcard address(es): {', '.join(sorted(wildcard_ips))}",
            recommendation="No action needed; this is informational and affects scan interpretation.",
        ))

    if not found:
        return findings

    findings.append(Finding(
        title=f"Subdomains Discovered ({len(found)})",
        description=f"Found {len(found)} subdomains for {domain} via certificate transparency and DNS.",
        severity=Severity.INFO,
        category="OSINT / Subdomains",
        evidence="\n".join(sorted(found.keys())[:30]),
        recommendation="Audit all exposed subdomains. Remove or restrict access to unused ones.",
    ))

    # Only flag sensitive names that were actually confirmed (not wildcard noise).
    confirmed = {} if wildcard_ips else brute_found
    confirmed.update({s: found[s] for s in found if found.get(s) == "crt.sh"})
    sensitive_found = [s for s in confirmed if any(k in s.split(".")[0] for k in SENSITIVE)]

    for sub in sensitive_found:
        findings.append(Finding(
            title=f"Sensitive Subdomain Exposed: {sub}",
            description="A subdomain with a sensitive name is publicly resolvable.",
            severity=Severity.MEDIUM,
            category="OSINT / Subdomains",
            evidence=f"{sub} → {found[sub]}",
            recommendation="Restrict access to internal/staging/admin subdomains via firewall or authentication.",
            url=f"https://{sub}",
        ))

    return findings


async def _detect_wildcard(domain: str, resolver) -> set[str]:
    """Resolve random improbable hostnames; any returned IPs indicate wildcard DNS."""
    import uuid
    probes = [f"{uuid.uuid4().hex[:12]}.{domain}" for _ in range(2)]
    ips: set[str] = set()
    results = await asyncio.gather(*[_resolve(p, resolver) for p in probes], return_exceptions=True)
    for r in results:
        if isinstance(r, str):
            ips.add(r)
    return ips


async def _crtsh(domain: str) -> list[str]:
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(f"https://crt.sh/?q=%.{domain}&output=json")
            if r.status_code == 200:
                data = r.json()
                subs = set()
                for entry in data:
                    name = entry.get("name_value", "")
                    for line in name.splitlines():
                        line = line.strip().lstrip("*.")
                        if line.endswith(f".{domain}") and "*" not in line:
                            subs.add(line)
                return list(subs)
    except Exception:
        pass
    return []


async def _resolve(hostname: str, resolver: dns.asyncresolver.Resolver) -> str | None:
    try:
        answers = await resolver.resolve(hostname, "A")
        return str(answers[0])
    except Exception:
        return None


def _strip_scheme(target: str) -> str:
    return target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
