"""Detect software versions from response fingerprints and match against known CVEs."""
import re
from app.core.context import ScanContext
from app.core.finding import Finding
from app.core.severity import Severity
from app.services.intelligence.cve_db import lookup

# Map header tokens to CVE-DB product keys.
PRODUCT_PATTERNS = [
    (re.compile(r"nginx/([\d.]+)", re.I), "nginx"),
    (re.compile(r"apache/([\d.]+)", re.I), "apache"),
    (re.compile(r"openssh[_/]([\d.]+)", re.I), "openssh"),
    (re.compile(r"php/([\d.]+)", re.I), "php"),
    (re.compile(r"microsoft-iis/([\d.]+)", re.I), "iis"),
]

GENERATOR_RE = re.compile(r'name=["\']generator["\'][^>]+content=["\']wordpress\s*([\d.]+)', re.I)


async def run(ctx: ScanContext) -> list[Finding]:
    findings = []
    detected: dict[str, str] = {}  # product -> version

    try:
        r = await ctx.client.get(ctx.base_url)
        banner = " ".join(f"{k}: {v}" for k, v in r.headers.items())
    except Exception:
        return findings

    for pattern, product in PRODUCT_PATTERNS:
        m = pattern.search(banner)
        if m:
            detected[product] = m.group(1)

    # WordPress version from homepage markup
    html = ctx.homepage_html or r.text
    wp = GENERATOR_RE.search(html)
    if wp:
        detected["wordpress"] = wp.group(1)

    if not detected:
        return findings

    for product, version in detected.items():
        cves = lookup(product, version)
        for cve in cves:
            findings.append(Finding(
                title=f"{cve['cve']}: {product} {version} vulnerable",
                description=f"Detected {product} {version}, which is affected by {cve['cve']}. {cve['desc']}",
                severity=Severity(cve["severity"]),
                category="Intelligence / CVE",
                evidence=f"Fingerprint: {product} {version} (fixed in {cve['fixed_below']}+)",
                recommendation=f"Upgrade {product} to {cve['fixed_below']} or later. Verify against the official advisory for {cve['cve']}.",
                url=ctx.base_url,
                cvss=cve["cvss"],
            ))

    if not findings and detected:
        # Versions detected but no known CVE in our curated DB — still worth noting the version leak.
        listed = ", ".join(f"{p} {v}" for p, v in detected.items())
        findings.append(Finding(
            title=f"Software Versions Disclosed: {listed}",
            description="Exact software versions are exposed in response headers. No match in the curated CVE set, "
                        "but version disclosure helps attackers find applicable exploits.",
            severity=Severity.LOW,
            category="Intelligence / CVE",
            evidence=listed,
            recommendation="Suppress version banners (e.g. server_tokens off; ServerTokens Prod). "
                           "Cross-check versions against the full NVD database for completeness.",
        ))

    return findings
