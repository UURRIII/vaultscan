"""CMS detection + version fingerprinting."""
import re
from app.core.context import ScanContext
from app.core.finding import Finding
from app.core.severity import Severity

GENERATOR_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)


async def run(ctx: ScanContext) -> list[Finding]:
    findings = []
    html = ctx.homepage_html
    if not html:
        try:
            r = await ctx.client.get(ctx.base_url)
            html = r.text
        except Exception:
            return findings

    detected = None
    version = None

    # 1. Generator meta tag (most reliable)
    m = GENERATOR_RE.search(html)
    if m:
        gen = m.group(1)
        vm = re.search(r"([\d]+\.[\d.]+)", gen)
        version = vm.group(1) if vm else None
        low = gen.lower()
        if "wordpress" in low:
            detected = "WordPress"
        elif "joomla" in low:
            detected = "Joomla"
        elif "drupal" in low:
            detected = "Drupal"
        else:
            detected = gen.split()[0]

    # 2. Path/markup fingerprints
    if not detected:
        if "/wp-content/" in html or "/wp-includes/" in html:
            detected = "WordPress"
        elif "/sites/default/files" in html or "Drupal.settings" in html:
            detected = "Drupal"
        elif "/media/jui/" in html or "joomla" in html.lower():
            detected = "Joomla"
        elif "cdn.shopify.com" in html:
            detected = "Shopify"
        elif "wix.com" in html:
            detected = "Wix"

    # 3. WordPress version fallback via readme / RSS generator
    if detected == "WordPress" and not version:
        version = await _wp_version(ctx)

    if not detected:
        return findings

    ver_txt = f" {version}" if version else ""
    findings.append(Finding(
        title=f"CMS Detected: {detected}{ver_txt}",
        description=f"The site runs {detected}{(' version ' + version) if version else ''}.",
        severity=Severity.INFO,
        category="Tech / CMS",
        evidence=(m.group(0)[:200] if m else f"{detected} fingerprint found in markup"),
        recommendation="Keep the CMS and all plugins/themes updated. Hide version banners where possible.",
    ))

    # Exposed version is a low-severity info-leak finding on its own.
    if version:
        findings.append(Finding(
            title=f"{detected} Version Disclosed: {version}",
            description=f"The exact {detected} version is publicly visible, helping attackers match known exploits.",
            severity=Severity.LOW,
            category="Tech / CMS",
            evidence=f"{detected} {version}",
            recommendation="Remove generator meta tags and version strings from public output.",
            cvss=3.7,
        ))

    # WordPress-specific exposed endpoints
    if detected == "WordPress":
        findings += await _wp_checks(ctx)

    return findings


async def _wp_version(ctx: ScanContext) -> str | None:
    for path in ["/feed/", "/?feed=rss2"]:
        try:
            r = await ctx.client.get(ctx.base_url + path)
            m = re.search(r"<generator>https?://wordpress\.org/\?v=([\d.]+)", r.text)
            if m:
                return m.group(1)
        except Exception:
            pass
    return None


async def _wp_checks(ctx: ScanContext) -> list[Finding]:
    findings = []
    # User enumeration via REST API
    try:
        r = await ctx.client.get(ctx.base_url + "/wp-json/wp/v2/users")
        if r.status_code == 200 and r.text.strip().startswith("["):
            import json
            users = json.loads(r.text)
            names = [u.get("slug") for u in users if isinstance(u, dict)][:10]
            if names:
                findings.append(Finding(
                    title="WordPress Username Enumeration",
                    description="The WordPress REST API exposes valid usernames, aiding brute-force attacks.",
                    severity=Severity.MEDIUM,
                    category="Tech / CMS",
                    evidence=f"/wp-json/wp/v2/users leaked: {', '.join(filter(None, names))}",
                    recommendation="Restrict the users endpoint or require authentication for the REST API.",
                    url=ctx.base_url + "/wp-json/wp/v2/users",
                    cvss=5.3,
                ))
    except Exception:
        pass

    # xmlrpc.php (brute-force / DDoS amplification)
    try:
        r = await ctx.client.get(ctx.base_url + "/xmlrpc.php")
        if r.status_code in (200, 405) and "XML-RPC" in r.text:
            findings.append(Finding(
                title="WordPress XML-RPC Enabled",
                description="xmlrpc.php is enabled and can be abused for brute-force amplification and pingback DDoS.",
                severity=Severity.LOW,
                category="Tech / CMS",
                evidence="/xmlrpc.php is reachable",
                recommendation="Disable XML-RPC if unused, or restrict access at the web-server level.",
                url=ctx.base_url + "/xmlrpc.php",
            ))
    except Exception:
        pass

    return findings
