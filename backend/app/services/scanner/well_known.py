"""Parse robots.txt and sitemap.xml to discover endpoints and disallowed paths."""
import re
from app.core.context import ScanContext
from app.core.finding import Finding
from app.core.severity import Severity

INTERESTING = ["admin", "login", "backup", "private", "internal", "api",
               "config", "wp-admin", "dashboard", "panel", "secret", "test", "dev"]


async def run(ctx: ScanContext) -> list[Finding]:
    findings = []

    # robots.txt
    try:
        r = await ctx.client.get(ctx.base_url + "/robots.txt")
        if r.status_code == 200 and ("disallow" in r.text.lower() or "user-agent" in r.text.lower()):
            disallowed = re.findall(r"(?i)disallow:\s*(\S+)", r.text)
            juicy = [d for d in disallowed if any(k in d.lower() for k in INTERESTING)]
            findings.append(Finding(
                title=f"robots.txt Found ({len(disallowed)} disallowed paths)",
                description="robots.txt lists paths the site wants hidden from crawlers — often a map of "
                            "sensitive areas for an attacker.",
                severity=Severity.INFO,
                category="Recon / well-known",
                evidence="\n".join(disallowed[:25]),
                recommendation="Don't rely on robots.txt for security; protect sensitive paths with auth.",
                url=ctx.base_url + "/robots.txt",
            ))
            for path in juicy[:8]:
                full = ctx.base_url + path if path.startswith("/") else f"{ctx.base_url}/{path}"
                ctx.urls.append(full)
                findings.append(Finding(
                    title=f"Interesting Disallowed Path: {path}",
                    description="A sensitive-looking path is referenced in robots.txt.",
                    severity=Severity.LOW,
                    category="Recon / well-known",
                    evidence=f"Disallow: {path}",
                    recommendation="Ensure this path requires authentication; obscurity is not protection.",
                    url=full,
                ))
    except Exception:
        pass

    # sitemap.xml — feed URLs into the crawl set
    try:
        r = await ctx.client.get(ctx.base_url + "/sitemap.xml")
        if r.status_code == 200 and "<urlset" in r.text or "<sitemapindex" in r.text:
            locs = re.findall(r"<loc>([^<]+)</loc>", r.text)
            for loc in locs:
                if loc not in ctx.urls:
                    ctx.urls.append(loc)
            if locs:
                findings.append(Finding(
                    title=f"sitemap.xml Found ({len(locs)} URLs)",
                    description="sitemap.xml enumerates site URLs, expanding the discovered attack surface.",
                    severity=Severity.INFO,
                    category="Recon / well-known",
                    evidence="\n".join(locs[:20]),
                    recommendation="No action needed; informational.",
                    url=ctx.base_url + "/sitemap.xml",
                ))
    except Exception:
        pass

    return findings
