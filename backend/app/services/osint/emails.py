"""Harvest email addresses exposed on the site."""
import re
from app.core.context import ScanContext
from app.core.finding import Finding
from app.core.severity import Severity

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
# Common pages worth checking beyond the homepage.
EXTRA_PATHS = ["/contact", "/contacto", "/contacte", "/about", "/legal", "/privacy", "/team"]


async def run(ctx: ScanContext) -> list[Finding]:
    findings = []
    emails: set[str] = set()

    pages = [ctx.base_url] + [ctx.base_url + p for p in EXTRA_PATHS]
    # Include a few crawled URLs
    pages += ctx.urls[:10]

    seen_pages = set()
    for url in pages:
        if url in seen_pages:
            continue
        seen_pages.add(url)
        try:
            r = await ctx.client.get(url)
            for match in EMAIL_RE.findall(r.text):
                if not match.lower().endswith((".png", ".jpg", ".gif", ".svg", ".webp", ".js", ".css")):
                    emails.add(match.lower())
        except Exception:
            continue

    # Filter obvious noise
    emails = {e for e in emails if not e.startswith(("example@", "email@", "user@", "name@"))}

    if not emails:
        return findings

    domain_emails = [e for e in emails if ctx.host.split(".")[-2] in e] if "." in ctx.host else list(emails)

    findings.append(Finding(
        title=f"Email Addresses Harvested ({len(emails)})",
        description="Publicly exposed email addresses can be used for phishing and social-engineering attacks.",
        severity=Severity.LOW if domain_emails else Severity.INFO,
        category="OSINT / Emails",
        evidence="\n".join(sorted(emails)[:20]),
        recommendation="Use contact forms or obfuscate email addresses to reduce scraping and phishing exposure.",
    ))
    return findings
