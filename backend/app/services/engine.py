import asyncio
from datetime import datetime
from sqlalchemy.orm import Session
from app.models.scan import Scan, Finding as DBFinding
from app.core import risk
from app.core.context import ScanContext, build_client, normalize
from app.services import crawler
from app.services.osint import (
    dns_enum, whois_lookup, ssl_check, tls_ciphers, subdomains, technologies, emails,
)
from app.services.scanner import (
    headers, directories, cors, info_disclosure, ports, takeover, http_methods,
    waf, js_secrets, security_txt, open_redirect, cms, sensitive_files, cookies,
    well_known, csrf, graphql, js_libraries, jwt_analysis, clickjacking,
)
from app.services.intelligence import cve_match
from app.services.active import xss, sqli, lfi, ssrf, default_creds, host_header, crlf, idor

# (label, fn, active_only)
MODULES = [
    ("WHOIS",            whois_lookup.run,   False),
    ("DNS",              dns_enum.run,       False),
    ("SSL / TLS",        ssl_check.run,      False),
    ("TLS Ciphers",      tls_ciphers.run,    False),
    ("Ports",            ports.run,          False),
    ("Subdomains",       subdomains.run,     False),
    ("Takeover",         takeover.run,       False),
    ("Technologies",     technologies.run,   False),
    ("CMS",              cms.run,            False),
    ("WAF",              waf.run,            False),
    ("HTTP Headers",     headers.run,        False),
    ("HTTP Methods",     http_methods.run,   False),
    ("Cookies",          cookies.run,        False),
    ("CSRF",             csrf.run,           False),
    ("Clickjacking",     clickjacking.run,   False),
    ("GraphQL",          graphql.run,        False),
    ("JS Libraries",     js_libraries.run,   False),
    ("JWT",              jwt_analysis.run,   False),
    ("Directories",      directories.run,    False),
    ("Sensitive Files",  sensitive_files.run, False),
    ("Robots / Sitemap", well_known.run,     False),
    ("CORS",             cors.run,           False),
    ("Open Redirect",    open_redirect.run,  False),
    ("JS Secrets",       js_secrets.run,     False),
    ("Email Harvest",    emails.run,         False),
    ("security.txt",     security_txt.run,   False),
    ("Info Disclosure",  info_disclosure.run, False),
    ("CVE Intelligence", cve_match.run,      False),
    # Active (aggressive mode only)
    ("XSS (active)",     xss.run,            True),
    ("SQLi (active)",    sqli.run,           True),
    ("LFI (active)",     lfi.run,            True),
    ("SSRF (active)",    ssrf.run,           True),
    ("CRLF (active)",    crlf.run,           True),
    ("Host Header",      host_header.run,    True),
    ("IDOR (active)",    idor.run,           True),
    ("Default Creds",    default_creds.run,  True),
]


async def run_scan(scan_id: int, target: str, db: Session, queue: asyncio.Queue, mode: str = "safe") -> None:
    scan = db.get(Scan, scan_id)
    scan.status = "running"
    db.commit()

    norm, host, base_url = normalize(target)
    ctx = ScanContext(target=norm, host=host, base_url=base_url, mode=mode, client=build_client())

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    active_modules = [m for m in MODULES if not m[2] or mode == "aggressive"]
    total = len(active_modules) + 1  # +1 for crawler

    try:
        # Crawler first — populates ctx.urls / ctx.params / ctx.forms.
        await queue.put({"type": "module_start", "module": "Crawler", "index": 0, "total": total})
        try:
            crawl_findings = await crawler.run(ctx)
            await _persist(crawl_findings, scan_id, db, queue, severity_counts)
        except Exception as e:
            await queue.put({"type": "module_error", "module": "Crawler", "error": str(e)})
        await queue.put({"type": "module_done", "module": "Crawler", "index": 0})

        for i, (name, module_fn, _active) in enumerate(active_modules, start=1):
            await queue.put({"type": "module_start", "module": name, "index": i, "total": total})
            try:
                findings = await module_fn(ctx)
                await _persist(findings, scan_id, db, queue, severity_counts)
            except Exception as e:
                await queue.put({"type": "module_error", "module": name, "error": str(e)})
            await queue.put({"type": "module_done", "module": name, "index": i})
    finally:
        await ctx.client.aclose()

    risk_result = risk.compute_risk(severity_counts)
    scan.status = "done"
    scan.finished_at = datetime.utcnow()
    scan.risk_score = risk_result["score"]
    scan.risk_grade = risk_result["grade"]
    db.commit()

    await queue.put({"type": "scan_done", "risk": risk_result})


async def _persist(findings, scan_id, db, queue, severity_counts):
    for f in findings or []:
        payload = f.to_dict()
        db_f = DBFinding(
            scan_id=scan_id,
            title=payload["title"],
            description=payload["description"],
            severity=payload["severity"],
            category=payload["category"],
            evidence=payload["evidence"],
            recommendation=payload["recommendation"],
            url=payload["url"],
            cvss=payload["cvss"],
            owasp=payload.get("owasp", ""),
            cwe=payload.get("cwe", ""),
            confidence=payload.get("confidence", ""),
        )
        db.add(db_f)
        db.commit()
        db.refresh(db_f)
        severity_counts[payload["severity"]] = severity_counts.get(payload["severity"], 0) + 1
        await queue.put({"type": "finding", "finding": {
            "id": db_f.id, **payload, "created_at": db_f.created_at.isoformat(),
        }})
