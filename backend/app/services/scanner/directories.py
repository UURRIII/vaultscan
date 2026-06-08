import asyncio
import httpx
from app.core.finding import Finding
from app.core.severity import Severity

PATHS = [
    ("/.git/HEAD",        Severity.CRITICAL, "Exposed Git repository"),
    ("/.env",             Severity.CRITICAL, "Exposed environment file"),
    ("/.env.local",       Severity.CRITICAL, "Exposed environment file"),
    ("/config.php",       Severity.CRITICAL, "Exposed config file"),
    ("/wp-config.php",    Severity.CRITICAL, "WordPress config exposed"),
    ("/phpinfo.php",      Severity.HIGH,     "PHP info page exposed"),
    ("/admin",            Severity.HIGH,     "Admin panel exposed"),
    ("/admin/",           Severity.HIGH,     "Admin panel exposed"),
    ("/wp-admin/",        Severity.HIGH,     "WordPress admin exposed"),
    ("/phpmyadmin/",      Severity.HIGH,     "phpMyAdmin exposed"),
    ("/adminer.php",      Severity.HIGH,     "Adminer DB tool exposed"),
    ("/backup",           Severity.HIGH,     "Backup directory exposed"),
    ("/backup.zip",       Severity.HIGH,     "Backup archive exposed"),
    ("/backup.tar.gz",    Severity.HIGH,     "Backup archive exposed"),
    ("/db.sql",           Severity.HIGH,     "Database dump exposed"),
    ("/swagger-ui.html",  Severity.MEDIUM,   "Swagger API docs exposed"),
    ("/api/swagger",      Severity.MEDIUM,   "Swagger API docs exposed"),
    ("/api-docs",         Severity.MEDIUM,   "API docs exposed"),
    ("/api/v1",           Severity.MEDIUM,   "API endpoint discovered"),
    ("/server-status",    Severity.MEDIUM,   "Apache server-status exposed"),
    ("/server-info",      Severity.MEDIUM,   "Apache server-info exposed"),
    ("/.DS_Store",        Severity.LOW,      "macOS .DS_Store file exposed"),
    ("/.htaccess",        Severity.LOW,      "Apache .htaccess exposed"),
    ("/sitemap.xml",      Severity.INFO,     "Sitemap discovered"),
    ("/robots.txt",       Severity.INFO,     "robots.txt discovered"),
    ("/crossdomain.xml",  Severity.LOW,      "crossdomain.xml discovered"),
]


async def run(ctx) -> list[Finding]:
    target = ctx.target
    base = target if target.startswith("http") else f"https://{target}"
    base = base.rstrip("/")
    findings = []

    async with httpx.AsyncClient(
        timeout=8,
        follow_redirects=False,
        headers={"User-Agent": "Mozilla/5.0 VaultScan/1.0"},
        verify=False,
    ) as client:
        tasks = [_check(client, base, path, sev, label) for path, sev, label in PATHS]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    for r in results:
        if isinstance(r, Finding):
            findings.append(r)

    return findings


async def _check(client: httpx.AsyncClient, base: str, path: str, severity: Severity, label: str):
    url = base + path
    try:
        r = await client.get(url)
        if r.status_code in (200, 403):
            status = f"HTTP {r.status_code}"
            content_preview = r.text[:200].strip() if r.status_code == 200 else "(403 Forbidden)"
            return Finding(
                title=label,
                description=f"The path '{path}' is accessible (HTTP {r.status_code}).",
                severity=severity if r.status_code == 200 else Severity.LOW,
                category="Scanner / Directories",
                evidence=f"URL: {url}\nStatus: {status}\nPreview: {content_preview}",
                recommendation=f"Restrict access to '{path}'. Remove sensitive files from the web root.",
                url=url,
            )
    except Exception:
        pass
    return None
