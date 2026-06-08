"""Check for exposed sensitive files and directories, with a soft-404 guard."""
import asyncio
import uuid
from app.core.context import ScanContext
from app.core.finding import Finding
from app.core.severity import Severity

# path: (description, severity, recommendation, optional content marker)
SENSITIVE_PATHS = {
    "/.git/config":        ("Exposed Git repository", Severity.HIGH, "Block access to .git/ at the web server.", "[core]"),
    "/.git/HEAD":          ("Exposed Git HEAD", Severity.HIGH, "Block access to .git/.", "ref:"),
    "/.env":               ("Exposed .env file (may contain secrets)", Severity.CRITICAL, "Move .env outside the web root and block access.", "="),
    "/.env.local":         ("Exposed .env.local", Severity.CRITICAL, "Remove environment files from the web root.", "="),
    "/config.php.bak":     ("Backup of config.php", Severity.CRITICAL, "Delete backup files from the web root.", None),
    "/wp-config.php.bak":  ("Backup of wp-config.php", Severity.CRITICAL, "Delete backup files.", None),
    "/.DS_Store":          ("macOS .DS_Store (leaks file names)", Severity.LOW, "Remove .DS_Store files from the server.", None),
    "/backup.zip":         ("Exposed backup archive", Severity.HIGH, "Remove backups from the web root.", None),
    "/backup.sql":         ("Exposed SQL dump", Severity.CRITICAL, "Remove database dumps from the web root.", None),
    "/dump.sql":           ("Exposed SQL dump", Severity.CRITICAL, "Remove database dumps.", None),
    "/.htaccess":          ("Exposed .htaccess", Severity.MEDIUM, "Block access to .htaccess.", None),
    "/.svn/entries":       ("Exposed SVN metadata", Severity.HIGH, "Block access to .svn/.", None),
    "/web.config":         ("Exposed web.config", Severity.MEDIUM, "Block access to web.config.", None),
    "/phpinfo.php":        ("Exposed phpinfo()", Severity.HIGH, "Remove phpinfo files from production.", "phpinfo"),
    "/.well-known/security.txt": ("security.txt present", Severity.INFO, "Keep contact details current.", None),
    "/server-status":      ("Apache server-status exposed", Severity.MEDIUM, "Restrict mod_status to localhost.", None),
    "/.aws/credentials":   ("Exposed AWS credentials", Severity.CRITICAL, "Remove cloud credentials from the web root immediately.", None),
    "/id_rsa":             ("Exposed SSH private key", Severity.CRITICAL, "Remove private keys and rotate them.", None),
}


async def run(ctx: ScanContext) -> list[Finding]:
    findings = []

    # Soft-404 baseline: does a random path return 200?
    soft404 = await _soft_404(ctx)

    tasks = [_check(ctx, path, meta, soft404) for path, meta in SENSITIVE_PATHS.items()]
    results = await asyncio.gather(*tasks)
    findings = [f for f in results if f is not None]
    return findings


async def _soft_404(ctx: ScanContext) -> bool:
    """If a guaranteed-nonexistent path returns 200, the server soft-404s."""
    rnd = f"/{uuid.uuid4().hex}-{uuid.uuid4().hex}.html"
    try:
        r = await ctx.client.get(ctx.base_url + rnd)
        return r.status_code == 200
    except Exception:
        return False


async def _check(ctx: ScanContext, path: str, meta, soft404: bool) -> Finding | None:
    desc, severity, rec, marker = meta
    url = ctx.base_url + path
    try:
        r = await ctx.client.get(url)
    except Exception:
        return None

    if r.status_code != 200:
        return None
    # Guard against soft-404 false positives
    if soft404 and marker is None:
        return None
    if marker and marker.lower() not in r.text.lower():
        return None
    if len(r.text.strip()) == 0:
        return None

    return Finding(
        title=f"Sensitive File Exposed: {path}",
        description=desc,
        severity=severity,
        category="Scanner / Sensitive Files",
        evidence=f"GET {url} → HTTP 200 ({len(r.content)} bytes)",
        recommendation=rec,
        url=url,
    )
