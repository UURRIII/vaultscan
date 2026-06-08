"""Clickjacking check — missing frame-protection + a ready-to-use PoC."""
from app.core.context import ScanContext
from app.core.finding import Finding
from app.core.severity import Severity


async def run(ctx: ScanContext) -> list[Finding]:
    try:
        r = await ctx.client.get(ctx.base_url)
    except Exception:
        return []

    headers = {k.lower(): v for k, v in r.headers.items()}
    xfo = headers.get("x-frame-options", "")
    csp = headers.get("content-security-policy", "")
    frame_ancestors = "frame-ancestors" in csp.lower()

    # Protected if either X-Frame-Options or CSP frame-ancestors is present.
    if xfo or frame_ancestors:
        return []

    poc = (
        "<!doctype html><html><body>\n"
        "  <h3>Clickjacking PoC</h3>\n"
        f"  <iframe src=\"{ctx.base_url}\" width=\"1000\" height=\"700\"\n"
        "          style=\"opacity:0.3\"></iframe>\n"
        "</body></html>"
    )
    return [Finding(
        title="Clickjacking Possible (no frame protection)",
        description="The page can be embedded in an <iframe> on an attacker's site because neither "
                    "X-Frame-Options nor a CSP frame-ancestors directive is set. This enables clickjacking "
                    "(UI-redress) attacks where a victim is tricked into clicking hidden elements.",
        severity=Severity.MEDIUM,
        category="Scanner / Clickjacking",
        evidence="No X-Frame-Options and no CSP 'frame-ancestors'. Proof-of-concept:\n\n" + poc,
        recommendation="Set 'X-Frame-Options: DENY' (or SAMEORIGIN) and a CSP 'frame-ancestors 'self'' directive.",
        url=ctx.base_url,
        cvss=4.3,
    )]
