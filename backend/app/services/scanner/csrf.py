"""Detect state-changing forms that lack an anti-CSRF token."""
from app.core.context import ScanContext
from app.core.finding import Finding
from app.core.severity import Severity

# Input names that look like CSRF tokens.
TOKEN_HINTS = ["csrf", "token", "authenticity", "nonce", "_token", "xsrf", "__requestverification"]


async def run(ctx: ScanContext) -> list[Finding]:
    findings = []
    vulnerable = []

    for form in ctx.forms:
        if form.get("method", "get").lower() != "post":
            continue
        inputs = [i.lower() for i in form.get("inputs", []) if i]
        has_token = any(any(h in name for h in TOKEN_HINTS) for name in inputs)
        if not has_token:
            vulnerable.append(form)

    for form in vulnerable[:10]:
        findings.append(Finding(
            title=f"Form Without CSRF Token: {_short(form['action'])}",
            description="A POST form has no detectable anti-CSRF token. If it performs a state-changing "
                        "action and relies only on cookies, an attacker can forge requests on a victim's behalf.",
            severity=Severity.MEDIUM,
            category="Scanner / CSRF",
            evidence=f"action: {form['action']}\nmethod: POST\ninputs: {', '.join(form.get('inputs', []) or ['(none)'])}",
            recommendation="Add a per-session anti-CSRF token to every state-changing form and validate it "
                           "server-side. Set SameSite=Lax/Strict on session cookies as defense in depth.",
            url=form["action"],
            cvss=6.5,
        ))

    return findings


def _short(url: str) -> str:
    from urllib.parse import urlparse
    p = urlparse(url)
    return (p.path or "/")[:40]
