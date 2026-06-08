"""Test a tiny set of default credentials against discovered login forms.

Aggressive mode only. Deliberately limited to a handful of attempts to avoid
locking out real accounts.
"""
import asyncio
from urllib.parse import urljoin
from app.core.context import ScanContext
from app.core.finding import Finding
from app.core.severity import Severity

# A short, high-signal list. Kept small on purpose — this is a check, not a brute-forcer.
CRED_PAIRS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("root", "root"),
]

USER_FIELDS = ["user", "username", "login", "email", "userid", "name"]
PASS_FIELDS = ["pass", "password", "passwd", "pwd"]
# Markers that suggest a *failed* login (still on a login page / error shown).
FAIL_MARKERS = ["invalid", "incorrect", "failed", "wrong", "denied", "try again",
                "authentication failed", "bad credentials"]
# Markers that suggest a *successful* login (landed on an authenticated page).
SUCCESS_MARKERS = ["logout", "log out", "sign out", "dashboard", "welcome",
                   "my account", "profile", "settings", "log off"]


async def run(ctx: ScanContext) -> list[Finding]:
    findings = []

    login_forms = []
    for form in ctx.forms:
        inputs = [i.lower() for i in form.get("inputs", []) if i]
        has_pass = any(any(p in name for p in PASS_FIELDS) for name in inputs)
        if has_pass and form.get("method", "get").lower() == "post":
            login_forms.append(form)

    for form in login_forms[:2]:  # cap to 2 login forms
        finding = await _try_form(ctx, form)
        if finding:
            findings.append(finding)

    return findings


async def _try_form(ctx: ScanContext, form: dict) -> Finding | None:
    inputs = [i for i in form.get("inputs", []) if i]
    user_field = next((i for i in inputs if any(u in i.lower() for u in USER_FIELDS)), None)
    pass_field = next((i for i in inputs if any(p in i.lower() for p in PASS_FIELDS)), None)
    if not user_field or not pass_field:
        return None

    action = form["action"]

    # Baseline: a clearly-wrong login, to learn what "failure" looks like.
    base_resp = await _submit(ctx, action, inputs, user_field, pass_field,
                              "vaultscan_nouser", "vaultscan_nopass")
    base_len = len(base_resp) if base_resp is not None else 0

    base_low = base_resp.lower() if base_resp else ""
    base_has_success = any(m in base_low for m in SUCCESS_MARKERS)

    for username, password in CRED_PAIRS:
        resp = await _submit(ctx, action, inputs, user_field, pass_field, username, password)
        if resp is None:
            continue
        low = resp.lower()
        looks_failed = any(m in low for m in FAIL_MARKERS)
        # Success markers that weren't already on the wrong-login baseline are strong evidence.
        gained_success = (not base_has_success) and any(m in low for m in SUCCESS_MARKERS)
        big_diff = abs(len(resp) - base_len) > 80
        # Confirmed if it doesn't look failed AND (auth-only marker appeared OR response changed a lot).
        if not looks_failed and (gained_success or big_diff):
            return Finding(
                title=f"Default Credentials Accepted: {username}/{password}",
                description="A login form appears to accept default credentials. This typically grants "
                            "full administrative access.",
                severity=Severity.CRITICAL,
                category="Active / Default Creds",
                evidence=f"Form: {action}\nAccepted: {username} / {password}",
                recommendation="Remove or change all default accounts. Enforce strong passwords and rate-limit logins.",
                url=action,
                cvss=9.8,
            )
    return None


async def _submit(ctx, action, inputs, user_field, pass_field, username, password) -> str | None:
    data = {}
    for name in inputs:
        if name == user_field:
            data[name] = username
        elif name == pass_field:
            data[name] = password
        else:
            data[name] = "1"
    try:
        r = await ctx.client.post(action, data=data)
        return r.text
    except Exception:
        return None
