"""Find JSON Web Tokens in responses and flag weak configurations."""
import re
import json
import base64
from app.core.context import ScanContext
from app.core.finding import Finding
from app.core.severity import Severity

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")
WEAK_ALGS = {"none", "hs256"}  # 'none' is critical; HS256 is fine but worth noting if secret-signed in client


async def run(ctx: ScanContext) -> list[Finding]:
    findings = []
    seen = set()

    # Look in the homepage + a few crawled pages + Set-Cookie headers.
    pages = [ctx.base_url] + ctx.urls[:6]
    blobs = []
    for url in dict.fromkeys(pages):
        try:
            r = await ctx.client.get(url)
            blobs.append(r.text)
            for c in (r.headers.get_list("set-cookie") if hasattr(r.headers, "get_list") else []):
                blobs.append(c)
        except Exception:
            continue
    if ctx.homepage_html:
        blobs.append(ctx.homepage_html)

    for blob in blobs:
        for token in JWT_RE.findall(blob):
            header = _decode_part(token.split(".")[0])
            if not header or "alg" not in header:
                continue
            alg = str(header.get("alg", "")).lower()
            fp = token[:25]
            if fp in seen:
                continue
            seen.add(fp)

            if alg == "none":
                findings.append(Finding(
                    title="JWT with 'alg: none' (signature bypass)",
                    description="A JSON Web Token uses the 'none' algorithm, meaning it is unsigned. If the server "
                                "accepts it, an attacker can forge arbitrary tokens and impersonate any user.",
                    severity=Severity.CRITICAL,
                    category="Scanner / JWT",
                    evidence=f"Token header: {json.dumps(header)}\nToken: {token[:40]}…",
                    recommendation="Reject the 'none' algorithm server-side. Pin an explicit allowed algorithm.",
                    url=ctx.base_url,
                    cvss=9.1,
                ))
            else:
                payload = _decode_part(token.split(".")[1]) or {}
                issues = []
                if "exp" not in payload:
                    issues.append("no expiry (exp) claim")
                findings.append(Finding(
                    title=f"JWT Exposed (alg: {header.get('alg')})",
                    description="A JSON Web Token is exposed in client-accessible content. "
                                + ("Issues: " + ", ".join(issues) if issues else "Review how it is stored and validated."),
                    severity=Severity.LOW if issues else Severity.INFO,
                    category="Scanner / JWT",
                    evidence=f"Header: {json.dumps(header)}\nClaims: {', '.join(payload.keys()) or '(unreadable)'}",
                    recommendation="Store JWTs in HttpOnly cookies, set short expiries, and verify the signature "
                                   "and algorithm server-side.",
                    url=ctx.base_url,
                ))

    return findings


def _decode_part(part: str) -> dict | None:
    try:
        padded = part + "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return None
