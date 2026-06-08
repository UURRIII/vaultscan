import httpx
from app.core.finding import Finding
from app.core.severity import Severity

# Signatures: substring found in headers/cookies/body -> WAF/CDN name.
WAF_SIGNATURES = {
    "cloudflare":          "Cloudflare",
    "cf-ray":              "Cloudflare",
    "__cfduid":            "Cloudflare",
    "x-akamai":            "Akamai",
    "akamaighost":         "Akamai",
    "x-sucuri":            "Sucuri",
    "sucuri/cloudproxy":   "Sucuri",
    "incapsula":           "Imperva Incapsula",
    "x-iinfo":             "Imperva Incapsula",
    "x-amz-cf-id":         "AWS CloudFront",
    "awselb":              "AWS ELB / WAF",
    "x-aws-waf":           "AWS WAF",
    "barracuda":           "Barracuda",
    "x-powered-by-360wzb": "360 Web Application Firewall",
    "ddos-guard":          "DDoS-Guard",
    "wzws":                "WangZhanBao WAF",
    "x-s/x-sl":            "BIG-IP / F5",
    "big-ip":              "F5 BIG-IP",
    "fortiwafsid":         "Fortinet FortiWeb",
}


async def run(ctx) -> list[Finding]:
    target = ctx.target
    url = target if target.startswith("http") else f"https://{target}"
    findings = []

    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as client:
            r = await client.get(url, headers={"User-Agent": "Mozilla/5.0 VaultScan/1.0"})
    except Exception:
        return findings

    haystack = " ".join(f"{k}: {v}" for k, v in r.headers.items()).lower()
    haystack += " " + " ".join(r.cookies.keys()).lower()

    detected = set()
    for sig, name in WAF_SIGNATURES.items():
        if sig in haystack:
            detected.add(name)

    if detected:
        findings.append(Finding(
            title=f"WAF / CDN Detected: {', '.join(sorted(detected))}",
            description="A Web Application Firewall or CDN protects this target. "
                        "This is good for defense, but worth noting for testing scope.",
            severity=Severity.INFO,
            category="Scanner / WAF",
            evidence=f"Detected via response fingerprints: {', '.join(sorted(detected))}",
            recommendation="No action needed. A WAF is a positive security control.",
            url=url,
        ))
    else:
        findings.append(Finding(
            title="No WAF Detected",
            description="No Web Application Firewall was identified from response fingerprints. "
                        "The application may be directly exposed without an additional filtering layer.",
            severity=Severity.LOW,
            category="Scanner / WAF",
            evidence="No known WAF/CDN signatures found in response headers or cookies.",
            recommendation="Consider deploying a WAF (Cloudflare, AWS WAF, etc.) to filter malicious traffic.",
            url=url,
        ))

    return findings
