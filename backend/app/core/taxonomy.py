"""Map findings to OWASP Top 10 (2021), CWE, and a confidence level.

Centralized so the 31 scan modules don't each need to know their taxonomy —
the engine enriches every finding from here based on its category and title.
"""

OWASP_NAMES = {
    "A01": "A01:2021 Broken Access Control",
    "A02": "A02:2021 Cryptographic Failures",
    "A03": "A03:2021 Injection",
    "A04": "A04:2021 Insecure Design",
    "A05": "A05:2021 Security Misconfiguration",
    "A06": "A06:2021 Vulnerable & Outdated Components",
    "A07": "A07:2021 Identification & Authentication Failures",
    "A08": "A08:2021 Software & Data Integrity Failures",
    "A09": "A09:2021 Security Logging & Monitoring Failures",
    "A10": "A10:2021 Server-Side Request Forgery",
}

# Confidence levels.
CONFIRMED = "Confirmed"   # actively proven, or an indisputable observed fact
PROBABLE = "Probable"     # strong inference, not exploited (e.g. version → known CVE)
POSSIBLE = "Possible"     # heuristic / low-signal, verify manually

# category -> (owasp_code, cwe, default_confidence)
CATEGORY_MAP = {
    "Active / XSS":            ("A03", "CWE-79", CONFIRMED),
    "Active / SQLi":           ("A03", "CWE-89", CONFIRMED),
    "Active / LFI":            ("A03", "CWE-22", CONFIRMED),
    "Active / SSRF":           ("A10", "CWE-918", CONFIRMED),
    "Active / CRLF":           ("A03", "CWE-93", CONFIRMED),
    "Active / Host Header":    ("A03", "CWE-644", PROBABLE),
    "Active / IDOR":           ("A01", "CWE-639", POSSIBLE),
    "Active / Default Creds":  ("A07", "CWE-1392", CONFIRMED),
    "Scanner / CSRF":          ("A01", "CWE-352", PROBABLE),
    "Scanner / GraphQL":       ("A05", "CWE-200", CONFIRMED),
    "Scanner / Headers":       ("A05", "CWE-693", CONFIRMED),
    "Scanner / Clickjacking":  ("A05", "CWE-1021", CONFIRMED),
    "Scanner / Cookies":       ("A05", "CWE-614", CONFIRMED),
    "Scanner / Sensitive Files": ("A05", "CWE-538", CONFIRMED),
    "Scanner / Ports":         ("A05", "CWE-668", CONFIRMED),
    "Scanner / Takeover":      ("A05", "CWE-350", PROBABLE),
    "Scanner / Open Redirect": ("A01", "CWE-601", CONFIRMED),
    "Scanner / JS Secrets":    ("A02", "CWE-798", PROBABLE),
    "Scanner / JS Libraries":  ("A06", "CWE-1395", PROBABLE),
    "Scanner / JWT":           ("A02", "CWE-347", PROBABLE),
    "Scanner / WAF":           ("A05", "CWE-693", POSSIBLE),
    "Scanner / HTTP Methods":  ("A05", "CWE-650", CONFIRMED),
    "Scanner / security.txt":  ("A09", "CWE-778", CONFIRMED),
    "Scanner / Info Disclosure": ("A05", "CWE-200", CONFIRMED),
    "OSINT / DNS":             ("A05", "CWE-16", CONFIRMED),
    "OSINT / SSL":             ("A02", "CWE-295", CONFIRMED),
    "OSINT / TLS":             ("A02", "CWE-327", CONFIRMED),
    "OSINT / WHOIS":           ("A05", "CWE-200", CONFIRMED),
    "OSINT / Subdomains":      ("A05", "CWE-200", PROBABLE),
    "OSINT / Emails":          ("A09", "CWE-200", CONFIRMED),
    "Tech / CMS":              ("A06", "CWE-1395", PROBABLE),
    "Intelligence / CVE":      ("A06", "CWE-1395", PROBABLE),
    "Recon / Crawler":         ("A05", "CWE-200", CONFIRMED),
    "Recon / well-known":      ("A05", "CWE-200", CONFIRMED),
}

# Title keyword -> (owasp, cwe) overrides for findings that differ from their category default.
TITLE_OVERRIDES = [
    ("x-frame-options",        ("A05", "CWE-1021")),   # clickjacking
    ("content-security-policy", ("A05", "CWE-693")),
    ("strict-transport",       ("A02", "CWE-319")),    # cleartext transmission
    ("spf",                    ("A05", "CWE-16")),
    ("dmarc",                  ("A05", "CWE-16")),
    ("dnssec",                 ("A05", "CWE-350")),
    ("zone transfer",          ("A01", "CWE-200")),
    ("expired",                ("A02", "CWE-298")),
    ("xml-rpc",                ("A05", "CWE-16")),
    ("username enumeration",   ("A07", "CWE-204")),
    ("git",                    ("A05", "CWE-527")),     # exposed VCS
    (".env",                   ("A05", "CWE-538")),
]

# Categories whose findings are purely informational (no real weakness).
_INFO_TITLES = ("information", "discovered", "detected", "enumeration", "found",
                "complete", "present", "supported", "no waf")


def classify(title: str, category: str, severity: str) -> dict:
    title_l = (title or "").lower()
    owasp, cwe, confidence = CATEGORY_MAP.get(category, ("A05", "CWE-200", PROBABLE))

    for kw, (o, c) in TITLE_OVERRIDES:
        if kw in title_l:
            owasp, cwe = o, c
            break

    # INFO-severity items are observations, not weaknesses — always Confirmed facts.
    if severity == "INFO":
        confidence = CONFIRMED

    return {
        "owasp": owasp,
        "owasp_name": OWASP_NAMES.get(owasp, owasp),
        "cwe": cwe,
        "confidence": confidence,
    }
