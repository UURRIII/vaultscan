"""Detect outdated JavaScript libraries with known vulnerabilities (retire.js style)."""
import re
import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from app.core.context import ScanContext
from app.core.finding import Finding
from app.core.severity import Severity

# Curated subset: library -> list of {below, severity, cve, note}. Versions < `below` are affected.
VULN_DB = {
    "jquery": [
        {"below": "3.5.0", "severity": Severity.MEDIUM, "cve": "CVE-2020-11022/11023",
         "note": "XSS via jQuery.htmlPrefilter / DOM manipulation."},
        {"below": "1.9.0", "severity": Severity.MEDIUM, "cve": "CVE-2012-6708",
         "note": "Selector-based XSS."},
    ],
    "bootstrap": [
        {"below": "3.4.1", "severity": Severity.MEDIUM, "cve": "CVE-2019-8331",
         "note": "XSS in data-template / tooltip."},
        {"below": "4.3.1", "severity": Severity.MEDIUM, "cve": "CVE-2019-8331",
         "note": "XSS in tooltip/popover."},
    ],
    "angular": [
        {"below": "1.8.0", "severity": Severity.HIGH, "cve": "Multiple",
         "note": "AngularJS 1.x is end-of-life; multiple sandbox-bypass / XSS issues."},
    ],
    "lodash": [
        {"below": "4.17.21", "severity": Severity.HIGH, "cve": "CVE-2021-23337",
         "note": "Command injection / prototype pollution."},
    ],
    "moment": [
        {"below": "2.29.4", "severity": Severity.MEDIUM, "cve": "CVE-2022-31129",
         "note": "ReDoS via crafted date string."},
    ],
    "handlebars": [
        {"below": "4.7.7", "severity": Severity.HIGH, "cve": "CVE-2021-23369",
         "note": "Prototype pollution leading to RCE in some setups."},
    ],
    "vue": [
        {"below": "2.6.11", "severity": Severity.MEDIUM, "cve": "Multiple",
         "note": "Older Vue 2.x has known XSS edge cases."},
    ],
}

# Patterns to extract "library version" from markup, file names, or inline JS.
VERSION_PATTERNS = [
    ("jquery", re.compile(r"jquery[/-]?v?([0-9]+\.[0-9]+\.[0-9]+)", re.I)),
    ("jquery", re.compile(r'jquery["\']?\s*[:=]\s*["\']?([0-9]+\.[0-9]+\.[0-9]+)', re.I)),
    ("bootstrap", re.compile(r"bootstrap[/-]?v?([0-9]+\.[0-9]+\.[0-9]+)", re.I)),
    ("angular", re.compile(r"angular[.-]?(?:js)?[/-]?v?([0-9]+\.[0-9]+\.[0-9]+)", re.I)),
    ("lodash", re.compile(r"lodash[/-]?v?([0-9]+\.[0-9]+\.[0-9]+)", re.I)),
    ("moment", re.compile(r"moment[/-]?v?([0-9]+\.[0-9]+\.[0-9]+)", re.I)),
    ("handlebars", re.compile(r"handlebars[/-]?v?([0-9]+\.[0-9]+\.[0-9]+)", re.I)),
    ("vue", re.compile(r"vue[/-]?v?([0-9]+\.[0-9]+\.[0-9]+)", re.I)),
]


async def run(ctx: ScanContext) -> list[Finding]:
    findings = []
    html = ctx.homepage_html
    if not html:
        try:
            r = await ctx.client.get(ctx.base_url)
            html = r.text
        except Exception:
            return findings

    # Build a haystack: the HTML + script src URLs.
    soup = BeautifulSoup(html, "html.parser")
    haystack = html
    for s in soup.find_all("script", src=True):
        haystack += "\n" + s["src"]

    detected = {}  # lib -> version
    for lib, pattern in VERSION_PATTERNS:
        m = pattern.search(haystack)
        if m and lib not in detected:
            detected[lib] = m.group(1)

    for lib, version in detected.items():
        vulns = [v for v in VULN_DB.get(lib, []) if _version_lt(version, v["below"])]
        if vulns:
            v = vulns[0]
            findings.append(Finding(
                title=f"Outdated JS Library: {lib} {version}",
                description=f"{lib} {version} is outdated and affected by known issues ({v['cve']}). {v['note']}",
                severity=v["severity"],
                category="Scanner / JS Libraries",
                evidence=f"Detected {lib} {version} (fixed in {v['below']}+). Reference: {v['cve']}",
                recommendation=f"Upgrade {lib} to {v['below']} or later.",
                url=ctx.base_url,
            ))
        else:
            findings.append(Finding(
                title=f"JS Library Detected: {lib} {version}",
                description=f"{lib} {version} is in use (no known vulnerability in the curated DB).",
                severity=Severity.INFO,
                category="Scanner / JS Libraries",
                evidence=f"{lib} {version}",
                recommendation="Keep client-side libraries current and cross-check against the full retire.js DB.",
                url=ctx.base_url,
            ))

    return findings


def _version_lt(a: str, b: str) -> bool:
    def parse(v):
        out = []
        for part in v.split("."):
            num = "".join(c for c in part if c.isdigit())
            out.append(int(num) if num else 0)
        return tuple(out)
    pa, pb = parse(a), parse(b)
    n = max(len(pa), len(pb))
    pa += (0,) * (n - len(pa)); pb += (0,) * (n - len(pb))
    return pa < pb
