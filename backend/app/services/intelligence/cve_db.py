"""Curated subset of well-known CVEs keyed by product, with affected version ranges.

This is intentionally a small, high-signal database — not a full NVD mirror.
Each entry flags versions <= `fixed_below` as affected.
"""

# product -> list of {cve, fixed_below, severity, cvss, desc}
CVE_DB = {
    "nginx": [
        {"cve": "CVE-2021-23017", "fixed_below": "1.21.0", "severity": "HIGH", "cvss": 7.7,
         "desc": "Off-by-one in the resolver allowing memory corruption / potential RCE."},
        {"cve": "CVE-2019-9511", "fixed_below": "1.16.1", "severity": "HIGH", "cvss": 7.5,
         "desc": "HTTP/2 'Data Dribble' denial-of-service."},
    ],
    "apache": [
        {"cve": "CVE-2021-41773", "fixed_below": "2.4.50", "severity": "CRITICAL", "cvss": 9.8,
         "desc": "Path traversal and RCE in Apache HTTP Server 2.4.49."},
        {"cve": "CVE-2021-42013", "fixed_below": "2.4.51", "severity": "CRITICAL", "cvss": 9.8,
         "desc": "Path traversal / RCE (incomplete fix of CVE-2021-41773)."},
        {"cve": "CVE-2017-15715", "fixed_below": "2.4.30", "severity": "HIGH", "cvss": 8.1,
         "desc": "Possible upload filter bypass via crafted filename."},
    ],
    "openssh": [
        {"cve": "CVE-2024-6387", "fixed_below": "9.8", "severity": "HIGH", "cvss": 8.1,
         "desc": "'regreSSHion' — unauthenticated RCE via signal handler race condition."},
        {"cve": "CVE-2023-38408", "fixed_below": "9.3.2", "severity": "CRITICAL", "cvss": 9.8,
         "desc": "RCE via ssh-agent PKCS#11 forwarding."},
    ],
    "php": [
        {"cve": "CVE-2024-4577", "fixed_below": "8.3.8", "severity": "CRITICAL", "cvss": 9.8,
         "desc": "CGI argument injection leading to RCE on Windows."},
        {"cve": "CVE-2019-11043", "fixed_below": "7.3.11", "severity": "CRITICAL", "cvss": 9.8,
         "desc": "Buffer underflow in php-fpm leading to RCE."},
    ],
    "wordpress": [
        {"cve": "CVE-2022-21661", "fixed_below": "5.8.3", "severity": "HIGH", "cvss": 8.0,
         "desc": "SQL injection via WP_Query."},
        {"cve": "CVE-2023-2745", "fixed_below": "6.2.1", "severity": "MEDIUM", "cvss": 5.3,
         "desc": "Directory traversal exposing draft content."},
    ],
    "iis": [
        {"cve": "CVE-2015-1635", "fixed_below": "10.0", "severity": "CRITICAL", "cvss": 9.8,
         "desc": "HTTP.sys remote code execution (MS15-034)."},
    ],
}


def parse_version(v: str) -> tuple:
    parts = []
    for chunk in v.split("."):
        num = ""
        for ch in chunk:
            if ch.isdigit():
                num += ch
            else:
                break
        parts.append(int(num) if num else 0)
    return tuple(parts) or (0,)


def version_lt(a: str, b: str) -> bool:
    pa, pb = parse_version(a), parse_version(b)
    length = max(len(pa), len(pb))
    pa += (0,) * (length - len(pa))
    pb += (0,) * (length - len(pb))
    return pa < pb


def lookup(product: str, version: str) -> list[dict]:
    entries = CVE_DB.get(product.lower(), [])
    return [e for e in entries if version_lt(version, e["fixed_below"])]
