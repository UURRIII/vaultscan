import asyncio
import httpx
import dns.asyncresolver
from app.core.finding import Finding
from app.core.severity import Severity

# Service fingerprints: CNAME pattern -> (service name, response fingerprint that signals "unclaimed").
TAKEOVER_SIGNATURES = [
    ("github.io",            "GitHub Pages",   "There isn't a GitHub Pages site here"),
    ("herokuapp.com",        "Heroku",         "No such app"),
    ("herokudns.com",        "Heroku",         "No such app"),
    ("s3.amazonaws.com",     "AWS S3",         "NoSuchBucket"),
    ("amazonaws.com",        "AWS S3",         "NoSuchBucket"),
    ("cloudfront.net",       "AWS CloudFront", "Bad request"),
    ("azurewebsites.net",    "Azure",          "404 Web Site not found"),
    ("cloudapp.net",         "Azure",          "404 Web Site not found"),
    ("trafficmanager.net",   "Azure",          "404 Web Site not found"),
    ("ghost.io",             "Ghost",          "Domain error"),
    ("fastly.net",           "Fastly",         "Fastly error: unknown domain"),
    ("zendesk.com",          "Zendesk",        "Help Center Closed"),
    ("readthedocs.io",       "ReadTheDocs",    "unknown to Read the Docs"),
    ("wpengine.com",         "WP Engine",      "The site you were looking for couldn't be found"),
    ("pantheonsite.io",      "Pantheon",       "The gods are wise"),
    ("surge.sh",             "Surge.sh",       "project not found"),
    ("bitbucket.io",         "Bitbucket",      "Repository not found"),
    ("netlify.app",          "Netlify",        "Not Found"),
    ("netlify.com",          "Netlify",        "Not Found"),
]

# Reuse a small probe wordlist; takeovers usually live on app/marketing subdomains.
PROBE_SUBS = ["www", "blog", "shop", "docs", "help", "support", "status", "app",
              "staging", "dev", "test", "cdn", "assets", "media", "mail", "go",
              "careers", "jobs", "events", "api"]


async def run(ctx) -> list[Finding]:
    target = ctx.target
    domain = _strip_scheme(target)
    findings = []
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 4

    candidates = [domain] + [f"{s}.{domain}" for s in PROBE_SUBS]
    tasks = [_check_host(host, resolver) for host in candidates]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, Finding):
            findings.append(result)

    return findings


async def _check_host(host: str, resolver) -> Finding | None:
    # 1. Resolve CNAME chain
    try:
        answers = await resolver.resolve(host, "CNAME")
        cnames = [str(r.target).rstrip(".").lower() for r in answers]
    except Exception:
        return None

    # 2. Match CNAME against known takeover-prone services
    for cname in cnames:
        for pattern, service, fingerprint in TAKEOVER_SIGNATURES:
            if pattern in cname:
                # 3. Fetch the page and look for the "unclaimed" fingerprint
                vulnerable = await _probe_fingerprint(host, fingerprint)
                if vulnerable:
                    return Finding(
                        title=f"Possible Subdomain Takeover: {host}",
                        description=f"'{host}' has a dangling CNAME pointing to {service} ({cname}), "
                                    f"and the target responds with an 'unclaimed resource' fingerprint. "
                                    f"An attacker may be able to claim this resource and serve content under your domain.",
                        severity=Severity.HIGH,
                        category="Scanner / Takeover",
                        evidence=f"{host} → CNAME → {cname} ({service})\nFingerprint matched: \"{fingerprint}\"",
                        recommendation=f"Remove the dangling DNS record for {host}, or reclaim the {service} resource immediately.",
                        url=f"https://{host}",
                        cvss=8.1,
                    )
                else:
                    # CNAME points to a takeover-prone service but resource seems claimed — informational
                    return Finding(
                        title=f"Third-party CNAME: {host}",
                        description=f"'{host}' points to {service}. Verify the resource is actively claimed to avoid future takeover.",
                        severity=Severity.INFO,
                        category="Scanner / Takeover",
                        evidence=f"{host} → CNAME → {cname} ({service})",
                        recommendation="Periodically audit third-party CNAMEs to ensure the backing resource still exists.",
                        url=f"https://{host}",
                    )
    return None


async def _probe_fingerprint(host: str, fingerprint: str) -> bool:
    for scheme in ("https", "http"):
        try:
            async with httpx.AsyncClient(timeout=8, follow_redirects=True, verify=False) as client:
                r = await client.get(f"{scheme}://{host}",
                                     headers={"User-Agent": "Mozilla/5.0 VaultScan/1.0"})
                if fingerprint.lower() in r.text.lower():
                    return True
        except Exception:
            continue
    return False


def _strip_scheme(target: str) -> str:
    return target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
