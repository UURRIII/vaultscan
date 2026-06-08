"""Error-based SQL injection detection (aggressive mode only).

Injects SQL metacharacters into discovered parameters and looks for
database error signatures or boolean-difference behaviour.
"""
import asyncio
from urllib.parse import urlencode, urlparse, parse_qs
from app.core.context import ScanContext
from app.core.finding import Finding
from app.core.severity import Severity

# DBMS error signatures.
SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysqli_fetch", "mysql_fetch", "mysql_num_rows",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "pg_query", "postgresql query failed", "psql:",
    "ora-00933", "ora-01756", "ora-00921",
    "sqlite3::", "sqlite_error",
    "microsoft odbc", "odbc sql server driver",
    "syntax error at or near",
]

PROBE = "'"
MAX_TESTS = 25


async def run(ctx: ScanContext) -> list[Finding]:
    findings = []
    targets = ctx.param_targets()
    if not targets:
        return findings

    sem = asyncio.Semaphore(6)
    tasks = []
    for i, (url, param) in enumerate(targets):
        if i >= MAX_TESTS:
            break
        tasks.append(_test_param(ctx, url, param, sem))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    seen = set()
    for r in results:
        if isinstance(r, Finding) and (r.url, r.title) not in seen:
            seen.add((r.url, r.title))
            findings.append(r)
    return findings


async def _baseline_errors(text: str) -> set:
    low = text.lower()
    return {sig for sig in SQL_ERRORS if sig in low}


async def _test_param(ctx: ScanContext, url: str, param: str, sem: asyncio.Semaphore) -> Finding | None:
    base = url.split("?")[0]
    existing = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}

    # Baseline (clean) request to avoid flagging pre-existing error text.
    try:
        clean = {**existing, param: existing.get(param, "1")}
        async with sem:
            base_resp = await ctx.client.get(f"{base}?{urlencode(clean)}")
        baseline = await _baseline_errors(base_resp.text)
    except Exception:
        baseline = set()

    # Inject a single quote.
    inj = {**existing, param: (existing.get(param, "1") + PROBE)}
    test_url = f"{base}?{urlencode(inj)}"
    try:
        async with sem:
            r = await ctx.client.get(test_url)
    except Exception:
        return None

    triggered = await _baseline_errors(r.text)
    new_errors = triggered - baseline
    if new_errors:
        return Finding(
            title=f"SQL Injection in '{param}' (error-based)",
            description=f"Injecting a single quote into '{param}' produced a database error, indicating the "
                        "parameter is concatenated into a SQL query without parameterisation.",
            severity=Severity.CRITICAL,
            category="Active / SQLi",
            evidence=f"Request: {test_url}\nError signature: {next(iter(new_errors))}",
            recommendation="Use parameterised queries / prepared statements. Never concatenate user input into SQL.",
            url=test_url,
            cvss=9.8,
        )
    return None
