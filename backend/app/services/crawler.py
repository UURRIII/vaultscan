"""Lightweight breadth-first crawler.

Discovers internal URLs, query parameters and forms, storing them on the
ScanContext so downstream modules (especially the active injection ones)
have real attack surface to work with.
"""
import asyncio
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from app.core.context import ScanContext
from app.core.finding import Finding
from app.core.severity import Severity

MAX_PAGES = 40
MAX_DEPTH = 2
CONCURRENCY = 8


async def run(ctx: ScanContext) -> list[Finding]:
    findings = []
    seen: set[str] = set()
    params: dict[str, set] = {}
    forms: list[dict] = []
    queue: asyncio.Queue = asyncio.Queue()

    start = ctx.base_url
    await queue.put((start, 0))
    seen.add(_canonical(start))

    sem = asyncio.Semaphore(CONCURRENCY)
    pages_crawled = 0

    async def worker():
        nonlocal pages_crawled
        while pages_crawled < MAX_PAGES:
            try:
                url, depth = await asyncio.wait_for(queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                return
            try:
                async with sem:
                    r = await ctx.client.get(url)
                pages_crawled += 1
                ctype = r.headers.get("content-type", "")
                if "text/html" not in ctype:
                    queue.task_done()
                    continue

                html = r.text
                if url == start or url == start + "/":
                    ctx.homepage_html = html

                soup = BeautifulSoup(html, "html.parser")

                # Record params already present on this URL
                _record_params(url, params)

                # Forms → attack surface
                for form in soup.find_all("form"):
                    action = urljoin(url, form.get("action") or url)
                    if _same_host(action, ctx.host):
                        inputs = [inp.get("name") for inp in form.find_all(["input", "textarea", "select"])
                                  if inp.get("name")]
                        forms.append({
                            "action": action,
                            "method": (form.get("method") or "get").lower(),
                            "inputs": inputs,
                        })
                        for name in inputs:
                            params.setdefault(action, set()).add(name)

                # Links → enqueue + collect params
                for a in soup.find_all("a", href=True):
                    link = urljoin(url, a["href"])
                    if not _same_host(link, ctx.host):
                        continue
                    _record_params(link, params)
                    canon = _canonical(link)
                    if canon not in seen and depth < MAX_DEPTH and pages_crawled < MAX_PAGES:
                        seen.add(canon)
                        await queue.put((link, depth + 1))
            except Exception:
                pass
            finally:
                queue.task_done()

    workers = [asyncio.create_task(worker()) for _ in range(CONCURRENCY)]
    await asyncio.gather(*workers, return_exceptions=True)

    ctx.urls = sorted(seen)
    ctx.params = params
    ctx.forms = forms

    total_params = sum(len(v) for v in params.values())
    findings.append(Finding(
        title=f"Crawl Complete: {len(seen)} URLs, {len(forms)} forms, {total_params} parameters",
        description="Mapped the application's attack surface. Parameters and forms feed the active "
                    "vulnerability checks when aggressive mode is enabled.",
        severity=Severity.INFO,
        category="Recon / Crawler",
        evidence="\n".join(ctx.urls[:25]) + ("\n…" if len(ctx.urls) > 25 else ""),
        recommendation="Review exposed endpoints; ensure none leak sensitive functionality.",
    ))
    return findings


def _record_params(url: str, params: dict):
    qs = parse_qs(urlparse(url).query)
    if qs:
        base = url.split("?")[0]
        params.setdefault(base, set()).update(qs.keys())


def _same_host(url: str, host: str) -> bool:
    try:
        return urlparse(url).netloc.split(":")[0].endswith(host)
    except Exception:
        return False


def _canonical(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}{p.path}".rstrip("/")
