"""Shared context passed to every scan module.

Carries the target, scan mode, a shared HTTP client, and everything the
crawler discovers so modules don't re-fetch the same pages.
"""
from dataclasses import dataclass, field
import httpx

USER_AGENT = "Mozilla/5.0 (compatible; VaultScan/3.0; +https://vaultscan.local)"


@dataclass
class ScanContext:
    target: str                                   # raw user input, normalized
    host: str                                     # hostname only
    base_url: str                                 # scheme://host
    mode: str = "safe"                            # "safe" | "aggressive"
    client: httpx.AsyncClient = None              # shared async client

    # Populated by the crawler:
    urls: list[str] = field(default_factory=list)            # discovered pages
    params: dict[str, set] = field(default_factory=dict)     # url -> {param names}
    forms: list[dict] = field(default_factory=list)          # {action, method, inputs}
    homepage_html: str = ""                                   # cached homepage body

    @property
    def is_aggressive(self) -> bool:
        return self.mode == "aggressive"

    def param_targets(self) -> list[tuple[str, str]]:
        """Flatten discovered params into (url, param) pairs for injection modules."""
        pairs = []
        for url, names in self.params.items():
            for name in names:
                pairs.append((url, name))
        return pairs


def build_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=10,
        follow_redirects=True,
        verify=False,
        headers={"User-Agent": USER_AGENT},
        limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
    )


def normalize(target: str) -> tuple[str, str, str]:
    """Return (normalized_target, host, base_url)."""
    t = target.strip().rstrip("/")
    scheme = "https"
    rest = t
    if "://" in t:
        scheme, rest = t.split("://", 1)
    host = rest.split("/")[0].split(":")[0]
    base_url = f"{scheme}://{host}"
    return t, host, base_url
