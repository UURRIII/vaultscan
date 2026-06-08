from dataclasses import dataclass
from typing import Optional
from .severity import Severity


@dataclass
class Finding:
    title: str
    description: str
    severity: Severity
    category: str
    evidence: str
    recommendation: str
    url: str = ""
    cvss: Optional[float] = None  # explicit CVSS base score; falls back to severity default
    confidence: Optional[str] = None  # explicit confidence; else derived from taxonomy

    @property
    def cvss_score(self) -> float:
        return self.cvss if self.cvss is not None else self.severity.default_cvss

    def to_dict(self) -> dict:
        from .taxonomy import classify
        tax = classify(self.title, self.category, self.severity.value)
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "url": self.url,
            "cvss": round(self.cvss_score, 1),
            "owasp": tax["owasp"],
            "owasp_name": tax["owasp_name"],
            "cwe": tax["cwe"],
            "confidence": self.confidence or tax["confidence"],
        }
