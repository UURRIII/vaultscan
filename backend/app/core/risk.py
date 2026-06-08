"""Global risk scoring for a scan based on its findings."""

# Points each severity contributes to the raw risk accumulation.
SEVERITY_POINTS = {
    "CRITICAL": 40,
    "HIGH": 20,
    "MEDIUM": 8,
    "LOW": 2,
    "INFO": 0,
}


def compute_risk(severity_counts: dict[str, int]) -> dict:
    """
    Returns a risk score 0-100 and a letter grade.

    The score uses diminishing returns so that one critical doesn't
    instantly max out, but several criticals push firmly into the red.
    """
    raw = sum(SEVERITY_POINTS.get(sev, 0) * count for sev, count in severity_counts.items())

    # Saturating curve: 0 → 0, grows fast, asymptotically approaches 100.
    score = round(100 * (1 - (0.5 ** (raw / 50))))
    score = max(0, min(100, score))

    grade = _grade(score, severity_counts)
    return {"score": score, "grade": grade, "raw": raw}


def _grade(score: int, counts: dict[str, int]) -> str:
    # A clean bill of health only if there are no medium+ findings.
    if counts.get("CRITICAL", 0) > 0:
        return "F"
    if counts.get("HIGH", 0) >= 3:
        return "F"
    if counts.get("HIGH", 0) > 0:
        return "D"
    if score >= 40:
        return "C"
    if score >= 15:
        return "B"
    return "A"
