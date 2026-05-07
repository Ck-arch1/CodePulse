from __future__ import annotations


def score_confidence(evidence: dict, category: str) -> float:
    """Deterministic confidence scoring for lightweight analysis evidence."""
    analysis_type = evidence.get("analysis_type", "heuristic")
    tainted = bool(evidence.get("tainted"))
    reachable = bool(evidence.get("reachable", True))
    matched_pattern = str(evidence.get("matched_pattern", "")).lower()
    exact = bool(evidence.get("exact", False))
    inferred = bool(evidence.get("inferred", False))
    sanitized = bool(evidence.get("sanitized", False))

    if tainted:
        if inferred:
            return 0.78
        return 0.98 if reachable else 0.92
    if analysis_type == "taint":
        return 0.97
    if analysis_type == "ast":
        if exact or any(term in matched_pattern for term in ("call", "assignment", "literal zero", "bare except")):
            return 0.96
        return 0.9
    if analysis_type in {"bandit", "semgrep"}:
        return 0.88
    if category == "syntax" and ("bracket" in matched_pattern or "unfinished" in matched_pattern):
        return 0.35
    if inferred or category == "runtime":
        return 0.55
    if analysis_type == "heuristic":
        if any(term in matched_pattern for term in ("secret assignment", "shell command", "eval-like", "sql")):
            return 0.5
        return 0.45 if not sanitized else 0.4
    return 0.6 if reachable else 0.5


def should_keep_finding(finding: dict) -> bool:
    """Suppress weak, low-value heuristics while keeping explainable syntax signals."""
    confidence = float(finding.get("confidence", 0.0))
    category = finding.get("category")
    severity = finding.get("severity")
    evidence = finding.get("evidence", {})
    analysis_type = evidence.get("analysis_type")
    if category == "syntax":
        return True
    if evidence.get("tainted"):
        return True
    if analysis_type == "heuristic" and severity == "low" and confidence < 0.5:
        return False
    if severity == "low" and confidence < 0.4:
        return False
    return True
