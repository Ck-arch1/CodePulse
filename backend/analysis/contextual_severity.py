from __future__ import annotations


SEVERITY_ORDER = ["low", "medium", "high", "critical"]


def _shift(severity: str, amount: int) -> str:
    index = SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else 0
    return SEVERITY_ORDER[max(0, min(len(SEVERITY_ORDER) - 1, index + amount))]


def contextualize_severity(base_severity: str, context: dict) -> str:
    """Adjust severity using reachability, blast radius, exposure, sanitization, and confidence."""
    severity = base_severity if base_severity in SEVERITY_ORDER else "low"
    confidence = float(context.get("confidence", 0.0))
    category = context.get("category")
    isolated = int(context.get("graph_degree", 1)) == 0

    if context.get("tainted") and not context.get("inferred"):
        severity = _shift(severity, 1)
    if context.get("external_exposure"):
        severity = _shift(severity, 1)
    if int(context.get("blast_radius", 0)) >= 2:
        severity = _shift(severity, 1)
    if context.get("sanitized"):
        severity = _shift(severity, -1)
    if isolated and not context.get("tainted") and category == "security":
        severity = _shift(severity, -1)
    if confidence < 0.5 and not context.get("tainted"):
        severity = _shift(severity, -1)
    if confidence >= 0.95 and context.get("tainted") and category == "security":
        severity = _shift(severity, 1)
    return severity
