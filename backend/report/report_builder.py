from __future__ import annotations

from collections import Counter
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape
from config import get_settings
from parser.graph_builder import graph_to_json


def _severity_rank(severity: str) -> int:
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(str(severity).upper(), 0)


def _limit_findings(findings: list[dict], limit: int) -> tuple[list[dict], dict | None]:
    ranked = sorted(
        findings,
        key=lambda item: (
            -_severity_rank(item.get("severity", item.get("type", "LOW"))),
            -float(item.get("confidence", 0.5)),
            item.get("line_number", item.get("line", 0)) or 0,
        ),
    )
    limited = ranked if len(ranked) <= limit else ranked[:limit]
    for finding in limited:
        if isinstance(finding.get("explanation"), str) and len(finding["explanation"]) > 1200:
            finding["explanation"] = f"{finding['explanation'][:1200]}..."
        if isinstance(finding.get("message"), str) and len(finding["message"]) > 500:
            finding["message"] = f"{finding['message'][:500]}..."
    if len(ranked) <= limit:
        return limited, None
    return limited, {"truncated": True, "reason": "Finding limit exceeded; lowest-priority findings were omitted from the report.", "limit": limit, "original_count": len(findings)}


def _limit_graph(graph_json: dict, max_nodes: int, max_edges: int) -> tuple[dict, dict | None]:
    nodes = list(graph_json.get("nodes") or [])
    edges = list(graph_json.get("edges") or [])
    warnings = []
    if len(nodes) > max_nodes:
        nodes = sorted(nodes, key=lambda item: -float(item.get("data", {}).get("risk", 0) or 0))[:max_nodes]
        kept = {item.get("data", {}).get("id") for item in nodes}
        edges = [edge for edge in edges if edge.get("data", {}).get("source") in kept and edge.get("data", {}).get("target") in kept]
        warnings.append({"truncated": True, "reason": "Graph node limit exceeded", "limit": max_nodes, "original_count": len(graph_json.get("nodes") or [])})
    if len(edges) > max_edges:
        edges = edges[:max_edges]
        warnings.append({"truncated": True, "reason": "Graph edge limit exceeded", "limit": max_edges, "original_count": len(graph_json.get("edges") or [])})
    return {"nodes": nodes, "edges": edges}, warnings[0] if warnings else None


def build_report_json(file_name: str, parsed, graph, findings: list[dict], scores: dict, taint: dict, blast_radii: dict, scan_time_ms: int) -> dict:
    settings = get_settings()
    warnings = []
    findings, finding_warning = _limit_findings(findings, settings.max_findings)
    if finding_warning:
        warnings.append(finding_warning)
    graph_json, graph_warning = _limit_graph(graph_to_json(graph), settings.max_graph_nodes, settings.max_graph_edges)
    if graph_warning:
        warnings.append(graph_warning)
    if taint.get("truncated"):
        warnings.append({"truncated": True, "reason": "Graph traversal depth or node limit reached during taint analysis."})
    total_blast_radius = sum(int(item.get("count", 0) or 0) for item in blast_radii.values())
    risk_score = int(round(min(100, (max(scores.values()) * 10) if scores else 0)))
    severity_counts = dict(Counter(f["severity"] for f in findings))
    category_counts = dict(Counter(f.get("category", f.get("type", "informational")) for f in findings))
    confidence_distribution = {"high": 0, "medium": 0, "low": 0}
    for finding in findings:
        confidence = float(finding.get("confidence", 0.0))
        if confidence >= 0.9:
            confidence_distribution["high"] += 1
        elif confidence >= 0.6:
            confidence_distribution["medium"] += 1
        else:
            confidence_distribution["low"] += 1
    top = sorted(scores.items(), key=lambda item: item[1], reverse=True)[:5]
    return {
        "file_name": file_name,
        "language": "Python",
        "lines_of_code": parsed.lines_of_code,
        "scan_time_ms": scan_time_ms,
        "risk_score": risk_score,
        "graph": graph_json,
        "findings": findings,
        "scores": scores,
        "taint_paths": taint.get("paths", [])[: settings.max_taint_paths],
        "tainted_functions": taint.get("tainted_functions", []),
        "taint_sources": taint.get("sources", []),
        "taint_flows": taint.get("paths", [])[: settings.max_taint_paths],
        "blast_radius": total_blast_radius,
        "blast_radii": blast_radii,
        "warnings": warnings,
        "truncated": any(item.get("truncated") for item in warnings),
        "graph_truncated": any("Graph" in str(item.get("reason", "")) and item.get("truncated") for item in warnings),
        "limits": {
            "max_findings": settings.max_findings,
            "max_graph_nodes": settings.max_graph_nodes,
            "max_graph_edges": settings.max_graph_edges,
            "max_taint_paths": settings.max_taint_paths,
        },
        "category_counts": category_counts,
        "confidence_distribution": confidence_distribution,
        "stats": {"total_findings": len(findings), "severity_counts": severity_counts, "top_risky_functions": [{"name": name, "score": score} for name, score in top], "taint_path_count": len(taint.get("paths", []))},
    }


def render_html_report(report: dict) -> str:
    template_dir = Path(__file__).parent / "templates"
    env = Environment(loader=FileSystemLoader(template_dir), autoescape=select_autoescape())
    return env.get_template("report_template.html").render(report=report)
