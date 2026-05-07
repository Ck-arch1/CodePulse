from __future__ import annotations

from collections import Counter
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape
from parser.graph_builder import graph_to_json


def build_report_json(file_name: str, parsed, graph, findings: list[dict], scores: dict, taint: dict, blast_radii: dict, scan_time_ms: int) -> dict:
    severity_counts = dict(Counter(f["severity"] for f in findings))
    top = sorted(scores.items(), key=lambda item: item[1], reverse=True)[:5]
    return {
        "file_name": file_name,
        "language": "Python",
        "lines_of_code": parsed.lines_of_code,
        "scan_time_ms": scan_time_ms,
        "graph": graph_to_json(graph),
        "findings": findings,
        "scores": scores,
        "taint_paths": taint.get("paths", []),
        "tainted_functions": taint.get("tainted_functions", []),
        "taint_sources": taint.get("sources", []),
        "blast_radii": blast_radii,
        "stats": {"total_findings": len(findings), "severity_counts": severity_counts, "top_risky_functions": [{"name": name, "score": score} for name, score in top], "taint_path_count": len(taint.get("paths", []))},
    }


def render_html_report(report: dict) -> str:
    template_dir = Path(__file__).parent / "templates"
    env = Environment(loader=FileSystemLoader(template_dir), autoescape=select_autoescape())
    return env.get_template("report_template.html").render(report=report)
