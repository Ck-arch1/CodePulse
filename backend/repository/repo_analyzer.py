from __future__ import annotations

import re
import shutil
import zipfile
import io
from collections import Counter, defaultdict
from pathlib import Path
from typing import Callable

from config import get_settings
from utils.language_detector import detect_language


SUPPORTED_EXTENSIONS = {".py", ".js", ".ts", ".cpp", ".cc", ".cxx", ".c", ".java", ".go", ".rs", ".cs"}
IGNORED_DIRS = {"node_modules", "venv", ".venv", "dist", "build", "__pycache__", ".git", ".idea", ".vscode"}


def _looks_binary_bytes(content: bytes) -> bool:
    sample = content[:4096]
    return b"\x00" in sample or (bool(sample) and sum(1 for byte in sample if byte < 9 or (13 < byte < 32)) / len(sample) > 0.08)


def safe_extract_zip(zip_bytes: bytes, scan_id: str) -> tuple[Path, list[dict]]:
    settings = get_settings()
    root = settings.repo_upload_dir / scan_id
    root.mkdir(parents=True, exist_ok=True)
    warnings: list[dict] = []
    total = 0
    extracted = 0
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            raw_name = info.filename.replace("\\", "/")
            target = (root / raw_name).resolve()
            if not str(target).startswith(str(root.resolve())):
                warnings.append({"truncated": False, "reason": f"Skipped unsafe ZIP path: {raw_name}"})
                continue
            if any(part in IGNORED_DIRS for part in Path(raw_name).parts):
                continue
            if Path(raw_name).suffix.lower() not in SUPPORTED_EXTENSIONS:
                continue
            if info.file_size > settings.max_repo_file_bytes:
                warnings.append({"truncated": True, "reason": f"Skipped oversized file: {raw_name}", "limit": settings.max_repo_file_bytes})
                continue
            total += info.file_size
            if total > settings.max_repo_extracted_bytes:
                warnings.append({"truncated": True, "reason": "Repository extraction limit exceeded.", "limit": settings.max_repo_extracted_bytes})
                break
            target.parent.mkdir(parents=True, exist_ok=True)
            data = archive.read(info)
            if _looks_binary_bytes(data):
                warnings.append({"truncated": False, "reason": f"Skipped binary-like file: {raw_name}"})
                continue
            target.write_bytes(data)
            extracted += 1
            if extracted >= settings.max_repo_files:
                warnings.append({"truncated": True, "reason": "Repository file limit exceeded.", "limit": settings.max_repo_files})
                break
    return root, warnings


def write_uploaded_files(files: list[tuple[str, bytes]], scan_id: str) -> tuple[Path, list[dict]]:
    settings = get_settings()
    root = settings.repo_upload_dir / scan_id
    root.mkdir(parents=True, exist_ok=True)
    warnings: list[dict] = []
    total = 0
    for index, (name, content) in enumerate(files):
        clean_name = Path(name).name or f"source-{index}"
        if Path(clean_name).suffix.lower() not in SUPPORTED_EXTENSIONS:
            warnings.append({"truncated": False, "reason": f"Skipped unsupported file: {clean_name}"})
            continue
        if len(content) > settings.max_repo_file_bytes:
            warnings.append({"truncated": True, "reason": f"Skipped oversized file: {clean_name}", "limit": settings.max_repo_file_bytes})
            continue
        total += len(content)
        if total > settings.max_repo_extracted_bytes:
            warnings.append({"truncated": True, "reason": "Repository upload byte limit exceeded.", "limit": settings.max_repo_extracted_bytes})
            break
        if _looks_binary_bytes(content):
            warnings.append({"truncated": False, "reason": f"Skipped binary-like file: {clean_name}"})
            continue
        (root / clean_name).write_bytes(content)
    return root, warnings


def discover_source_files(root: Path) -> tuple[list[Path], list[dict]]:
    settings = get_settings()
    warnings: list[dict] = []
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in IGNORED_DIRS for part in path.relative_to(root).parts):
            continue
        if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            continue
        files.append(path)
        if len(files) >= settings.max_repo_files:
            warnings.append({"truncated": True, "reason": "Repository file discovery limit exceeded.", "limit": settings.max_repo_files})
            break
    return files, warnings


def _extract_dependencies(relative_path: str, source: str) -> list[str]:
    suffix = Path(relative_path).suffix.lower()
    deps: set[str] = set()
    patterns = []
    if suffix == ".py":
        patterns = [r"^\s*import\s+([A-Za-z_][\w.]*)", r"^\s*from\s+([A-Za-z_][\w.]*)\s+import\s+"]
    elif suffix in {".js", ".ts"}:
        patterns = [r"import\s+.*?\s+from\s+['\"]([^'\"]+)['\"]", r"require\(['\"]([^'\"]+)['\"]\)"]
    elif suffix in {".c", ".cc", ".cpp", ".cxx"}:
        patterns = [r"^\s*#include\s+[<\"]([^>\"]+)[>\"]"]
    elif suffix == ".java":
        patterns = [r"^\s*import\s+([\w.]+);"]
    elif suffix == ".go":
        patterns = [r"^\s*import\s+\"([^\"]+)\""]
    elif suffix == ".rs":
        patterns = [r"^\s*use\s+([\w:]+)"]
    elif suffix == ".cs":
        patterns = [r"^\s*using\s+([\w.]+);"]
    for pattern in patterns:
        for match in re.finditer(pattern, source, re.MULTILINE):
            deps.add(match.group(1))
    return sorted(deps)[:20]


def _severity_rank(severity: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(str(severity), 0)


def analyze_repository(root: Path, analyze_source: Callable[[str, str], dict], initial_warnings: list[dict] | None = None) -> dict:
    settings = get_settings()
    files, discovery_warnings = discover_source_files(root)
    warnings = [*(initial_warnings or []), *discovery_warnings]
    file_reports: list[dict] = []
    findings: list[dict] = []
    language_counts: Counter[str] = Counter()
    dependency_edges: list[dict] = []
    dependency_counts: Counter[str] = Counter()

    for path in files:
        relative = path.relative_to(root).as_posix()
        content = path.read_text(encoding="utf-8", errors="replace")
        language = detect_language(relative)["language"]
        language_counts[language] += 1
        report = analyze_source(content, relative)
        report["file_name"] = relative
        report["lines_of_code"] = len(content.splitlines())
        deps = _extract_dependencies(relative, content)
        dependency_counts.update(deps)
        for dep in deps:
            dependency_edges.append({"data": {"source": relative, "target": dep, "kind": "dependency", "risky": False}})
        for finding in report.get("findings", []):
            finding = dict(finding)
            finding["file"] = relative
            finding["id"] = f"{relative}:{finding.get('id', len(findings) + 1)}"
            findings.append(finding)
        file_reports.append(report)

    ranked_findings = sorted(
        findings,
        key=lambda item: (-_severity_rank(item.get("severity", item.get("type", "low"))), -float(item.get("confidence", 0.0)), item.get("file", "")),
    )
    if len(ranked_findings) > settings.max_findings:
        warnings.append({"truncated": True, "reason": "Repository finding limit exceeded.", "limit": settings.max_findings, "original_count": len(ranked_findings)})
        ranked_findings = ranked_findings[: settings.max_findings]

    file_risk: dict[str, int] = {}
    for report in file_reports:
        file_risk[report["file_name"]] = int(report.get("risk_score", 0) or 0)

    graph_nodes = [
        {
            "data": {
                "id": name,
                "label": Path(name).name,
                "risk": min(10, max(1, risk // 10 or 1)),
                "node_type": "sink" if risk >= 70 else "tainted" if risk >= 35 else "normal",
                "reachable": True,
                "blast_radius": int(next((r.get("blast_radius", 0) for r in file_reports if r.get("file_name") == name), 0) or 0),
                "file": name,
            }
        }
        for name, risk in file_risk.items()
    ]
    dep_nodes = [
        {"data": {"id": dep, "label": dep, "risk": 1, "node_type": "dependency", "reachable": True, "blast_radius": 0}}
        for dep, _ in dependency_counts.most_common(settings.max_graph_nodes)
        if dep not in file_risk
    ]
    graph = {"nodes": graph_nodes + dep_nodes, "edges": dependency_edges}
    graph = _limit_repo_graph(graph, settings.max_graph_nodes, settings.max_graph_edges, warnings)

    category_counts = Counter(f.get("category", f.get("type", "informational")) for f in ranked_findings)
    confidence_distribution = {"high": 0, "medium": 0, "low": 0}
    for finding in ranked_findings:
        confidence = float(finding.get("confidence", 0.0))
        confidence_distribution["high" if confidence >= 0.9 else "medium" if confidence >= 0.6 else "low"] += 1

    critical_files = sorted(file_risk.items(), key=lambda item: item[1], reverse=True)[:8]
    highest_blast = sorted(
        ((r.get("file_name"), int(r.get("blast_radius", 0) or 0)) for r in file_reports),
        key=lambda item: item[1],
        reverse=True,
    )[:8]
    risk_score = min(99, int(round(max(file_risk.values(), default=0) * 0.7 + min(len(ranked_findings), 50) * 0.6)))
    repo_summary = {
        "risk_score": risk_score,
        "total_findings": len(ranked_findings),
        "critical_files": [{"file": name, "risk_score": risk} for name, risk in critical_files if risk > 0],
        "language_distribution": dict(language_counts),
        "highest_blast_radius_modules": [{"file": name, "blast_radius": count} for name, count in highest_blast if count > 0],
        "top_risky_dependencies": [{"dependency": dep, "count": count} for dep, count in dependency_counts.most_common(10)],
        "finding_categories": dict(category_counts),
        "confidence_distribution": confidence_distribution,
        "analyzed_files": len(file_reports),
    }
    return {
        "file_name": root.name,
        "language": "repository",
        "analysis_mode": "repository-lightweight",
        "supported_ast": True,
        "risk_score": risk_score,
        "repo_summary": repo_summary,
        "file_reports": _compact_file_reports(file_reports),
        "findings": ranked_findings,
        "graph": graph,
        "dependency_graph": graph,
        "category_counts": dict(category_counts),
        "confidence_distribution": confidence_distribution,
        "warnings": warnings,
        "truncated": any(item.get("truncated") for item in warnings),
        "graph_truncated": any("Graph" in str(item.get("reason", "")) and item.get("truncated") for item in warnings),
        "lines_of_code": sum(int(report.get("lines_of_code", 0) or 0) for report in file_reports),
        "blast_radius": sum(int(report.get("blast_radius", 0) or 0) for report in file_reports),
        "taint_flows": [flow for report in file_reports for flow in (report.get("taint_flows") or [])][: settings.max_taint_paths],
        "stats": {"total_findings": len(ranked_findings), "severity_counts": dict(Counter(f.get("severity", "low") for f in ranked_findings)), "taint_path_count": 0},
    }


def _compact_file_reports(file_reports: list[dict]) -> list[dict]:
    return [
        {
            "file_name": report.get("file_name"),
            "language": report.get("language"),
            "analysis_mode": report.get("analysis_mode"),
            "risk_score": report.get("risk_score", 0),
            "findings_count": len(report.get("findings") or []),
            "blast_radius": report.get("blast_radius", 0),
            "warnings": report.get("warnings", []),
        }
        for report in file_reports
    ]


def _limit_repo_graph(graph: dict, max_nodes: int, max_edges: int, warnings: list[dict]) -> dict:
    nodes = list(graph.get("nodes") or [])
    edges = list(graph.get("edges") or [])
    if len(nodes) > max_nodes:
        nodes = sorted(nodes, key=lambda node: (-int(node.get("data", {}).get("risk", 0) or 0), node.get("data", {}).get("id", "")))[:max_nodes]
        kept = {node.get("data", {}).get("id") for node in nodes}
        edges = [edge for edge in edges if edge.get("data", {}).get("source") in kept and edge.get("data", {}).get("target") in kept]
        warnings.append({"truncated": True, "reason": "Graph node limit exceeded for repository view.", "limit": max_nodes})
    if len(edges) > max_edges:
        edges = edges[:max_edges]
        warnings.append({"truncated": True, "reason": "Graph edge limit exceeded for repository view.", "limit": max_edges})
    return {"nodes": nodes, "edges": edges}


def cleanup_repo(scan_id: str) -> None:
    shutil.rmtree(get_settings().repo_upload_dir / scan_id, ignore_errors=True)
