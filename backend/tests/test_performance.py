from __future__ import annotations

import logging
import time
from pathlib import Path

from analysis.blast_radius import compute_blast_radius
from analysis.graph_cache import GraphQueryCache
from analysis.risk_scorer import score_functions
from analysis.security_scanner import fallback_scan
from analysis.sql_analyzer import detect_sql_issues
from analysis.taint_analyzer import trace_taint
from config import get_settings
from parser.ast_parser import parse_python_file
from parser.graph_builder import build_call_graph

logger = logging.getLogger("codepulse.performance")


def test_python_analysis_stress_metrics():
    root = Path(__file__).resolve().parents[2]
    samples = [
        root / "demo_files" / "large_call_graph.py",
        root / "demo_files" / "recursive_chain.py",
        root / "demo_files" / "huge_ast.py",
    ]
    for sample in samples:
        started = time.perf_counter()
        parsed = parse_python_file(sample)
        ast_ms = int((time.perf_counter() - started) * 1000)

        started = time.perf_counter()
        graph = build_call_graph(parsed)
        graph_ms = int((time.perf_counter() - started) * 1000)

        findings = [*fallback_scan(parsed), *detect_sql_issues(parsed)]
        cache = GraphQueryCache(graph, max_depth=get_settings().max_graph_traversal_depth, max_nodes=get_settings().max_graph_nodes)

        started = time.perf_counter()
        taint = trace_taint(parsed, graph, findings, cache)
        taint_ms = int((time.perf_counter() - started) * 1000)

        blast = compute_blast_radius(graph, findings, cache)
        scores = score_functions(graph, findings, taint, blast)
        logger.info(
            "sample=%s ast_ms=%s graph_ms=%s taint_ms=%s ast_nodes=%s graph_nodes=%s graph_edges=%s findings=%s scores=%s cache_truncated=%s",
            sample.name,
            ast_ms,
            graph_ms,
            taint_ms,
            parsed.ast_index.node_count,
            graph.number_of_nodes(),
            graph.number_of_edges(),
            len(findings),
            len(scores),
            cache.truncated,
        )
        assert parsed.ast_index.node_count > 0
        assert graph.number_of_nodes() > 0
