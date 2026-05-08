from __future__ import annotations

import ast
from networkx import DiGraph

from analysis.graph_cache import GraphQueryCache
from config import get_settings
from parser.ast_parser import ParsedPythonFile, call_name, function_for_line

SOURCES = {"input", "sys.argv", "request.args", "request.json", "request.form", "request.get_json"}


def _is_source(node: ast.AST) -> bool:
    if isinstance(node, ast.Call):
        return (call_name(node.func) or "") in SOURCES
    return call_name(node) in SOURCES


def trace_taint(parsed: ParsedPythonFile, graph: DiGraph, findings: list[dict], cache: GraphQueryCache | None = None) -> dict:
    settings = get_settings()
    graph_cache = cache or GraphQueryCache(graph, max_depth=settings.max_graph_traversal_depth, max_nodes=settings.max_graph_nodes)
    tainted_functions: set[str] = set()
    taint_lines: list[dict] = []
    for node in parsed.ast_index.nodes:
        if _is_source(node):
            line = getattr(node, "lineno", 1)
            fn = function_for_line(parsed, line)
            tainted_functions.add(fn)
            taint_lines.append({"function_name": fn, "line_number": line, "source": ast.unparse(node)})
    affected = set(tainted_functions)
    for fn in list(tainted_functions):
        if fn in graph:
            affected.update(graph_cache.descendants(fn))
    vulnerable = {
        function_name
        for finding in findings
        for function_name in [finding.get("function") or finding.get("function_name")]
        if function_name
    }
    paths = []
    for src in tainted_functions:
        for dst in vulnerable:
            if len(paths) >= settings.max_taint_paths:
                break
            if src in graph and dst in graph and graph_cache.has_path(src, dst):
                path = graph_cache.shortest_path(src, dst)
                if path:
                    paths.append(path)
    return {"tainted_functions": sorted(affected), "sources": taint_lines, "paths": paths, "truncated": graph_cache.truncated}
