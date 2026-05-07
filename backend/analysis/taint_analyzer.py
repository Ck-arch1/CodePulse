from __future__ import annotations

import ast
from networkx import DiGraph, descendants, has_path, shortest_path

from parser.ast_parser import ParsedPythonFile, call_name, function_for_line

SOURCES = {"input", "sys.argv", "request.args", "request.json", "request.form", "request.get_json"}


def _is_source(node: ast.AST) -> bool:
    if isinstance(node, ast.Call):
        return (call_name(node.func) or "") in SOURCES
    return call_name(node) in SOURCES


def trace_taint(parsed: ParsedPythonFile, graph: DiGraph, findings: list[dict]) -> dict:
    tainted_functions: set[str] = set()
    taint_lines: list[dict] = []
    for node in ast.walk(parsed.ast_tree):
        if _is_source(node):
            line = getattr(node, "lineno", 1)
            fn = function_for_line(parsed, line)
            tainted_functions.add(fn)
            taint_lines.append({"function_name": fn, "line_number": line, "source": ast.unparse(node)})
    affected = set(tainted_functions)
    for fn in list(tainted_functions):
        if fn in graph:
            affected.update(descendants(graph, fn))
    vulnerable = {f["function_name"] for f in findings}
    paths = []
    for src in tainted_functions:
        for dst in vulnerable:
            if src in graph and dst in graph and has_path(graph, src, dst):
                paths.append(shortest_path(graph, src, dst))
    return {"tainted_functions": sorted(affected), "sources": taint_lines, "paths": paths}
