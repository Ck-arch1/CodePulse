from __future__ import annotations

from networkx import DiGraph
from networkx.readwrite import json_graph

from parser.ast_parser import ParsedPythonFile


def _resolve_call(name: str, known: dict[str, str]) -> str | None:
    return known.get(name) or known.get(name.split(".")[-1])


def build_call_graph(parsed: ParsedPythonFile) -> DiGraph:
    graph = DiGraph()
    known = {fn.name: fn.qualname for fn in parsed.functions} | {fn.qualname: fn.qualname for fn in parsed.functions}
    for fn in parsed.functions:
        graph.add_node(fn.qualname, id=fn.qualname, label=fn.name, line_number=fn.line_number, end_line_number=fn.end_line_number, risk_score=0, has_taint=False, has_sql_issue=False)
    if not parsed.functions:
        graph.add_node("<module>", id="<module>", label="<module>", line_number=1, end_line_number=max(1, len(parsed.source.splitlines())), risk_score=0, has_taint=False, has_sql_issue=False)
    for fn in parsed.functions:
        for called in fn.calls:
            target = _resolve_call(called, known)
            if target:
                graph.add_edge(fn.qualname, target, kind="call")
    return graph


def graph_to_json(graph: DiGraph) -> dict:
    return json_graph.node_link_data(graph, edges="edges")
