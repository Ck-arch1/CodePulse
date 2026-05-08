from __future__ import annotations

from networkx import DiGraph

from analysis.graph_cache import GraphQueryCache
from config import get_settings


def compute_blast_radius(graph: DiGraph, findings: list[dict], cache: GraphQueryCache | None = None) -> dict[str, dict]:
    settings = get_settings()
    graph_cache = cache or GraphQueryCache(graph, max_depth=settings.max_graph_traversal_depth, max_nodes=settings.max_graph_nodes)
    vulnerable = {
        function_name
        for finding in findings
        for function_name in [finding.get("function") or finding.get("function_name")]
        if function_name
    }
    radii = {}
    for fn in vulnerable:
        if fn in graph:
            radii[fn] = graph_cache.blast_radius(fn)
        else:
            radii[fn] = {"count": 0, "affected_functions": []}
    return radii
