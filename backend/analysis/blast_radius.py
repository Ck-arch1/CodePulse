from __future__ import annotations

from networkx import DiGraph, descendants


def compute_blast_radius(graph: DiGraph, findings: list[dict]) -> dict[str, dict]:
    vulnerable = {f["function_name"] for f in findings}
    radii = {}
    for fn in vulnerable:
        if fn in graph:
            affected = sorted(descendants(graph, fn))
            radii[fn] = {"count": len(affected), "affected_functions": affected}
        else:
            radii[fn] = {"count": 0, "affected_functions": []}
    return radii
