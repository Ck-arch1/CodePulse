from __future__ import annotations

from collections import defaultdict
from collections import deque
from networkx import DiGraph

from config import get_settings

WEIGHTS = {"LOW": 1.5, "MEDIUM": 3.0, "HIGH": 5.0, "CRITICAL": 7.0}


def score_functions(graph: DiGraph, findings: list[dict], taint: dict, blast_radii: dict) -> dict[str, float]:
    settings = get_settings()
    by_function = defaultdict(list)
    for finding in findings:
        function_name = finding.get("function") or finding.get("function_name")
        if function_name:
            by_function[function_name].append(finding)
    roots = [node for node, degree in graph.in_degree() if degree == 0] or list(graph.nodes)
    depth = {}
    for root in roots:
        seen = {root}
        queue = deque([(root, 0)])
        while queue:
            node, dist = queue.popleft()
            depth[node] = min(depth.get(node, dist), dist)
            if dist >= settings.max_recursion_depth:
                continue
            for child in graph.successors(node):
                if child in seen:
                    continue
                seen.add(child)
                queue.append((child, dist + 1))
    tainted = set(taint.get("tainted_functions", []))
    scores = {}
    for node in graph.nodes:
        severity = sum(WEIGHTS.get(f["severity"], 1.0) for f in by_function.get(node, []))
        depth_bonus = min(depth.get(node, 0) * 0.4, 1.5)
        taint_bonus = 1.5 if node in tainted else 0
        blast_bonus = min(blast_radii.get(node, {}).get("count", 0) * 0.6, 2.0)
        scores[node] = round(min(10.0, severity + depth_bonus + taint_bonus + blast_bonus), 2)
        graph.nodes[node]["risk_score"] = scores[node]
        graph.nodes[node]["has_taint"] = node in tainted
        graph.nodes[node]["has_sql_issue"] = any(f["type"] == "sql-injection" for f in by_function.get(node, []))
    return scores
