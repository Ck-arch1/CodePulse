from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from networkx import DiGraph


@dataclass
class GraphQueryCache:
    graph: DiGraph
    max_depth: int = 12
    max_nodes: int = 500
    _descendants: dict[tuple[str, int], set[str]] = field(default_factory=dict)
    _has_path: dict[tuple[str, str, int], bool] = field(default_factory=dict)
    _shortest_path: dict[tuple[str, str, int], list[str] | None] = field(default_factory=dict)
    _blast_radius: dict[tuple[str, int], dict] = field(default_factory=dict)
    truncated: bool = False

    def descendants(self, source: str, max_depth: int | None = None) -> set[str]:
        depth_limit = max_depth or self.max_depth
        key = (source, depth_limit)
        if key in self._descendants:
            return set(self._descendants[key])
        if source not in self.graph:
            self._descendants[key] = set()
            return set()

        seen: set[str] = set()
        queue = deque([(source, 0)])
        while queue:
            node, depth = queue.popleft()
            if depth >= depth_limit:
                self.truncated = True
                continue
            for child in self.graph.successors(node):
                if child in seen:
                    continue
                seen.add(child)
                if len(seen) >= self.max_nodes:
                    self.truncated = True
                    self._descendants[key] = seen
                    return set(seen)
                queue.append((child, depth + 1))
        self._descendants[key] = seen
        return set(seen)

    def has_path(self, source: str, target: str, max_depth: int | None = None) -> bool:
        depth_limit = max_depth or self.max_depth
        key = (source, target, depth_limit)
        if key not in self._has_path:
            self._has_path[key] = target in self.descendants(source, depth_limit) or source == target
        return self._has_path[key]

    def shortest_path(self, source: str, target: str, max_depth: int | None = None) -> list[str] | None:
        depth_limit = max_depth or self.max_depth
        key = (source, target, depth_limit)
        if key in self._shortest_path:
            path = self._shortest_path[key]
            return list(path) if path else None
        if source not in self.graph or target not in self.graph:
            self._shortest_path[key] = None
            return None
        queue = deque([(source, [source])])
        seen = {source}
        while queue:
            node, path = queue.popleft()
            if node == target:
                self._shortest_path[key] = path
                return list(path)
            if len(path) - 1 >= depth_limit:
                self.truncated = True
                continue
            for child in self.graph.successors(node):
                if child in seen:
                    continue
                seen.add(child)
                if len(seen) >= self.max_nodes:
                    self.truncated = True
                    self._shortest_path[key] = None
                    return None
                queue.append((child, [*path, child]))
        self._shortest_path[key] = None
        return None

    def blast_radius(self, source: str, max_depth: int | None = None) -> dict:
        depth_limit = max_depth or self.max_depth
        key = (source, depth_limit)
        if key not in self._blast_radius:
            affected = sorted(self.descendants(source, depth_limit))
            self._blast_radius[key] = {"count": len(affected), "affected_functions": affected}
        return dict(self._blast_radius[key])
