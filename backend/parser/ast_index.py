from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any


DANGEROUS_SINKS = {
    "eval",
    "exec",
    "os.system",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.run",
    "pickle.loads",
    "yaml.load",
}


def call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return call_name(node.func)
    return None


def assigned_names(node: ast.Assign | ast.AnnAssign) -> list[str]:
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    names: list[str] = []
    for target in targets:
        if isinstance(target, ast.Name):
            names.append(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            names.extend(item.id for item in target.elts if isinstance(item, ast.Name))
    return names


@dataclass(slots=True)
class FunctionIndex:
    name: str
    qualname: str
    line_number: int
    end_line_number: int
    args: list[str] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)
    decorators: list[str] = field(default_factory=list)
    node: ast.FunctionDef | ast.AsyncFunctionDef | None = None


@dataclass(slots=True)
class CallSite:
    name: str
    line_number: int
    function_name: str
    node: ast.Call


@dataclass(slots=True)
class AssignmentInfo:
    names: list[str]
    line_number: int
    function_name: str
    value: ast.AST | None
    node: ast.Assign | ast.AnnAssign


@dataclass(slots=True)
class LiteralInfo:
    value: object
    line_number: int
    function_name: str
    node: ast.Constant


@dataclass(slots=True)
class ReturnInfo:
    line_number: int
    function_name: str
    value: ast.AST | None
    node: ast.Return


@dataclass(slots=True)
class ControlFlowHint:
    kind: str
    line_number: int
    function_name: str
    node: ast.AST


@dataclass(slots=True)
class AstIndex:
    tree: ast.AST
    node_count: int
    nodes: list[ast.AST]
    functions: list[FunctionIndex]
    function_map: dict[str, FunctionIndex]
    function_ranges: dict[str, tuple[int, int]]
    calls: list[CallSite]
    imports: list[ast.Import | ast.ImportFrom]
    assignments: list[AssignmentInfo]
    literals: list[LiteralInfo]
    dangerous_sinks: list[CallSite]
    returns: list[ReturnInfo]
    control_flow_hints: list[ControlFlowHint]
    line_to_function: dict[int, str]
    calls_by_function: dict[str, list[CallSite]]
    assignments_by_function: dict[str, list[AssignmentInfo]]
    returns_by_function: dict[str, list[ReturnInfo]]

    def function_for_line(self, line_number: int) -> str:
        if line_number in self.line_to_function:
            return self.line_to_function[line_number]
        candidates = [
            (name, start)
            for name, (start, end) in self.function_ranges.items()
            if start <= line_number <= end
        ]
        return max(candidates, key=lambda item: item[1])[0] if candidates else "<module>"


class _AstIndexer(ast.NodeVisitor):
    def __init__(self) -> None:
        self.stack: list[str] = []
        self.nodes: list[ast.AST] = []
        self.functions: list[FunctionIndex] = []
        self.function_map: dict[str, FunctionIndex] = {}
        self.function_ranges: dict[str, tuple[int, int]] = {}
        self.calls: list[CallSite] = []
        self.imports: list[ast.Import | ast.ImportFrom] = []
        self.assignments: list[AssignmentInfo] = []
        self.literals: list[LiteralInfo] = []
        self.dangerous_sinks: list[CallSite] = []
        self.returns: list[ReturnInfo] = []
        self.control_flow_hints: list[ControlFlowHint] = []
        self.calls_by_function: dict[str, list[CallSite]] = {}
        self.assignments_by_function: dict[str, list[AssignmentInfo]] = {}
        self.returns_by_function: dict[str, list[ReturnInfo]] = {}

    @property
    def current_function(self) -> str:
        return ".".join(self.stack) if self.stack else "<module>"

    def visit(self, node: ast.AST) -> Any:
        self.nodes.append(node)
        return super().visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self._visit_function(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        qualname = ".".join([*self.stack, node.name]) if self.stack else node.name
        info = FunctionIndex(
            name=node.name,
            qualname=qualname,
            line_number=node.lineno,
            end_line_number=int(getattr(node, "end_lineno", node.lineno)),
            args=[arg.arg for arg in node.args.args],
            decorators=[call_name(item) or ast.unparse(item) for item in node.decorator_list],
            node=node,
        )
        self.functions.append(info)
        self.function_map[qualname] = info
        self.function_map.setdefault(node.name, info)
        self.function_ranges[qualname] = (info.line_number, info.end_line_number)
        self.function_ranges.setdefault(node.name, (info.line_number, info.end_line_number))
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()
        info.calls = sorted({call.name for call in self.calls_by_function.get(qualname, [])})

    def visit_Call(self, node: ast.Call) -> Any:
        name = call_name(node.func)
        if name:
            site = CallSite(name=name, line_number=getattr(node, "lineno", 1), function_name=self.current_function, node=node)
            self.calls.append(site)
            self.calls_by_function.setdefault(self.current_function, []).append(site)
            if name in DANGEROUS_SINKS or name.split(".")[-1] in DANGEROUS_SINKS:
                self.dangerous_sinks.append(site)
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> Any:
        self.imports.append(node)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        self.imports.append(node)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        self._visit_assignment(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        self._visit_assignment(node)

    def _visit_assignment(self, node: ast.Assign | ast.AnnAssign) -> None:
        info = AssignmentInfo(assigned_names(node), getattr(node, "lineno", 1), self.current_function, node.value, node)
        self.assignments.append(info)
        self.assignments_by_function.setdefault(self.current_function, []).append(info)
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> Any:
        self.literals.append(LiteralInfo(node.value, getattr(node, "lineno", 1), self.current_function, node))
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> Any:
        info = ReturnInfo(getattr(node, "lineno", 1), self.current_function, node.value, node)
        self.returns.append(info)
        self.returns_by_function.setdefault(self.current_function, []).append(info)
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> Any:
        self._control("if", node)

    def visit_For(self, node: ast.For) -> Any:
        self._control("for", node)

    def visit_While(self, node: ast.While) -> Any:
        self._control("while", node)

    def visit_Try(self, node: ast.Try) -> Any:
        self._control("try", node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> Any:
        self._control("except", node)

    def _control(self, kind: str, node: ast.AST) -> None:
        self.control_flow_hints.append(ControlFlowHint(kind, getattr(node, "lineno", 1), self.current_function, node))
        self.generic_visit(node)


def build_ast_index(tree: ast.AST) -> AstIndex:
    indexer = _AstIndexer()
    indexer.visit(tree)
    line_to_function: dict[int, str] = {}
    for fn in indexer.functions:
        for line in range(fn.line_number, fn.end_line_number + 1):
            current = line_to_function.get(line)
            current_start = indexer.function_ranges.get(current or "", (0, 0))[0]
            if not current or fn.line_number >= current_start:
                line_to_function[line] = fn.qualname
    return AstIndex(
        tree=tree,
        node_count=len(indexer.nodes),
        nodes=indexer.nodes,
        functions=indexer.functions,
        function_map=indexer.function_map,
        function_ranges=indexer.function_ranges,
        calls=indexer.calls,
        imports=indexer.imports,
        assignments=indexer.assignments,
        literals=indexer.literals,
        dangerous_sinks=indexer.dangerous_sinks,
        returns=indexer.returns,
        control_flow_hints=indexer.control_flow_hints,
        line_to_function=line_to_function,
        calls_by_function=indexer.calls_by_function,
        assignments_by_function=indexer.assignments_by_function,
        returns_by_function=indexer.returns_by_function,
    )
