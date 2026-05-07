from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    from tree_sitter import Language, Parser
    import tree_sitter_python as tspython
except Exception:
    Language = Parser = tspython = None


@dataclass
class FunctionNode:
    name: str
    qualname: str
    line_number: int
    end_line_number: int
    args: list[str] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)
    decorators: list[str] = field(default_factory=list)


@dataclass
class ParsedPythonFile:
    path: str
    source: str
    tree_sitter_root_type: str
    functions: list[FunctionNode]
    ast_tree: ast.AST
    lines_of_code: int


def _tree_sitter_root_type(source: str) -> str:
    if not Parser or not Language or not tspython:
        return "module"
    try:
        parser = Parser()
        language = Language(tspython.language(), "python")
        parser.set_language(language)
        return parser.parse(source.encode("utf-8")).root_node.type
    except Exception:
        return "module"


def call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return call_name(node.func)
    return None


class _FunctionCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.stack: list[str] = []
        self.functions: list[FunctionNode] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        self._collect(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self._collect(node)

    def _collect(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        qualname = ".".join([*self.stack, node.name]) if self.stack else node.name
        calls = sorted({name for child in ast.walk(node) if isinstance(child, ast.Call) for name in [call_name(child.func)] if name})
        self.functions.append(FunctionNode(
            name=node.name,
            qualname=qualname,
            line_number=node.lineno,
            end_line_number=int(getattr(node, "end_lineno", node.lineno)),
            args=[arg.arg for arg in node.args.args],
            calls=calls,
            decorators=[call_name(item) or ast.unparse(item) for item in node.decorator_list],
        ))
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()


def parse_python_file(path: str | Path) -> ParsedPythonFile:
    source_path = Path(path)
    source = source_path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(source, filename=str(source_path))

    except SyntaxError:
        return ParsedPythonFile(
        path=str(source_path),
        source=source,
        tree_sitter_root_type="syntax_error",
        functions=[],
        ast_tree=ast.Module(body=[], type_ignores=[]),
        lines_of_code=len(source.splitlines())
    )

    collector = _FunctionCollector()
    collector.visit(tree)
    return ParsedPythonFile(
        path=str(source_path),
        source=source,
        tree_sitter_root_type=_tree_sitter_root_type(source),
        functions=collector.functions,
        ast_tree=tree,
        lines_of_code=sum(1 for line in source.splitlines() if line.strip()),
    )


def function_for_line(parsed: ParsedPythonFile, line_number: int) -> str:
    candidates = [fn for fn in parsed.functions if fn.line_number <= line_number <= fn.end_line_number]
    return max(candidates, key=lambda fn: fn.line_number).qualname if candidates else "<module>"
