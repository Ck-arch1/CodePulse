from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from parser.ast_index import AstIndex, build_ast_index, call_name

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
    ast_index: AstIndex
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


def parse_python_file(path: str | Path) -> ParsedPythonFile:
    source_path = Path(path)
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(source_path))
    ast_index = build_ast_index(tree)
    functions = [
        FunctionNode(
            name=fn.name,
            qualname=fn.qualname,
            line_number=fn.line_number,
            end_line_number=fn.end_line_number,
            args=fn.args,
            calls=fn.calls,
            decorators=fn.decorators,
        )
        for fn in ast_index.functions
    ]
    return ParsedPythonFile(
        path=str(source_path),
        source=source,
        tree_sitter_root_type=_tree_sitter_root_type(source),
        functions=functions,
        ast_tree=tree,
        ast_index=ast_index,
        lines_of_code=sum(1 for line in source.splitlines() if line.strip()),
    )


def function_for_line(parsed: ParsedPythonFile, line_number: int) -> str:
    return parsed.ast_index.function_for_line(line_number)
