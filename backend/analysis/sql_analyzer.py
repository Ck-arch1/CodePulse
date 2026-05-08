from __future__ import annotations

import ast
import sqlglot

from parser.ast_parser import ParsedPythonFile, function_for_line

SQL_WORDS = ("select ", "insert ", "update ", "delete ", "drop ", "where ")


def _looks_sql(value: str) -> bool:
    lower = value.lower()
    return any(word in lower for word in SQL_WORDS)


def _sqlglot_can_parse(value: str) -> bool:
    try:
        sqlglot.parse(value)
        return True
    except Exception:
        return _looks_sql(value)


def detect_sql_issues(parsed: ParsedPythonFile) -> list[dict]:
    findings: list[dict] = []
    for node in parsed.ast_index.nodes:
        risky = False
        line = getattr(node, "lineno", 1)
        expression = ast.unparse(node)
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)) and _looks_sql(expression) and _sqlglot_can_parse(expression.replace("+", " ")):
            risky = True
        if isinstance(node, ast.JoinedStr) and _looks_sql(expression) and _sqlglot_can_parse(expression):
            risky = True
        if risky:
            msg = "SQL string interpolation or concatenation may allow SQL injection."
            findings.append({"id": f"sql-{line}-{len(findings)}", "type": "sql-injection", "severity": "HIGH", "line_number": line, "message": msg, "function_name": function_for_line(parsed, line), "tool": "sqlglot"})
    return findings
