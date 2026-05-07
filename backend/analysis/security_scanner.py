from __future__ import annotations

import asyncio
import ast
import json
from pathlib import Path
from uuid import uuid4

from parser.ast_parser import ParsedPythonFile, function_for_line

SEVERITY_MAP = {"INFO": "LOW", "LOW": "LOW", "WARNING": "MEDIUM", "MEDIUM": "MEDIUM", "ERROR": "HIGH", "HIGH": "HIGH", "CRITICAL": "CRITICAL"}
LOCAL_SEMGREP_RULES = """
rules:
  - id: python-dangerous-eval
    message: Avoid eval/exec on user-controlled values.
    severity: ERROR
    languages: [python]
    pattern-either:
      - pattern: eval(...)
      - pattern: exec(...)
  - id: python-subprocess-shell-true
    message: shell=True can allow command injection.
    severity: WARNING
    languages: [python]
    pattern: subprocess.$FUNC(..., shell=True, ...)
  - id: python-bare-except
    message: Bare except can hide security and reliability failures.
    severity: WARNING
    languages: [python]
    pattern: |
      try:
        ...
      except:
        ...
"""


async def _run_json(args: list[str]) -> dict:
    try:
        proc = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, _ = await proc.communicate()
        return json.loads(stdout.decode("utf-8", "replace")) if stdout else {}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _id(prefix: str, line: int, message: str) -> str:
    return f"{prefix}-{line}-{abs(hash((prefix, line, message))) % 10000000}"


def _finding(parsed: ParsedPythonFile, prefix: str, kind: str, severity: str, line: int, message: str, tool: str) -> dict:
    return {"id": _id(prefix, line, message), "type": kind, "severity": severity, "line_number": line, "message": message, "function_name": function_for_line(parsed, line), "tool": tool}


class FallbackScanner(ast.NodeVisitor):
    def __init__(self, parsed: ParsedPythonFile) -> None:
        self.parsed = parsed
        self.findings: list[dict] = []

    def visit_Call(self, node: ast.Call) -> None:
        name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr if isinstance(node.func, ast.Attribute) else ""
        if name in {"eval", "exec"}:
            self.findings.append(_finding(self.parsed, "fallback", "dangerous-call", "HIGH", node.lineno, f"Use of {name} can execute arbitrary code.", "fallback"))
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                self.findings.append(_finding(self.parsed, "fallback", "subprocess-shell", "HIGH", node.lineno, "subprocess with shell=True can enable command injection.", "fallback"))
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.type is None:
            self.findings.append(_finding(self.parsed, "fallback", "bare-except", "MEDIUM", node.lineno, "Bare except hides the concrete failure mode.", "fallback"))
        self.generic_visit(node)


def fallback_scan(parsed: ParsedPythonFile) -> list[dict]:
    scanner = FallbackScanner(parsed)
    scanner.visit(parsed.ast_tree)
    return scanner.findings


async def run_security_scanners(file_path: str | Path, parsed: ParsedPythonFile) -> list[dict]:
    path = Path(file_path)
    findings: list[dict] = []
    bandit = await _run_json(["bandit", "-q", "-f", "json", str(path)])
    for item in bandit.get("results", []):
        line = int(item.get("line_number", 1))
        findings.append(_finding(parsed, "bandit", item.get("test_id", "bandit"), SEVERITY_MAP.get(str(item.get("issue_severity", "LOW")).upper(), "LOW"), line, item.get("issue_text", "Bandit finding"), "bandit"))
    rules_path = path.parent / f"codepulse-semgrep-{uuid4().hex}.yml"
    try:
        rules_path.write_text(LOCAL_SEMGREP_RULES, encoding="utf-8")
        semgrep = await _run_json(["semgrep", "--quiet", "--json", "--config", str(rules_path), str(path)])
        for item in semgrep.get("results", []):
            line = int(item.get("start", {}).get("line", 1))
            extra = item.get("extra", {})
            findings.append(_finding(parsed, "semgrep", item.get("check_id", "semgrep"), SEVERITY_MAP.get(str(extra.get("severity", "LOW")).upper(), "LOW"), line, extra.get("message", "Semgrep finding"), "semgrep"))
    finally:
        rules_path.unlink(missing_ok=True)
    findings.extend(fallback_scan(parsed))
    unique = {}
    for f in findings:
        unique[(f["type"], f["line_number"], f["message"])] = f
    return list(unique.values())
