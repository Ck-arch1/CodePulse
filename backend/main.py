from __future__ import annotations

import ast
import re
import time
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel

from analysis.blast_radius import compute_blast_radius
from analysis.confidence_engine import score_confidence, should_keep_finding
from analysis.contextual_severity import contextualize_severity
from analysis.risk_scorer import score_functions
from analysis.security_scanner import run_security_scanners
from analysis.sql_analyzer import detect_sql_issues
from analysis.taint_analyzer import trace_taint
from config import get_settings
from llm.explainer import stream_explanation
from llm.ollama_client import ollama_health
from parser.ast_parser import parse_python_file
from parser.graph_builder import build_call_graph, graph_to_json
from report.report_builder import build_report_json, render_html_report
from utils.language_detector import detect_language

app = FastAPI(title="CodePulse", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"], allow_methods=["*"], allow_headers=["*"])

LAST_SCAN = {"report": None, "file_content": "", "graph": {"nodes": [], "edges": []}, "findings": []}


class ExplainRequest(BaseModel):
    finding_id: str


def _call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    return None


def _finding(
    finding_id: int,
    category: str,
    severity: str,
    message: str,
    line: int,
    function: str,
    tool: str,
    explanation: str,
    recommendation: str,
    evidence: dict | None = None,
    cause_chain: list[str] | None = None,
) -> dict:
    evidence = evidence or {"analysis_type": "heuristic", "matched_pattern": message, "tainted": False, "reachable": True}
    confidence = score_confidence(evidence, category)
    return {
        "id": f"finding-{finding_id}",
        "category": category,
        "type": severity,
        "message": message,
        "line": line,
        "function": function,
        "tool": tool,
        "explanation": explanation,
        "recommendation": recommendation,
        "confidence": confidence,
        "evidence": evidence,
        "cause_chain": cause_chain or [],
        "severity": severity,
        "title": message,
    }


def _function_for_line(function_ranges: dict[str, tuple[int, int]], line: int) -> str | None:
    matches = [
        (name, start)
        for name, (start, end) in function_ranges.items()
        if start <= line <= end
    ]
    if not matches:
        return None
    return max(matches, key=lambda item: item[1])[0]


def _risk_bucket(score: int) -> int:
    if score >= 40:
        return 8
    if score >= 15:
        return 4
    return 1


def _severity_for_risk(risk: int) -> str:
    if risk >= 30:
        return "high"
    if risk >= 15:
        return "medium"
    return "low"


def _iter_names(node: ast.AST) -> set[str]:
    names: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            names.add(child.id)
    return names


def _contains_sql_text(node: ast.AST) -> bool:
    sql_words = ("select ", "insert ", "update ", "delete ", "drop ", "where ")
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            lowered = child.value.lower()
            if any(word in lowered for word in sql_words):
                return True
    return False


def _is_sql_concat(node: ast.AST) -> bool:
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return _contains_sql_text(node) and bool(_iter_names(node))
    if isinstance(node, ast.JoinedStr):
        return _contains_sql_text(node)
    return False


def _source_name(node: ast.AST) -> str | None:
    name = _call_name(node)
    if name == "input":
        return "input"
    if name in {"request.args", "request.json", "request.form", "request.get_json", "sys.argv"}:
        return name
    if isinstance(node, ast.Call):
        return _source_name(node.func)
    if isinstance(node, ast.Subscript):
        return _source_name(node.value)
    return None


def _source_label(source: str) -> str:
    return f"{source}()" if source == "input" else source


def _dedupe_chain(chain: list[str]) -> list[str]:
    compact: list[str] = []
    for item in chain:
        if item and (not compact or compact[-1] != item):
            compact.append(item)
    return compact


def _subprocess_run_shell_true(node: ast.Call) -> bool:
    return any(
        keyword.arg == "shell"
        and isinstance(keyword.value, ast.Constant)
        and keyword.value.value is True
        for keyword in node.keywords
    )


def _hardcoded_secret_name(name: str) -> bool:
    lowered = name.lower()
    secret_terms = ("password", "passwd", "pwd", "secret", "token", "api_key", "apikey", "access_key")
    return any(term in lowered for term in secret_terms)


def _assigned_names(node: ast.Assign | ast.AnnAssign) -> list[str]:
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    names: list[str] = []
    for target in targets:
        if isinstance(target, ast.Name):
            names.append(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            names.extend(item.id for item in target.elts if isinstance(item, ast.Name))
    return names


def _call_tail(node: ast.AST) -> str | None:
    name = _call_name(node)
    return name.split(".")[-1] if name else None


def _template_explanation(finding: dict) -> str:
    message = finding["message"]
    if "eval()" in message:
        return "Use of eval() detected. This may allow arbitrary code execution if user input reaches this function."
    if "exec()" in message:
        return "Use of exec() detected. This can execute attacker-controlled Python code."
    if "os.system()" in message:
        return "Use of os.system() detected. Shell command construction can lead to command injection."
    if "subprocess.Popen()" in message:
        return "Use of subprocess.Popen() detected. Validate command arguments and avoid shell-controlled input."
    if "subprocess.call()" in message:
        return "Use of subprocess.call() detected. Validate command arguments before executing subprocesses."
    if "subprocess.run(shell=True)" in message:
        return "subprocess.run(shell=True) detected. shell=True expands attacker-controlled strings through a shell."
    if "pickle.loads()" in message:
        return "pickle.loads() detected. Unpickling untrusted bytes can execute arbitrary code."
    if "yaml.load()" in message:
        return "yaml.load() detected. Use yaml.safe_load() for untrusted YAML input."
    if "secret" in message.lower():
        return "Hardcoded secret detected. Move credentials to environment variables or a secret manager."
    if "SQL" in message:
        return "SQL string concatenation detected. Use parameterized queries instead of joining user input into SQL."
    if "Bare except" in message:
        return "Bare except detected. Catch specific exceptions so security failures are not silently hidden."
    if "Tainted data" in message:
        return "User-controlled data reaches a dangerous sink. Validate or sanitize the value before use."
    if "syntax" in message.lower() or "bracket" in message.lower():
        return "Syntax anomaly detected. The analyzer continued with heuristic checks instead of crashing."
    return message


def _upgrade_explanation(finding: dict, blast_radius: int) -> str:
    confidence = float(finding.get("confidence", 0.0))
    chain = finding.get("cause_chain") or []
    chain_text = " -> ".join(chain) if chain else "No confirmed propagation path was required for this finding."
    impact = "This may increase security or reliability risk in the affected function."
    if finding["category"] == "security":
        impact = "This can expose the application to attacker-controlled behavior or sensitive data exposure."
    elif finding["category"] == "runtime":
        impact = "This may cause crashes, hangs, or unpredictable runtime behavior."
    elif finding["category"] == "syntax":
        impact = "This can prevent deeper analysis and may indicate malformed source code."
    flow = f"Data flow: {chain_text}."
    if finding.get("evidence", {}).get("tainted") and len(chain) >= 2:
        flow = f"Data flow: user-controlled data propagates through {' -> '.join(chain)}."
    return (
        f"{finding['severity'].upper()} RISK (confidence: {confidence:.2f})\n"
        f"What: {finding['message']} in {finding['function']} at line {finding['line']}.\n"
        f"Why it matters: {impact}\n"
        f"{flow}\n"
        f"What could happen: affected behavior can spread to {blast_radius} downstream connection(s).\n"
        f"Suggested remediation: {finding['recommendation']}"
    )


def _dedupe_findings(findings: list[dict]) -> list[dict]:
    unique: list[dict] = []
    seen: set[tuple[str, str, int, str]] = set()
    strong_lines = {
        (finding.get("category"), finding.get("line"))
        for finding in findings
        if finding.get("evidence", {}).get("analysis_type") in {"ast", "taint", "bandit", "semgrep"}
    }
    for finding in findings:
        if finding.get("evidence", {}).get("analysis_type") == "heuristic" and (finding.get("category"), finding.get("line")) in strong_lines:
            continue
        key = (finding["category"], finding["message"], finding["line"], finding["function"])
        if key in seen:
            continue
        seen.add(key)
        if should_keep_finding(finding):
            finding["id"] = f"finding-{len(unique) + 1}"
            unique.append(finding)
    return unique


def _compose_risk(findings: list[dict], blast_radius: int) -> tuple[int, dict]:
    weights = {
        "syntax": 12,
        "runtime": 18,
        "security": 45,
        "reliability": 18,
        "logical": 15,
        "informational": 5,
    }
    composition = {key: 0.0 for key in weights}
    composition["propagation"] = 0.0
    composition["blast_radius"] = min(blast_radius * 5, 20)

    severity_factor = {"low": 0.35, "medium": 0.65, "high": 1.0, "critical": 1.25}
    dominant = 0.0
    for finding in findings:
        category = finding.get("category", "informational")
        severity = finding.get("severity", "low")
        confidence = float(finding.get("confidence", 0.45))
        contribution = weights.get(category, 8) * severity_factor.get(severity, 0.35) * confidence
        composition[category] = composition.get(category, 0.0) + contribution
        if finding.get("evidence", {}).get("tainted"):
            composition["propagation"] += 35 * confidence
            dominant = max(dominant, 72 * confidence)

    caps = {"syntax": 15, "runtime": 20, "security": 60, "reliability": 20, "logical": 15, "informational": 5, "propagation": 35, "blast_radius": 20}
    rounded = {key: round(min(value, caps.get(key, value)), 2) for key, value in composition.items() if value > 0}
    composed = int(round(sum(rounded.values())))
    return min(100, max(composed, int(round(dominant)))), rounded


def analyze_upload_source(source: str, filename: str) -> dict:
    language_info = detect_language(filename)
    language = language_info["language"]
    supported_ast = language_info["supported_ast"]
    analysis_mode = "deep-ast" if supported_ast else "heuristic"

    lines = source.splitlines()
    findings: list[dict] = []
    total_risk = 0
    function_risk: dict[str, int] = {}
    taint_flows: list[dict] = []
    graph = {"nodes": [], "edges": []}

    def add_finding(
        category: str,
        severity: str,
        message: str,
        line: int,
        risk: int,
        function: str = "module",
        tool: str = "heuristic",
        recommendation: str = "Review this code path and prefer safer, explicit handling.",
        evidence: dict | None = None,
        cause_chain: list[str] | None = None,
    ) -> None:
        nonlocal total_risk
        analysis_type = "heuristic"
        if tool in {"python-ast", "recursion-heuristic"}:
            analysis_type = "ast"
        elif tool == "taint-analysis":
            analysis_type = "taint"
        evidence = evidence or {
            "analysis_type": analysis_type,
            "matched_pattern": message,
            "tainted": tool == "taint-analysis",
            "reachable": True,
        }
        finding = _finding(
            len(findings) + 1,
            category,
            severity,
            message,
            max(1, line),
            function,
            tool,
            _template_explanation({"message": message}),
            recommendation,
            evidence,
            cause_chain,
        )
        findings.append(finding)
        total_risk += risk
        function_risk[function] = max(function_risk.get(function, 0), risk)

    def universal_heuristic_analysis() -> None:
        bracket_pairs = {"(": ")", "[": "]", "{": "}"}
        openers = set(bracket_pairs)
        closers = {value: key for key, value in bracket_pairs.items()}
        stack: list[tuple[str, int]] = []

        secret_pattern = re.compile(r"(password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*['\"][^'\"]+['\"]", re.IGNORECASE)
        shell_pattern = re.compile(r"\b(system|popen|exec|spawn|ProcessBuilder|Runtime\.getRuntime|child_process)\b")
        eval_pattern = re.compile(r"\b(eval|execScript|Function)\s*\(")
        sql_concat_pattern = re.compile(r"(select|insert|update|delete|drop)\s+.+(\+|%|\$\{|format\()", re.IGNORECASE)

        for index, line in enumerate(lines, start=1):
            stripped = line.strip()
            for char in line:
                if char in openers:
                    stack.append((char, index))
                elif char in closers:
                    if not stack or stack[-1][0] != closers[char]:
                        add_finding("syntax", "medium", f"Unmatched closing bracket '{char}'", index, 10, tool="syntax-heuristic", recommendation="Check bracket structure around this line.")
                        break
                    stack.pop()

            lower_line = line.lower()
            sensitive_context = any(term in lower_line for term in ("auth", "login", "password", "token", "permission"))
            if "TODO" in line or "FIXME" in line:
                category = "reliability" if sensitive_context else "informational"
                severity = "medium" if sensitive_context else "low"
                add_finding(category, severity, "TODO/FIXME marker found", index, 8 if sensitive_context else 2, tool="keyword-heuristic", recommendation="Track or resolve this note before release.")
            if len(line) > 140:
                add_finding("reliability", "low", "Extremely long line may hide complex logic", index, 5, tool="line-heuristic", recommendation="Split long logic into clearer statements.")
            if secret_pattern.search(line):
                add_finding("security", "medium", "Hardcoded secret detected", index, 25, tool="secret-heuristic", recommendation="Move credentials to environment variables or a secret store.", evidence={"analysis_type": "heuristic", "matched_pattern": "secret assignment", "tainted": False, "reachable": True})
            if shell_pattern.search(line):
                add_finding("security", "medium", "Suspicious shell command execution pattern detected", index, 25, tool="command-heuristic", recommendation="Avoid shelling out with user-controlled data.", evidence={"analysis_type": "heuristic", "matched_pattern": "shell command keyword", "tainted": False, "reachable": True})
            if eval_pattern.search(line):
                add_finding("security", "medium", "Suspicious eval-like execution detected", index, 25, tool="eval-heuristic", recommendation="Avoid dynamic code execution.", evidence={"analysis_type": "heuristic", "matched_pattern": "eval-like keyword", "tainted": False, "reachable": True})
            if sql_concat_pattern.search(line):
                add_finding("security", "medium", "Possible SQL string concatenation detected", index, 25, tool="sql-heuristic", recommendation="Use parameterized queries.")
            if re.search(r"/\s*0\b", line):
                add_finding("runtime", "medium", "Possible divide-by-zero operation", index, 10, tool="runtime-heuristic", recommendation="Check denominator values before division.")
            if re.search(r"\[[^\]]+\]", line) and not any(term in stripped for term in ("if ", "try", "catch", "except")):
                add_finding("runtime", "low", "Potential unchecked indexing operation", index, 5, tool="runtime-heuristic", recommendation="Validate collection bounds before indexing.")
            if stripped.endswith((".", "+", "-", "*", "/", "=", ",")):
                add_finding("syntax", "low", "Line appears to end with an unfinished statement", index, 5, tool="syntax-heuristic", recommendation="Check whether this statement is incomplete.")

        for opener, line_number in stack[:3]:
            add_finding("syntax", "medium", f"Unclosed bracket '{opener}'", line_number, 10, tool="syntax-heuristic", recommendation="Close this bracket or block.")

    universal_heuristic_analysis()

    if not supported_ast:
        for finding in findings:
            finding["severity"] = contextualize_severity(finding["severity"], {"confidence": finding.get("confidence", 0.0), "tainted": False, "blast_radius": 0})
            finding["type"] = finding["severity"]
            finding["explanation"] = _upgrade_explanation(finding, 0)
        stable = _dedupe_findings(findings)
        risk_score, risk_composition = _compose_risk(stable, 0)
        graph["nodes"] = [{"data": {"id": "module", "label": language, "risk": _risk_bucket(risk_score), "node_type": "normal", "reachable": True, "blast_radius": 0}}]
        return {
            "language": language,
            "supported_ast": False,
            "analysis_mode": analysis_mode,
            "risk_score": risk_score,
            "risk_composition": risk_composition,
            "findings": stable,
            "graph": graph,
            "taint_flows": taint_flows,
            "blast_radius": 0,
            "explanations": [finding["explanation"] for finding in stable],
        }

    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        add_finding("syntax", "medium", f"Invalid Python syntax near line {exc.lineno or 1}", exc.lineno or 1, 10, tool="python-ast", recommendation="Fix Python syntax before deep AST analysis can run.")
        for finding in findings:
            finding["severity"] = contextualize_severity(finding["severity"], {"confidence": finding.get("confidence", 0.0), "tainted": False, "blast_radius": 0})
            finding["type"] = finding["severity"]
            finding["explanation"] = _upgrade_explanation(finding, 0)
        stable = _dedupe_findings(findings)
        risk_score, risk_composition = _compose_risk(stable, 0)
        graph["nodes"] = [{"data": {"id": "module", "label": "python", "risk": _risk_bucket(risk_score), "node_type": "normal", "reachable": True, "blast_radius": 0}}]
        return {
            "language": language,
            "supported_ast": True,
            "analysis_mode": "heuristic",
            "risk_score": risk_score,
            "risk_composition": risk_composition,
            "findings": stable,
            "graph": graph,
            "taint_flows": taint_flows,
            "blast_radius": 0,
            "explanations": [finding["explanation"] for finding in stable],
        }

    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    function_ranges: dict[str, tuple[int, int]] = {}
    tainted_vars: dict[str, str] = {}
    tainted_var_chains: dict[str, list[str]] = {}

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions[node.name] = node
            function_ranges[node.name] = (node.lineno, int(getattr(node, "end_lineno", node.lineno)))

    tainted_returns: dict[str, str] = {}
    tainted_return_chains: dict[str, list[str]] = {}

    def function_for(line: int) -> str:
        return _function_for_line(function_ranges, line) or "module"

    def add_python_finding(
        message: str,
        line: int,
        risk: int,
        category: str = "security",
        severity: str | None = None,
        tool: str = "python-ast",
        recommendation: str = "Use safer APIs and validate user-controlled data.",
        evidence: dict | None = None,
        cause_chain: list[str] | None = None,
    ) -> None:
        add_finding(category, severity or _severity_for_risk(risk), message, line, risk, function_for(line), tool, recommendation, evidence, cause_chain)

    def local_expr_chain(node: ast.AST, local_tainted: dict[str, list[str]]) -> list[str] | None:
        direct = _source_name(node)
        if direct:
            return [_source_label(direct)]
        if isinstance(node, ast.Call):
            tail = _call_tail(node.func)
            if tail in tainted_return_chains:
                return _dedupe_chain([*tainted_return_chains[tail], f"{tail}()"])
        for name in _iter_names(node):
            if name in local_tainted:
                return _dedupe_chain([*local_tainted[name], name])
        return None

    def chain_source(chain: list[str] | None) -> str | None:
        if not chain:
            return None
        return chain[0].removesuffix("()")

    changed = True
    while changed:
        changed = False
        for name, fn_node in functions.items():
            local_tainted: dict[str, list[str]] = {}
            for child in ast.walk(fn_node):
                if isinstance(child, (ast.Assign, ast.AnnAssign)) and child.value is not None:
                    source_chain = local_expr_chain(child.value, local_tainted)
                    if source_chain:
                        for assigned in _assigned_names(child):
                            local_tainted[assigned] = _dedupe_chain([*source_chain, assigned])
                elif isinstance(child, ast.Return) and child.value is not None:
                    source_chain = local_expr_chain(child.value, local_tainted)
                    source_name = chain_source(source_chain)
                    if source_name and tainted_returns.get(name) != source_name:
                        tainted_returns[name] = source_name
                        tainted_return_chains[name] = _dedupe_chain([*(source_chain or [_source_label(source_name)]), f"{name}()"])
                        changed = True

    def expr_taint_chain(node: ast.AST) -> list[str] | None:
        direct = _source_name(node)
        if direct:
            return [_source_label(direct)]
        if isinstance(node, ast.Call):
            tail = _call_tail(node.func)
            if tail in tainted_return_chains:
                return _dedupe_chain([*tainted_return_chains[tail], f"{tail}()"])
        for name in _iter_names(node):
            if name in tainted_vars:
                return _dedupe_chain([*tainted_var_chains.get(name, [_source_label(tainted_vars[name])]), name])
        return None

    def expr_is_tainted(node: ast.AST) -> str | None:
        return chain_source(expr_taint_chain(node))

    def sink_chain(node: ast.AST, sink: str) -> list[str]:
        chain = expr_taint_chain(node) or []
        function_name = function_for(getattr(node, "lineno", 1))
        return _dedupe_chain([*chain, f"{function_name}()", f"{sink}()"])

    for fn in functions.values():
        for arg in fn.args.args:
            tainted_vars.setdefault(arg.arg, "function argument")

    for name, fn in functions.items():
        calls_self = any(isinstance(node, ast.Call) and _call_name(node.func) == name for node in ast.walk(fn))
        has_base_case = any(isinstance(node, ast.If) for node in ast.walk(fn))
        if calls_self and not has_base_case:
            add_python_finding("Possible infinite recursion without an obvious base case", fn.lineno, 15, "runtime", "medium", "recursion-heuristic", "Add a clear base case before recursive calls.", evidence={"analysis_type": "heuristic", "matched_pattern": "self-recursive call without if", "tainted": False, "reachable": True})

    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            if value is not None:
                source_chain = expr_taint_chain(value)
                source_name = chain_source(source_chain)
                for name in _assigned_names(node):
                    if source_name:
                        tainted_vars[name] = source_name
                        tainted_var_chains[name] = _dedupe_chain([*(source_chain or [_source_label(source_name)]), name])
                    if _hardcoded_secret_name(name) and isinstance(value, ast.Constant) and isinstance(value.value, str) and value.value.strip():
                        add_python_finding("Hardcoded secret detected", node.lineno, 25, "security", "medium", "python-ast", "Move secrets to environment variables or a secret store.", evidence={"analysis_type": "ast", "matched_pattern": f"assignment to {name}", "tainted": False, "reachable": True, "exact": True})
                if _is_sql_concat(value):
                    inferred_taint = source_name == "function argument"
                    add_python_finding("Dangerous SQL string concatenation detected", node.lineno, 25, "security", "medium", "python-ast", "Use parameterized SQL queries.", evidence={"analysis_type": "ast", "matched_pattern": "SQL string concatenation", "tainted": bool(source_name), "reachable": True, "exact": True, "inferred": inferred_taint})
                    if source_name:
                        taint_flows.append({"source": source_name, "sink": "sql-concat", "line": node.lineno})
                        add_python_finding("Tainted data flows into SQL string concatenation", node.lineno, 50, "security", "high" if inferred_taint else "critical", "taint-analysis", "Validate input and use parameterized queries.", evidence={"analysis_type": "taint", "matched_pattern": "tainted SQL concat", "tainted": True, "reachable": True, "exact": True, "inferred": inferred_taint}, cause_chain=sink_chain(value, "sql-concat"))

        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div) and isinstance(node.right, ast.Constant) and node.right.value == 0:
            add_python_finding("Possible divide-by-zero operation", node.lineno, 10, "runtime", "medium", "python-ast", "Guard denominator values before division.", evidence={"analysis_type": "ast", "matched_pattern": "division by literal zero", "tainted": False, "reachable": True, "exact": True})
        elif isinstance(node, ast.Subscript):
            add_python_finding("Potential unchecked indexing operation", getattr(node, "lineno", 1), 5, "runtime", "low", "python-ast", "Validate collection bounds before indexing.", evidence={"analysis_type": "heuristic", "matched_pattern": "subscript access", "tainted": False, "reachable": True, "inferred": True})
        elif isinstance(node, ast.Call):
            name = _call_name(node.func)
            taint_source = expr_is_tainted(node)
            if name == "eval":
                literal_only = bool(node.args) and isinstance(node.args[0], ast.Constant)
                add_python_finding(
                    "Use of eval() detected",
                    node.lineno,
                    15 if literal_only and not taint_source else 40,
                    "security",
                    "medium" if literal_only and not taint_source else "high",
                    "python-ast",
                    "Replace eval() with ast.literal_eval() or structured parsing.",
                    evidence={"analysis_type": "ast", "matched_pattern": "eval call", "tainted": bool(taint_source), "reachable": True, "exact": True, "inferred": taint_source == "function argument"},
                    cause_chain=sink_chain(node, "eval") if taint_source else [],
                )
            elif name == "exec":
                add_python_finding("Use of exec() detected", node.lineno, 40, "security", "high", evidence={"analysis_type": "ast", "matched_pattern": "exec call", "tainted": bool(taint_source), "reachable": True, "exact": True, "inferred": taint_source == "function argument"}, cause_chain=sink_chain(node, "exec") if taint_source else [])
            elif name == "os.system":
                add_python_finding("Use of os.system() detected", node.lineno, 35, "security", "high", evidence={"analysis_type": "ast", "matched_pattern": "os.system call", "tainted": bool(taint_source), "reachable": True, "exact": True, "inferred": taint_source == "function argument"}, cause_chain=sink_chain(node, "os.system") if taint_source else [])
            elif name == "subprocess.Popen":
                add_python_finding("Use of subprocess.Popen() detected", node.lineno, 35, "security", "high", evidence={"analysis_type": "ast", "matched_pattern": "subprocess.Popen call", "tainted": bool(taint_source), "reachable": True, "exact": True, "inferred": taint_source == "function argument"}, cause_chain=sink_chain(node, "subprocess.Popen") if taint_source else [])
            elif name == "subprocess.call":
                add_python_finding("Use of subprocess.call() detected", node.lineno, 35, "security", "high", evidence={"analysis_type": "ast", "matched_pattern": "subprocess.call call", "tainted": bool(taint_source), "reachable": True, "exact": True, "inferred": taint_source == "function argument"}, cause_chain=sink_chain(node, "subprocess.call") if taint_source else [])
            elif name == "subprocess.run" and _subprocess_run_shell_true(node):
                add_python_finding("Use of subprocess.run(shell=True) detected", node.lineno, 35, "security", "high", evidence={"analysis_type": "ast", "matched_pattern": "subprocess.run shell=True", "tainted": bool(taint_source), "reachable": True, "exact": True, "inferred": taint_source == "function argument"}, cause_chain=sink_chain(node, "subprocess.run") if taint_source else [])
            elif name == "pickle.loads":
                add_python_finding("Use of pickle.loads() detected", node.lineno, 30, "security", "high", evidence={"analysis_type": "ast", "matched_pattern": "pickle.loads call", "tainted": bool(taint_source), "reachable": True, "exact": True})
            elif name == "yaml.load":
                add_python_finding("Use of yaml.load() detected", node.lineno, 30, "security", "high", evidence={"analysis_type": "ast", "matched_pattern": "yaml.load call", "tainted": bool(taint_source), "reachable": True, "exact": True})

            dangerous = name in {"eval", "exec", "os.system", "subprocess.Popen", "subprocess.call"} or (name == "subprocess.run" and _subprocess_run_shell_true(node))
            if dangerous and taint_source:
                sink = name or "dangerous-call"
                chain = sink_chain(node, sink)
                taint_flows.append({"source": taint_source, "sink": sink, "line": node.lineno, "cause_chain": chain})
                inferred_taint = taint_source == "function argument"
                add_python_finding(f"Tainted data flows into {sink}", node.lineno, 50, "security", "high" if inferred_taint else "critical", "taint-analysis", "Sanitize or strictly validate the tainted value before this sink.", evidence={"analysis_type": "taint", "matched_pattern": f"{taint_source} -> {sink}", "tainted": True, "reachable": True, "exact": True, "inferred": inferred_taint}, cause_chain=chain)
        elif isinstance(node, ast.ExceptHandler) and node.type is None:
            fn = function_for(node.lineno).lower()
            sensitive = any(term in fn for term in ("auth", "login", "token", "password", "permission"))
            add_python_finding("Bare except detected", node.lineno, 25 if sensitive else 15, "reliability", "high" if sensitive else "medium", "python-ast", "Catch specific exception classes.", evidence={"analysis_type": "ast", "matched_pattern": "bare except handler", "tainted": False, "reachable": True, "exact": True})

    known_functions = set(functions)
    edges = []
    seen_edges: set[tuple[str, str]] = set()
    outgoing_counts: dict[str, int] = {}
    for source_name, fn_node in functions.items():
        for node in ast.walk(fn_node):
            if isinstance(node, ast.Call):
                target = (_call_name(node.func) or "").split(".")[-1]
                edge = (source_name, target)
                if target in known_functions and edge not in seen_edges:
                    seen_edges.add(edge)
                    edges.append({"data": {"source": source_name, "target": target}})
                    outgoing_counts[source_name] = outgoing_counts.get(source_name, 0) + 1

    vulnerable_functions = {finding["function"] for finding in findings if finding["function"] != "module"}
    blast_radius = sum(outgoing_counts.get(name, 0) for name in vulnerable_functions)
    if blast_radius:
        total_risk += min(blast_radius * 5, 20)
        for name in vulnerable_functions:
            function_risk[name] = function_risk.get(name, 0) + min(outgoing_counts.get(name, 0) * 5, 20)

    for finding in findings:
        context = {
            "confidence": finding.get("confidence", 0.0),
            "category": finding.get("category"),
            "tainted": finding.get("evidence", {}).get("tainted", False),
            "inferred": finding.get("evidence", {}).get("inferred", False),
            "blast_radius": outgoing_counts.get(finding.get("function"), 0),
            "graph_degree": outgoing_counts.get(finding.get("function"), 0),
            "external_exposure": finding.get("function") in {"login", "auth", "authenticate", "controller"},
            "sanitized": "sanitize" in " ".join(finding.get("cause_chain", [])).lower(),
        }
        finding["severity"] = contextualize_severity(finding["severity"], context)
        finding["type"] = finding["severity"]
        finding["explanation"] = _upgrade_explanation(finding, context["blast_radius"])

    tainted_functions = {
        finding["function"]
        for finding in findings
        if finding.get("evidence", {}).get("tainted") and finding["function"] != "module"
    }
    sink_functions = {
        finding["function"]
        for finding in findings
        if finding["category"] == "security" and finding["function"] != "module"
    }
    source_functions = {
        function_for(getattr(node, "lineno", 1))
        for node in ast.walk(tree)
        if _source_name(node)
    }

    stable_findings = _dedupe_findings(findings)
    risk_score, risk_composition = _compose_risk(stable_findings, blast_radius)

    risky_edge_pairs = set()
    for finding in stable_findings:
        chain = finding.get("cause_chain") or []
        for left, right in zip(chain, chain[1:]):
            risky_edge_pairs.add((left.removesuffix("()"), right.removesuffix("()")))
    graph["edges"] = [
        {
            "data": {
                **edge["data"],
                "risky": (edge["data"]["source"], edge["data"]["target"]) in risky_edge_pairs
                or edge["data"]["source"] in tainted_functions
                or edge["data"]["target"] in sink_functions,
            }
        }
        for edge in edges
    ]
    graph["nodes"] = [
        {
            "data": {
                "id": name,
                "label": name,
                "risk": _risk_bucket(function_risk.get(name, 0)),
                "node_type": "source" if name in source_functions else "sink" if name in sink_functions else "tainted" if name in tainted_functions else "normal",
                "reachable": True,
                "blast_radius": outgoing_counts.get(name, 0),
            }
        }
        for name in functions
    ] or [{"data": {"id": "module", "label": "python", "risk": _risk_bucket(risk_score), "node_type": "normal", "reachable": True, "blast_radius": 0}}]

    return {
        "language": language,
        "supported_ast": True,
        "analysis_mode": analysis_mode,
        "risk_score": risk_score,
        "risk_composition": risk_composition,
        "findings": stable_findings,
        "graph": graph,
        "taint_flows": taint_flows,
        "blast_radius": blast_radius,
        "explanations": [finding["explanation"] for finding in stable_findings],
    }


async def _save_upload(upload: UploadFile) -> Path:
    settings = get_settings()
    if not upload.filename or not upload.filename.endswith(".py"):
        raise HTTPException(status_code=400, detail="Only .py files are supported.")
    content = await upload.read()
    if len(content) > settings.max_file_size_bytes:
        raise HTTPException(status_code=413, detail=f"File exceeds {settings.max_file_size_mb}MB limit.")
    path = settings.upload_dir / f"{uuid4().hex}-{Path(upload.filename).name}"
    path.write_bytes(content)
    LAST_SCAN["file_content"] = content.decode("utf-8", errors="replace")
    return path


@app.get("/health")
async def health():
    return {"status": "ok", "ollama": await ollama_health()}


@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(status_code=400, detail="A source file name is required.")

    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    source = content.decode("utf-8", errors="replace")
    result = analyze_upload_source(source, file.filename)
    LAST_SCAN.update({
        "report": {
            **result,
            "file_name": file.filename,
            "lines_of_code": len(source.splitlines()),
            "scan_time_ms": 0,
        },
        "file_content": source,
        "graph": result["graph"],
        "findings": result["findings"],
    })
    return result


@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    started = time.perf_counter()
    path = await _save_upload(file)
    parsed = parse_python_file(path)
    graph = build_call_graph(parsed)
    findings = await run_security_scanners(path, parsed)
    findings.extend(detect_sql_issues(parsed))
    taint = trace_taint(parsed, graph, findings)
    blast = compute_blast_radius(graph, findings)
    scores = score_functions(graph, findings, taint, blast)
    elapsed = int((time.perf_counter() - started) * 1000)
    report = build_report_json(file.filename or path.name, parsed, graph, findings, scores, taint, blast, elapsed)
    LAST_SCAN.update({"report": report, "graph": graph_to_json(graph), "findings": findings})
    return report


@app.get("/findings")
async def findings():
    return LAST_SCAN["findings"]


@app.post("/explain")
async def explain(payload: ExplainRequest):
    report = LAST_SCAN.get("report")
    if not report:
        raise HTTPException(status_code=404, detail="No scan is available.")
    finding = next((item for item in report["findings"] if item["id"] == payload.finding_id), None)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found.")
    context = {"risk_score": report["scores"].get(finding["function_name"]), "blast_radius": report["blast_radii"].get(finding["function_name"]), "taint_paths": report["taint_paths"]}
    return StreamingResponse(stream_explanation(finding, context), media_type="text/event-stream")


@app.get("/graph")
async def graph():
    return LAST_SCAN["graph"]


@app.get("/report", response_class=HTMLResponse)
async def report():
    if not LAST_SCAN.get("report"):
        raise HTTPException(status_code=404, detail="No scan is available.")
    return render_html_report(LAST_SCAN["report"])


@app.get("/file-content", response_class=PlainTextResponse)
async def file_content():
    return LAST_SCAN["file_content"]
