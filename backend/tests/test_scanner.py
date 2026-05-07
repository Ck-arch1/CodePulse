from pathlib import Path
from analysis.risk_scorer import score_functions
from analysis.security_scanner import fallback_scan
from parser.ast_parser import parse_python_file
from parser.graph_builder import build_call_graph


def test_fallback_scanner_and_risk(tmp_path: Path):
    sample = tmp_path / "vuln.py"
    sample.write_text("def run(x):\n    return eval(x)\n", encoding="utf-8")
    parsed = parse_python_file(sample)
    graph = build_call_graph(parsed)
    findings = fallback_scan(parsed)
    scores = score_functions(graph, findings, {"tainted_functions": []}, {"run": {"count": 0}})
    assert findings
    assert scores["run"] >= 5
