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

def test_safe_code_not_flagged(tmp_path: Path):
    sample = tmp_path / "safe.py"

    sample.write_text(
        'def hello():\n    print("eval is dangerous")',
        encoding="utf-8"
    )

    parsed = parse_python_file(sample)

    findings = fallback_scan(parsed)

    assert len(findings) == 0

def test_malicious_code_not_executed(tmp_path: Path, capsys):
    sample = tmp_path / "malicious.py"

    sample.write_text(
        'import os\nos.system("echo hacked")',
        encoding="utf-8"
    )

    parsed = parse_python_file(sample)

    findings = fallback_scan(parsed)

    captured = capsys.readouterr()

    assert "hacked" not in captured.out


def test_indirect_eval_detection(tmp_path: Path):
    sample = tmp_path / "indirect.py"

    sample.write_text(
        "def run(x):\n"
        "    dangerous = eval\n"
        "    return dangerous(x)\n",
        encoding="utf-8"
    )

    parsed = parse_python_file(sample)

    findings = fallback_scan(parsed)

    assert findings

def test_imported_eval_detection(tmp_path: Path):
    sample = tmp_path / "imported_eval.py"

    sample.write_text(
        "from builtins import eval\n"
        "def run(x):\n"
        "    return eval(x)\n",
        encoding="utf-8"
    )

    parsed = parse_python_file(sample)

    findings = fallback_scan(parsed)

    assert findings

def test_multiple_vulnerabilities_detected(tmp_path: Path):
    sample = tmp_path / "multi_vuln.py"

    sample.write_text(
        "import subprocess\n\n"
        "def run(x):\n"
        "    eval(x)\n"
        "    subprocess.run(x, shell=True)\n"
        "    try:\n"
        "        pass\n"
        "    except:\n"
        "        pass\n",
        encoding="utf-8"
    )

    parsed = parse_python_file(sample)

    findings = fallback_scan(parsed)

    assert len(findings) >= 3

def test_duplicate_findings_removed(tmp_path: Path):
    sample = tmp_path / "duplicate.py"

    sample.write_text(
        "def run(x):\n"
        "    eval(x)\n",
        encoding="utf-8"
    )

    parsed = parse_python_file(sample)

    findings = fallback_scan(parsed)

    unique_messages = set(f["message"] for f in findings)

    assert len(unique_messages) == len(findings)