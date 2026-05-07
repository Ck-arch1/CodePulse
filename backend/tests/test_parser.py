from pathlib import Path
from parser.ast_parser import parse_python_file
from parser.graph_builder import build_call_graph


def test_parser_and_graph(tmp_path: Path):
    sample = tmp_path / "sample.py"
    sample.write_text("def a():\n    b()\n\ndef b():\n    return 1\n", encoding="utf-8")
    parsed = parse_python_file(sample)
    graph = build_call_graph(parsed)
    assert {fn.name for fn in parsed.functions} == {"a", "b"}
    assert graph.has_edge("a", "b")
