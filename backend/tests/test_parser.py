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

def test_broken_python_file(tmp_path: Path):
    sample = tmp_path / "broken.py"

    sample.write_text(
        "def broken(:\n    print('hello')",
        encoding="utf-8"
    )

    try:
        parsed = parse_python_file(sample)
        assert parsed is not None

    except Exception as e:
        assert False, f"Parser crashed on broken syntax: {e}"


def test_empty_python_file(tmp_path: Path):
    sample = tmp_path / "empty.py"

    sample.write_text("", encoding="utf-8")

    parsed = parse_python_file(sample)

    assert parsed is not None
    assert parsed.functions == []



def test_recursive_function_graph(tmp_path: Path):
    sample = tmp_path / "recursive.py"

    sample.write_text(
        "def a():\n    b()\n\n"
        "def b():\n    a()\n",
        encoding="utf-8"
    )

    parsed = parse_python_file(sample)

    graph = build_call_graph(parsed)

    assert graph.has_edge("a", "b")
    assert graph.has_edge("b", "a")


def test_large_python_file(tmp_path: Path):
    sample = tmp_path / "large.py"

    large_code = "def a():\n    pass\n\n" * 10000

    sample.write_text(large_code, encoding="utf-8")

    parsed = parse_python_file(sample)

    assert parsed is not None
    assert len(parsed.functions) > 0