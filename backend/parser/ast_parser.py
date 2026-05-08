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
            ast_index=AstIndex(functions=[]),
            lines_of_code=len(source.splitlines()),
        )

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