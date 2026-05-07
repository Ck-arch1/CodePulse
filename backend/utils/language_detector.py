from __future__ import annotations

from pathlib import Path


LANGUAGE_BY_EXTENSION = {
    ".py": "python",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".c": "c",
    ".java": "java",
    ".js": "javascript",
    ".ts": "typescript",
    ".cs": "csharp",
    ".go": "go",
    ".rs": "rust",
}


def detect_language(filename: str) -> dict:
    extension = Path(filename).suffix.lower()
    language = LANGUAGE_BY_EXTENSION.get(extension, "unknown")
    return {
        "language": language,
        "supported_ast": language == "python",
    }
