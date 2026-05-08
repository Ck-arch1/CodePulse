from functools import lru_cache
from pathlib import Path
import os

from dotenv import load_dotenv

load_dotenv()


class Settings:
    ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434")
    ollama_model = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:1.5b")
    backend_port = int(os.getenv("BACKEND_PORT", "8000"))
    frontend_port = int(os.getenv("FRONTEND_PORT", "5173"))
    upload_dir = Path(os.getenv("UPLOAD_DIR", "./backend/tmp/uploads"))
    repo_upload_dir = Path(os.getenv("REPO_UPLOAD_DIR", "./backend/tmp/repos"))
    max_file_size_mb = int(os.getenv("MAX_FILE_SIZE_MB", "5"))
    max_repo_files = int(os.getenv("MAX_REPO_FILES", "80"))
    max_repo_extracted_bytes = int(os.getenv("MAX_REPO_EXTRACTED_MB", "12")) * 1024 * 1024
    max_repo_file_bytes = int(os.getenv("MAX_REPO_FILE_BYTES", "750000"))
    max_ast_nodes = int(os.getenv("MAX_AST_NODES", "8000"))
    max_findings = int(os.getenv("MAX_FINDINGS", "200"))
    max_graph_nodes = int(os.getenv("MAX_GRAPH_NODES", "160"))
    max_graph_edges = int(os.getenv("MAX_GRAPH_EDGES", "260"))
    max_render_lines = int(os.getenv("MAX_RENDER_LINES", "4000"))
    max_taint_paths = int(os.getenv("MAX_TAINT_PATHS", "50"))
    max_recursion_depth = int(os.getenv("MAX_RECURSION_DEPTH", "2000"))
    max_graph_traversal_depth = int(os.getenv("MAX_GRAPH_TRAVERSAL_DEPTH", "12"))
    scan_ttl_seconds = int(os.getenv("SCAN_TTL_SECONDS", "1800"))
    max_scan_retention = int(os.getenv("MAX_SCAN_RETENTION", "20"))
    max_prompt_chars = int(os.getenv("MAX_PROMPT_CHARS", "6000"))

    @property
    def max_file_size_bytes(self) -> int:
        return self.max_file_size_mb * 1024 * 1024


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    settings.repo_upload_dir.mkdir(parents=True, exist_ok=True)
    return settings
