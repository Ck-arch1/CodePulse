from __future__ import annotations

import io
import zipfile

from main import analyze_upload_source
from repository.repo_analyzer import analyze_repository, cleanup_repo, safe_extract_zip


def test_repository_zip_analysis_blocks_zip_slip():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("app.py", "def run(x):\n    return eval(x)\n")
        archive.writestr("../evil.py", "print('escape')\n")

    scan_id = "test-repo-zip-slip"
    root, warnings = safe_extract_zip(buffer.getvalue(), scan_id)
    try:
        report = analyze_repository(root, analyze_upload_source, warnings)
        assert report["repo_summary"]["analyzed_files"] == 1
        assert report["findings"]
        assert any("unsafe ZIP path" in item["reason"] for item in report["warnings"])
    finally:
        cleanup_repo(scan_id)
