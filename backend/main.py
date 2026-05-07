from __future__ import annotations

import time
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel

from analysis.blast_radius import compute_blast_radius
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

app = FastAPI(title="CodePulse", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"], allow_methods=["*"], allow_headers=["*"])

LAST_SCAN = {"report": None, "file_content": "", "graph": {"nodes": [], "edges": []}, "findings": []}


class ExplainRequest(BaseModel):
    finding_id: str


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
