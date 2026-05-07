# CodePulse

CodePulse is a full-stack Python and React static code analysis tool. It uploads Python files, parses AST structure, builds call graphs, detects vulnerabilities, scores risk, traces tainted inputs, computes blast radius, and streams local LLM explanations through Ollama.

## Features

- FastAPI backend with multipart upload validation for `.py` files and a 5MB default limit
- Tree-sitter-backed parser with Python `ast` extraction for functions and calls
- NetworkX call graph exported with `node_link_data()`
- Bandit, Semgrep, SQL string risk checks, fallback scanner, taint analysis, blast radius, and risk scoring
- SSE explanation endpoint powered by local Ollama `qwen2.5-coder:1.5b`
- React UI with Cytoscape fcose graph layout, Monaco code viewer, findings list, report panel, and streamed explanations

## Demo Script

1. Start Ollama: `ollama run qwen2.5-coder:1.5b`
2. Create and activate a venv, then install backend dependencies:
   `python -m venv venv`
   `venv\Scripts\activate`
   `pip install -r requirements.txt`
3. Start backend:
   `cd backend`
   `uvicorn main:app --reload --port 8000`
4. Start frontend:
   `cd ..\frontend`
   `npm install`
   `npm run dev`
5. Open `http://localhost:5173`
6. Upload a Python file with known vulnerabilities such as `eval()`, SQL string concatenation, or bare `except`
7. See the call graph render with risk-colored nodes
8. Click a finding to stream a local LLM explanation in the side panel

## API Routes

- `POST /analyze`
- `GET /health`
- `GET /findings`
- `POST /explain`
- `GET /graph`
- `GET /report`
- `GET /file-content`
