# CodePulse

**CodePulse is a Layered Static Code Intelligence Platform** for hackathon-ready security and reliability analysis. It accepts source files from multiple languages, always performs useful lightweight analysis, and activates deeper AST-based intelligence for Python.

The goal is graceful degradation: unsupported languages should still produce meaningful findings instead of failing.

## Product Overview

CodePulse combines:

- FastAPI upload and analysis backend
- React frontend
- Monaco source viewer
- Cytoscape call graph visualization
- Universal heuristic analysis for many languages
- Deep Python AST analysis
- Lightweight taint flow tracking
- Blast radius scoring
- Template-based explanations

## Architecture

```text
Browser
  |
  | multipart/form-data
  v
POST /upload
  |
  v
Language Detector
  |
  +--> Layer 1: Universal Heuristic Analysis
  |       - secrets
  |       - shell commands
  |       - TODO/FIXME
  |       - long lines
  |       - bracket imbalance
  |       - eval-like usage
  |
  +--> Layer 2: Language-Aware Validation
  |       - extension based detection
  |       - AST support decision
  |
  +--> Layer 3: Python Deep AST Analysis
          - Python syntax validation
          - function graph
          - dangerous calls
          - taint flow
          - blast radius
          - risk propagation
```

## Layered Analysis

### Layer 1: Universal Heuristic Analysis

Runs for every uploaded text source file. It uses regex, token scanning, line checks, bracket balancing, and suspicious keyword detection.

This layer detects:

- hardcoded passwords, tokens, API keys, and secrets
- suspicious shell command execution
- TODO/FIXME markers
- extremely long lines
- possible command injection patterns
- eval-like keywords
- malformed bracket structures
- possible divide-by-zero
- unsafe indexing hints

### Layer 2: Language-Aware Validation

Language is detected from file extension.

| Extension | Language | Deep AST |
| --- | --- | --- |
| `.py` | Python | yes |
| `.cpp`, `.cc`, `.cxx` | C++ | no |
| `.c` | C | no |
| `.java` | Java | no |
| `.js` | JavaScript | no |
| `.ts` | TypeScript | no |
| `.cs` | C# | no |
| `.go` | Go | no |
| `.rs` | Rust | no |
| other | unknown | no |

### Layer 3: Python AST Analysis

Python uploads activate deep AST mode:

- `ast.parse()` syntax validation
- function definition detection
- function call edge generation
- dangerous API detection
- simple taint propagation
- recursion risk heuristics
- blast radius scoring

## Taint Flow

CodePulse tracks simple user-controlled data paths.

```text
input()
  |
  v
variable assignment
  |
  v
helper function return
  |
  v
dangerous sink: eval / os.system / subprocess / SQL concat
```

Example:

```python
def get_command():
    return input("cmd> ")

def run():
    command = get_command()
    subprocess.Popen(command)
```

Produces:

```json
{
  "source": "input",
  "sink": "subprocess.Popen",
  "line": 6
}
```

## Blast Radius

Blast radius estimates how far risk can propagate through the function graph.

```text
vulnerable function -> helper -> database -> shell
```

If a vulnerable function calls multiple internal functions, CodePulse increases overall risk and raises that function's graph node risk.

## Response Format

`POST /upload` always returns a frontend-compatible payload:

```json
{
  "language": "python",
  "supported_ast": true,
  "analysis_mode": "deep-ast",
  "risk_score": 95,
  "findings": [],
  "graph": {
    "nodes": [],
    "edges": []
  },
  "taint_flows": [],
  "blast_radius": 0,
  "explanations": []
}
```

Each finding includes:

```json
{
  "id": "finding-1",
  "category": "security",
  "severity": "high",
  "type": "high",
  "message": "Use of eval() detected",
  "title": "Use of eval() detected",
  "line": 7,
  "function": "evaluate_expression",
  "tool": "python-ast",
  "explanation": "Use of eval() detected...",
  "recommendation": "Use safer APIs and validate user-controlled data."
}
```

## Complexity Analysis

Let:

- `N` = AST nodes, source tokens, or scanned lines
- `E` = graph edges

| Stage | Time Complexity | Space Complexity |
| --- | --- | --- |
| Universal heuristic analysis | approximately `O(N)` | `O(N)` findings worst case |
| Python AST traversal | approximately `O(N)` | `O(N)` |
| Graph generation | `O(N + E)` | `O(N + E)` |
| Taint propagation | worst-case `O(N^2)` | `O(N)` |
| Response rendering | `O(N + E)` | `O(N + E)` |

Overall practical MVP complexity is linear for typical demo files, with taint propagation bounded by simple function-return propagation.

## Screenshots

Place screenshots here before submission:

- `docs/screenshots/upload.png`
- `docs/screenshots/python-risk.png`
- `docs/screenshots/cpp-heuristic.png`
- `docs/screenshots/taint-flow.png`

## Demo Files

Use files in `demo_files/`:

- `safe.py`
- `eval_vuln.py`
- `syntax_error.py`
- `unsupported.cpp`
- `recursion_risk.py`
- `command_injection.py`
- `sql_vuln.py`
- `taint_demo.py`

Expected behavior:

- different files produce different findings
- Python files use `deep-ast` when syntax is valid
- invalid Python falls back to structured syntax findings
- unsupported languages use `heuristic`
- frontend remains stable for every upload

## Running Locally

Backend:

```powershell
cd C:\Users\aryan\OneDrive\Desktop\CodePulse\backend
..\venv\Scripts\python.exe -m uvicorn main:app --reload --port 8000
```

Frontend:

```powershell
cd C:\Users\aryan\OneDrive\Desktop\CodePulse\frontend
npm run dev
```

Open:

```text
http://localhost:5173
```

## Limitations

- Deep AST analysis currently supports Python only.
- Non-Python languages use heuristic scanning, not compiler-grade parsing.
- Taint analysis is intentionally lightweight and does not perform symbolic execution.
- Bracket balancing may flag brackets inside strings or comments.
- SQL detection is heuristic and does not understand every database API.
- Runtime risk detection is heuristic and should be treated as a signal, not proof.

## Roadmap

- Normalize graph schemas between `/upload` and `/analyze`
- Add richer JavaScript and C++ parser plugins
- Add configurable rule packs
- Add severity filtering in the frontend
- Add report export for universal analysis mode
- Expand taint propagation across more Python data structures
- Add optional local LLM summarization for full scan reports
