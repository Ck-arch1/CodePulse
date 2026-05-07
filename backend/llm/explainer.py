from __future__ import annotations

from llm.ollama_client import stream_completion


def build_prompt(finding: dict, context: dict) -> str:
    return f"""You are CodePulse, a precise static-analysis assistant.
Explain this Python security finding for a developer.

Finding:
- ID: {finding.get('id')}
- Type: {finding.get('type')}
- Severity: {finding.get('severity')}
- Function: {finding.get('function_name')}
- Line: {finding.get('line_number')}
- Message: {finding.get('message')}

Risk score: {context.get('risk_score')}
Blast radius: {context.get('blast_radius')}
Taint paths: {context.get('taint_paths')}

Respond with: what is wrong, exploit scenario, and concrete fix."""


async def stream_explanation(finding: dict, context: dict):
    async for token in stream_completion(build_prompt(finding, context)):
        yield f"data: {token.replace(chr(10), ' ')}\n\n"
    yield "event: done\ndata: done\n\n"
