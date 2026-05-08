from __future__ import annotations

import json
import logging
import httpx

from config import get_settings

logger = logging.getLogger("codepulse.llm")

async def ollama_health() -> bool:
    settings = get_settings()
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            response = await client.get(f"{settings.ollama_url}/api/tags")
            return response.status_code == 200
    except httpx.HTTPError:
        return False


async def stream_completion(prompt: str):
    settings = get_settings()
    payload = {"model": settings.ollama_model, "prompt": prompt, "stream": True}
    try:
        async with httpx.AsyncClient(timeout=None) as client:
            async with client.stream("POST", f"{settings.ollama_url}/api/generate", json=payload) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if not line:
                        continue
                    data = json.loads(line)
                    token = data.get("response", "")
                    if token:
                        yield token
                    if data.get("done"):
                        break
    except Exception:
        logger.warning("Local Ollama explanation failed")
        yield "LLM explanation temporarily unavailable. The static analysis result remains available."
