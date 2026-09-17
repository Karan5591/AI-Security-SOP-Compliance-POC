"""
Minimal client for an OpenAI-chat-completions-compatible LLM gateway.
Works with most self-hosted Llama 3 70B servers (vLLM, TGI w/ OpenAI shim,
LM Studio, etc.) - just point llm_base_url/llm_api_key/llm_model in .env.
"""
import httpx

from app.core.config import get_settings

settings = get_settings()

_client: httpx.Client | None = None


def _get_client() -> httpx.Client:
    global _client
    if _client is None:
        _client = httpx.Client(
            base_url=settings.llm_base_url,
            headers={"Authorization": f"Bearer {settings.llm_api_key}"},
            timeout=settings.llm_timeout_seconds,
        )
    return _client


def close_client() -> None:
    global _client
    if _client is not None:
        _client.close()
    _client = None


def chat_completion(system_prompt: str, user_prompt: str) -> str:
    """Send a single-turn chat completion request, return the raw text content."""
    client = _get_client()
    response = client.post(
        "/chat/completions",
        json={
            "model": settings.llm_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0,
        },
    )
    response.raise_for_status()
    data = response.json()
    return data["choices"][0]["message"]["content"]
