"""OpenAI-compatible HTTP LLM client configured via environment variables."""

import logging

import httpx

from app.llm.base import BaseLLMClient, LLMClientError

logger = logging.getLogger(__name__)


class OpenAICompatibleLLMClient(BaseLLMClient):
    """Provider-agnostic client for OpenAI-compatible Chat Completions APIs."""

    provider_name = "openai"

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.openai.com/v1",
        model: str = "gpt-4o-mini",
        timeout_seconds: float = 20.0,
    ) -> None:
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._timeout_seconds = timeout_seconds

    def generate_json(self, system_prompt: str, user_prompt: str) -> str:
        """Call chat completions requesting a JSON object response."""
        if not self._api_key:
            raise LLMClientError("LLM_API_KEY is not configured for OpenAI-compatible provider.")

        url = f"{self._base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self._model,
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }

        try:
            with httpx.Client(timeout=self._timeout_seconds) as client:
                response = client.post(url, headers=headers, json=payload)
        except httpx.HTTPError as exc:
            logger.warning("LLM HTTP request failed: %s", exc)
            raise LLMClientError(f"LLM HTTP transport error: {exc}") from exc

        if response.status_code != 200:
            logger.warning("LLM provider returned HTTP %d", response.status_code)
            raise LLMClientError(f"LLM provider returned status {response.status_code}")

        try:
            data = response.json()
            content = data["choices"][0]["message"]["content"]
            if not isinstance(content, str):
                raise LLMClientError("LLM response content is not a string")
            return content
        except (KeyError, IndexError, ValueError, TypeError) as exc:
            raise LLMClientError(f"Malformed LLM provider payload: {exc}") from exc
