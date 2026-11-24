"""Provider-agnostic LLM client interface and shared exceptions."""

from abc import ABC, abstractmethod


class LLMClientError(Exception):
    """Raised when an LLM provider fails due to network, auth, or upstream error."""


class BaseLLMClient(ABC):
    """Abstract interface for LLM providers generating structured incident JSON."""

    provider_name: str = "base"

    @abstractmethod
    def generate_json(self, system_prompt: str, user_prompt: str) -> str:
        """Send prompts to the LLM and return the raw JSON text response."""
