"""Lazily-built singletons shared by the views (Ollama client)."""

from __future__ import annotations

from functools import lru_cache

from django.conf import settings

from services.ai.client import OllamaService


@lru_cache(maxsize=1)
def ollama_service() -> OllamaService:
    return OllamaService(settings.OLLAMA_HOST, settings.OLLAMA_MODEL, settings.OLLAMA_NUM_CTX, settings.OLLAMA_TIMEOUT)
