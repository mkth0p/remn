"""Thin wrapper around the Ollama Python client (streaming chat, structured output, model listing)."""
from __future__ import annotations

import json
import logging
from typing import Any, Iterator

log = logging.getLogger(__name__)


class OllamaService:
    def __init__(self, host: str, default_model: str, num_ctx: int = 32768, timeout: float = 600) -> None:
        self.host = host
        self.default_model = default_model
        self.num_ctx = num_ctx
        self.timeout = timeout

    def _client(self, timeout: float | None = None) -> Any:
        import ollama

        return ollama.Client(host=self.host, timeout=timeout if timeout is not None else self.timeout)

    # Short timeout for metadata calls: a busy CPU-bound Ollama must not freeze /api/health.
    META_TIMEOUT = 8.0

    def ping(self) -> dict[str, Any]:
        try:
            models = self.list_models()
            return {"reachable": True, "host": self.host, "models": models, "defaultModel": self.default_model,
                    "defaultAvailable": any(m["name"] == self.default_model or m["name"].split(":")[0] == self.default_model.split(":")[0] for m in models)}
        except Exception as exc:  # noqa: BLE001
            return {"reachable": False, "host": self.host, "error": str(exc)[:200], "models": [], "defaultModel": self.default_model}

    def list_models(self) -> list[dict[str, Any]]:
        resp = self._client(self.META_TIMEOUT).list()
        out: list[dict[str, Any]] = []
        for m in getattr(resp, "models", []) or []:
            details = getattr(m, "details", None)
            out.append({
                "name": getattr(m, "model", None) or getattr(m, "name", None),
                "size": getattr(m, "size", None),
                "modifiedAt": str(getattr(m, "modified_at", "") or ""),
                "family": getattr(details, "family", None) if details else None,
                "parameterSize": getattr(details, "parameter_size", None) if details else None,
                "quantization": getattr(details, "quantization_level", None) if details else None,
            })
        return out

    def capabilities(self, model: str) -> list[str]:
        try:
            info = self._client(self.META_TIMEOUT).show(model)
            caps = getattr(info, "capabilities", None)
            if caps is None and isinstance(info, dict):
                caps = info.get("capabilities")
            return list(caps or [])
        except Exception as exc:  # noqa: BLE001
            log.debug("show %s failed: %s", model, exc)
            return []

    def chat_stream(self, messages: list[dict[str, Any]], model: str | None = None, tools: list[dict[str, Any]] | None = None,
                    think: bool | None = None, options: dict[str, Any] | None = None, fmt: Any = None) -> Iterator[dict[str, Any]]:
        """
        Yield normalised chunks: {"type": "token"|"thinking"|"tool_calls"|"done"|"error", ...}
        """
        model = model or self.default_model
        opts = {"num_ctx": self.num_ctx, "temperature": 0.2}
        opts.update(options or {})
        kwargs: dict[str, Any] = {"model": model, "messages": messages, "stream": True, "options": opts}
        if tools:
            kwargs["tools"] = tools
        if think is not None:
            kwargs["think"] = think
        if fmt is not None:
            kwargs["format"] = fmt
        client = self._client()
        try:
            stream = client.chat(**kwargs)
        except TypeError:
            kwargs.pop("think", None)
            stream = client.chat(**kwargs)
        pending_calls: list[dict[str, Any]] = []
        for chunk in stream:
            msg = getattr(chunk, "message", None)
            if msg is None and isinstance(chunk, dict):
                msg = chunk.get("message")
            if msg is not None:
                thinking = getattr(msg, "thinking", None) if not isinstance(msg, dict) else msg.get("thinking")
                if thinking:
                    yield {"type": "thinking", "content": thinking}
                content = getattr(msg, "content", None) if not isinstance(msg, dict) else msg.get("content")
                if content:
                    yield {"type": "token", "content": content}
                calls = getattr(msg, "tool_calls", None) if not isinstance(msg, dict) else msg.get("tool_calls")
                if calls:
                    for c in calls:
                        fn = getattr(c, "function", None) if not isinstance(c, dict) else c.get("function")
                        name = getattr(fn, "name", None) if not isinstance(fn, dict) else fn.get("name")
                        args = getattr(fn, "arguments", None) if not isinstance(fn, dict) else fn.get("arguments")
                        if isinstance(args, str):
                            try:
                                args = json.loads(args)
                            except ValueError:
                                args = {"_raw": args}
                        pending_calls.append({"name": name, "arguments": args or {}})
            done = getattr(chunk, "done", None) if not isinstance(chunk, dict) else chunk.get("done")
            if done:
                if pending_calls:
                    yield {"type": "tool_calls", "calls": pending_calls}
                    pending_calls = []
                stats = {}
                for key in ("total_duration", "load_duration", "prompt_eval_count", "eval_count", "eval_duration", "done_reason"):
                    val = getattr(chunk, key, None) if not isinstance(chunk, dict) else chunk.get(key)
                    if val is not None:
                        stats[key] = val
                yield {"type": "done", "model": model, "stats": stats}
        if pending_calls:
            yield {"type": "tool_calls", "calls": pending_calls}
            yield {"type": "done", "model": model, "stats": {}}

    def chat_json(self, messages: list[dict[str, Any]], schema: dict[str, Any], model: str | None = None,
                  think: bool | None = False, options: dict[str, Any] | None = None) -> dict[str, Any]:
        """Non-streaming structured output. Returns {"data": parsed|None, "raw": text, "model": ...}."""
        model = model or self.default_model
        opts = {"num_ctx": self.num_ctx, "temperature": 0}
        opts.update(options or {})
        client = self._client()
        kwargs: dict[str, Any] = {"model": model, "messages": messages, "stream": False, "options": opts, "format": schema}
        if think is not None:
            kwargs["think"] = think
        try:
            resp = client.chat(**kwargs)
        except TypeError:
            kwargs.pop("think", None)
            resp = client.chat(**kwargs)
        msg = getattr(resp, "message", None) or (resp.get("message") if isinstance(resp, dict) else None)
        text = (getattr(msg, "content", None) if not isinstance(msg, dict) else msg.get("content")) or ""
        data = None
        try:
            data = json.loads(text)
        except ValueError:
            # try to salvage a JSON object from the text
            start, end = text.find("{"), text.rfind("}")
            if start != -1 and end > start:
                try:
                    data = json.loads(text[start:end + 1])
                except ValueError:
                    data = None
        return {"data": data, "raw": text, "model": model}
