"""
Ollama proxy. The browser owns the conversation and executes tool calls
against IndexedDB; the server only relays one model turn at a time.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Iterator

from django.conf import settings
from django.http import HttpRequest, JsonResponse, StreamingHttpResponse
from django.views.decorators.http import require_GET, require_POST

from api.services import ollama_service
from services.ai import claude_code, prompts
from services.ai.tools import QUERY_SCHEMA, TOOLS

log = logging.getLogger(__name__)
MAX_MESSAGES = 200
MAX_MESSAGE_CHARS = 200_000


def _sse(event: dict[str, Any]) -> bytes:
    return f"data: {json.dumps(event, ensure_ascii=False)}\n\n".encode("utf-8")


def _clean_messages(raw: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not isinstance(raw, list):
        return out
    for m in raw[:MAX_MESSAGES]:
        if not isinstance(m, dict):
            continue
        role = str(m.get("role") or "user")
        if role not in ("system", "user", "assistant", "tool"):
            continue
        msg: dict[str, Any] = {"role": role, "content": str(m.get("content") or "")[:MAX_MESSAGE_CHARS]}
        if role == "assistant" and m.get("tool_calls"):
            msg["tool_calls"] = [{"function": {"name": str(c.get("name") or (c.get("function") or {}).get("name") or ""),
                                               "arguments": c.get("arguments") if isinstance(c.get("arguments"), dict) else ((c.get("function") or {}).get("arguments") or {})}}
                                 for c in m["tool_calls"] if isinstance(c, dict)]
        if role == "tool" and m.get("tool_name"):
            msg["tool_name"] = str(m["tool_name"])[:100]
        out.append(msg)
    return out


@require_GET
def ai_meta(request: HttpRequest):
    """Prompts, tool schemas and defaults for the browser-direct Ollama transport.
    Keeps backend/services/ai as the single source of truth for prompt text."""
    from services.ai.tools import QUERY_SCHEMA, TOOLS
    from services.store.queries import SCHEMA_DOC

    resp = JsonResponse({
        "prompts": {"analyst": prompts.SYSTEM_ANALYST, "query": prompts.SYSTEM_QUERY, "explain": prompts.SYSTEM_EXPLAIN,
                    "rule": prompts.SYSTEM_RULE, "report": prompts.SYSTEM_REPORT, "triage": prompts.SYSTEM_TRIAGE, "free": ""},
        "tools": TOOLS,
        "querySchema": QUERY_SCHEMA,
        "schemaDoc": SCHEMA_DOC,
        "numCtx": settings.OLLAMA_NUM_CTX,
        "defaultModel": settings.OLLAMA_MODEL,
        "limits": {"maxMessages": MAX_MESSAGES, "maxMessageChars": MAX_MESSAGE_CHARS},
        "version": prompts.prompts_version(),
    })
    resp["Cache-Control"] = "no-store"
    return resp


@require_GET
def models(request: HttpRequest):
    svc = ollama_service()
    info = svc.ping()
    if info.get("reachable"):
        for m in info["models"]:
            m["capabilities"] = svc.capabilities(m["name"])
    return JsonResponse(info)


def _query_messages(body: dict[str, Any]) -> list[dict[str, Any]] | None:
    question = str(body.get("question") or "").strip()
    if not question:
        return None
    context = body.get("context") or {}
    ctx_lines = [f"Reference time (now, UTC): {context.get('now') or 'unknown'}"]
    if context.get("businessHours"):
        ctx_lines.append(f"Business hours: {context['businessHours']}")
    if context.get("timeRange"):
        ctx_lines.append(f"Data time range: {context['timeRange']}")
    if context.get("facets"):
        ctx_lines.append("Known values (facets): " + json.dumps(context["facets"], ensure_ascii=False)[:4000])
    if context.get("source"):
        ctx_lines.append(f"Preferred source: {context['source']}")
    return [
        {"role": "system", "content": prompts.SYSTEM_QUERY},
        {"role": "user", "content": "\n".join(ctx_lines) + f"\n\nRequest: {question}"},
    ]


@require_POST
def query(request: HttpRequest):
    """Natural language -> filter DSL (structured output)."""
    try:
        body = json.loads(request.body or b"{}")
    except ValueError:
        return JsonResponse({"error": "invalid JSON"}, status=400)
    messages = _query_messages(body)
    if messages is None:
        return JsonResponse({"error": "question is required"}, status=400)
    try:
        res = ollama_service().chat_json(messages, QUERY_SCHEMA, model=body.get("model"), think=False)
    except Exception as exc:  # noqa: BLE001
        log.warning("ai query failed: %s", exc)
        return JsonResponse({"error": f"Ollama error: {str(exc)[:200]}"}, status=502)
    return JsonResponse({"query": res["data"], "raw": res["raw"], "model": res["model"]})


@require_POST
def chat(request: HttpRequest):
    """One model turn, streamed as SSE. Body: {messages, mode, tools(bool), think(bool), model, options, context}."""
    try:
        body = json.loads(request.body or b"{}")
    except ValueError:
        return JsonResponse({"error": "invalid JSON"}, status=400)
    messages = _clean_messages(body.get("messages"))
    if not messages:
        return JsonResponse({"error": "messages are required"}, status=400)
    mode = str(body.get("mode") or "analyst")
    context = body.get("context") or {}
    system = prompts.compose_system(mode, context)
    if system:
        if messages[0]["role"] == "system":
            messages[0]["content"] = (system + "\n\n" + messages[0]["content"]).strip()
        else:
            messages.insert(0, {"role": "system", "content": system})
    use_tools = bool(body.get("tools", mode == "analyst"))
    think = body.get("think")
    options = body.get("options") if isinstance(body.get("options"), dict) else None
    model = body.get("model") or None
    svc = ollama_service()

    def gen() -> Iterator[bytes]:
        try:
            for chunk in svc.chat_stream(messages, model=model, tools=TOOLS if use_tools else None, think=think if isinstance(think, bool) else None, options=options):
                yield _sse(chunk)
        except Exception as exc:  # noqa: BLE001
            log.warning("ai chat failed: %s", exc)
            yield _sse({"type": "error", "error": str(exc)[:300]})
            yield _sse({"type": "done", "model": model or settings.OLLAMA_MODEL, "stats": {}})

    resp = StreamingHttpResponse(gen(), content_type="text/event-stream; charset=utf-8")
    resp["Cache-Control"] = "no-store"
    resp["X-Accel-Buffering"] = "no"
    return resp


# ---------------------------------------------------------------------------
# Claude Code connector: same contract as the Ollama proxy, the model turn runs
# through the local "claude" command line (see services/ai/claude_code.py).
# ---------------------------------------------------------------------------
@require_GET
def claude_status(request: HttpRequest):
    resp = JsonResponse(claude_code.status(force=request.GET.get("refresh") == "1"))
    resp["Cache-Control"] = "no-store"
    return resp


@require_POST
def claude_chat(request: HttpRequest):
    """One model turn through Claude Code, streamed as SSE. Body: {messages, mode, tools(bool), model, context}."""
    try:
        body = json.loads(request.body or b"{}")
    except ValueError:
        return JsonResponse({"error": "invalid JSON"}, status=400)
    if not claude_code.enabled():
        return JsonResponse({"error": "the Claude Code connector is switched off on this server"}, status=403)
    messages = _clean_messages(body.get("messages"))
    if not messages:
        return JsonResponse({"error": "messages are required"}, status=400)
    mode = str(body.get("mode") or "analyst")
    system = prompts.compose_system(mode, body.get("context") or {})
    if messages[0]["role"] == "system":
        system = (system + "\n\n" + messages[0]["content"]).strip()
    use_tools = bool(body.get("tools", mode == "analyst"))
    model = str(body.get("model") or "") or None

    def gen() -> Iterator[bytes]:
        try:
            for chunk in claude_code.chat_stream(messages, system, model=model, tools=TOOLS if use_tools else None):
                yield _sse(chunk)
        except Exception as exc:  # noqa: BLE001
            log.warning("claude chat failed: %s", exc)
            yield _sse({"type": "error", "error": str(exc)[:300]})
            yield _sse({"type": "done", "model": model or claude_code.DEFAULT_MODEL, "stats": {}})

    resp = StreamingHttpResponse(gen(), content_type="text/event-stream; charset=utf-8")
    resp["Cache-Control"] = "no-store"
    resp["X-Accel-Buffering"] = "no"
    return resp


@require_POST
def claude_query(request: HttpRequest):
    """Natural language -> filter DSL through Claude Code."""
    try:
        body = json.loads(request.body or b"{}")
    except ValueError:
        return JsonResponse({"error": "invalid JSON"}, status=400)
    if not claude_code.enabled():
        return JsonResponse({"error": "the Claude Code connector is switched off on this server"}, status=403)
    messages = _query_messages(body)
    if messages is None:
        return JsonResponse({"error": "question is required"}, status=400)
    try:
        res = claude_code.chat_json(messages[1:], messages[0]["content"], QUERY_SCHEMA, model=str(body.get("model") or "") or None)
    except Exception as exc:  # noqa: BLE001
        log.warning("claude query failed: %s", exc)
        return JsonResponse({"error": f"Claude Code error: {str(exc)[:200]}"}, status=502)
    return JsonResponse({"query": res["data"], "raw": res["raw"], "model": res["model"]})
