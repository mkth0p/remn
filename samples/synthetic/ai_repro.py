"""Reproduce the AI second turn directly against Ollama and dump the raw chunks (debug helper)."""

from __future__ import annotations

import json
import sys
import time

sys.path.insert(0, "backend")
import ollama  # noqa: E402

from services.ai import prompts  # noqa: E402
from services.ai.tools import TOOLS  # noqa: E402

MODEL = sys.argv[1] if len(sys.argv) > 1 else "gemma4-hauhaucs:latest"
THINK = None if len(sys.argv) < 3 else (sys.argv[2] == "true")
tool_result = json.dumps(
    {
        "field": "flags",
        "total": 11,
        "distinct": 50,
        "groups": [
            {"value": "spf_fail", "count": 5},
            {"value": "replyto_webmail", "count": 3},
            {"value": "att_office_macro", "count": 3},
            {"value": "lexicon_gift_card", "count": 3},
            {"value": "sender_lookalike_internal", "count": 0},
            {"value": "url_text_href_mismatch", "count": 3},
        ],
    }
)
messages = [
    {"role": "system", "content": prompts.SYSTEM_ANALYST},
    {"role": "user", "content": "Which mails look like phishing or BEC? Rank them and explain the indicators."},
    {"role": "assistant", "content": "", "tool_calls": [{"function": {"name": "aggregate_mails", "arguments": {"field": "flags", "filter": {}}}}]},
    {"role": "tool", "content": tool_result, "tool_name": "aggregate_mails"},
]
client = ollama.Client(host="http://127.0.0.1:11434", timeout=900)
kwargs = dict(model=MODEL, messages=messages, tools=TOOLS, stream=True, options={"num_ctx": 32768, "temperature": 0.2})
if THINK is not None:
    kwargs["think"] = THINK
t0 = time.time()
n = 0
for chunk in client.chat(**kwargs):
    n += 1
    m = chunk.message
    rec = {
        "t": round(time.time() - t0, 1),
        "content": m.content,
        "thinking": getattr(m, "thinking", None),
        "tool_calls": [{"name": c.function.name, "args": c.function.arguments} for c in (m.tool_calls or [])],
        "done": chunk.done,
    }
    if chunk.done:
        rec["stats"] = {"eval_count": chunk.eval_count, "prompt_eval_count": chunk.prompt_eval_count, "done_reason": chunk.done_reason}
    print(json.dumps(rec, ensure_ascii=False), flush=True)
print(f"chunks={n} elapsed={time.time() - t0:.1f}s", flush=True)
