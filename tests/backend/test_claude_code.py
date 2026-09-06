"""Claude Code connector: transcript rendering, the JSON tool-call protocol, stream parsing with a fake command line, and the API views."""
from __future__ import annotations

import json
import subprocess

import pytest
from django.test import Client, override_settings

from services.ai import claude_code as cc
from services.ai.tools import TOOLS

HDR = {"HTTP_X_FORENSIC_CLIENT": "1"}


def _sse_events(resp) -> list[dict]:
    body = b"".join(resp.streaming_content).decode("utf-8")
    return [json.loads(line[5:].strip()) for line in body.splitlines() if line.startswith("data:")]


# ---------------------------------------------------------------- pure parts
def test_render_prompt_transcript_headings():
    msgs = [
        {"role": "system", "content": "ignored here"},
        {"role": "user", "content": "How many mails?"},
        {"role": "assistant", "content": "", "tool_calls": [{"function": {"name": "search_mails", "arguments": {"limit": 5}}}]},
        {"role": "tool", "tool_name": "search_mails", "content": '{"total": 7}'},
        {"role": "user", "content": "and now?"},
    ]
    p = cc.render_prompt(msgs)
    assert p.startswith("User:\nHow many mails?")
    assert 'Assistant:\n{"tool_calls": [{"name": "search_mails", "arguments": {"limit": 5}}]}' in p
    assert "Tool result (search_mails):\n{\"total\": 7}" in p
    assert p.endswith("User:\nand now?")
    assert "ignored here" not in p


@pytest.mark.parametrize("text,expected", [
    ('{"tool_calls":[{"name":"list_findings","arguments":{}}]}', [{"name": "list_findings", "arguments": {}}]),
    ('```json\n{"tool_calls":[{"name":"search_mails","arguments":{"text":"invoice"}}]}\n```', [{"name": "search_mails", "arguments": {"text": "invoice"}}]),
    ('Let me look.\n{"tool_calls":[{"name":"get_event","arguments":{"id":3}}]}', [{"name": "get_event", "arguments": {"id": 3}}]),
    ('{"tool_calls":[{"name":"x","arguments":"not a dict"}]}', [{"name": "x", "arguments": {}}]),
    ('{"tool_calls":[{"name":"a","arguments":{}}]}\nTool result (a): {"x": 1}\n{"tool_calls":[{"name":"b","arguments":{}}]}', [{"name": "a", "arguments": {}}]),
    ("The mailbox holds three phishing mails.", None),
    ('{"answer": "no tools here"}', None),
    ('{"tool_calls": []}', None),
])
def test_parse_tool_calls(text, expected):
    assert cc.parse_tool_calls(text) == expected


def test_compose_system_adds_protocol_only_with_tools():
    with_tools = cc.compose_system("SYS", TOOLS)
    assert with_tools.startswith("SYS")
    assert '{"tool_calls": [{"name": "<tool name>"' in with_tools
    assert '"search_mails"' in with_tools
    without = cc.compose_system("SYS", None)
    assert "tool_calls" not in without
    assert "transcript" in without


def test_base_args_are_locked_down_and_model_validated():
    args = cc._base_args("claude", "opus")
    for flag in ("--safe-mode", "--no-session-persistence", "--disable-slash-commands", "--include-partial-messages"):
        assert flag in args
    assert args[args.index("--tools") + 1] == ""
    assert args[args.index("--model") + 1] == "opus"
    assert cc._base_args("claude", "rm -rf; evil")[-1] == cc.DEFAULT_MODEL
    assert cc._base_args("claude", None)[-1] == cc.DEFAULT_MODEL


# ---------------------------------------------------------------- stream parsing with a fake command line
class _FakeStream:
    def __init__(self, lines: list[bytes]):
        self._lines = lines

    def __iter__(self):
        return iter(self._lines)


class _FakeStdin:
    def write(self, _b):
        pass

    def close(self):
        pass


class _FakePopen:
    """Stands in for subprocess.Popen: plays prepared stream-json lines."""

    script: list[dict] = []
    returncode_value = 0
    last_args: list[str] = []

    def __init__(self, args, **_kw):
        _FakePopen.last_args = list(args)
        self.stdout = _FakeStream([(json.dumps(ev) + "\n").encode("utf-8") for ev in self.script])
        self.stderr = _FakeStream([])
        self.stdin = _FakeStdin()
        self.returncode = None

    def poll(self):
        return self.returncode

    def kill(self):
        self.returncode = -9 if self.returncode is None else self.returncode

    def wait(self, timeout=None):
        if self.returncode is None:
            self.returncode = self.returncode_value
        return self.returncode


def _delta(text: str) -> dict:
    return {"type": "stream_event", "event": {"type": "content_block_delta", "delta": {"type": "text_delta", "text": text}}}


def _result(text: str, is_error: bool = False) -> dict:
    return {"type": "result", "subtype": "error_during_execution" if is_error else "success", "is_error": is_error, "result": text,
            "duration_ms": 1234, "stop_reason": "end_turn", "total_cost_usd": 0.00123,
            "usage": {"input_tokens": 10, "cache_read_input_tokens": 90, "output_tokens": 5}}


@pytest.fixture
def fake_cli(monkeypatch, tmp_path):
    monkeypatch.setattr(cc.subprocess, "Popen", _FakePopen)
    monkeypatch.setattr(cc, "binary", lambda: "claude")
    monkeypatch.setattr(cc, "_cwd", lambda: tmp_path)
    _FakePopen.returncode_value = 0
    yield _FakePopen


def test_plain_answer_streams_tokens(fake_cli):
    fake_cli.script = [
        {"type": "stream_event", "event": {"type": "message_start", "message": {"model": "claude-sonnet-5"}}},
        {"type": "stream_event", "event": {"type": "content_block_delta", "delta": {"type": "thinking_delta", "thinking": "hmm"}}},
        _delta("The "), _delta("mailbox "), _delta("holds three phishing mails."),
        _result("The mailbox holds three phishing mails."),
    ]
    chunks = list(cc.chat_stream([{"role": "user", "content": "q"}], "SYS", model="sonnet", tools=TOOLS))
    types = [c["type"] for c in chunks]
    assert types[0] == "thinking"
    assert "tool_calls" not in types
    assert "".join(c["content"] for c in chunks if c["type"] == "token") == "The mailbox holds three phishing mails."
    done = chunks[-1]
    assert done["type"] == "done" and done["model"] == "claude-sonnet-5"
    assert done["stats"]["prompt_eval_count"] == 100 and done["stats"]["eval_count"] == 5 and done["stats"]["cost_usd"] == 0.0012
    assert "--system-prompt-file" in fake_cli.last_args


def test_json_reply_is_held_back_and_becomes_tool_calls(fake_cli):
    fake_cli.script = [
        _delta('{"tool_'), _delta('calls":[{"name":"search_mails",'), _delta('"arguments":{"text":"invoice"}}]}'),
        _result('{"tool_calls":[{"name":"search_mails","arguments":{"text":"invoice"}}]}'),
    ]
    chunks = list(cc.chat_stream([{"role": "user", "content": "q"}], "SYS", tools=TOOLS))
    assert [c["type"] for c in chunks] == ["tool_calls", "done"]
    assert chunks[0]["calls"] == [{"name": "search_mails", "arguments": {"text": "invoice"}}]


def test_invented_tool_result_is_cut_at_the_first_object(fake_cli):
    fake_cli.script = [
        _delta('{"tool_calls": [{"name": "get_case_summary", "arguments": {}}]}'),
        _delta('\nTool result (get_case_summary):\n{"files": ["a"]}\n\n{"tool_calls": [{"name": "search_mails", "arguments": {}}]}'),
        _result("(whatever the model went on to write)"),
    ]
    chunks = list(cc.chat_stream([{"role": "user", "content": "q"}], "SYS", tools=TOOLS))
    assert [c["type"] for c in chunks] == ["tool_calls", "done"]
    assert chunks[0]["calls"] == [{"name": "get_case_summary", "arguments": {}}]


def test_json_that_is_not_a_tool_call_is_delivered_as_text(fake_cli):
    fake_cli.script = [_delta('{"answer": 42}'), _result('{"answer": 42}')]
    chunks = list(cc.chat_stream([{"role": "user", "content": "q"}], "SYS", tools=TOOLS))
    assert [c["type"] for c in chunks] == ["token", "done"]
    assert chunks[0]["content"] == '{"answer": 42}'


def test_tool_calls_ignored_when_tools_disabled(fake_cli):
    fake_cli.script = [_delta('{"tool_calls":[{"name":"search_mails","arguments":{}}]}'), _result('{"tool_calls":[{"name":"search_mails","arguments":{}}]}')]
    chunks = list(cc.chat_stream([{"role": "user", "content": "q"}], "SYS", tools=None))
    assert [c["type"] for c in chunks] == ["token", "done"]


def test_error_result_becomes_error_chunk(fake_cli):
    fake_cli.script = [_result("Not logged in. Please run /login", is_error=True)]
    chunks = list(cc.chat_stream([{"role": "user", "content": "q"}], "SYS", tools=None))
    assert chunks[0]["type"] == "error" and "Not logged in" in chunks[0]["error"]
    assert chunks[-1]["type"] == "done"


def test_missing_binary_is_an_error_chunk(monkeypatch):
    monkeypatch.setattr(cc, "binary", lambda: None)
    cc.reset_status_cache()
    chunks = list(cc.chat_stream([{"role": "user", "content": "q"}], "SYS"))
    assert chunks[0]["type"] == "error" and "not installed" in chunks[0]["error"]
    cc.reset_status_cache()


def test_chat_json_parses_fenced_object(fake_cli):
    fake_cli.script = [_delta("```json\n{\"text\": \"invoice\", \"limit\": 5}\n```"), _result("```json\n{\"text\": \"invoice\", \"limit\": 5}\n```")]
    res = cc.chat_json([{"role": "user", "content": "mails about invoices"}], "QUERY", {"type": "object"})
    assert res["data"] == {"text": "invoice", "limit": 5}


# ---------------------------------------------------------------- views
def test_status_view_reports_disabled_connector():
    c = Client()
    with override_settings(CLAUDE_CODE_ENABLED=False):
        cc.reset_status_cache()
        r = c.get("/api/ai/claude/status", **HDR)
        assert r.status_code == 200
        body = r.json()
        assert body["enabled"] is False and body["available"] is False and "switched off" in body["error"]
        assert c.post("/api/ai/claude/chat", data=json.dumps({"messages": [{"role": "user", "content": "hi"}]}), content_type="application/json", **HDR).status_code == 403
        assert c.post("/api/ai/claude/query", data=json.dumps({"question": "hi"}), content_type="application/json", **HDR).status_code == 403
    cc.reset_status_cache()


def test_chat_view_streams_sse_from_fake_cli(fake_cli):
    fake_cli.script = [_delta("Hello "), _delta("analyst."), _result("Hello analyst.")]
    c = Client()
    r = c.post("/api/ai/claude/chat", data=json.dumps({"messages": [{"role": "user", "content": "hi"}], "mode": "free", "tools": False, "model": "haiku"}), content_type="application/json", **HDR)
    assert r.status_code == 200
    events = _sse_events(r)
    assert "".join(e["content"] for e in events if e["type"] == "token") == "Hello analyst."
    assert events[-1]["type"] == "done"
    assert fake_cli.last_args[fake_cli.last_args.index("--model") + 1] == "haiku"


def test_chat_view_validates_body():
    c = Client()
    assert c.post("/api/ai/claude/chat", data="not json", content_type="application/json", **HDR).status_code == 400
    assert c.post("/api/ai/claude/chat", data=json.dumps({"messages": []}), content_type="application/json", **HDR).status_code == 400
    assert c.post("/api/ai/claude/query", data=json.dumps({"question": ""}), content_type="application/json", **HDR).status_code == 400


def test_health_lists_connector():
    c = Client()
    h = c.get("/api/health", **HDR).json()
    assert "claudeCode" in h["optional"]
    assert isinstance(h["optional"]["claudeCode"], bool)


def test_real_popen_kwargs_do_not_leak_a_console(monkeypatch, tmp_path):
    monkeypatch.setattr(cc, "_cwd", lambda: tmp_path)
    kw = cc._popen_kwargs()
    assert kw["cwd"] == str(tmp_path)
    assert kw["stdin"] is subprocess.PIPE and kw["stdout"] is subprocess.PIPE and kw["stderr"] is subprocess.PIPE
