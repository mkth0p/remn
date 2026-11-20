"""What the AI settings are on an install that sets none of them: no connector that sends evidence
off the machine, and no model name the operator never chose."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from types import ModuleType
from unittest import mock

import pytest

SETTINGS = Path(__file__).resolve().parents[2] / "backend" / "forensic" / "settings.py"


def _settings(**env: str | None) -> ModuleType:
    """The settings module as it loads with the given variables set (None: unset) and no .env file."""
    environ = {k: v for k, v in os.environ.items() if k not in env}
    environ.update({k: v for k, v in env.items() if v is not None})
    spec = importlib.util.spec_from_file_location("settings_probe", SETTINGS)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    with mock.patch.dict(os.environ, environ, clear=True), mock.patch("dotenv.load_dotenv"):
        spec.loader.exec_module(module)
    return module


def test_the_claude_code_connector_is_off_on_an_install_that_does_not_turn_it_on():
    assert _settings(CLAUDE_CODE_ENABLED=None).CLAUDE_CODE_ENABLED is False


def test_one_setting_turns_the_claude_code_connector_on():
    assert _settings(CLAUDE_CODE_ENABLED="1").CLAUDE_CODE_ENABLED is True


# ---------------------------------------------------------------- the model when none is set
class _Listed:
    def __init__(self, name: str) -> None:
        self.model = name
        self.details = None


class _FakeOllama:
    """Stands in for ollama.Client: lists the given models and records the model each chat asks for."""

    def __init__(self, names: list[str]) -> None:
        self.names = names
        self.asked: list[str] = []

    def list(self):
        return type("Listing", (), {"models": [_Listed(n) for n in self.names]})()

    def show(self, model: str):
        self.asked.append(model)
        return {"capabilities": ["completion", "tools"]}

    def chat(self, **kwargs):
        self.asked.append(kwargs["model"])
        if kwargs.get("stream"):
            return iter([{"message": {"content": "ok"}}, {"done": True, "eval_count": 1}])
        return {"message": {"content": '{"source": "events"}'}}


def _service(monkeypatch, names: list[str], default: str = ""):
    from services.ai.client import OllamaService

    svc = OllamaService("http://127.0.0.1:11434", default)
    fake = _FakeOllama(names)
    monkeypatch.setattr(svc, "_client", lambda timeout=None: fake)
    return svc, fake


def test_the_server_names_no_model_on_an_install_that_sets_none():
    assert _settings(OLLAMA_MODEL=None).OLLAMA_MODEL == ""


def test_with_no_model_set_the_server_uses_the_first_model_its_ollama_lists_and_says_which(monkeypatch):
    # invented names; the first stands for an install whose only model is the one the server used to name by default
    svc, fake = _service(monkeypatch, ["only-model:latest"])
    chunks = list(svc.chat_stream([{"role": "user", "content": "hi"}]))
    assert fake.asked == ["only-model:latest"]
    assert chunks[-1] == {"type": "done", "model": "only-model:latest", "stats": {"eval_count": 1}}
    assert svc.chat_json([{"role": "user", "content": "hi"}], {"type": "object"})["model"] == "only-model:latest"
    ping = svc.ping()
    assert ping["defaultModel"] == "only-model:latest" and ping["defaultAvailable"] is True
    assert svc.capabilities("") == ["completion", "tools"] and fake.asked[-1] == "only-model:latest"


def test_the_model_the_analyst_picks_comes_before_the_first_one_listed(monkeypatch):
    svc, fake = _service(monkeypatch, ["first:8b", "second:8b"])
    chunks = list(svc.chat_stream([{"role": "user", "content": "hi"}], model="second:8b"))
    assert fake.asked == ["second:8b"] and chunks[-1]["model"] == "second:8b"


def test_a_model_the_operator_sets_is_used_when_the_analyst_picks_none(monkeypatch):
    svc, fake = _service(monkeypatch, ["first:8b", "chosen:8b"], default="chosen:8b")
    list(svc.chat_stream([{"role": "user", "content": "hi"}]))
    assert fake.asked == ["chosen:8b"]


def test_an_ollama_with_no_model_says_to_pull_one_instead_of_asking_for_an_empty_name(monkeypatch):
    svc, fake = _service(monkeypatch, [])
    with pytest.raises(RuntimeError, match="ollama pull"):
        list(svc.chat_stream([{"role": "user", "content": "hi"}]))
    assert fake.asked == []
