"""What the AI settings are on an install that sets none of them: no connector that sends evidence
off the machine, and no model name the operator never chose."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from types import ModuleType
from unittest import mock

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
