from __future__ import annotations

import json
from pathlib import Path

from django.test import Client

from services.ai.prompts import compose_system, prompts_version
from services.ai.tools import TOOL_NAMES

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "ai_system_compose.json"
HDR = {"HTTP_X_FORENSIC_CLIENT": "1"}


def test_ai_meta_endpoint():
    c = Client()
    assert c.get("/api/ai/meta").status_code == 403  # header required
    r = c.get("/api/ai/meta", **HDR)
    assert r.status_code == 200
    body = r.json()
    assert set(body["prompts"]) == {"analyst", "query", "explain", "rule", "report", "triage", "free"}
    assert body["prompts"]["free"] == "" and len(body["prompts"]["analyst"]) > 3000
    names = [t["function"]["name"] for t in body["tools"]]
    assert "timeline_mails" in names and "sql" in names and len(names) == 16
    assert body["querySchema"]["properties"]["source"]["enum"] == ["events", "mails"]
    assert "events(" in body["schemaDoc"]
    assert body["numCtx"] > 0 and body["limits"]["maxMessages"] == 200
    assert body["version"] == prompts_version()


def test_compose_system_matches_golden_fixture():
    """Parity contract with the TS mirror (frontend/src/ai/meta.ts). If this fails after an
    intentional prompt change, regenerate tests/fixtures/ai_system_compose.json."""
    fx = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert fx["version"] == prompts_version(), "prompts changed: regenerate the fixture (see docstring)"
    for case in fx["cases"]:
        assert compose_system(case["mode"], case["context"]) == case["expected"], case["name"]


def test_tool_names_cover_frontend_handlers():
    # every tool the browser executor implements must be declared to the model
    expected = {"get_case_summary", "search_events", "aggregate_events", "timeline_events", "get_event",
                "search_mails", "aggregate_mails", "timeline_mails", "get_mail", "list_findings",
                "regex_test", "lookup_ioc", "pivot", "sql", "get_chain", "suggest_review"}
    assert set(TOOL_NAMES) == expected
