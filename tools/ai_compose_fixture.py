#!/usr/bin/env python
"""
Regenerate tests/fixtures/ai_system_compose.json, the parity contract between the server's
compose_system (backend/services/ai/prompts.py) and its browser mirror (frontend/src/ai/meta.ts).

    .venv/bin/python tools/ai_compose_fixture.py

Run it after an intended change to a prompt or to compose_system; both test suites read the file.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "forensic.settings")

OUT = ROOT / "tests" / "fixtures" / "ai_system_compose.json"

CASES = [
    {
        "name": "analyst-browser",
        "mode": "analyst",
        "context": {
            "now": "2026-09-03T10:00:00.000Z",
            "networkAllowed": False,
            "storage": "browser",
            "caseSettings": {
                "internalDomains": ["interne.fr"],
                "vipNames": ["Marie Lefevre"],
                "businessHours": {"start": 8, "end": 19, "tz": "Europe/Paris"},
                "weekendDays": [0, 6],
                "internalIps": ["10.0.0.0/8"],
            },
        },
    },
    {
        "name": "analyst-server",
        "mode": "analyst",
        "context": {
            "now": "2026-09-03T10:00:00.000Z",
            "networkAllowed": True,
            "storage": "server",
            "caseSettings": {
                "internalDomains": [],
                "vipNames": [],
                "businessHours": {"start": 8, "end": 19, "tz": "UTC"},
                "weekendDays": [0, 6],
                "internalIps": [],
            },
        },
    },
    {
        "name": "analyst-agent-run",
        "mode": "analyst",
        "context": {
            "now": "2026-09-03T10:00:00.000Z",
            "networkAllowed": False,
            "storage": "browser",
            "steps": {"used": 5, "budget": 24},
            "memory": "Plan:\n- [done] Shape of the logons\n- [doing] Find the source of the failures\nHypotheses:\n- h1 (open, medium): password spraying from 10.0.0.5 [ev:12] [ev:40]",
            "omitted": 7,
        },
    },
    {"name": "free-minimal", "mode": "free", "context": {"now": "2026-09-03T10:00:00.000Z", "storage": "browser"}},
    {"name": "report-mode", "mode": "report", "context": {"storage": "browser", "networkAllowed": False}},
    {"name": "narrative-mode", "mode": "narrative", "context": {"storage": "browser"}},
    {"name": "json-mode", "mode": "json", "context": {"storage": "browser", "now": "2026-01-01T00:00:00Z"}},
    {"name": "unknown-mode-falls-back", "mode": "bogus", "context": {"storage": "browser"}},
    {"name": "triage-mode", "mode": "triage", "context": {"now": "2026-01-01T00:00:00Z", "storage": "browser"}},
]


def main() -> int:
    import django

    django.setup()
    from services.ai import prompts
    from services.store.queries import SCHEMA_DOC

    fixture = {
        "version": prompts.prompts_version(),
        "meta": {"prompts": {**prompts.SYSTEM_BY_MODE, "query": prompts.SYSTEM_QUERY}, "schemaDoc": SCHEMA_DOC},
        "cases": [{**c, "expected": prompts.compose_system(c["mode"], c["context"])} for c in CASES],
    }
    OUT.write_text(json.dumps(fixture, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}: {len(CASES)} cases, prompts {fixture['version']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
