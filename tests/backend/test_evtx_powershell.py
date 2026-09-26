from __future__ import annotations

import json
from pathlib import Path

import pytest

from services.parsers import evtx_parser

CASES = Path(__file__).resolve().parents[1] / "fixtures" / "evtx" / "powershell-commands.json"


@pytest.mark.parametrize("case", json.loads(CASES.read_text(encoding="utf-8")), ids=lambda c: c["name"])
def test_powershell_4103_and_800_give_the_command_who_ran_it_and_the_script(case):
    # frontend/src/parsers/evtx/powershellCommands.test.ts reads the same cases through the browser parser
    row = evtx_parser.flatten(case["event"], None, include_raw=False)
    assert {k: row.get(k) for k in case["expect"]} == case["expect"]
