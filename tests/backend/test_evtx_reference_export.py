"""The in-browser EVTX parser reads the server's tables from a generated file; it must not fall behind them."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("export_evtx_reference", ROOT / "tools" / "export_evtx_reference.py")
X = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(X)


def test_the_browser_parser_reads_the_tables_the_server_parser_reads():
    assert X.OUT.read_text(encoding="utf-8") == X.render(), "run tools/export_evtx_reference.py"
