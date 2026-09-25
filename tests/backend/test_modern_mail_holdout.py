"""Score and incident-rule results are checked independently on held-out synthetic messages."""

import importlib.util
from pathlib import Path

from mail_calibration import SETTINGS
from modern_mail_holdout import examples


def test_modern_mail_holdout(tmp_path):
    spec = importlib.util.spec_from_file_location("calibrate_tool", Path(__file__).resolve().parents[2] / "tools/calibrate_mail.py")
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    result = tool.evaluate(examples(), SETTINGS, temp_dir=tmp_path)
    assert result["scoreHighFalsePositives"] == 0, result["examples"]
    assert result["scoreHighMalicious"] == 3, result["examples"]
    for pack in result["packs"].values():
        assert not pack["errors"]
        assert pack["highFalsePositives"] == 0, pack["rules"]
