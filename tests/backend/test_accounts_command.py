"""`manage.py accounts` and `manage.py audit`: create, list, disable and rotate accounts, set who may
open a case, read and verify the audit log. Every name here is invented."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from team_server import team  # noqa: F401 - the fixture

from forensic.accounts import store

ROOT = Path(__file__).resolve().parents[2]


def _run(*args: str) -> str:
    out = io.StringIO()
    call_command(*args, stdout=out)
    return out.getvalue()


@pytest.fixture
def files(tmp_path, settings):
    settings.FORENSIC_ACCOUNTS_FILE = tmp_path / "accounts.json"
    settings.FORENSIC_AUDIT_LOG = tmp_path / "audit.log"
    settings.FORENSIC_AUDIT_KEY = ""
    return tmp_path


def test_create_prints_the_token_once_and_list_never_shows_it(files):
    said = _run("accounts", "create", "ana", "--role", "analyst")
    token = said.strip().splitlines()[-1]
    assert token.startswith("remn_") and store().authenticate(token)[0].name == "ana"
    listed = _run("accounts", "list")
    assert "ana" in listed and "analyst" in listed and token.split("_")[1] in listed
    assert token.split("_", 2)[2] not in listed and token.split("_", 2)[2] not in (files / "accounts.json").read_text()


def test_rotate_disable_enable_role_and_revoke(files):
    first = _run("accounts", "create", "ben", "--role", "viewer").strip().splitlines()[-1]
    second = _run("accounts", "rotate", "ben").strip().splitlines()[-1]
    assert store().authenticate(first)[0] is None and store().authenticate(second)[0].name == "ben"
    _run("accounts", "disable", "ben")
    assert store().authenticate(second)[0] is None
    _run("accounts", "enable", "ben")
    _run("accounts", "role", "ben", "analyst")
    assert store().authenticate(second)[0].role == "analyst"
    assert "1 token(s) of ben revoked" in _run("accounts", "revoke", "ben")
    assert store().authenticate(second)[0] is None
    with pytest.raises(CommandError, match="no account named"):
        _run("accounts", "disable", "nobody")


def test_an_admin_gives_an_ownerless_store_an_owner_from_the_command(team):  # noqa: F811
    from services.store.casestore import registry

    key = str(uuid.uuid4())
    registry.get(key, create=True)
    assert f"{key}  no owner" in _run("accounts", "cases")
    _run("accounts", "case", key, "--owner", "ana", "--members", "vic")
    assert team.accounts.case(key)["owner"] == "ana" and team.accounts.case(key)["members"] == ["vic"]
    assert team.get("vic", f"/api/store/{key}").status_code == 200
    with pytest.raises(CommandError):
        _run("accounts", "case", "not-a-key", "--owner", "ana")


def test_every_change_is_in_the_audit_log_and_the_log_verifies(files):
    _run("accounts", "create", "ana", "--role", "analyst")
    _run("accounts", "disable", "ana")
    shown = [json.loads(line) for line in _run("audit", "show").splitlines()]
    assert [e["route"] for e in shown] == ["accounts create ana --role analyst", "accounts disable ana"]
    assert all(e["method"] == "COMMAND" and e["account"].startswith("manage.py") for e in shown)
    said = _run("audit", "verify")
    assert "2 entries" in said and "the chain holds" in said
    head = shown[-1]["mac"]
    assert "the chain holds" in _run("audit", "verify", "--head", head[:16])
    lines = (files / "audit.log").read_text().splitlines()
    (files / "audit.log").write_text(lines[0] + "\n")
    with pytest.raises(CommandError, match="does not verify"):
        _run("audit", "verify", "--head", head)


def test_a_command_run_beside_a_live_server_leaves_its_staging_area_alone(tmp_path):
    # a parse in progress keeps its files in the staging area; the start-up cleaning would remove them
    staging = tmp_path / "tmp"
    staging.mkdir()
    in_progress = staging / "invented.member"
    in_progress.write_bytes(b"x")
    env = {**os.environ, "FORENSIC_DATA_DIR": str(tmp_path), "FORENSIC_TMP_DIR": str(staging)}
    done = subprocess.run([sys.executable, str(ROOT / "backend" / "manage.py"), "accounts", "list"], env=env, capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr
    assert "no accounts" in done.stdout and in_progress.exists()
