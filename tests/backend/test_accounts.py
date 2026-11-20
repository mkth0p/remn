"""Accounts: with none, the server works as it always has; with some, every request carries a
personal token, kept on the server only as a salted digest, that can be revoked, rotated and
refused with its account. Every name and token here is invented."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest
from django.test import Client, override_settings
from team_server import team  # noqa: F401 - the fixture

from forensic.accounts import AccountError, AccountStore, store
from forensic.middleware import ApiClientHeaderMiddleware

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

import run  # noqa: E402


@pytest.fixture(autouse=True)
def _fresh_allowance():
    ApiClientHeaderMiddleware.reset()
    yield
    ApiClientHeaderMiddleware.reset()


def test_without_an_accounts_file_the_server_works_as_before(tmp_path, settings):
    settings.FORENSIC_ACCOUNTS_FILE = tmp_path / "accounts.json"
    settings.FORENSIC_AUTH_TOKEN = ""
    c = Client()
    assert c.get("/api/meta", HTTP_X_FORENSIC_CLIENT="remn").status_code == 200
    health = c.get("/api/health", HTTP_X_FORENSIC_CLIENT="remn").json()
    assert health["accounts"] is False and health["account"] is None
    # and the one shared token, when it is set, is what every request needs
    settings.FORENSIC_AUTH_TOKEN = "invented-shared-token"
    assert c.get("/api/meta", HTTP_X_FORENSIC_CLIENT="remn").status_code == 401
    assert c.get("/api/meta", HTTP_X_FORENSIC_CLIENT="invented-shared-token").status_code == 200
    assert not (tmp_path / "accounts.json").exists() and not (tmp_path / "audit.log").exists()


def test_with_accounts_every_request_needs_a_personal_token(team):  # noqa: F811
    c = Client()
    for value in ("remn", "1", "invented-wrong", team.tokens["ana"][:-1] + "x"):
        r = c.get("/api/meta", HTTP_X_FORENSIC_CLIENT=value)
        assert r.status_code == 401 and r.json()["code"] == "auth" and r.json()["accounts"] is True, value
    assert c.get("/api/meta", **team.headers("ana")).status_code == 200
    # the health probe without the header still learns only that the server is up
    assert c.get("/api/health").json() == {"ok": True}
    health = c.get("/api/health", **team.headers("vic")).json()
    assert health["accounts"] is True and health["account"] == {"name": "vic", "role": "viewer"}


def test_the_shared_token_is_not_accepted_once_accounts_exist(team, settings):  # noqa: F811
    settings.FORENSIC_AUTH_TOKEN = "invented-shared-token"
    assert Client().get("/api/meta", HTTP_X_FORENSIC_CLIENT="invented-shared-token").status_code == 401
    assert Client().get("/api/meta", **team.headers("ana")).status_code == 200


def test_a_token_is_kept_only_as_a_salted_digest_in_a_file_only_the_server_reads(team):  # noqa: F811
    text = team.accounts.path.read_text(encoding="utf-8")
    for token in team.tokens.values():
        secret = token.split("_", 2)[2]
        assert token not in text and secret not in text
    data = json.loads(text)
    digests = [t["hash"] for acc in data["accounts"].values() for t in acc["tokens"]]
    salts = [t["salt"] for acc in data["accounts"].values() for t in acc["tokens"]]
    assert len(set(digests)) == len(digests) and len(set(salts)) == len(salts) and all(len(s) == 32 for s in salts)
    if os.name == "posix":
        assert (team.accounts.path.stat().st_mode & 0o777) == 0o600
    # written whole: no temporary file is left beside it
    assert sorted(p.name for p in team.folder.iterdir() if p.name.startswith(".accounts")) == []


def test_a_revoked_token_and_a_disabled_account_are_refused_and_a_rotated_token_replaces_the_old(team):  # noqa: F811
    old = team.tokens["ana"]
    new = team.accounts.rotate("ana")
    assert new != old
    assert Client().get("/api/meta", HTTP_X_FORENSIC_CLIENT=old).status_code == 401
    assert Client().get("/api/meta", HTTP_X_FORENSIC_CLIENT=new).status_code == 200
    team.accounts.set_disabled("ana", True)
    assert Client().get("/api/meta", HTTP_X_FORENSIC_CLIENT=new).status_code == 401
    team.accounts.set_disabled("ana", False)
    assert Client().get("/api/meta", HTTP_X_FORENSIC_CLIENT=new).status_code == 200
    token_id = new.split("_")[1]
    assert team.accounts.revoke("ana", token_id) == 1
    assert Client().get("/api/meta", HTTP_X_FORENSIC_CLIENT=new).status_code == 401
    with pytest.raises(AccountError):
        team.accounts.revoke("ana", "0000000000")


def test_a_change_to_the_file_takes_effect_without_a_restart(team):  # noqa: F811
    # another process (the management command) writes the file: the server reads it again
    other = AccountStore(team.accounts.path)
    token = other.create("dee", "viewer")
    assert Client().get("/api/meta", HTTP_X_FORENSIC_CLIENT=token).status_code == 200
    other.set_role("dee", "analyst")
    assert Client().get("/api/health", HTTP_X_FORENSIC_CLIENT=token).json()["account"]["role"] == "analyst"


def test_an_accounts_file_that_cannot_be_read_refuses_everyone_rather_than_opening_the_server(team):  # noqa: F811
    team.accounts.path.write_text("{ not json", encoding="utf-8")
    assert store().enabled()
    for name in team.tokens:
        assert Client().get("/api/meta", **team.headers(name)).status_code == 401
    assert Client().get("/api/meta", HTTP_X_FORENSIC_CLIENT="remn").status_code == 401


@override_settings(FORENSIC_AUTH_FAILURES_PER_MIN=3)
def test_wrong_personal_tokens_use_the_same_allowance_as_wrong_shared_tokens(team):  # noqa: F811
    c = Client()
    codes = [c.get("/api/meta", HTTP_X_FORENSIC_CLIENT=f"remn_0123456789_{'x' * 43}").status_code for _ in range(4)]
    assert codes == [401, 401, 401, 429]
    # the placeholder the page sends before it holds a token is refused but not counted
    ApiClientHeaderMiddleware.reset()
    for _ in range(5):
        assert c.get("/api/meta", HTTP_X_FORENSIC_CLIENT="remn").status_code == 401
    assert c.get("/api/meta", **team.headers("ana")).status_code == 200


def test_names_and_roles_are_checked(team):  # noqa: F811
    for name, role in (("Upper", "analyst"), ("", "analyst"), ("a b", "analyst"), ("new", "owner")):
        with pytest.raises(AccountError):
            team.accounts.create(name, role)
    with pytest.raises(AccountError):
        team.accounts.create("ana", "analyst")


def test_the_server_starts_beyond_loopback_with_accounts_and_no_shared_token(team, settings):  # noqa: F811
    settings.FORENSIC_AUTH_TOKEN = ""
    settings.FORENSIC_ALLOW_NO_TOKEN = False
    settings.FORENSIC_PUBLISHED_ON = ""
    assert run.refusal("0.0.0.0") is None


@override_settings(FORENSIC_AUTH_TOKEN="", FORENSIC_ALLOW_NO_TOKEN=False, FORENSIC_PUBLISHED_ON="", FORENSIC_BROWSER_ONLY=False)
def test_the_refusal_to_start_names_accounts_as_a_choice(tmp_path, settings):
    settings.FORENSIC_ACCOUNTS_FILE = tmp_path / "accounts.json"
    said = run.refusal("0.0.0.0")
    assert said is not None and "manage.py accounts create" in said
