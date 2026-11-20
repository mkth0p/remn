"""The audit log of a server with accounts: what is recorded, and that an entry changed, removed,
moved or written without the server's key is found. Every account and case here is invented."""

from __future__ import annotations

import json
import uuid

import pytest
from django.test import Client
from team_server import team  # noqa: F401 - the fixture

from forensic.audit import AuditLog
from forensic.middleware import ApiClientHeaderMiddleware


def _rewrite(path, entries: list[dict]) -> None:
    path.write_text("".join(json.dumps(e, separators=(",", ":")) + "\n" for e in entries), encoding="utf-8")


def test_a_change_to_a_case_is_recorded_with_who_when_what_and_how_it_ended(team):  # noqa: F811
    key = team.new_case("ana")
    entry = team.audit()[-1]
    assert entry["account"] == "ana" and entry["role"] == "analyst"
    assert entry["method"] == "POST" and entry["route"] == "/api/store/<str:key>/import" and entry["path"] == f"/api/store/{key}/import"
    assert entry["case"] == key and entry["status"] == 200 and entry["outcome"] == "ok"
    assert entry["time"].endswith("Z") and entry["address"] == "127.0.0.1"


def test_reads_are_not_recorded_and_evidence_leaving_the_server_is(team):  # noqa: F811
    key = team.new_case("ana")
    before = len(team.audit())
    team.get("ana", f"/api/store/{key}")
    team.post("ana", f"/api/store/{key}/search", {"source": "events"})
    team.get("ana", "/api/health")
    assert len(team.audit()) == before
    r = team.get("ana", f"/api/store/{key}/export")
    b"".join(r.streaming_content)
    entry = team.audit()[-1]
    assert entry["route"] == "/api/store/<str:key>/export" and entry["method"] == "GET" and entry["case"] == key


def test_a_failed_authentication_is_recorded_with_the_account_the_token_names(team):  # noqa: F811
    team.accounts.set_disabled("ben", True)
    Client().get("/api/meta", **team.headers("ben"))
    Client().get("/api/meta", HTTP_X_FORENSIC_CLIENT="invented-wrong-token")
    # the placeholder the page sends before it holds a token is not an attempt
    Client().get("/api/meta", HTTP_X_FORENSIC_CLIENT="remn")
    failed = [e for e in team.audit() if e["outcome"] == "failed authentication"]
    assert [(e["account"], e["role"], e["status"], e["route"]) for e in failed] == [("ben", None, 401, "/api/meta"), (None, None, 401, "/api/meta")]


def test_a_request_the_access_check_refuses_is_recorded(team):  # noqa: F811
    key = team.new_case("ana")
    team.get("ben", f"/api/store/{key}")
    team.delete("vic", f"/api/store/{key}")
    refused = [e for e in team.audit() if e["outcome"] == "refused"]
    assert [(e["account"], e["method"], e["case"], e["status"]) for e in refused] == [("ben", "GET", key, 404), ("vic", "DELETE", key, 403)]


def test_a_case_named_in_the_body_is_recorded_as_the_case(team):  # noqa: F811
    key = team.new_case("ana")
    team.post("ana", "/api/enrich/mails", {"storeKey": key, "settings": {}})
    entry = team.audit()[-1]
    assert entry["route"] == "/api/enrich/mails" and entry["case"] == key


def test_an_intact_log_verifies(team):  # noqa: F811
    for _ in range(3):
        team.new_case("ana")
    result = AuditLog(team.folder / "audit.log").verify()
    assert result["ok"] and result["entries"] == len(team.audit()) and result["head"]["seq"] == len(team.audit())


@pytest.mark.parametrize("damage", ["edit", "remove", "move", "recompute"])
def test_an_entry_changed_removed_moved_or_recomputed_without_the_key_is_found(team, damage):  # noqa: F811
    for _ in range(4):
        team.new_case("ana")
    entries = team.audit()
    if damage == "edit":
        entries[2]["account"] = "ben"
    elif damage == "remove":
        del entries[2]
    elif damage == "move":
        entries[1], entries[2] = entries[2], entries[1]
    else:
        # the whole chain rewritten from the third entry on, with a key that is not the server's
        forger = AuditLog(team.folder / "forged.log")
        forger._key = b"invented-key-that-is-not-the-servers"
        for e in entries[2:]:
            e["account"] = "ben"
        _rewrite(team.folder / "forged.log", entries[:2])
        for e in entries[2:]:
            forger.append(**{k: v for k, v in e.items() if k not in ("seq", "prev", "mac")})
        entries = [json.loads(line) for line in (team.folder / "forged.log").read_text().splitlines()]
    _rewrite(team.folder / "audit.log", entries)
    result = AuditLog(team.folder / "audit.log").verify()
    assert not result["ok"] and result["problems"], damage


def test_entries_cut_off_the_end_are_found_against_a_head_noted_earlier(team):  # noqa: F811
    for _ in range(3):
        team.new_case("ana")
    log = AuditLog(team.folder / "audit.log")
    head = log.verify()["head"]["mac"]
    entries = team.audit()
    _rewrite(team.folder / "audit.log", entries[:-1])
    # the chain that is left holds on its own: only the noted head shows what went
    assert log.verify()["ok"]
    result = log.verify([head])
    assert not result["ok"] and "no longer in the log" in result["problems"][0]


def test_an_admin_reads_and_verifies_the_log_through_the_api_and_no_one_else_does(team):  # noqa: F811
    key = team.new_case("ana")
    r = team.get("root", f"/api/audit?case={key}")
    assert r.status_code == 200 and [e["case"] for e in r.json()["entries"]] == [key]
    v = team.get("root", "/api/audit/verify").json()
    assert v["ok"] and v["entries"] >= 1
    for name in ("ana", "vic"):
        r = team.get(name, "/api/audit")
        assert r.status_code == 403 and r.json()["error"] == "this needs an admin account"
    # the server's own last entry is checked too: a log cut short while it runs does not verify
    entries = team.audit()
    team.post("ana", f"/api/store/{key}/access", {"name": "invented case"})
    _rewrite(team.folder / "audit.log", entries)
    assert not team.get("root", "/api/audit/verify").json()["ok"]


def test_without_accounts_nothing_is_written(tmp_path, settings):
    settings.FORENSIC_ACCOUNTS_FILE = tmp_path / "accounts.json"
    settings.FORENSIC_AUDIT_LOG = tmp_path / "audit.log"
    settings.FORENSIC_AUTH_TOKEN = ""
    ApiClientHeaderMiddleware.reset()
    c = Client()
    c.post(f"/api/store/{uuid.uuid4()}/access", data="{}", content_type="application/json", HTTP_X_FORENSIC_CLIENT="remn")
    c.get("/api/meta", HTTP_X_FORENSIC_CLIENT="remn")
    r = c.get("/api/audit", HTTP_X_FORENSIC_CLIENT="remn")
    assert r.status_code == 404 and r.json()["code"] == "noAccounts"
    assert not (tmp_path / "audit.log").exists() and not (tmp_path / "audit.key").exists()


def test_the_key_is_kept_beside_the_log_readable_by_the_server_only_unless_one_is_configured(team, settings):  # noqa: F811
    import os

    team.new_case("ana")
    key_file = team.folder / "audit.key"
    assert key_file.exists()
    if os.name == "posix":
        assert (key_file.stat().st_mode & 0o777) == 0o600 and ((team.folder / "audit.log").stat().st_mode & 0o777) == 0o600
    settings.FORENSIC_AUDIT_KEY = "invented-configured-key"
    log = AuditLog(team.folder / "other.log")
    log.append(account="ana", outcome="ok")
    assert log.verify()["ok"] and not (team.folder / "other.key").exists()
    settings.FORENSIC_AUDIT_KEY = "another-invented-key"
    assert not log.verify()["ok"]
