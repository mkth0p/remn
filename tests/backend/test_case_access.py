"""Roles and case membership on a server with accounts: an admin opens every case, an analyst the
cases it owns or is a member of, a viewer reads the cases it is a member of and changes nothing.
The key of a case does not open it on its own. Every account, host and case here is invented."""

from __future__ import annotations

import threading
import uuid

from django.test import Client, override_settings
from team_server import team  # noqa: F401 - the fixture

from api.jobs import manager
from services.store.casestore import registry


def _unknown(r) -> bool:
    return r.status_code == 404 and r.json()["code"] == "caseAccess"


def test_the_first_analyst_to_write_to_a_new_key_owns_the_case(team):  # noqa: F811
    key = team.new_case("ana")
    rec = team.accounts.case(key)
    assert rec["owner"] == "ana" and rec["members"] == []
    assert team.get("ana", f"/api/store/{key}").status_code == 200


def test_the_key_alone_does_not_open_a_case_of_other_accounts(team):  # noqa: F811
    key = team.new_case("ana")
    stranger = str(uuid.uuid4())
    for name in ("ben", "vic"):
        for path in (f"/api/store/{key}", f"/api/store/{key}/export", f"/api/store/{key}/facets", f"/api/jobs?case={key}"):
            r = team.get(name, path)
            # answered as a key nobody uses is, so a case of others cannot be told from no case
            assert _unknown(r), (name, path, r.status_code)
            assert r.content == team.get(name, path.replace(key, stranger)).content
        assert _unknown(team.post(name, f"/api/store/{key}/search", {"source": "events"}))
        assert _unknown(team.post(name, "/api/stories/build", {"storeKey": key}))
    assert _unknown(team.post("ben", f"/api/store/{key}/import"))
    assert _unknown(team.delete("ben", f"/api/store/{key}"))
    assert registry.exists(key)


def test_a_viewer_member_reads_the_case_and_changes_nothing(team):  # noqa: F811
    key = team.new_case("ana", members=("vic",))
    assert team.get("vic", f"/api/store/{key}").status_code == 200
    assert team.post("vic", f"/api/store/{key}/search", {"source": "events"}).json()["rows"]
    assert team.get("vic", f"/api/store/{key}/export").status_code == 200
    for r in (
        team.post("vic", f"/api/store/{key}/import"),
        team.post("vic", f"/api/store/{key}/reputation", {"items": []}),
        team.delete("vic", f"/api/store/{key}/evidence/1"),
        team.delete("vic", f"/api/store/{key}"),
        team.post("vic", f"/api/store/{key}/access", {"members": []}),
        team.post("vic", "/api/enrich/mails", {"storeKey": key}),
        team.post("vic", "/api/upload/init", {"name": "invented.evtx", "size": 10}),
        team.post("vic", "/api/reputation/lookup", {"items": []}),
    ):
        assert r.status_code == 403 and r.json()["code"] == "role" and "viewer" in r.json()["error"]
    assert registry.exists(key)
    # a viewer cannot create a case either
    assert team.post("vic", f"/api/store/{uuid.uuid4()}/import").status_code == 403


def test_an_analyst_member_works_on_the_case_but_only_its_owner_or_an_admin_deletes_it_or_changes_who_is_in_it(team):  # noqa: F811
    key = team.new_case("ana", members=("ben",))
    assert team.delete("ben", f"/api/store/{key}/evidence/1").status_code == 200
    for r in (team.delete("ben", f"/api/store/{key}"), team.post("ben", f"/api/store/{key}/access", {"members": ["ben", "vic"]})):
        assert r.status_code == 403 and r.json()["code"] == "role" and "owner" in r.json()["error"]
    assert team.post("ana", f"/api/store/{key}/access", {"members": ["ben", "vic"]}).json()["members"] == ["ben", "vic"]
    assert team.post("root", f"/api/store/{key}/access", {"members": ["vic"]}).json()["members"] == ["vic"]


def test_membership_names_real_accounts_and_only_an_admin_gives_a_case_another_owner(team):  # noqa: F811
    key = team.new_case("ana")
    r = team.post("ana", f"/api/store/{key}/access", {"members": ["nobody"]})
    assert r.status_code == 400 and "nobody" in r.json()["error"]
    r = team.post("ana", f"/api/store/{key}/access", {"owner": "ben"})
    assert r.status_code == 403
    r = team.post("root", f"/api/store/{key}/access", {"owner": "ben"})
    assert r.status_code == 200 and r.json()["owner"] == "ben"
    assert _unknown(team.get("ana", f"/api/store/{key}"))
    described = team.get("ben", f"/api/store/{key}/access").json()
    assert described["owner"] == "ben" and described["may"] == {"read": True, "write": True, "own": True}


def test_a_store_written_before_accounts_opens_only_for_an_admin_until_it_has_an_owner(team):  # noqa: F811
    key = str(uuid.uuid4())
    registry.get(key, create=True)
    assert team.accounts.case(key) is None
    assert _unknown(team.get("ana", f"/api/store/{key}"))
    # writing to it does not make an analyst its owner
    assert _unknown(team.post("ana", f"/api/store/{key}/import"))
    assert team.accounts.case(key) is None
    assert team.get("root", f"/api/store/{key}").status_code == 200
    assert key in [s["key"] for s in team.get("root", "/api/store").json()["stores"]]
    team.post("root", f"/api/store/{key}/access", {"owner": "ana"})
    assert team.get("ana", f"/api/store/{key}").status_code == 200


def test_the_case_listing_shows_each_account_the_cases_it_may_read(team):  # noqa: F811
    mine = team.new_case("ana", members=("vic",))
    theirs = team.new_case("ben")
    legacy = str(uuid.uuid4())
    registry.get(legacy, create=True)

    def listed(name: str) -> set[str]:
        r = team.get(name, "/api/store")
        assert r.status_code == 200
        return {s["key"] for s in r.json()["stores"]}

    assert listed("ana") == {mine}
    assert listed("ben") == {theirs}
    assert listed("vic") == {mine}
    assert listed("root") == {mine, theirs, legacy}
    entry = next(s for s in team.get("vic", "/api/store").json()["stores"] if s["key"] == mine)
    assert entry["owner"] == "ana" and entry["members"] == ["vic"] and entry["may"] == {"read": True, "write": False, "own": False}
    assert "root" not in team.get("vic", "/api/store").json()


def test_deleting_a_case_forgets_who_was_in_it_and_emptying_it_does_not(team):  # noqa: F811
    key = team.new_case("ana", members=("vic",))
    assert team.delete("ana", f"/api/store/{key}?keepAccess=1").json() == {"deleted": True}
    assert team.accounts.case(key)["members"] == ["vic"]
    assert team.delete("ana", f"/api/store/{key}").status_code == 200
    assert team.accounts.case(key) is None


def test_the_jobs_of_a_case_are_listed_to_its_members_and_a_viewer_cancels_only_the_job_it_started(team):  # noqa: F811
    key = team.new_case("ana", members=("vic",))
    release = threading.Event()
    by_ana = manager.submit("ingest", key, lambda j: release.wait(30), label="invented.evtx", account="ana")
    by_vic = manager.submit("rules", key, lambda j: release.wait(30), label="1 rules", account="vic")
    try:
        ids = {j["id"] for j in team.get("vic", f"/api/jobs?case={key}").json()["jobs"]}
        assert {by_ana.id, by_vic.id} <= ids
        assert _unknown(team.get("ben", f"/api/jobs?case={key}"))
        assert _unknown(team.get("ben", f"/api/jobs/{by_ana.id}?case={key}"))
        r = team.delete("vic", f"/api/jobs/{by_ana.id}?case={key}")
        assert r.status_code == 403 and not by_ana.cancelled
        assert team.delete("vic", f"/api/jobs/{by_vic.id}?case={key}").status_code == 200 and by_vic.cancelled
        assert team.delete("ana", f"/api/jobs/{by_ana.id}?case={key}").status_code == 200 and by_ana.cancelled
    finally:
        release.set()


def test_a_body_without_a_case_needs_only_a_signed_in_account(team):  # noqa: F811
    r = team.post("vic", "/api/stories/build", {"events": [], "mails": [], "findings": [], "settings": {}})
    assert r.status_code == 200
    r = team.post("vic", "/api/enrich/mails", {"mails": [], "settings": {}})
    assert r.status_code == 200


def test_an_admin_opens_every_case(team):  # noqa: F811
    key = team.new_case("ana")
    assert team.get("root", f"/api/store/{key}").status_code == 200
    assert team.post("root", f"/api/store/{key}/search", {"source": "events"}).status_code == 200
    assert team.delete("root", f"/api/store/{key}").status_code == 200


@override_settings(FORENSIC_AUTH_TOKEN="")
def test_without_accounts_the_key_still_opens_the_case_and_membership_does_not_exist(tmp_path, settings):
    settings.FORENSIC_ACCOUNTS_FILE = tmp_path / "accounts.json"
    old = registry.root
    registry.configure(tmp_path / "cases")
    try:
        key = str(uuid.uuid4())
        registry.get(key, create=True)
        c = Client()
        assert c.get(f"/api/store/{key}", HTTP_X_FORENSIC_CLIENT="remn").status_code == 200
        r = c.get(f"/api/store/{key}/access", HTTP_X_FORENSIC_CLIENT="remn")
        assert r.status_code == 404 and r.json()["code"] == "noAccounts"
        assert c.get("/api/store", HTTP_X_FORENSIC_CLIENT="remn").json()["code"] == "listing"
    finally:
        registry.close_all()
        if old:
            registry.configure(old)


def test_a_file_added_from_another_browser_under_a_number_the_case_already_uses_is_refused(team, monkeypatch, settings):  # noqa: F811
    from api.views import store as store_views

    settings.FILE_UPLOAD_TEMP_DIR = team.folder / "staging"
    key = team.new_case("ana", members=("ben",))
    registry.get(key).upsert_evidence({"id": 1, "name": "invented-ana.evtx", "kind": "evtx", "sha256Client": "a" * 64, "status": "done"})
    started = []
    monkeypatch.setattr(store_views.manager, "submit", lambda *a, **k: started.append(a) or type("J", (), {"id": "job"})())

    def ingest(sha: str):
        data = b"invented evidence bytes"
        uid = team.post("ben", "/api/upload/init", {"name": "invented-ben.evtx", "size": len(data)}).json()["uploadId"]
        Client().generic("PUT", f"/api/upload/{uid}/chunk?offset=0", data, content_type="application/octet-stream", **team.headers("ben"))
        Client().post(f"/api/upload/{uid}/complete", **team.headers("ben"))
        return team.post(
            "ben", f"/api/store/{key}/ingest", {"uploadId": uid, "kind": "evtx", "evidence": {"id": 1, "name": "invented-ben.evtx", "sha256Client": sha}}
        )

    r = ingest("b" * 64)
    assert r.status_code == 409 and r.json()["code"] == "evidenceId" and "invented-ana.evtx" in r.json()["error"]
    assert not started
    held = registry.get(key).cursor().execute("SELECT name FROM evidence WHERE id = 1").fetchone()
    assert held[0] == "invented-ana.evtx"
    # the same file again (a retry) is not another file
    assert ingest("a" * 64).status_code == 200 and len(started) == 1


def test_a_staged_upload_is_sent_finished_or_cancelled_only_by_the_account_that_started_it_or_an_admin(team, monkeypatch, settings):  # noqa: F811
    from api.views import store as store_views

    settings.FILE_UPLOAD_TEMP_DIR = team.folder / "staging"
    started = []
    monkeypatch.setattr(store_views.manager, "submit", lambda *a, **k: started.append(a) or type("J", (), {"id": "job"})())
    data = b"invented evidence bytes"
    uid = team.post("ana", "/api/upload/init", {"name": "invented-ana.evtx", "size": len(data)}).json()["uploadId"]

    def chunk(name: str):
        return Client().generic("PUT", f"/api/upload/{uid}/chunk?offset=0", data, content_type="application/octet-stream", **team.headers(name))

    # another analyst is answered as for an id nobody uses, whatever it tries
    assert chunk("ben").status_code == 404
    assert chunk("ana").status_code == 200
    assert team.post("ben", f"/api/upload/{uid}/complete").status_code == 404
    assert team.post("ana", f"/api/upload/{uid}/complete").status_code == 200
    assert team.get("ben", f"/api/upload/{uid}").status_code == 404
    assert team.delete("ben", f"/api/upload/{uid}").status_code == 404
    # nor does it parse the file into a case of its own, on the server or in its browser
    key = str(uuid.uuid4())
    r = team.post("ben", f"/api/store/{key}/ingest", {"uploadId": uid, "kind": "evtx", "evidence": {"id": 1, "name": "invented-ana.evtx"}})
    assert r.status_code == 404 and not started
    assert Client().post("/api/ingest/evtx", {"uploadId": uid, "engines": "0"}, **team.headers("ben")).status_code == 404
    # the file is still there for the account that sent it, and an admin may cancel it
    assert team.get("ana", f"/api/upload/{uid}").json()["complete"] is True
    assert team.delete("root", f"/api/upload/{uid}").json() == {"ok": True}
    assert team.get("ana", f"/api/upload/{uid}").status_code == 404
