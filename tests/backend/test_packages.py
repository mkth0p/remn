from __future__ import annotations

import csv
import hashlib
import io
import json
import tarfile
import uuid
import zipfile

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, override_settings

from services.analysis.relationships import build
from services.ingest.package import PackageSource
from services.ingest.reconcile import MAX_EXPECTATIONS, reconcile
from services.parsers.collection import normalize, records
from services.parsers.mail.common import ParseContext
from services.store import queries as Q
from services.store.casestore import StoreRegistry
from services.store.writers import EventWriter, MailWriter

HDR = {"HTTP_X_FORENSIC_CLIENT": "1"}
HOST = "WS01"
HASH = "a" * 64
COLLECTED = "2026-09-09T10:00:00Z"


def archive(members):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        for name, value in members:
            z.writestr(name, value)
    return out.getvalue()


def package_bytes():
    return archive(
        [
            ("Processes/processes.csv", f"Name,ExecutablePath,ProcessId,CreationDate,SHA256\nagent.exe,C:\\Tools\\agent.exe,123,{COLLECTED},{HASH}\n"),
            ("Services/services.json", json.dumps([{"Name": "Agent", "PathName": r"C:\Tools\agent.exe"}])),
            ("Network Connections/connections.csv", "OwningProcess,RemoteAddress,RemotePort\n123,203.0.113.10,443\n"),
            ("mail/message.eml", "From: sender@example.test\nTo: analyst@example.test\nSubject: collection\n\nSee https://example.test/path\n"),
            ("Prefetch Files/unknown.bin", b"unsupported binary"),
            ("Temp Directories/unknown.bin", b"unknown contents"),
            ("../escape.txt", b"must not be read"),
            ("collection-manifest.json", json.dumps({"host": HOST, "collectedAt": COLLECTED, "collector": "synthetic"})),
        ]
    )


def parse(tmp_path, data=None, name="collection.zip"):
    blob = data if data is not None else package_bytes()
    source = PackageSource(name, None, blob, str(tmp_path), ParseContext(analyze_attachments=False), package_id=hashlib.sha256(blob).hexdigest())
    return list(source), source.stats()


def test_native_prefetch_registry_cab_and_reconciliation(tmp_path):
    from cabarchive import CabArchive, CabFile
    from native_artifacts import STAMP, prefetch_bytes, registry_bytes

    cab = CabArchive()
    cab["MPLog.txt"] = CabFile(b"threat detected: synthetic test\n")
    inner = archive([("processes.csv", "Name,PID\nx.exe,5\n"), ("Forensics Collection Summary.csv", "Artifact,Count\nProcesses,2\n")])
    rows, stats = parse(
        tmp_path,
        archive(
            [
                ("Prefetch Files/POWERSHELL.pf", prefetch_bytes()),
                ("Registry/test.hiv", registry_bytes()),
                ("WdSupportLogs/test.cab", cab.save()),
                ("nested.zip", inner),
                ("Forensics Collection Summary.csv", "Artifact,Count\nProcesses,1\nServices,3\n"),
            ]
        ),
    )
    assert stats["errors"] == 0, stats["files"]
    runs = [r for r in rows if r.get("artifactType") == "prefetch"]
    assert {r["ts"] for r in runs} == {STAMP, STAMP - 60000}
    assert all(r["processName"] == "POWERSHELL.EXE" and r["data"]["RunCount"] == 3 for r in runs)
    assert len({r["sourceIndex"] for r in runs}) == 2
    hive = next(r for r in rows if r.get("artifactType") == "registry")
    assert hive["ts"] is None and hive["data"]["LastWriteTime"] == "2026-09-09T10:00:00+00:00"
    defender = next(r for r in rows if r.get("artifactType") == "defender")
    assert defender["message"] == "threat detected: synthetic test" and defender["sourceFile"] == "WdSupportLogs/test.cab!/MPLog.txt"
    checks = {c["name"]: c["status"] for c in stats["reconciliation"]}
    assert checks == {"Processes": "matched", "Services": "missing", "nested.zip!/Processes": "mismatch"}
    assert not list(tmp_path.iterdir())


def test_native_bad_input_and_nested_limits(tmp_path, monkeypatch):
    rows, stats = parse(tmp_path, archive([("bad.pf", b"broken"), ("bad.hiv", b"regfbroken")]))
    assert not rows and stats["errors"] == 2
    data = archive([("processes.csv", "Name,PID\nx,1\n")])
    for _ in range(4):
        data = archive([("nested.zip", data)])
    rows, stats = parse(tmp_path, data)
    assert not rows and stats["errors"] == 1
    assert any("depth" in f.get("reason", "") for f in stats["files"])
    from services.parsers import native

    monkeypatch.setattr(native, "MAX_OUTPUT", 2)
    path = tmp_path / "large.pf"
    path.write_bytes(b"oversized")
    with pytest.raises(ValueError, match="exceeds"):
        native.decode("prefetch", str(path), str(tmp_path))


def test_nested_archive_failure_keeps_emitted_counts_and_inventory(tmp_path, monkeypatch):
    original = PackageSource.__iter__

    def interrupted(source):
        yield from original(source)
        if source.depth == 1:
            raise OSError("nested archive read interrupted")

    monkeypatch.setattr(PackageSource, "__iter__", interrupted)
    rows, stats = parse(tmp_path, archive([("inner.zip", archive([("processes.csv", "Name,PID\nx,1\n")]))]))
    assert len(rows) == stats["count"] == 1
    assert stats["errors"] == 1 and stats["inventoryComplete"] is False
    assert stats["files"][1]["name"] == "inner.zip!/processes.csv"
    assert not list(tmp_path.iterdir())


def test_task_xml_clixml_and_netstat_exports(tmp_path):
    rows, stats = parse(
        tmp_path,
        archive(
            [
                (
                    "Scheduled Tasks/a.xml",
                    '<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><RegistrationInfo><URI>Demo</URI></RegistrationInfo><Actions><Exec><Command>C:\\Tools\\demo.exe</Command><Arguments>--test</Arguments></Exec></Actions></Task>',
                ),
                ("Processes/a.xml", '<Objs><Obj><Props><S N="Name">demo.exe</S><I32 N="Id">42</I32></Props></Obj></Objs>'),
                ("Network Connections/netstat.txt", "TCP  127.0.0.1:3000  [2001:db8::1]:443  ESTABLISHED  42\n"),
                ("Services/sc.txt", "Name : Example\nPathName : C:\\Tools\\demo.exe\n\n"),
                ("Scheduled Tasks/unsupported.xml", "<Task><Actions><ComHandler /></Actions></Task>"),
            ]
        ),
    )
    assert stats["errors"] == 1 and len(rows) == 4
    assert rows[0]["taskName"] == "Demo" and rows[0]["image"] == r"C:\Tools\demo.exe"
    assert rows[1]["processId"] == 42
    assert rows[2]["destinationIp"] == "2001:db8::1" and rows[2]["destinationPort"] == 443
    assert rows[3]["serviceName"] == "Example"


def test_explicit_aliases_and_unique_snapshot_pid_resolution():
    base = {"computer": "WS01", "packageId": "pkg", "observedAt": 1788948000000, "processId": 42, "recordKind": "observation"}
    rows = [
        {**base, "id": 1, "artifactType": "process", "processStart": COLLECTED},
        {**base, "id": 2, "artifactType": "connection", "destinationIp": "203.0.113.10"},
    ]
    result = build(rows, [], {"aliases": {"hosts": {"ws01": "ws01.example"}}})
    assert len([n for n in result["nodes"] if n["kind"] == "process"]) == 1
    assert any(n["kind"] == "host" and n["value"] == "ws01.example" for n in result["nodes"])
    assert any(e["confidence"] == "contextual" and "snapshot match" in e["reason"] for e in result["edges"])
    assert rows[1].get("processStart") is None, "original evidence must not be mutated"
    resolved = next(e for e in result["edges"] if "snapshot match" in e["reason"])
    assert {r["id"] for r in resolved["refs"]} == {1, 2}
    paged = build([rows[1]], [], process_context=[rows[0]])
    assert any(n["kind"] == "process" for n in paged["nodes"])
    ambiguous = build([*rows, {**rows[0], "id": 3}], [])
    assert any(n["kind"] == "process-observation" for n in ambiguous["nodes"])
    other = build([rows[0], {**rows[1], "packageId": "other"}], [])
    assert any(n["kind"] == "process-observation" for n in other["nodes"])
    with pytest.raises(ValueError, match="cycles"):
        build(rows, [], {"aliases": {"hosts": {"a": "b", "b": "a"}}})


def test_server_relationship_cursor_pages(tmp_path, registry, monkeypatch):
    key = str(uuid.uuid4())
    store = registry.get(key)
    writer = EventWriter(store, 1)
    for i in range(5):
        writer.add({"computer": f"host{i}", "ts": None, "eventId": None})
    writer.flush()
    monkeypatch.setattr("api.views.relationships.registry", registry)
    cursor, seen = {}, []
    while cursor is not None:
        response = Client().post(
            "/api/relationships/build", json.dumps({"storeKey": key, "pageSize": 2, "cursor": cursor}), content_type="application/json", **HDR
        )
        assert response.status_code == 200, response.content
        page = response.json()
        seen.extend(n["value"] for n in page["nodes"] if n["kind"] == "host")
        cursor = page["cursor"]
    assert seen == [f"host{i}" for i in range(5)]


def test_mixed_package_and_explicit_coverage(tmp_path):
    blob = package_bytes()
    rows, stats = parse(tmp_path, blob)
    assert len(rows) == 4 and stats["observations"] == 3 and stats["mails"] == 1
    assert len(stats["files"]) == 8 and stats["unsupported"] == 2 and stats["skipped"] == 1
    assert stats["inventoryComplete"] is True and stats["errors"] == 0
    process = next(r for r in rows if r.get("artifactType") == "process")
    assert process["ts"] is None and process["eventId"] is None
    assert process["computer"] == HOST and process["observedAt"] == 1788948000000
    assert process["data"]["Name"] == "agent.exe" and process["sourceIndex"] == 0
    assert process["packageId"] == hashlib.sha256(blob).hexdigest()
    assert process["sourceSha256"] == stats["files"][0]["sha256"]
    assert not list(tmp_path.iterdir()), "temporary members must be cleaned up"
    assert stats["files"][6]["reason"] == "unsafe member path"
    assert "sha256" not in stats["files"][6]


def test_parser_errors_are_visible_and_other_members_continue(tmp_path):
    data = archive([("Processes/broken.json", b"not json"), ("Services/services.csv", b"Name,PathName\nSvc,C:\\svc.exe\n")])
    rows, stats = parse(tmp_path, data)
    assert len(rows) == 1 and stats["errors"] == 1
    assert stats["files"][0]["status"] == "error" and stats["files"][1]["status"] == "parsed"


def test_utf16_powershell_csv_and_ambiguous_timestamps(tmp_path):
    p = tmp_path / "processes.csv"
    p.write_bytes(('#TYPE System.Process\n"Name";"PID";"CollectedAt"\n"Agent";"42";"09/09/2026 10:00"\n').encode("utf-16"))
    raw = list(records(str(p), p.name))[0]
    row = normalize(raw, "Processes/processes.csv", 0, {})
    assert row["processId"] == 42 and row["observedAt"] is None and row["ts"] is None
    assert row["data"]["CollectedAt"] == "09/09/2026 10:00"


def test_tar_and_limits_are_reported(tmp_path, monkeypatch):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as tar:
        info = tarfile.TarInfo("processes.csv")
        data = b"Name,PID\nAgent,42\n"
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
        link = tarfile.TarInfo("link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        tar.addfile(link)
    rows, stats = parse(tmp_path, out.getvalue(), "collection.tar")
    assert len(rows) == 1 and stats["skipped"] == 1
    monkeypatch.setattr("services.ingest.package.MAX_MEMBER", 2)
    rows, stats = parse(tmp_path)
    assert rows == [] and stats["skipped"] == 8


def test_inventory_cap_never_claims_completeness(tmp_path, monkeypatch):
    monkeypatch.setattr("services.ingest.package.MAX_FILES", 2)
    _, stats = parse(tmp_path)
    assert len(stats["files"]) == 2 and stats["inventoryComplete"] is False


def test_browser_stream_is_mixed_and_keeps_relative_paths(tmp_path):
    response = Client().post("/api/ingest/package", {"file": SimpleUploadedFile("collection.zip", package_bytes())}, **HDR)
    assert response.status_code == 200
    lines = [json.loads(line) for line in b"".join(response.streaming_content).splitlines()]
    assert lines[0]["type"] == "meta" and lines[-1]["type"] == "done"
    assert {r["type"] for r in lines[1:-1]} == {"event", "mail"}
    assert lines[-1]["stats"]["unsupported"] == 2
    response = Client().post("/api/ingest/package", {"file": SimpleUploadedFile("x.csv", b"Name,PID\nAgent,42\n"), "sourceName": "host/Processes/x.csv"}, **HDR)
    lines = [json.loads(line) for line in b"".join(response.streaming_content).splitlines()]
    assert lines[1]["sourceFile"] == "host/Processes/x.csv"


@pytest.fixture
def registry(tmp_path):
    reg = StoreRegistry()
    reg.configure(tmp_path / "cases")
    yield reg
    reg.close_all()


def test_store_roundtrip_relationship_parity_and_deletion(tmp_path, registry, monkeypatch):
    key = str(uuid.uuid4())
    store = registry.get(key)
    rows, _ = parse(tmp_path)
    ew, mw = EventWriter(store, 1), MailWriter(store, 1)
    for row in rows:
        (mw if row["type"] == "mail" else ew).add(row)
    ew.flush()
    mw.flush()
    events = Q.search(store, "events", {}, full=True)["rows"]
    mails = [Q.get_row(store, "mails", 1)]
    assert len(events) == 3 and all(e["recordKind"] == "observation" and e["ts"] is None for e in events)
    assert all(e["sourceSha256"] and e["packageId"] and e["observedAt"] for e in events)
    assert mails[0]["sourceFile"] == "mail/message.eml" and mails[0]["sourceSha256"]
    monkeypatch.setattr("api.views.relationships.registry", registry)
    c = Client()
    response = c.post("/api/relationships/build", json.dumps({"storeKey": key}), content_type="application/json", **HDR)
    assert response.status_code == 200, response.content
    server = response.json()
    browser = build(sorted(events, key=lambda e: e["id"]), mails)
    assert server == browser
    assert any(e["relation"] == "configured executable" for e in server["edges"])
    assert any(n["kind"] == "domain" and n["value"] == "example.test" for n in server["nodes"])
    store.delete_evidence(1)
    empty = c.post("/api/relationships/build", json.dumps({"storeKey": key}), content_type="application/json", **HDR).json()
    assert empty["nodes"] == [] and empty["edges"] == []


def test_relationship_scope_pid_reuse_and_digest_bridge():
    rows = [
        {"id": 1, "computer": "A", "processId": 123, "image": r"C:\agent.exe", "hashes": "SHA256=" + HASH, "recordKind": "observation"},
        {"id": 2, "computer": "A", "processId": 123, "image": r"C:\agent.exe", "recordKind": "observation"},
        {"id": 3, "computer": "B", "processId": 123, "image": r"C:\agent.exe", "recordKind": "observation"},
        {"id": 4, "computer": "A", "processId": 123, "processStart": COLLECTED, "image": r"C:\agent.exe", "recordKind": "observation"},
        {"id": 5, "computer": "A", "processId": 123, "processStart": "2026-09-10T10:00:00Z", "image": r"C:\agent.exe", "recordKind": "observation"},
    ]
    graph = build(rows, [{"id": 1, "attachments": [{"sha256": HASH}], "fromAddr": "sender@example.test"}])
    nodes = graph["nodes"]
    assert len([n for n in nodes if n["kind"] == "file"]) == 2
    assert len([n for n in nodes if n["kind"] == "process-observation"]) == 3
    assert len([n for n in nodes if n["kind"] == "process"]) == 2
    digest = next(n["id"] for n in nodes if n["kind"] == "hash")
    assert {e["relation"] for e in graph["edges"] if e["target"] == digest} == {"reports hash", "reported digest", "attachment digest"}


def test_no_filename_or_unqualified_user_merge():
    graph = build([{"id": 1, "image": "agent.exe", "targetUser": "alice"}, {"id": 2, "image": "agent.exe", "targetUser": "alice"}], [])
    assert not any(n["kind"] == "file" for n in graph["nodes"])
    assert len([n for n in graph["nodes"] if n["kind"] == "account"]) == 2


@pytest.mark.parametrize("body", [[], {"events": "bad"}, {"events": [None]}, {"mails": [{"urls": "bad"}]}, {"evidenceId": "1"}])
def test_relationship_invalid_inputs(body):
    response = Client().post("/api/relationships/build", json.dumps(body), content_type="application/json", **HDR)
    assert response.status_code == 400


def test_browser_only_mode_allows_browser_graph_but_never_store_keys():
    with override_settings(FORENSIC_BROWSER_ONLY=True):
        c = Client()
        denied = c.post("/api/relationships/build", json.dumps({"storeKey": str(uuid.uuid4())}), content_type="application/json", **HDR)
        assert denied.status_code == 403 and denied.json()["code"] == "browserOnly"
        allowed = c.post("/api/relationships/build", json.dumps({"events": [{"id": 1, "computer": "WS01"}]}), content_type="application/json", **HDR)
        assert allowed.status_code == 200 and allowed.json()["nodes"]


def test_unsafe_manifest_cannot_supply_collection_identity(tmp_path):
    rows, stats = parse(tmp_path, archive([("../collection-manifest.json", json.dumps({"host": "WRONG"})), ("Processes/p.csv", "Name,PID\nAgent,1\n")]))
    assert rows[0]["computer"] is None and stats["context"] == {}


def test_generated_package_includes_real_parseable_evtx(tmp_path):
    from make_package import generate

    path = tmp_path / "generated.zip"
    generate(path)
    source = PackageSource(path.name, str(path), None, str(tmp_path), ParseContext(analyze_attachments=False))
    rows = list(source)
    assert any(row.get("eventId") == 4688 for row in rows)
    assert source.stats()["errors"] == 0
    assert source.stats()["unsupported"] == 2


def test_server_package_ingestion_job_routes_both_record_types(tmp_path, registry, monkeypatch):
    from api.jobs import Job

    key = str(uuid.uuid4())
    blob = package_bytes()
    path = tmp_path / "input.zip"
    path.write_bytes(blob)
    digest = hashlib.sha256(blob).hexdigest()
    monkeypatch.setattr("api.views.store.registry", registry)
    monkeypatch.setattr("api.views.store.get_upload", lambda _: (path, {"name": path.name, "size": len(blob), "sha256": digest}))
    discarded = []
    monkeypatch.setattr("api.views.store.discard_upload", discarded.append)
    results = []

    def submit(kind, case_key, fn, label):
        job = Job(kind, case_key, label)
        results.append(fn(job))
        return job

    monkeypatch.setattr("api.views.store.manager.submit", submit)
    response = Client().post(
        f"/api/store/{key}/ingest",
        json.dumps({"uploadId": "synthetic-upload", "kind": "package", "evidence": {"id": 7, "sha256Client": digest}}),
        content_type="application/json",
        **HDR,
    )
    assert response.status_code == 200, response.content
    assert results[0]["count"] == 4 and results[0]["stats"]["unsupported"] == 2
    assert results[0]["integrity"] == "verified"
    assert registry.get(key).counts()["events"] == 3 and registry.get(key).counts()["mails"] == 1
    assert discarded == ["synthetic-upload"]
    evidence = Q.summary(registry.get(key))["evidence"][0]
    assert evidence["kind"] == "package" and len(evidence["stats"]["files"]) == 8


def _member(name, count, artifact_type, status="parsed", **extra):
    return {"name": name, "count": count, "artifactType": artifact_type, "status": status, "format": "csv", **extra}


def test_a_declared_path_that_was_never_collected_reads_as_missing():
    """The category fallback answers "Processes"; it must never answer a specific absent file.

    Matching a missing path against an unrelated member of the same category told the analyst the
    evidence was collected and complete when it was never collected at all.
    """
    collected = [_member("Processes/tasklist.csv", 3, "process")]
    declared = [{"path": "Processes/processes.csv", "count": 3}]
    assert reconcile(collected, declared)[0]["status"] == "missing"
    # a category expectation, the shape the fallback exists for, still matches
    assert reconcile(collected, [{"artifact": "Processes", "count": 3}])[0]["status"] == "matched"
    # and the same path, actually present, still matches
    assert reconcile([_member("Processes/processes.csv", 3, "process")], declared)[0]["status"] == "matched"


def test_a_member_that_was_never_hashed_is_not_a_digest_mismatch():
    unparsed = [_member("Processes/processes.csv", 0, "process", status="error", sha256=None)]
    result = reconcile(unparsed, [{"path": "Processes/processes.csv", "sha256": "abc123"}])[0]
    assert result["status"] == "incomplete" and "differs from manifest" not in result["reason"]
    parsed_but_wrong = [_member("Processes/processes.csv", 3, "process", sha256="deadbeef")]
    assert reconcile(parsed_but_wrong, [{"path": "Processes/processes.csv", "sha256": "abc123"}])[0]["status"] == "mismatch"


def test_expectations_beyond_the_cap_are_reported_not_dropped():
    out = reconcile([], [{"artifact": f"cat{i}", "count": 1} for i in range(MAX_EXPECTATIONS + 50)])
    assert out[-1]["status"] == "unresolved" and "50 further" in out[-1]["reason"]


def test_reconciliation_is_linear_in_members_and_expectations():
    """The quadratic form took minutes of server CPU on a few hundred KB of upload."""
    import time

    files = [_member(f"m{i}/file{i}.csv", 1, f"type{i % 7}") for i in range(4000)]
    expectations = [{"path": f"absent/{i}.csv", "count": 1} for i in range(MAX_EXPECTATIONS)]
    start = time.perf_counter()
    reconcile(files, expectations)
    assert time.perf_counter() - start < 10.0


def test_a_worker_that_fails_part_way_keeps_what_it_decoded(tmp_path, monkeypatch):
    """Damaged artefacts are normal in forensics: records decoded before the failure are evidence.

    The worker used to reopen its output in "w" mode on any error, truncating everything already
    written, so a failure at record N lost records 1..N-1 as well.
    """
    from services.parsers import native

    output = tmp_path / "out.ndjson"
    output.write_text(
        json.dumps({"Key": "Run", "Value": "a.exe"})
        + "\n"
        + json.dumps({"Key": "Run", "Value": "b.exe"})
        + "\n"
        + json.dumps({"_partial": "registry: NotImplementedError: big data", "_decoded": 2})
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(native, "decode", lambda kind, path, tmp_dir: str(output))

    seen = []
    with pytest.raises(native.PartialDecode) as caught:
        for record in native.records("registry", "ignored", str(tmp_path)):
            seen.append(record)
    assert [r["Value"] for r in seen] == ["a.exe", "b.exe"]
    assert "NotImplementedError" in str(caught.value)


def test_the_worker_reports_a_total_failure_as_before(tmp_path, monkeypatch):
    from services.parsers import native

    output = tmp_path / "out.ndjson"
    output.write_text(json.dumps({"Key": "Run", "Value": "a.exe"}) + "\n", encoding="utf-8")
    monkeypatch.setattr(native, "decode", lambda kind, path, tmp_dir: str(output))
    assert [r["Value"] for r in native.records("registry", "ignored", str(tmp_path))] == ["a.exe"]


def test_the_graph_uses_the_subject_pid_of_an_event_not_the_writers():
    """evtx_parser puts the Execution ProcessID in processId: the PID of the service that wrote
    the record. The subject is newProcessId (created) or callerProcessId (acting)."""
    from services.analysis import relationships as R

    # a 4688: the event log service wrote it (PID 4), svchost spawned cmd.exe as PID 2244
    created = {"id": 1, "computer": "WS01", "processId": 4, "callerProcessId": 880, "newProcessId": 2244, "image": r"C:\Windows\System32\cmd.exe"}
    assert R.subject_process_id(created) == ("2244", "new process")
    # an event that only names the acting process
    acting = {"id": 2, "computer": "WS01", "processId": 4, "callerProcessId": "0x1f4"}
    assert R.subject_process_id(acting) == ("500", "caller")
    # a collector snapshot: processId is the real one
    assert R.subject_process_id({"id": 3, "recordKind": "observation", "processId": "0x1f4"}) == ("500", "process")
    # the writer's PID never becomes a node
    graph = build([created], [])
    observations = [n for n in graph["nodes"] if n["kind"] == "process-observation"]
    assert observations and all("2244" in n["label"] for n in observations), [n["label"] for n in observations]
    assert not any("4" == n["value"] for n in observations)


def test_hex_and_decimal_pids_are_the_same_process():
    from services.analysis import relationships as R

    assert R.process_id("0x1f4") == R.process_id("500") == "500"
    assert R.process_id(None) == "" and R.process_id("not-a-pid") == "not-a-pid"


def test_a_reported_digest_belongs_to_the_file_the_record_is_about():
    """A Sysmon FileCreateStreamHash or ImageLoad reports the digest of the target or the loaded
    module, not of the executable of the process doing it."""
    written = {
        "id": 1,
        "computer": "WS01",
        "recordKind": "observation",
        "processId": 900,
        "image": r"C:\Windows\System32\powershell.exe",
        "targetFilename": r"C:\Users\a\payload.dll",
        "hashes": "SHA256=" + HASH,
    }
    graph = build([written], [])
    digest = next(n["id"] for n in graph["nodes"] if n["kind"] == "hash")
    subject = next(e["source"] for e in graph["edges"] if e["target"] == digest and e["relation"] == "reported digest")
    label = next(n["label"] for n in graph["nodes"] if n["id"] == subject)
    assert "payload.dll" in label, f"digest attributed to {label}"
    assert "powershell" not in label


def test_a_loaded_module_is_its_own_node():
    loaded = {
        "id": 1,
        "computer": "WS01",
        "recordKind": "observation",
        "processId": 900,
        "image": r"C:\Windows\System32\svchost.exe",
        "imageLoaded": r"C:\Users\a\evil.dll",
    }
    graph = build([loaded], [])
    assert any(e["relation"] == "loads image" for e in graph["edges"])
    assert any("evil.dll" in n["label"] for n in graph["nodes"] if n["kind"] == "file")


def test_an_oversized_export_keeps_the_records_it_parsed(tmp_path, monkeypatch):
    """The byte ceiling used to reject before parsing, so a 200 MB file listing contributed nothing
    but a hash. Every other limit here raises during iteration and keeps what it read."""
    from services.parsers import collection

    monkeypatch.setattr(collection, "MAX_PARSE_BYTES", 64 * 1024)
    export = tmp_path / "processes.csv"
    with export.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["Name", "Id", "Path"])
        rows = 0
        while fh.tell() < 200 * 1024:
            writer.writerow([f"proc{rows}.exe", rows, "C:\\Windows\\System32\\proc.exe"])
            rows += 1

    parsed = 0
    reason = None
    try:
        for _ in collection.records(str(export), "Processes/processes.csv"):
            parsed += 1
    except ValueError as exc:
        reason = str(exc)
    assert parsed > 100, f"only {parsed} records survived the ceiling"
    assert reason and "parse limit" in reason and "not read" in reason


def test_an_oversized_member_is_partial_in_the_package_inventory(tmp_path, monkeypatch):
    from services.parsers import collection

    monkeypatch.setattr(collection, "MAX_PARSE_BYTES", 32 * 1024)
    body = io.StringIO()
    writer = csv.writer(body)
    writer.writerow(["Name", "Id", "Path"])
    for i in range(4000):
        writer.writerow([f"proc{i}.exe", i, "C:\\Windows\\System32\\proc.exe"])
    blob = archive([("Processes/processes.csv", body.getvalue())])
    src = PackageSource("pkg.zip", None, blob, str(tmp_path), ParseContext(analyze_attachments=False))
    produced = list(src)
    member = next(f for f in src.files if f["name"].endswith("processes.csv"))
    assert produced, "records parsed before the ceiling must reach the case"
    assert member["status"] == "error" and "parse limit" in member["reason"]
    assert member["count"] == len(produced) > 0


def test_one_package_cannot_spawn_unbounded_decoder_subprocesses(tmp_path):
    """Each decode is capped at 512 MiB and 30 seconds; without a count, a package of twenty
    thousand hives was twenty thousand subprocesses on a single request."""
    from services.ingest import package as P

    hive = b"regf" + bytes(4096)
    blob = archive([(f"Registry/hive{i}.dat", hive) for i in range(6)])
    src = PackageSource("pkg.zip", None, blob, str(tmp_path), ParseContext(analyze_attachments=False))
    original = P.MAX_NATIVE_DECODES
    P.MAX_NATIVE_DECODES = 2
    try:
        list(src)
    finally:
        P.MAX_NATIVE_DECODES = original

    skipped = [f for f in src.files if "native decoding budget" in str(f.get("reason", ""))]
    assert len(skipped) == 4, [(f.get("status"), f.get("reason")) for f in src.files]
    # the members past the budget are still inventoried and hashed: nothing is silently dropped
    assert all(f.get("sha256") for f in skipped)
