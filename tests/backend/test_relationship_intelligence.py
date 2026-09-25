"""Relationship identity benchmark: deliberate overlaps and look-alike negatives."""

import pytest

from services.analysis.collection_context import prepare
from services.analysis.relationships import build

GUID = "12345678-1234-1234-1234-123456789abc"
START = "2026-09-01T10:00:00Z"
AT = 1788257100000  # 2026-09-01 10:05 UTC


def instances(rows, kind="process"):
    return [n for n in build(rows, [])["nodes"] if n["kind"] == kind]


def test_guid_case_and_braces_resolve_one_instance():
    rows = [{"id": 1, "computer": "WS01", "processGuid": "{" + GUID.upper() + "}"}, {"id": 2, "computer": "ws01", "processGuid": GUID}]
    assert len(instances(rows)) == 1
    rows[1]["computer"] = "ws02"
    assert len(instances(rows)) == 2


@pytest.mark.parametrize("guid", ["not-a-guid", "{00000000-0000-0000-0000-000000000000}", ""])
def test_invalid_guid_never_becomes_an_instance(guid):
    assert not instances([{"id": 1, "computer": "ws01", "processGuid": guid, "callerProcessId": 42}])


def test_pid_reuse_and_writer_pid_never_merge():
    rows = [{"id": i, "computer": "ws01", "callerProcessId": 42, "processStart": start} for i, start in enumerate([START, "2026-09-01T12:00:00Z"])]
    assert len(instances(rows)) == 2
    assert not instances([{"id": 4, "computer": "ws01", "processId": 42, "processStart": START}])


@pytest.mark.parametrize("extra", [{"processStart": "2026-09-01T11:00:00Z"}, {"processEnd": "2026-09-01T09:00:00Z"}])
def test_impossible_lifetimes_are_retained_but_not_joined(extra):
    graph = build([{"id": 1, "computer": "ws01", "processGuid": GUID, "callerProcessId": 42, "ts": AT, "processStart": START, **extra}], [])
    assert not any(n["kind"] == "process" for n in graph["nodes"])
    assert any(e["refs"][0].get("identityIssues") for e in graph["edges"])


def test_sessions_require_a_host_and_boot_boundary():
    rows = [{"id": i, "computer": "ws01", "targetLogonId": "0x123", "bootId": boot} for i, boot in enumerate(["boot-a", "boot-b", ""])]
    assert len(instances(rows, "logon-session")) == 2
    assert len(instances(rows, "logon-observation")) == 1
    rows[1]["bootId"] = "boot-a"
    rows[1]["targetLogonId"] = "291"
    assert len(instances(rows, "logon-session")) == 1


def test_local_authorities_and_well_known_sids_are_host_scoped():
    rows = [{"id": i, "computer": host, "targetUser": r"NT AUTHORITY\SYSTEM", "targetSid": "S-1-5-18"} for i, host in enumerate(["ws01", "ws02"])]
    assert len(instances(rows, "account")) == 2
    assert len(instances(rows, "sid")) == 2


def test_snapshot_pid_normalization_and_lifetime_are_checked():
    process = {
        "id": 1,
        "recordKind": "observation",
        "artifactType": "process",
        "computer": "ws01",
        "processId": "0x2a",
        "processStart": START,
        "packageId": "p",
        "observedAt": AT,
    }
    connection = {**process, "id": 2, "artifactType": "connection", "processId": 42, "processStart": None}
    prepared = prepare([connection], process_context=[process])
    assert prepared[0]["processStart"] == START
    graph = build([connection], [], process_context=[process])
    assert next(e for e in graph["edges"] if e["relation"] == "observed process")["assertion"] == "correlated"
    process["processEnd"] = "2026-09-01T09:00:00Z"
    assert prepare([connection], process_context=[process])[0]["processStart"] is None


def test_reimported_content_is_one_supporting_observation():
    base = {"computer": "ws01", "image": r"C:\payload.exe", "hashes": "SHA256=" + "a" * 64, "sourceSha256": "b" * 64, "sourceIndex": 1}
    graph = build([{**base, "id": 1, "sourceFile": "original.csv"}, {**base, "id": 2, "sourceFile": "renamed.csv"}], [])
    edge = next(e for e in graph["edges"] if e["relation"] == "reported digest")
    assert edge["count"] == 1 and edge["assertion"] == "observed"


def test_ambiguous_file_digest_is_a_correlation():
    graph = build([{"id": 1, "computer": "ws01", "path": r"C:\a.exe", "targetFilename": r"C:\b.exe", "hashes": "SHA256=" + "a" * 64}], [])
    assert next(e for e in graph["edges"] if e["relation"] == "reported digest")["assertion"] == "correlated"
