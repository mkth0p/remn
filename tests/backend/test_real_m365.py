"""Microsoft 365 and Entra ID records written by the service, read as an uploaded file is read.

The committed file is described in tests/fixtures/real/m365/README.md. The heavy tests download
Splunk's attack_data recordings (Apache 2.0), which name accounts of research tenants: no name
is written here. Each heavy test reads the file a second time, independently of REMN, with
Python's json module, and compares what it finds there with what REMN read: how many records
there are of the file's kind, how many repeat an id, how many are of another kind or are not
JSON at all, and each record's time, address and outcome.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime

import pytest
from real_samples import FIXTURES, download

from services.ingest.pipeline import EvtxSource

ATTACK_DATA = "https://media.githubusercontent.com/media/splunk/attack_data/7a5e9d5bedf2c18450599777e870f7bfa42a4025/datasets"
SIGN_IN_CATEGORIES = ("SignInLogs", "NonInteractiveUserSignInLogs", "ServicePrincipalSignInLogs", "ManagedIdentitySignInLogs")


def ms(text: str) -> int:
    value = datetime.fromisoformat(text.replace("Z", "+00:00"))
    # the Unified Audit Log writes CreationTime in UTC without saying so
    return int((value if value.tzinfo else value.replace(tzinfo=UTC)).timestamp() * 1000)


def read(tmp_path, path):
    source = EvtxSource(path.name, str(path), None, str(tmp_path))
    rows = list(source)
    return rows, source


def stat(source, name: str) -> int:
    return int(getattr(source.stats, name, 0) or 0)


def test_unified_audit_log_records_give_their_time_operation_and_account(tmp_path):
    rows, source = read(tmp_path, FIXTURES / "m365" / "microsoft_audit_log.jsonl")
    assert source.format == "m365-ual-json"
    assert (len(rows), stat(source, "errors"), stat(source, "duplicates")) == (3, 0, 0)
    # plaso: the first record is Install-DefaultSharingPolicy at 2022-05-07T12:55:53 UTC, run by
    # the Exchange service host, in the Exchange workload
    assert [(r["tsIso"], r["operation"]) for r in rows] == [
        ("2022-05-07T12:55:53.000Z", "Install-DefaultSharingPolicy"),
        ("2022-05-07T12:56:18.000Z", "Set-MailboxPlan"),
        ("2022-05-07T12:56:24.000Z", "Set-AdminAuditLogConfig"),
    ]
    assert {r["user"] for r in rows} == {"NT AUTHORITY\\SYSTEM (Microsoft.Exchange.Servicehost)"}
    assert {r["channel"] for r in rows} == {"Exchange"}
    assert rows[0]["recordKey"] == "ual:c9d2d808-0efe-48cb-eaec-08da3028eb80"
    assert rows[0]["objectName"] == "sst5f.onmicrosoft.com\\952cae95-808b-4aa7-b783-a9151be9a05a"


def lines(path):
    """Each line's JSON object, or None for a line that is not JSON."""
    for line in path.read_bytes().split(b"\n"):
        if line.strip():
            try:
                yield json.loads(line)
            except ValueError:
                yield None


def ual_expected(path):
    records = [r for r in lines(path) if r is not None and "Operation" in r and "CreationTime" in r]
    first = {}
    for r in records:
        first.setdefault(r["Id"], r)
    return {
        "rows": len(first),
        "duplicates": len(records) - len(first),
        "errors": sum(1 for r in lines(path) if r is None or r not in records),
        "records": sorted((f"ual:{i}", ms(r["CreationTime"]), r["Operation"]) for i, r in first.items()),
    }


@pytest.mark.heavy
@pytest.mark.parametrize(
    ("path", "sha256", "counts"),
    [
        # every line one audit record, each id three or four times
        (
            "attack_techniques/T1110/o365_brute_force_login/o365_brute_force_login.json",
            "922f890f21279e6dcec8ec0f765e3451cb0715ba0640f014267c5d582998a16b",
            (788, 1753, 0),
        ),
        # one record cut short in the middle of a value
        (
            "attack_techniques/T1567/o365_sus_file_activity/o365_sus_file_activity.log",
            "ef3b8cc321fed3031bca6d16d4c35e7de3112ab40ea08f2fca02879a065d8774",
            (181, 64, 1),
        ),
        # two records whose lines were garbled
        ("attack_techniques/T1556/o365_disable_mfa/o365_disable_mfa.json", "c1745595692d3a0d3eecff501f995a26e6c4f45b506897eeca204b51ea800e2d", (787, 1752, 2)),
    ],
)
def test_a_unified_audit_log_recording_gives_each_record_once_and_counts_what_it_could_not_read(tmp_path, path, sha256, counts):
    sample = download(f"{ATTACK_DATA}/{path}", sha256)
    rows, source = read(tmp_path, sample)
    expected = ual_expected(sample)
    assert (expected["rows"], expected["duplicates"], expected["errors"]) == counts
    assert source.format == "m365-ual-json"
    assert (len(rows), stat(source, "duplicates"), stat(source, "errors")) == counts
    assert sorted((r["recordKey"], r["ts"], r["operation"]) for r in rows) == expected["records"]


def sign_in(record):
    """A sign-in's id, time, address and error code, from an Azure Monitor export or from Graph."""
    if "category" in record:
        if record["category"] not in SIGN_IN_CATEGORIES:
            return None
        record = {**record.get("properties", {}), "ipAddress": record.get("properties", {}).get("ipAddress") or record.get("callerIpAddress")}
    elif "createdDateTime" not in record:
        return None
    return (f"entra:{record['id']}", ms(record["createdDateTime"]), record.get("ipAddress"), str(record["status"]["errorCode"]))


@pytest.mark.heavy
@pytest.mark.parametrize(
    ("path", "sha256", "counts"),
    [
        # Azure Monitor's export of the sign-in logs, as Splunk's add-on collects it
        (
            "attack_techniques/T1110.003/password_spraying_azuread/azuread_signin.log",
            "14b4ded54e61209e62cd8d883032a8bb3f33753cec0423510a725142ae36c0f6",
            (29, 2, 0),
        ),
        # the same export holding sign-ins of three kinds, and also directory audits and risky users
        (
            "attack_techniques/T1098.003/azure_ad_pim_role_activated/azure-audit.log",
            "3f3d6e74d3fe107946e40000dd67acced5c34dc049d1b473865ccdd837fd9a3f",
            (104, 4, 32),
        ),
        # Graph sign-ins, and the rows of a Microsoft 365 usage report in the same file
        ("m365_copilot/m365_copilot_access.log", "8e4810642666d461b9233e58035946a915a83e5b1f205a8824c35d608a2be823", (67, 1, 120)),
    ],
)
def test_an_entra_sign_in_recording_gives_each_sign_in_once_and_says_what_it_did_not_read(tmp_path, path, sha256, counts):
    sample = download(f"{ATTACK_DATA}/{path}", sha256)
    rows, source = read(tmp_path, sample)
    records = [r for r in lines(sample) if r is not None]
    signins = [s for s in map(sign_in, records) if s]
    first = {s[0]: s for s in reversed(signins)}
    assert (len(first), len(signins) - len(first), len(records) - len(signins)) == counts
    assert source.format == "entra-signin-json"
    assert (len(rows), stat(source, "duplicates"), stat(source, "not_read")) == counts
    # a record of another kind is an error of the file, and said to be one not read
    assert stat(source, "errors") == counts[2]
    assert sorted((r["recordKey"], r["ts"], r["ipAddress"], r["status"]) for r in rows) == sorted(first.values())
    assert Counter(r["operation"] for r in rows) == Counter({"SignIn": counts[0]})
