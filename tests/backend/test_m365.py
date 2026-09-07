"""Microsoft 365 Unified Audit Log / Entra sign-in exports -> event rows -> BEC rules."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import make_m365
import pytest
import yaml
from django.test import Client

from services.ingest.pipeline import EvtxSource, detect_evtx_format
from services.parsers import m365
from services.store import rules as R
from services.store.casestore import StoreRegistry
from services.store.writers import EventWriter

HDR = {"HTTP_X_FORENSIC_CLIENT": "1"}
RULES = Path(__file__).resolve().parents[2] / "rules" / "m365" / "bec.yaml"


@pytest.fixture(scope="module")
def exports(tmp_path_factory):
    return make_m365.write_all(str(tmp_path_factory.mktemp("m365")))


@pytest.fixture
def store(tmp_path):
    reg = StoreRegistry()
    reg.configure(tmp_path / "cases")
    st = reg.get(str(uuid.uuid4()))
    yield st
    reg.close_all()


def _rows(path: str) -> list[dict]:
    src = EvtxSource(Path(path).name, path, None, str(Path(path).parent))
    return list(src), src


def test_format_detection(exports):
    for key, fmt in (("ual_csv", "m365-ual-csv"), ("ual_json", "m365-ual-json"), ("entra_json", "entra-signin-json"), ("entra_csv", "entra-signin-csv")):
        p = Path(exports[key])
        assert detect_evtx_format(p.name, p.read_bytes()[:512]) == fmt, key
    assert detect_evtx_format("System.evtx", b"ElfFile\x00" + b"\x00" * 100) == "evtx"
    assert m365.detect_format("random.csv", b"a,b,c\n1,2,3\n") is None


def test_ual_csv_rows(exports):
    rows, src = _rows(exports["ual_csv"])
    assert src.format == "m365-ual-csv" and src.stats.errors == 0
    assert len(rows) == len(make_m365.ual_records())
    rule = next(r for r in rows if r["operation"] == "New-InboxRule")
    assert rule["provider"] == m365.UAL_PROVIDER and rule["channel"] == "Exchange" and rule["category"] == "M365 Exchange"
    assert rule["subjectUser"] == make_m365.VICTIM and rule["ipAddress"] == make_m365.RU_IP and rule["objectName"] == "."
    assert rule["data"]["ForwardTo"] == "attacker@proton-mail.example" and rule["data"]["DeleteMessage"] == "True"
    assert "attacker@proton-mail.example" in rule["summary"] and rule["ts"] and rule["tsIso"].endswith("Z")
    assert rule["eventId"] is None and rule["recordId"] == 1
    role = next(r for r in rows if r["operation"] == "Add member to role.")
    assert role["data"]["Role.DisplayName"] == "Global Administrator" and role["targetUser"] == make_m365.ADMIN
    mia = [r for r in rows if r["operation"] == "MailItemsAccessed"]
    assert len(mia) == 30 and mia[0]["data"]["MailAccessType"] == "Sync" and mia[0]["data"]["FolderItemCount"] == 8 and mia[0]["targetUser"] == make_m365.VICTIM
    consent = next(r for r in rows if r["operation"] == "Consent to application.")
    assert "Mail.Read" in consent["data"]["ConsentAction.Permissions"] and consent["category"] == "M365 Entra"
    login = next(r for r in rows if r["operation"] == "UserLoggedIn")
    assert login["category"] == "M365 Entra" and login["data"]["UserAgent"].startswith("Mozilla")
    assert "raw" in rule and json.loads(rule["raw"])["Operation"] == "New-InboxRule"


def test_ual_json_and_entra_rows(exports):
    rows, src = _rows(exports["ual_json"])
    assert src.format == "m365-ual-json" and len(rows) == len(make_m365.ual_records())
    rows, src = _rows(exports["entra_json"])
    assert src.format == "entra-signin-json" and len(rows) == len(make_m365.entra_signins())
    ok = [r for r in rows if r["status"] == "0"]
    bad = [r for r in rows if r["status"] == "50126"]
    assert ok and bad and all(r["category"] == "Entra sign-in" and r["provider"] == m365.ENTRA_PROVIDER for r in rows)
    risky = next(r for r in rows if r["data"].get("riskState") == "atRisk")
    assert risky["data"]["country"] == "NL" and risky["data"]["riskLevelDuringSignIn"] == "high" and risky["ipAddress"] == make_m365.NL_IP
    assert "risk=high" in risky["summary"]
    legacy = next(r for r in rows if r["ipAddress"] == make_m365.RU_IP and r["status"] == "0")
    assert legacy["data"]["clientAppUsed"] == "Other clients" and legacy["data"]["country"] == "RU"
    # portal CSV carries the same facts
    rows2, src2 = _rows(exports["entra_csv"])
    assert src2.format == "entra-signin-csv" and len(rows2) == len(rows)
    r2 = next(r for r in rows2 if r["ipAddress"] == make_m365.NL_IP)
    assert r2["data"]["country"] == "NL" and r2["data"]["riskState"] == "atRisk" and r2["status"] == "0" and r2["data"]["appDisplayName"] == "Azure Portal"
    f2 = next(r for r in rows2 if r["status"] != "0")
    assert f2["status"] == "50126" and f2["statusText"]


def test_zip_of_exports_is_walked(exports, tmp_path):
    import zipfile

    z = tmp_path / "m365-acquisition.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.write(exports["ual_csv"], "ual/ual_export.csv")
        zf.write(exports["entra_json"], "entra/signins.json")
        zf.writestr("notes/readme.txt", "not a log")
    src = EvtxSource(z.name, str(z), None, str(tmp_path))
    rows = list(src)
    assert src.format == "zip" and len(rows) == len(make_m365.ual_records()) + len(make_m365.entra_signins())
    assert {f["format"] for f in src.files} == {"m365-ual-csv", "entra-signin-json"}
    assert {r["sourceFile"] for r in rows} == {"ual/ual_export.csv", "entra/signins.json"}


def test_bec_rules_fire_on_the_scenario(exports, store):
    w = EventWriter(store, 1)
    for key in ("ual_csv", "entra_json"):
        for row in _rows(exports[key])[0]:
            w.add(row)
    w.flush()
    rules = [d for d in yaml.safe_load_all(RULES.read_text(encoding="utf-8")) if isinstance(d, dict)]
    settings = {"internal_domains": ["contoso.com"], "expected_countries": ["FR"]}
    fired: dict[str, list] = {}
    errors = []
    for rule in rules:
        try:
            hits = R.run_rule(store, rule, settings)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{rule['id']}: {exc}")
            continue
        if hits:
            fired[rule["id"]] = hits
    assert not errors, errors
    expected = {
        "m365-inbox-rule-forwarding",
        "m365-inbox-rule-hiding",
        "m365-inbox-rule-any",
        "m365-mailbox-forwarding",
        "m365-mailitemsaccessed-burst",
        "m365-app-consent",
        "m365-privileged-role-assigned",
        "m365-role-assigned-any",
        "m365-signin-risky",
        "m365-signin-legacy-auth",
        "m365-signin-unexpected-country",
        "m365-signin-two-countries-24h",
        "m365-signin-password-spray",
        "m365-signin-bruteforce-account",
    }
    missing = expected - set(fired)
    assert not missing, f"rules that should fire on the scenario: {missing}; fired={sorted(fired)}"
    # sanity: the quiet rules stay quiet
    assert "m365-audit-disabled" not in fired and "m365-transport-rule-exfil" not in fired
    # entities carry the pivot keys
    fwd = fired["m365-inbox-rule-forwarding"][0]
    assert fwd["entities"]["subjectUser"] == make_m365.VICTIM and fwd["entities"]["ipAddress"] == make_m365.RU_IP
    spray = fired["m365-signin-password-spray"][0]
    assert spray["entities"]["ipAddress"] == make_m365.RU_IP and spray["count"] >= 8
    brute = fired["m365-signin-bruteforce-account"][0]
    assert brute["severity"] == "critical" and "Successful sign-in" in brute["title"]


def test_ingest_endpoint_streams_ual(exports):
    c = Client()
    with open(exports["ual_csv"], "rb") as fh:
        resp = c.post("/api/ingest/evtx", {"file": fh, "raw": "1"}, **HDR)
    assert resp.status_code == 200
    lines = [json.loads(l) for l in resp.getvalue().decode("utf-8").splitlines() if l.strip()]
    assert lines[0]["type"] == "meta" and lines[0]["format"] == "m365-ual-csv"
    events = [l for l in lines if l["type"] == "event"]
    assert len(events) == len(make_m365.ual_records()) and events[0]["provider"] == m365.UAL_PROVIDER
    assert lines[-1]["type"] == "done" and lines[-1]["stats"]["errors"] == 0
