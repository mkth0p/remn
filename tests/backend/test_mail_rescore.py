from __future__ import annotations

import copy
import json
import uuid
from pathlib import Path

import pytest
import yaml
from django.test import Client

from mail_calibration import examples, message, SETTINGS
from services.analysis import rescore
from services.analysis.mail_calibration import calibrate_mail
from services.analysis.attachments.analyzer import _score, rescore_attachment
from services.analysis.attachments.html import analyze_html
from services.store.casestore import StoreRegistry, _arrow_table, MAIL_COLUMNS
from services.store.writers import MailWriter
from services.store.rules import run_rule

HDR = {"HTTP_X_FORENSIC_CLIENT": "1"}


@pytest.fixture
def store(tmp_path):
    reg = StoreRegistry()
    reg.configure(tmp_path)
    st = reg.get(str(uuid.uuid4()))
    yield st
    reg.close_all()


def test_benign_capabilities_and_malicious_controls_through_rules(store):
    data = examples()
    writer = MailWriter(store, 1)
    for example in data:
        row = example["row"]
        assert row["risk"] < 60 if example["label"] == "benign" else row["risk"] >= 80
        writer.add(row)
    writer.flush()
    rules = [r for p in (Path(__file__).resolve().parents[2] / "rules/mail").glob("*.yaml") for r in yaml.safe_load_all(p.read_text(encoding="utf-8")) if isinstance(r, dict)]
    high = set()
    for rule in rules:
        for finding in run_rule(store, rule, SETTINGS):
            if finding["severity"] in ("high", "critical"):
                high.update(finding["refs"])
    assert high == {i for i, e in enumerate(data, 1) if e["label"] == "malicious"}


def test_correlated_attachment_flags_do_not_multiply_risk():
    assert _score(["html_attachment", "archive_contains_html", "archive_single_lure", "nested_html_attachment", "archive"]) < 40
    assert _score(["pdf_javascript", "pdf_auto_action", "pdf_form", "pdf_xfa"]) < 60
    assert _score(["archive_contains_executable", "archive_single_executable", "nested_executable"]) >= 90


def test_images_are_not_embedded_malware():
    import base64
    blob = base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"\x01" * 1500).decode()
    result = analyze_html(f'<html><img src="data:image/png;base64,{blob}"></html>'.encode(), "html")
    assert "html_embedded_payload" not in result["flags"]
    assert "html_smuggling" not in result["flags"]
    assert "html_embedded_document" in result["flags"]


def test_old_html_facts_can_be_rescored_and_missing_facts_are_explicit():
    old = {"name": "report.html", "risk": 100, "flags": ["html_smuggling", "html_script", "html_attachment"],
           "details": {"html": {"apis": ["Blob", "createObjectURL", "download_attr"], "decodedBlobTypes": []}}}
    r = rescore_attachment(old)
    assert r["risk"] < 60 and "html_smuggling" not in r["flags"]
    assert old["risk"] == 100 and "html_smuggling" in old["flags"]
    unknown = rescore_attachment({**old, "details": {}})
    assert unknown["risk"] == 100 and unknown["rescoreLimited"]


def test_history_reduces_anomalies_but_never_hides_compromised_sender_payload():
    r = message("Invoice", "Here is the invoice", reply_to="Accounts <accounts@example.org>")
    r.update(senderSolicited=True, senderPriorCount=12, senderDaysKnown=90)
    result = calibrate_mail(r, SETTINGS)
    assert "sender_expected" in result["flags"] and result["risk"] < 60
    dangerous = copy.deepcopy(examples()[-1]["row"])
    dangerous.update(senderSolicited=True, senderPriorCount=12, senderDaysKnown=90)
    assert calibrate_mail(dangerous, SETTINGS)["risk"] >= 80
    r["senderAuthRegression"] = True
    r["auth"] = {"spf": "fail", "dmarc": "fail"}
    r["flags"] += ["spf_fail", "dmarc_fail"]
    result = calibrate_mail(r, SETTINGS)
    assert "sender_expected" not in result["flags"] and "mail_corroborated" in result["flags"]


def test_unaligned_spf_never_grants_internal_sender_trust():
    r = message("Invoice")
    r.update(fromAddr="finance@interne.fr", fromDomain="interne.fr", fromRegistrable="interne.fr", auth={"spf": "pass", "spfDomain": "unrelated.example"}, flags=["spf_domain_unaligned", "returnpath_mismatch"])
    assert calibrate_mail(r, SETTINGS)["risk"] > 12


def test_rescore_store_is_idempotent_preserves_ids_bodies_and_updates_children(store):
    row = examples()[2]["row"]
    row["risk"] = 90
    row["flags"].append("att_html_smuggling")
    row["attachments"][0]["flags"].append("html_smuggling")
    row["attachments"][0]["risk"] = 100
    w = MailWriter(store, 42)
    w.add(row)
    w.flush()
    before = store._con.execute('SELECT id, "evidenceId" FROM mails').fetchall()
    bodies = store._con.execute('SELECT * FROM mail_bodies').fetchall()
    summary = rescore.store(store, SETTINGS)
    assert summary["highBefore"] == 1 and summary["highAfter"] == 0
    assert store._con.execute('SELECT id, "evidenceId" FROM mails').fetchall() == before
    assert store._con.execute('SELECT * FROM mail_bodies').fetchall() == bodies
    assert store._con.execute('SELECT risk FROM attachments').fetchone()[0] < 60
    snapshot = store._con.execute('SELECT risk, flags, attachments, assessment FROM mails').fetchall()
    assert rescore.store(store, SETTINGS)["changed"] == 0
    assert store._con.execute('SELECT risk, flags, attachments, assessment FROM mails').fetchall() == snapshot


def test_rescore_cancel_rolls_back_scores_and_child_updates(store):
    w = MailWriter(store, 1)
    r = examples()[2]["row"]
    r["risk"] = 90
    w.add(r)
    w.flush()
    class Cancel:
        cancelled = False
        def check(self):
            if self.cancelled:
                raise RuntimeError("cancelled")
        def update(self, **kw):
            self.cancelled = True
    with pytest.raises(RuntimeError, match="cancelled"):
        rescore.store(store, SETTINGS, Cancel())
    assert store._con.execute('SELECT risk FROM mails').fetchone()[0] == 90


def test_rescore_endpoint_and_input_validation():
    row = examples()[0]["row"] | {"id": 8}
    c = Client()
    response = c.post('/api/enrich/mails/rescore', json.dumps({"mails": [row], "settings": SETTINGS}), content_type='application/json', **HDR)
    assert response.status_code == 200
    assert response.json()["rows"][0]["id"] == 8
    for body in ([], {"mails": [{}]}, {"mails": [row] * 201}, {"settings": [], "mails": []}):
        assert c.post('/api/enrich/mails/rescore', json.dumps(body), content_type='application/json', **HDR).status_code == 400


@pytest.mark.parametrize("window", [None, "10m"])
def test_grouped_escalation_keeps_critical_evidence_beyond_ref_cap(store, window):
    w = MailWriter(store, 1)
    for i in range(502):
        w.add({"date": i, "fromAddr": "sender@example.org", "subject": "file", "flags": ["att_macro_vba_stomping"] if i == 501 else ["att_office_macro"]})
    w.flush()
    rule = {"id": "macro-review", "title": "Macro review", "source": "mails", "severity": "medium", "confidence": "low", "where": {}, "then_flags": [{"att_macro_vba_stomping": "critical"}]}
    if window:
        rule.update(group_by=["fromAddr"], threshold=">= 2", window=window)
    found = run_rule(store, rule, SETTINGS)
    assert len(found) == 1 and found[0]["severity"] == "critical" and found[0]["confidence"] == "low"
    assert 502 in found[0]["refs"] and len(found[0]["refs"]) == 500


def test_mail_writer_preserves_false_and_unknown_history(store):
    values = [False, True, None, "false", "False", "0", "true", "1", "unknown"]
    expected = [False, True, None, False, False, False, True, True, None]
    w = MailWriter(store, 1)
    for value in values:
        w.add({"senderSolicited": value, "senderAuthRegression": value})
    w.flush()
    assert store._con.execute('SELECT "senderSolicited", "senderAuthRegression" FROM mails ORDER BY id').fetchall() == [(v, v) for v in expected]
    assert _arrow_table(MAIL_COLUMNS, [{"senderAuthRegression": v} for v in values]).column("senderAuthRegression").to_pylist() == expected


def test_inbox_only_history_remains_unknown():
    from services.analysis.baseline import enrich
    rows = [{"id": 1, "date": 123, "fromAddr": "partner@example.org"}]
    assert enrich(rows, SETTINGS)[1]["senderSolicited"] is None


def test_calibration_report_covers_ingestion_history_and_rule_packs(tmp_path):
    import importlib.util
    spec = importlib.util.spec_from_file_location("calibration_cli", Path(__file__).resolve().parents[2] / "tools/calibrate_mail.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    result = module.evaluate(examples(), SETTINGS, temp_dir=tmp_path)
    assert result["scoreHighFalsePositives"] == 0
    assert result["scoreHighMalicious"] == 3
    assert result["packs"]["core"]["highFalsePositives"] == 0
    assert result["packs"]["core"]["highMalicious"] == 3
    assert not any(pack["errors"] for pack in result["packs"].values())
    # Browser engine fixture must reflect the current parser/calibration output.
    fixture = json.loads((Path(__file__).resolve().parents[2] / "samples/synthetic/mail-calibration.json").read_text(encoding="utf-8"))
    fresh = module.prepared_examples(examples(), SETTINGS)
    for saved, current in zip(fixture["examples"], fresh, strict=True):
        for field in ("risk", "flags", "assessment"):
            assert saved["row"][field] == current["row"][field], (saved["name"], field)
