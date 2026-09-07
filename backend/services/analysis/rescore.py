"""Recalibrate existing mail facts without changing record IDs or raw evidence."""

from __future__ import annotations

import json
from typing import Any

import pyarrow as pa

from services.analysis import baseline
from services.analysis.mail_calibration import VERSION, calibrate_mail
from services.store.casestore import rows_to_dicts

FIELDS = ("risk", "flags", "attachments", "maxAttachmentRisk", "assessment")


def batch(rows: list[dict[str, Any]], settings: dict[str, Any]) -> dict[str, Any]:
    changes = []
    summary = {"version": VERSION, "mails": 0, "changed": 0, "limited": 0, "highBefore": 0, "highAfter": 0}
    for row in rows:
        calibrated = calibrate_mail(row, settings)
        changes.append({"id": row["id"], **{k: calibrated[k] for k in FIELDS}})
        summary["mails"] += 1
        summary["changed"] += calibrated["risk"] != row.get("risk")
        summary["limited"] += bool(calibrated["assessment"]["limitations"])
        summary["highBefore"] += int(row.get("risk") or 0) >= 60
        summary["highAfter"] += calibrated["risk"] >= 60
    return {"rows": changes, "summary": summary}


def store(store: Any, settings: dict[str, Any], job: Any = None) -> dict[str, Any]:
    """Atomic score/attachment update; baseline is a separate non-destructive pass."""
    summary = batch([], settings)["summary"]
    with store.lock:
        baseline.enrich_store(store, settings)
        con = store._con
        total, last_id = con.execute("SELECT count(*), coalesce(max(id), 0) FROM mails").fetchone()
        cursor_id = -1
        con.execute("BEGIN TRANSACTION")
        try:
            while cursor_id < last_id:
                if job:
                    job.check()
                con.execute("SELECT * FROM mails WHERE id > ? AND id <= ? ORDER BY id LIMIT 200", [cursor_id, last_id])
                rows = rows_to_dicts(con, ("auth", "attachments", "keywordHits", "assessment"))
                if not rows:
                    break
                cursor_id = rows[-1]["id"]
                result = batch(rows, settings)
                for k in summary:
                    if k != "version":
                        summary[k] += result["summary"][k]
                updates = [{**r, "attachments": json.dumps(r["attachments"]), "assessment": json.dumps(r["assessment"])} for r in result["rows"]]
                con.register(
                    "_mail_calibration",
                    pa.Table.from_pylist(
                        updates,
                        schema=pa.schema(
                            [
                                ("id", pa.int64()),
                                ("risk", pa.int32()),
                                ("flags", pa.list_(pa.string())),
                                ("attachments", pa.string()),
                                ("maxAttachmentRisk", pa.int32()),
                                ("assessment", pa.string()),
                            ]
                        ),
                    ),
                )
                try:
                    con.execute(
                        'UPDATE mails SET risk=u.risk, flags=u.flags, attachments=u.attachments, "maxAttachmentRisk"=u."maxAttachmentRisk", assessment=u.assessment FROM _mail_calibration u WHERE mails.id=u.id'
                    )
                finally:
                    con.unregister("_mail_calibration")
                # Update the normalized attachment table as well as the mail JSON.
                for r in result["rows"]:
                    for a in r["attachments"]:
                        con.execute(
                            'UPDATE attachments SET risk=?, flags=?, details=? WHERE "mailId"=? AND name IS NOT DISTINCT FROM ? AND sha256 IS NOT DISTINCT FROM ?',
                            [a["risk"], a["flags"], json.dumps(a.get("details")), r["id"], a.get("name"), a.get("sha256")],
                        )
                if job:
                    job.update(done=summary["mails"], total=total)
            if job:
                job.check()
            con.execute("INSERT OR REPLACE INTO meta VALUES ('mail-calibration', ?)", [json.dumps(summary)])
            con.execute("COMMIT")
        except BaseException:
            con.execute("ROLLBACK")
            raise
    return summary
