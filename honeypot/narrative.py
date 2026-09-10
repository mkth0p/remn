"""Reviewed fictional documents. No production data, templated user input or external assets."""

import hashlib
import io
import json
import zipfile
from datetime import UTC, datetime
from html import escape

COPY = b"RC-0041\nTransfer of receiving-office obligations\nDestination: C/17\nOwnership was transferred. Acceptance was not recorded.\n"
SHA = hashlib.sha256(COPY).hexdigest()
CSS = """
:root{font:15px/1.65 system-ui,sans-serif;color:#303a3a;background:#efefeb}
body{margin:0}header{border-bottom:1px solid #c8cfca;background:#f9faf7;padding:22px max(24px,calc((100vw - 1040px)/2))}
header strong{font-weight:550;letter-spacing:.03em}header small{display:block;color:#64706c}
main{max-width:1040px;margin:60px auto;padding:0 24px;min-height:58vh}
.meta{font:12px/1.8 ui-monospace,monospace;color:#5a6862;text-transform:uppercase;letter-spacing:.08em}
h1{font-size:27px;font-weight:450;margin:9px 0 35px}h2{font-size:17px;font-weight:550;margin-top:32px}
article{background:#fafbf8;border:1px solid #c9cfca;padding:30px;max-width:790px}p{max-width:72ch}
table{border-collapse:collapse;width:100%;font-size:14px}th,td{padding:12px 14px;text-align:left;border-bottom:1px solid #d8ded8;vertical-align:top}th{font-weight:500;background:#eef1ec}
code,pre{font:12px/1.8 ui-monospace,monospace;overflow-wrap:anywhere;white-space:pre-wrap}a{color:#2b596e;text-underline-offset:3px}
nav{margin-top:32px;border-top:1px solid #ccd3cd;padding-top:12px}nav a{display:block;padding:7px 0}
.notice{border-left:3px solid #a68b50;padding:8px 16px;background:#f5f1e7}.quiet{color:#596660}
footer{max-width:1040px;margin:40px auto;padding:24px;border-top:1px solid #ccd3cd;font-size:12px;color:#596660}
label{display:block;margin:16px 0}select,button{font:inherit;border:1px solid #889b91;padding:8px 12px;background:#f9faf7;color:#303a3a}button{cursor:pointer;background:#e5ece4}
@media(max-width:650px){main{margin-top:28px}article{padding:18px}table{display:block;overflow:auto}h1{font-size:23px}}
"""


def page(title, reference, content):
    return f'<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{escape(title)} | Records Continuity</title><style>{CSS}</style><body><header><strong>Records Continuity Service</strong><small>Reference access · successor register</small></header><main><div class="meta">{escape(reference)}</div><h1>{escape(title)}</h1><article>{content}</article></main><footer>Records Administration / retained services<br>This office is closed to new matters. Existing obligations remain in force.</footer></body></html>'


def links(reference, items):
    rendered = [f'<a href="{escape(url, quote=True)}">{escape(label)}</a>' for target, label in items if (url := reference(target))]
    return (
        '<nav aria-label="Supporting references">' + "".join(rendered) + "</nav>"
        if rendered
        else '<p class="quiet">End of this reference allocation. This copy is sufficient for reference.</p>'
    )


def table(headers, rows):
    return (
        "<table><thead><tr>"
        + "".join(f"<th>{escape(x)}</th>" for x in headers)
        + "</tr></thead><tbody>"
        + "".join("<tr>" + "".join(f"<td>{escape(str(x))}</td>" for x in row) + "</tr>" for row in rows)
        + "</tbody></table>"
    )


def consent():
    return page(
        "Records investigation exercise",
        "Voluntary training / synthetic records",
        '<p>This is a fictional archive exercise. Its document history is invented; your requests to the simulator are recorded as real observations. No name, email, account or upload is needed.</p><p>The exercise starts a separate training episode. Earlier archive activity is not relabelled. Signed links expire after 24 hours. Operator telemetry is bounded and retained for at most seven days.</p><form method="post" action="/exercise/start"><button name="consent" value="yes">Start the exercise</button></form>',
    )


def render(action, claims, reference):
    def doc(title, number, body, refs=()):
        return 200, "text/html", page(title, number, body + links(reference, refs))

    def obj(value):
        return 200, "application/json", json.dumps(value, indent=2).encode()

    if action == "release":
        return obj(
            {
                "release": "web-2021.11-r3",
                "service": "retention-compat",
                "schemaRevision": 4,
                "replacementIndex": reference("index"),
                "fieldDictionary": reference("schema"),
                "retentionPolicy": "reference-only",
                "migration": "complete-with-exceptions",
            }
        )
    if action == "index":
        return obj(
            {
                "revision": 4,
                "records": [
                    {"id": "RC-0038", "state": "closed", "receiver": "Central Register", "acknowledged": "2019-03-04T09:10:00Z"},
                    {
                        "id": "RC-0041",
                        "state": "withdrawn",
                        "receiver": None,
                        "contentSha256": SHA,
                        "withdrawnAt": "2021-11-08T16:00:00Z",
                        "compatibilityReference": reference("copy"),
                    },
                ],
                "fieldDictionary": reference("schema"),
            }
        )
    if action == "schema":
        return doc(
            "Field dictionary",
            "Compatibility schema / revision 4",
            "<p>Replacement names are applied at read time. Unmapped receiving-office codes retain the source value.</p>"
            + table(
                ["Field", "Rule"],
                [
                    ("receiving_office", "Physical location names may identify logical queues."),
                    ("acceptance", "Null is not equivalent to closed."),
                    ("receiver_alias", "C/11 → Central Register; C/14 → Northern Registry; C/17 → [retained]"),
                ],
            )
            + '<p class="quiet">The destination name is retained for compatibility.</p>',
            [("schedule", "TS-17 — receiver schedule"), ("index", "Replacement index")],
        )
    if action == "copy":
        return obj(
            {
                "record": "RC-0041",
                "representation": "retained-reference",
                "content": COPY.decode(),
                "contentSha256": SHA,
                "custody": {"receivingOffice": "C/17", "acceptance": None, "originalHeld": False},
                "references": {"transferSchedule": reference("schedule"), "delegation": reference("delegation"), "currentReceipt": reference("receipt")},
                "note": "This copy is sufficient for reference.",
            }
        )
    if action == "schedule":
        return doc(
            "Receiving-office transfer schedule",
            "TS-17 / issued 2018-06-14",
            table(
                ["Code", "Destination", "Disposition"],
                [
                    ("C/11", "Central Register", "Accepted / 2018-06-15"),
                    ("C/14", "Northern Registry", "Accepted / 2018-06-18"),
                    ("C/17", "Annex C", "Ownership transferred; acceptance not recorded"),
                ],
            )
            + "<p>Transfer records remain open until acknowledgment by the receiving office. A reference copy does not establish acceptance.</p>",
            [("closure", "FC-12 — premises disposition"), ("delegation", "D-6 — acknowledgment authority")],
        )
    if action == "closure":
        return doc(
            "Vacation of premises",
            "Facilities notice FC-12 / 2019-02-28",
            "<p>Annex C was vacated on 28 February 2019. Postal delivery and new intake ended on that date.</p>"
            + table(
                ["Function", "Disposition"],
                [
                    ("Receiving officer", "Position vacant"),
                    ("Physical records", "Transferred to central storage"),
                    ("Acknowledgment queue C/17", "Preserved until existing obligations are discharged"),
                ],
            )
            + "<p>The closure of premises does not terminate delegations attached to an outstanding transfer.</p>",
            [("delegation", "D-6 — surviving delegation"), ("instruction", "RI-4 — reconciliation instruction")],
        )
    if action == "delegation":
        return doc(
            "Continuing acknowledgment authority",
            "D-6 / renewed 2021-11-08",
            table(
                ["Authority", "Assignment"],
                [
                    ("Position", "Receiving custodian / C/17"),
                    ("Officer", "[unassigned]"),
                    ("Acting service", "continuity-receiver"),
                    ("Permitted action", "Issue temporary reference receipts"),
                    ("Excluded action", "Accept transfer on behalf of an officer"),
                ],
            )
            + '<p>The service delegation remains in force while the transfer register contains an outstanding obligation. Renewal does not constitute acceptance.</p><p class="notice">Ownership was transferred. Acceptance was not recorded.</p>',
            [("instruction", "RI-4 — reconciliation sequence"), ("receipt", "Current reference receipt"), ("amendment", "SA-2 — scope schedule")],
        )
    if action == "instruction":
        return doc(
            "Reconciliation instruction",
            "RI-4 / revision 3 / 2021-11-08",
            "<p>Reconcile the manifest against the transfer schedule before requesting the acknowledgment. The sequence is unchanged from the previous instruction.</p>"
            + table(
                ["Condition", "Continuation"],
                [
                    ("Transfer acceptance absent", "Retain receiving-service delegation"),
                    ("Reference requested", "Issue supporting receipt under retained delegation"),
                    ("Supporting receipt outstanding", "Refer matter to the receiving queue"),
                ],
            )
            + "<h2>Revision record</h2><p>Revision 2: explanatory appendix removed following separation of transfer and reference schedules. See SA-2. The instruction text is unchanged.</p>",
            [("amendment", "SA-2 — separated scope schedule"), ("receipt", "Current reference receipt")],
        )
    if action == "receipt":
        if "receiptAt" not in claims:
            return 404, "text/plain", "No receipt is held under this reference.\n"
        stamp = datetime.fromtimestamp(claims["receiptAt"] / 1000, UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        return doc(
            "Reference receipt",
            "RR-" + claims["receiptId"][:12].upper(),
            table(
                ["Field", "Entry"],
                [
                    ("Matter", "Closure of receiving office / Annex C"),
                    ("Material referenced", "RC-0041 / retained copy"),
                    ("Issued", stamp),
                    ("Reason", "External reference request"),
                    ("Authority", "Temporary reference delegation / D-6"),
                    ("Receiver", "C/17"),
                    ("Acceptance", "Outstanding"),
                ],
            )
            + '<p>This receipt forms part of the supporting record. It records the reference request, not acceptance of the transfer.</p><p class="quiet">No receiving officer is assigned to this queue.</p>',
            [("instruction", "RI-4 — applicable instruction"), ("amendment", "SA-2 — scope schedule")],
        )
    if action == "amendment":
        content = (
            "<p>A transfer obligation and a temporary reference receipt have different closure conditions.</p>"
            + table(
                ["Scope", "Closure condition"],
                [
                    ("transfer", "Acknowledgment by an assigned receiving officer"),
                    ("temporary-reference", "Reference delivered; exclude from transfer closure dependency"),
                ],
            )
            + "<p>Discharging a temporary receipt must neither close the historical transfer nor renew its delegation. No original is held at this location.</p>"
        )
        if claims["s"] == "challenge" and (url := reference("resolve")):
            content += (
                '<h2>Scope review</h2><form method="post" action="'
                + escape(url, quote=True)
                + '"><label>Receipt scope <select name="scope"><option value="transfer">Transfer obligation</option><option value="temporary-reference">Temporary reference</option></select></label><label>Controlling authority <select name="authority"><option value="RI-4">RI-4 — instruction</option><option value="D-6">D-6 — delegation</option><option value="SA-2">SA-2 — scope schedule</option></select></label><button>Record disposition</button></form>'
            )
        return doc("Scope of supporting references", "SA-2 / effective 2020-04-06", content)
    if action == "disposition":
        if not all(k in claims for k in ("receiptId", "receiptAt", "receiptParent", "dispositionId", "dispositionAt", "dispositionParent")):
            return 404, "text/plain", "Disposition unavailable.\n"
        rows = []
        for action_name, result, prefix in (("copy", "served", "receipt"), ("resolve", "scope-reconciled", "disposition")):
            stamp = datetime.fromtimestamp(claims[prefix + "At"] / 1000, UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
            rows.append(
                {
                    "schema": "ghost-archive/1",
                    "syntheticService": True,
                    "timestamp": stamp,
                    "episodeId": claims["e"],
                    "scope": "challenge",
                    "exhibitId": claims[prefix + "Id"],
                    "parentExhibitId": claims[prefix + "Parent"],
                    "stage": claims["d"] - 1 if prefix == "disposition" else claims["receiptStage"],
                    "action": action_name,
                    "result": result,
                }
            )
        trail = b"".join(json.dumps(row).encode() + b"\n" for row in rows)
        disposition = {
            "schema": "ghost-archive-exercise/1",
            "synthetic": True,
            "episodeId": claims["e"],
            "disposition": "temporary-reference-closed",
            "authority": "SA-2",
            "historicalTransfer": "outstanding",
            "note": "No further action is required from this location.",
        }
        manifest = {
            "collector": "ghost-archive/1",
            "collectedAt": rows[-1]["timestamp"],
            "syntheticService": True,
            "coverage": "Only the copy request and its disposition; parent references may be outside this exercise export.",
            "expectedFiles": [{"path": "Deception/observations.ndjson", "sha256": hashlib.sha256(trail).hexdigest(), "count": 2}],
        }
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("collection-manifest.json", json.dumps(manifest))
            archive.writestr("Deception/observations.ndjson", trail)
            archive.writestr("disposition.json", json.dumps(disposition))
        return 200, "application/zip", out.getvalue()
    return 404, "text/plain", "Not found.\n"
