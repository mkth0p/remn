"""Validate generated evidence through REMN's real parsers and correlation engine.

Every record is parsed and every file hash checked. By default the rule/chain
evaluation retains all planted records and the first 500 background records per
source. --retain-all also evaluates rules/chains over the entire parsed pack.
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
import time
import uuid
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "backend"), str(Path(__file__).resolve().parent)]

import yaml
from make_linked_lab import digest

from services.analysis import baseline
from services.analysis.chains import build_chains
from services.analysis.mail_calibration import calibrate_mail
from services.ingest.pipeline import EvtxSource, MailSource
from services.parsers.mail.common import ParseContext
from services.store.casestore import StoreRegistry
from services.store.rules import run_rules
from services.store.writers import EventWriter, MailWriter


def check_evtx(path):
    records = chunks = 0
    with path.open("rb") as f:
        header = f.read(4096)
        assert header[:8] == b"ElfFile\0"
        assert zlib.crc32(header[:120]) == struct.unpack_from("<I", header, 124)[0]
        while block := f.read(65536):
            assert len(block) == 65536 and block[:8] == b"ElfChnk\0"
            assert zlib.crc32(block[:120] + block[128:512]) == struct.unpack_from("<I", block, 124)[0]
            end = struct.unpack_from("<I", block, 48)[0]
            assert zlib.crc32(block[512:end]) == struct.unpack_from("<I", block, 52)[0]
            pos = 512
            while pos < end:
                magic, size, rid = struct.unpack_from("<IIQ", block, pos)
                assert magic == 0x2A2A and size >= 28 and pos + size <= end
                assert struct.unpack_from("<I", block, pos + size - 4)[0] == size
                records += 1
                assert rid == records
                pos += size
            assert pos == end
            chunks += 1
        assert chunks == struct.unpack_from("<I", header, 42)[0]
    return records


def validate(pack, retain_all=False):
    manifest = json.loads((pack / "manifest.json").read_text())
    truth = [json.loads(line) for line in (pack / "ground-truth.jsonl").read_text().splitlines()]
    settings = {
        "internal_domains": manifest["settings"]["internalDomains"],
        "expected_countries": ["FR"],
        "trusted_senders": [],
        "vip_names": ["marie lefevre"],
        "internal_ips": ["10.0.0.0/8"],
        "businessHours": manifest["settings"]["businessHours"],
        "weekendDays": [0, 6],
    }
    ctx = ParseContext(internal_domains=settings["internal_domains"], analyze_attachments=True)
    rows_mail = []
    rows_event = []
    validations = []
    t0 = time.monotonic()
    for entry in manifest["files"]:
        path = pack / entry["path"]
        assert path.stat().st_size == entry["bytes"] and digest(path) == entry["sha256"], path
        if entry["kind"] == "evtx":
            assert check_evtx(path) == entry["records"]
        wanted = {r["ordinal"] for r in truth if r["file"] == entry["path"]}
        src = MailSource(path.name, str(path), None, ctx, str(pack)) if entry["kind"] == "mail" else EvtxSource(path.name, str(path), None, str(pack))
        count = 0
        found = set()
        for count, row in enumerate(src, 1):
            if count in wanted:
                found.add(count)
            if retain_all or count in wanted or count <= 500:
                row["id"] = (len(rows_mail) + 1) if entry["kind"] == "mail" else len(rows_event) + 1
                row["_file"] = path.name
                row["_ordinal"] = count
                (rows_mail if entry["kind"] == "mail" else rows_event).append(row)
            if count % (10000 if entry["kind"] == "mail" else 100000) == 0:
                print(f"Validated {path.name}: {count:,}", flush=True)
        assert count == entry["records"], (path, count, entry["records"])
        assert src.stats.errors == 0, (path, src.stats.errors)
        assert found == wanted, (path, wanted - found)
        validations.append({"file": path.name, "records": count, "parseErrors": src.stats.errors, "sha256Verified": True, "plantedLocated": len(found)})
        print(f"PASS {path.name}: {count:,} records", flush=True)

    history = baseline.enrich(rows_mail, settings)
    rows_mail = [calibrate_mail({**r, **history.get(r["id"], {})}, settings) for r in rows_mail]
    reg = StoreRegistry()
    reg.configure(ROOT / ".venv" / "linked-lab-validation-stores")
    store = reg.get(str(uuid.uuid4()))
    try:
        mw = MailWriter(store, 1)
        ew = EventWriter(store, 2)
        for row in rows_mail:
            mw.add(row)
        mw.flush()
        for row in rows_event:
            ew.add(row)
        ew.flush()
        rules = []
        for folder in (ROOT / "rules/mail", ROOT / "rules/m365", ROOT / "rules/windows"):
            for file in folder.rglob("*.yaml"):
                rules.extend(r for r in yaml.safe_load_all(file.read_text(encoding="utf-8")) if isinstance(r, dict))
        result = run_rules(store, rules, settings)
        assert not result["errors"], result["errors"]
        chains = build_chains(rows_mail, rows_event, settings=settings, findings=result["findings"])
        seeds = {r["id"]: r.get("messageId") for r in rows_mail}
        linked = {seeds.get(c["seed"]["id"]): c for c in chains["chains"]}
        checks = []
        for scenario in manifest["scenarios"]:
            if scenario["id"] in ("S05", "S07"):  # mail-only controls: no chain expected
                continue
            chain = linked.get(scenario["mailMessageId"])
            assert chain is not None, ("Missing chain", scenario["id"])
            assert chain["artifactLinks"] >= 2, (scenario["id"], chain["artifactLinks"])
            origins = {s.get("origin") for s in chain["steps"]}
            assert {"host", "m365"}.issubset(origins), (scenario["id"], origins)
            checks.append(
                {
                    "scenario": scenario["id"],
                    "identity": chain["identity"],
                    "severity": chain["severity"],
                    "score": chain["score"],
                    "artifactLinks": chain["artifactLinks"],
                    "steps": len(chain["steps"]),
                }
            )
        benign = [r for r in rows_mail if str(r.get("messageId", "")).startswith("<S05-")]
        assert len(benign) == 5
        high_refs = {rid for f in result["findings"] if f["source"] == "mails" and f["severity"] in ("high", "critical") for rid in f["refs"]}
        for row in benign:
            assert row["risk"] < 60 and row["id"] not in high_refs, (row["subject"], row["risk"])
        neg_ids = {r["id"] for r in rows_event if r.get("data", {}).get("ScenarioId") == "NEG-TENANT"}
        neg_links = [c["identity"] for c in chains["chains"] if any(s.get("id") in neg_ids for s in c["steps"] if s["source"] == "events")]
        report = {
            "pack": pack.name,
            "totalRecords": manifest["totalRecords"],
            "elapsedSeconds": round(time.monotonic() - t0, 2),
            "files": validations,
            "coreRulesEvaluated": len(rules),
            "ruleErrors": result["errors"],
            "findings": result["total"],
            "byRule": result["byRule"],
            "chains": checks,
            "benignControls": [{"messageId": r["messageId"], "risk": r["risk"]} for r in benign],
            "knownNegativeControlLimitation": {
                "sameLocalPartOtherTenantLinkedTo": neg_links,
                "expected": "No cross-tenant join. Current identity normalizer strips domain scope; this is a deliberate false-correlation control.",
            },
            "ruleAndChainScope": "all parsed rows"
            if retain_all
            else "all planted records plus first 500 background records per source; full parser/count/hash validation covers every record",
        }
        (pack / "validation-results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"chains": checks, "benignRisks": [r["risk"] for r in benign], "ruleErrors": 0}, indent=2), flush=True)
        return report
    finally:
        reg.close_all()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pack", type=Path)
    parser.add_argument("--retain-all", action="store_true")
    args = parser.parse_args()
    validate(args.pack, args.retain_all)
