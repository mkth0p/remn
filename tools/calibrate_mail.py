"""Measure mail priorities and per-rule/pack outcomes on a labelled corpus.

Usage: .venv/Scripts/python tools/calibrate_mail.py --synthetic [--output results.json]
       .venv/Scripts/python tools/calibrate_mail.py --manifest corpus.json
Manifest: {"settings": {"internal_domains": [...]}, "messages": [
  {"path": "relative/sample.eml", "label": "benign"|"malicious", "name": "optional label"}]}
Nothing is executed and no network lookups are performed. Originals are read-only.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "backend"), str(ROOT / "samples" / "synthetic")]

import yaml
from services.analysis.mail_calibration import VERSION, calibrate_mail
from services.analysis.baseline import enrich
from services.parsers.mail.common import ParseContext, parse_message_bytes
from services.store.casestore import StoreRegistry
from services.store.writers import MailWriter
from services.store.rules import run_rule


def prepared_examples(examples, settings):
    rows = [{**e["row"], "id": i} for i, e in enumerate(examples, 1)]
    history = enrich(rows, settings)
    return [{"name": e["name"], "label": e["label"], "row": calibrate_mail({**r, **history.get(r["id"], {})}, settings)} for e, r in zip(examples, rows)]


def evaluate(examples, settings, include_community=True, temp_dir=None):
    rows = [e["row"] for e in prepared_examples(examples, settings)]
    normal = {i for i, e in enumerate(examples, 1) if e["label"] == "benign"}
    bad = set(range(1, len(rows) + 1)) - normal
    scores = {i for i, r in enumerate(rows, 1) if r["risk"] >= 60}
    output = {"version": VERSION, "messages": len(rows), "benign": len(normal), "malicious": len(bad),
              "scoreHighFalsePositives": len(scores & normal), "scoreHighMalicious": len(scores & bad),
              "examples": [{"name": e["name"], "label": e["label"], "risk": r["risk"], "flags": r["flags"]} for e, r in zip(examples, rows)], "packs": {}}
    packs = {"core": ROOT / "rules" / "mail"}
    if include_community:
        packs["sublime"] = ROOT / "rules" / "community" / "sublime"
    with tempfile.TemporaryDirectory(prefix="remn-mail-calibration-", dir=temp_dir) as d:
        reg = StoreRegistry()
        reg.configure(Path(d))
        st = reg.get(str(uuid.uuid4()))
        try:
            writer = MailWriter(st, 1)
            for r in rows:
                writer.add(r)
            writer.flush()
            for name, directory in packs.items():
                matched, high = set(), set()
                per_rule, errors = [], []
                for file in sorted(directory.glob("*.yaml")):
                    for rule in yaml.safe_load_all(file.read_text(encoding="utf-8")):
                        if not isinstance(rule, dict):
                            continue
                        try:
                            findings = run_rule(st, rule, settings)
                            refs = {rid for f in findings for rid in f["refs"]}
                            high_refs = {rid for f in findings if f["severity"] in ("high", "critical") for rid in f["refs"]}
                            matched |= refs
                            high |= high_refs
                            if refs:
                                per_rule.append({"ruleId": rule["id"], "findings": len(findings), "referencedMessages": len(refs),
                                                 "benignReferences": len(refs & normal), "highFalsePositives": len(high_refs & normal),
                                                 "highMalicious": len(high_refs & bad)})
                        except Exception as exc:
                            errors.append({"ruleId": rule["id"], "error": str(exc)[:300]})
                output["packs"][name] = {"referencedMessages": len(matched), "highFalsePositives": len(high & normal), "highMalicious": len(high & bad),
                                         "rules": sorted(per_rule, key=lambda r: (-r["highFalsePositives"], r["ruleId"])), "errors": errors}
        finally:
            reg.close_all()
    output["note"] = "Counts refer to unique record references, not duplicate alerts. Large grouped findings may cap references. This labelled set does not establish accuracy on other mailboxes."
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--synthetic", action="store_true")
    source.add_argument("--manifest", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--export-fixture", type=Path, help="Export normalized synthetic rows for cross-engine regression tests")
    args = parser.parse_args()
    if args.synthetic:
        from mail_calibration import examples, SETTINGS
        data, settings = examples(), SETTINGS
    else:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        settings = manifest.get("settings") or {}
        ctx = ParseContext(internal_domains=settings.get("internal_domains") or [], trusted_senders=settings.get("trusted_senders") or [])
        data = []
        for e in manifest["messages"]:
            if e["label"] not in ("benign", "malicious"):
                raise ValueError("Each message needs a reviewed benign/malicious label")
            p = args.manifest.parent / e["path"]
            data.append({"name": e.get("name") or p.name, "label": e["label"], "row": parse_message_bytes(p.read_bytes(), ctx)})
    result = evaluate(data, settings)
    if args.export_fixture:
        if not args.synthetic:
            parser.error("--export-fixture is restricted to synthetic examples")
        fixture = {"version": VERSION, "settings": settings, "examples": prepared_examples(data, settings)}
        args.export_fixture.write_text(json.dumps(fixture, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    text = json.dumps(result, indent=2, ensure_ascii=False)
    if args.output:
        args.output.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 1 if any(p["errors"] for p in result["packs"].values()) else 0


if __name__ == "__main__":
    raise SystemExit(main())
