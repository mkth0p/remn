"""The investigative questions of the Questions page, from DFIQ and from REMN's own layer.

DFIQ (https://dfiq.org, Apache-2.0, Copyright 2024 Google LLC) is a catalog of investigative
questions in YAML: scenarios, facets, questions and approaches. This script reads the scenarios
REMN uses from a DFIQ release, keeps the questions tools/dfiq_remn.yaml gives hints for (the
evidence that can answer each one, a search, ATT&CK techniques and rule tags), adds REMN's own
scenarios from the same file, and writes one JSON file the frontend bundles:

    frontend/src/data/questions/dfiq.gen.json

DFIQ ids are kept as they are; REMN's own start with 0 (S0001, F0001, Q0001), the range DFIQ keeps
for private content. The DFIQ release is not vendored: point the script at an unpacked copy of the
`dfiq` wheel or of github.com/google/dfiq (the directory holding scenarios/, facets/, questions/ and
approaches/, or any directory above it).

    python tools/dfiq_import.py path/to/dfiq            # rewrite the file
    python tools/dfiq_import.py path/to/dfiq --check    # exit 1 when it is out of date
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
OVERLAY = ROOT / "tools" / "dfiq_remn.yaml"
OUT = ROOT / "frontend" / "src" / "data" / "questions" / "dfiq.gen.json"
KINDS = ("scenarios", "facets", "questions", "approaches")
ATTACK = re.compile(r"^T(A)?\d{4}(\.\d{3})?$")
SEARCH_SOURCES = ("events", "mails")
DERIVED = ("first-activity", "last-activity", "log-reach", "evidence-gaps")


def _text(value: Any) -> str:
    return " ".join(str(value).split()) if value not in (None, "") else ""


def find_data(path: Path) -> Path:
    """The directory holding scenarios/, facets/, questions/ and approaches/ under `path`."""
    for candidate in [path, *sorted(p.parent for p in path.rglob("scenarios") if p.is_dir())]:
        if all((candidate / k).is_dir() for k in ("scenarios", "facets", "questions")):
            return candidate
    raise SystemExit(f"no DFIQ data (scenarios/, facets/, questions/) under {path}")


def dfiq_version(path: Path) -> str:
    """The release, from the wheel's METADATA when the copy is an unpacked wheel."""
    for meta in path.rglob("METADATA"):
        found = re.search(r"^Version:\s*(\S+)", meta.read_text(encoding="utf-8"), re.M)
        if found:
            return found.group(1)
    return "unknown"


def load_dfiq(data: Path) -> dict[str, dict[str, dict[str, Any]]]:
    out: dict[str, dict[str, dict[str, Any]]] = {k: {} for k in KINDS}
    for kind in KINDS:
        folder = data / kind
        if not folder.is_dir():
            continue
        for f in sorted(folder.glob("*.yaml")):
            doc = yaml.safe_load(f.read_text(encoding="utf-8"))
            if isinstance(doc, dict) and doc.get("id"):
                out[kind][str(doc["id"])] = doc
    return out


def _attack(tags: list[Any] | None) -> list[str]:
    return [str(t) for t in tags or [] if ATTACK.match(str(t))]


def _plain_tags(tags: list[Any] | None) -> list[str]:
    return [str(t) for t in tags or [] if not ATTACK.match(str(t))]


def _merge(*lists: list[str]) -> list[str]:
    seen: dict[str, None] = {}
    for items in lists:
        for item in items:
            seen.setdefault(item, None)
    return list(seen)


def _searches(hint: dict[str, Any], where: str) -> list[dict[str, Any]]:
    items = list(hint.get("searches") or []) + ([hint["search"]] if hint.get("search") else [])
    for s in items:
        if s.get("source") not in SEARCH_SOURCES or not isinstance(s.get("filter"), dict) or not s.get("label"):
            raise SystemExit(f"{where}: a search needs a source (events or mails), a label and a filter")
    return [{"source": s["source"], "label": str(s["label"]), "filter": s["filter"]} for s in items]


def _hints(hint: dict[str, Any], evidence: dict[str, Any], where: str) -> dict[str, Any]:
    needs = [str(e) for e in hint.get("evidence") or []]
    unknown = [e for e in needs if e not in evidence]
    if not needs or unknown:
        raise SystemExit(f"{where}: evidence must name entries of the evidence table ({', '.join(unknown) or 'none given'})")
    derived = hint.get("derived")
    if derived is not None and derived not in DERIVED:
        raise SystemExit(f"{where}: derived must be one of {', '.join(DERIVED)}")
    out: dict[str, Any] = {
        "evidence": needs,
        "attack": [str(a) for a in hint.get("attack") or []],
        "ruleTags": [str(t) for t in hint.get("ruleTags") or []],
        "searches": _searches(hint, where),
    }
    if hint.get("note"):
        out["note"] = _text(hint["note"])
    if derived:
        out["derived"] = derived
    return out


def _approach(doc: dict[str, Any]) -> dict[str, Any]:
    desc = doc.get("description") or {}
    notes = (doc.get("view") or {}).get("notes") or {}
    return {
        "id": str(doc["id"]),
        "name": _text(doc.get("display_name")),
        "summary": _text(desc.get("summary") if isinstance(desc, dict) else desc),
        "covered": [_text(x) for x in notes.get("covered") or []],
        "notCovered": [_text(x) for x in notes.get("not_covered") or []],
    }


def build(dfiq: dict[str, dict[str, dict[str, Any]]], overlay: dict[str, Any], version: str) -> dict[str, Any]:
    evidence = overlay.get("evidence") or {}
    hints = overlay.get("questions") or {}
    wanted = [str(s) for s in (overlay.get("include") or {}).get("scenarios") or []]
    for sid in wanted:
        if sid not in dfiq["scenarios"]:
            raise SystemExit(f"scenario {sid} is not in this DFIQ release")
    for qid in hints:
        if qid not in dfiq["questions"]:
            raise SystemExit(f"{qid} has hints but is not a question of this DFIQ release")

    facets_of = {sid: sorted(fid for fid, f in dfiq["facets"].items() if sid in (f.get("parent_ids") or [])) for sid in wanted}
    questions_of: dict[str, list[str]] = {}
    for qid, q in sorted(dfiq["questions"].items()):
        for fid in q.get("parent_ids") or []:
            questions_of.setdefault(str(fid), []).append(qid)
    approaches_of: dict[str, list[dict[str, Any]]] = {}
    for aid, a in sorted(dfiq["approaches"].items()):
        approaches_of.setdefault(aid.rsplit(".", 1)[0], []).append(_approach(a))

    scenarios: list[dict[str, Any]] = []
    facets: dict[str, dict[str, Any]] = {}
    questions: dict[str, dict[str, Any]] = {}
    skipped: dict[str, str] = {}
    for sid in wanted:
        s = dfiq["scenarios"][sid]
        kept_facets = []
        for fid in facets_of[sid]:
            kept = [qid for qid in questions_of.get(fid, []) if qid in hints]
            for qid in questions_of.get(fid, []):
                if qid not in hints:
                    skipped[qid] = _text(dfiq["questions"][qid].get("display_name"))
            if not kept:
                continue
            kept_facets.append(fid)
            f = dfiq["facets"][fid]
            facets.setdefault(
                fid,
                {
                    "id": fid,
                    "name": _text(f.get("display_name")),
                    "description": _text(f.get("description")),
                    "tags": _plain_tags(f.get("tags")),
                    "attack": _attack(f.get("tags")),
                    "questions": kept,
                },
            )
            for qid in kept:
                if qid in questions:
                    continue
                q = dfiq["questions"][qid]
                h = _hints(hints[qid], evidence, qid)
                questions[qid] = {
                    "id": qid,
                    "origin": "dfiq",
                    "name": _text(q.get("display_name")),
                    "description": _text(q.get("description")),
                    "tags": _plain_tags(q.get("tags")),
                    **h,
                    "attack": _merge(_attack(q.get("tags")), h["attack"]),
                    "approaches": approaches_of.get(qid, []),
                }
        scenarios.append(
            {
                "id": sid,
                "origin": "dfiq",
                "name": _text(s.get("display_name")),
                "description": _text(s.get("description")),
                "tags": _plain_tags(s.get("tags")),
                "attack": _attack(s.get("tags")),
                "facets": kept_facets,
            }
        )

    for s in overlay.get("scenarios") or []:
        sid = str(s["id"])
        if not sid.startswith("S0"):
            raise SystemExit(f"{sid}: REMN's own scenarios take ids starting with S0")
        fids = []
        for f in s.get("facets") or []:
            fid = str(f["id"])
            if not fid.startswith("F0") or fid in facets:
                raise SystemExit(f"{fid}: REMN's own facets take unique ids starting with F0")
            qids = []
            for q in f.get("questions") or []:
                qid = str(q["id"])
                if not qid.startswith("Q0") or qid in questions:
                    raise SystemExit(f"{qid}: REMN's own questions take unique ids starting with Q0")
                questions[qid] = {
                    "id": qid,
                    "origin": "remn",
                    "name": _text(q["name"]),
                    "description": _text(q.get("description")),
                    "tags": [str(t) for t in q.get("tags") or []],
                    **_hints(q, evidence, qid),
                    "approaches": [],
                }
                qids.append(qid)
            facets[fid] = {
                "id": fid,
                "name": _text(f["name"]),
                "description": _text(f.get("description")),
                "tags": _plain_tags(f.get("tags")),
                "attack": _attack(f.get("tags")),
                "questions": qids,
            }
            fids.append(fid)
        scenarios.append(
            {
                "id": sid,
                "origin": "remn",
                "name": _text(s["name"]),
                "description": _text(s.get("description")),
                "tags": _plain_tags(s.get("tags")),
                "attack": _attack(s.get("tags")),
                "facets": fids,
            }
        )

    for qid in list(skipped):
        if qid in questions:
            del skipped[qid]
    return {
        "generatedBy": "tools/dfiq_import.py from DFIQ and tools/dfiq_remn.yaml; do not edit",
        "dfiq": {
            "version": version,
            "url": "https://dfiq.org",
            "repository": "https://github.com/google/dfiq",
            "license": "Apache-2.0",
            "copyright": "Copyright 2024 Google LLC",
        },
        "evidence": evidence,
        "scenarios": scenarios,
        "facets": list(facets.values()),
        "questions": list(questions.values()),
        "skipped": [{"id": k, "name": v} for k, v in sorted(skipped.items())],
    }


def render(catalog: dict[str, Any]) -> str:
    return json.dumps(catalog, ensure_ascii=False, indent=1) + "\n"


def load_overlay(path: Path = OVERLAY) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dfiq", type=Path, help="an unpacked DFIQ release (the wheel or the repository)")
    ap.add_argument("--check", action="store_true", help="exit 1 when the generated file is out of date")
    ap.add_argument("--out", type=Path, default=OUT)
    args = ap.parse_args()
    data = find_data(args.dfiq)
    text = render(build(load_dfiq(data), load_overlay(), dfiq_version(args.dfiq)))
    if args.check:
        current = args.out.read_text(encoding="utf-8") if args.out.exists() else ""
        if current != text:
            print(f"{args.out} is out of date: run tools/dfiq_import.py", file=sys.stderr)
            return 1
        return 0
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(text, encoding="utf-8")
    catalog = json.loads(text)
    print(
        f"{args.out}: {len(catalog['scenarios'])} scenarios, {len(catalog['facets'])} facets, {len(catalog['questions'])} questions ({len(catalog['skipped'])} DFIQ questions left out)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
