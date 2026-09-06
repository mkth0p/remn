"""Run REMN's mail scoring over public corpora and print recall / false-positive figures.

Corpora (downloaded once into samples/public/, all redistributable):
  nazario     Jose Nazario's hand-classified phishing mailboxes, 2004-2007 (CC BY 4.0), mbox     - positives
  phishpot    rf-peixoto/phishing_pot honeypot phishing, 2022 onwards, .eml in a zip           - positives (large; --phishpot)
  easy_ham    SpamAssassin public corpus easy_ham (2003), legitimate list mail                 - negatives
  hard_ham    SpamAssassin public corpus hard_ham (2003), legitimate mail that looks like spam - negatives
  tika_pst    Apache Tika's test PST (7 messages)                                              - format smoke test
  invictus    Invictus IR Office 365 Unified Audit Log records from real BEC cases (CC BY 4.0) - M365 parser smoke test

Usage:
  .venv/Scripts/python.exe tools/validate_public.py            # download what is missing, run, print the table
  .venv/Scripts/python.exe tools/validate_public.py --phishpot --sample 800
  .venv/Scripts/python.exe tools/validate_public.py --json samples/public/validation.json

Scores use the default case settings (no internal domains, no VIPs, no baseline), so the numbers are a
floor: the sender history and internal-domain rules only add signal on a real case.
"""
from __future__ import annotations

import argparse
import collections
import io
import json
import os
import random
import sys
import tarfile
import time
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "forensic.settings")

from services.parsers.mail.common import ParseContext  # noqa: E402
from services.parsers.mail.eml import iter_eml_files  # noqa: E402
from services.parsers.mail.mbox import iter_mbox  # noqa: E402

CACHE = ROOT / "samples" / "public"
BANDS = (("critical", 80), ("high", 60), ("medium", 40), ("low", 20), ("clean", 0))

SOURCES = {
    "nazario": [("phishing0.mbox", "https://monkey.org/~jose/phishing/phishing0.mbox"), ("phishing1.mbox", "https://monkey.org/~jose/phishing/phishing1.mbox"),
                ("phishing2.mbox", "https://monkey.org/~jose/phishing/phishing2.mbox"), ("phishing3.mbox", "https://monkey.org/~jose/phishing/phishing3.mbox")],
    "easy_ham": [("20030228_easy_ham.tar.bz2", "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2")],
    "hard_ham": [("20030228_hard_ham.tar.bz2", "https://spamassassin.apache.org/old/publiccorpus/20030228_hard_ham.tar.bz2")],
    "phishpot": [("phishing_pot.zip", "https://codeload.github.com/rf-peixoto/phishing_pot/zip/refs/heads/main")],
    "tika_pst": [("testPST.pst", "https://raw.githubusercontent.com/apache/tika/main/tika-parsers/tika-parsers-standard/tika-parsers-standard-modules/tika-parser-microsoft-module/src/test/resources/test-documents/testPST.pst")],
    "invictus": [("auditrecords.7z", "https://raw.githubusercontent.com/invictus-ir/o365_dataset/main/auditrecords.7z")],
}


def fetch(name: str, url: str) -> Path:
    CACHE.mkdir(parents=True, exist_ok=True)
    dest = CACHE / name
    if dest.exists() and dest.stat().st_size > 0:
        return dest
    print(f"  downloading {name} …", flush=True)
    req = urllib.request.Request(url, headers={"User-Agent": "remn-validate/1"})
    with urllib.request.urlopen(req, timeout=600) as r, open(dest, "wb") as f:
        while True:
            chunk = r.read(1 << 20)
            if not chunk:
                break
            f.write(chunk)
    return dest


def band(risk: int) -> str:
    for name, lo in BANDS:
        if risk >= lo:
            return name
    return "clean"


def summarize(rows: list[dict[str, Any]], positive: bool) -> dict[str, Any]:
    n = len(rows)
    bands = collections.Counter(band(int(r.get("risk") or 0)) for r in rows)
    at60 = sum(1 for r in rows if int(r.get("risk") or 0) >= 60)
    at40 = sum(1 for r in rows if int(r.get("risk") or 0) >= 40)
    flags = collections.Counter(f for r in rows for f in r.get("flags") or [])
    weak = [r for r in rows if int(r.get("risk") or 0) < 40] if positive else [r for r in rows if int(r.get("risk") or 0) >= 60]
    drivers = collections.Counter(f for r in weak for f in r.get("flags") or [])
    return {"n": n, "bands": dict(bands), "rate60": round(at60 / n, 3) if n else None, "rate40": round(at40 / n, 3) if n else None,
            "topFlags": flags.most_common(12), "outlierFlags": drivers.most_common(10), "positive": positive}


def eml_items_from_tar(path: Path, member_dir: str) -> Iterable[tuple[str, bytes]]:
    with tarfile.open(path, "r:bz2") as t:
        for m in t.getmembers():
            if not m.isfile() or "/" not in m.name or member_dir not in m.name:
                continue
            f = t.extractfile(m)
            if f:
                yield m.name.split("/")[-1] + ".eml", f.read()


def run_mail(corpus: str, sample: int | None, ctx: ParseContext) -> dict[str, Any]:
    t0 = time.time()
    rows: list[dict[str, Any]] = []
    if corpus == "nazario":
        for name, url in SOURCES[corpus]:
            try:
                rows.extend(iter_mbox(str(fetch(name, url)), ctx))
            except OSError as e:
                # endpoint protection quarantines some phishing mailboxes mid-download: keep going
                print(f"  {name}: unreadable ({e.strerror or e}); skipped", flush=True)
    elif corpus in ("easy_ham", "hard_ham"):
        name, url = SOURCES[corpus][0]
        items = list(eml_items_from_tar(fetch(name, url), corpus))
        if sample and len(items) > sample:
            items = random.Random(7).sample(items, sample)
        rows.extend(iter_eml_files(iter(items), ctx))
    elif corpus == "phishpot":
        name, url = SOURCES[corpus][0]
        z = zipfile.ZipFile(fetch(name, url))
        names = [n for n in z.namelist() if n.lower().endswith(".eml")]
        if sample and len(names) > sample:
            names = random.Random(7).sample(names, sample)
        rows.extend(iter_eml_files(((n.split("/")[-1], z.read(n)) for n in names), ctx))
    out = summarize(rows, positive=corpus in ("nazario", "phishpot"))
    out["seconds"] = round(time.time() - t0, 1)
    return out


def run_pst(ctx: ParseContext) -> dict[str, Any]:
    from services.parsers.mail import pst
    if not pst.available():
        return {"skipped": "libpff-python not installed"}
    import pypff
    name, url = SOURCES["tika_pst"][0]
    f = pypff.file()
    f.open(str(fetch(name, url)))
    try:
        rows = list(pst.iter_pst_file(f, ctx))
    finally:
        f.close()
    return {"n": len(rows), "folders": sorted({r.get("folder") for r in rows}), "bands": dict(collections.Counter(band(int(r.get("risk") or 0)) for r in rows))}


def run_invictus() -> dict[str, Any]:
    from services.parsers import m365
    name, url = SOURCES["invictus"][0]
    archive = fetch(name, url)
    csv_path = CACHE / "auditrecords.csv"
    if not csv_path.exists():
        try:
            import py7zr
        except ImportError:
            return {"skipped": "pip install py7zr to extract auditrecords.7z"}
        with py7zr.SevenZipFile(archive) as a:
            a.extractall(CACHE)
    head = csv_path.read_bytes()[:4096]
    fmt = m365.detect_format(csv_path.name, head)
    rows = list(m365.iter_records(str(csv_path), None, fmt, stats=None, include_raw=False))
    ops = collections.Counter(r.get("operation") for r in rows)
    return {"format": fmt, "n": len(rows), "operations": ops.most_common(10), "users": len({r.get("targetUser") for r in rows}),
            "inboxRules": sum(v for k, v in ops.items() if "InboxRule" in str(k)), "spanDays": round((max(r["ts"] for r in rows) - min(r["ts"] for r in rows)) / 86_400_000, 1) if rows else 0}


def table(results: dict[str, Any]) -> str:
    lines = ["| corpus | kind | mails | critical | high | medium | low | clean | >= high | >= medium |", "|---|---|---|---|---|---|---|---|---|---|"]
    for name, r in results.items():
        if "bands" not in r or "rate60" not in r:
            continue
        b = r["bands"]
        kind = "phishing" if r["positive"] else "legitimate"
        lines.append(f"| {name} | {kind} | {r['n']} | {b.get('critical', 0)} | {b.get('high', 0)} | {b.get('medium', 0)} | {b.get('low', 0)} | {b.get('clean', 0)} | {r['rate60']:.0%} | {r['rate40']:.0%} |")
    return "\n".join(lines)


def main() -> None:
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # Windows consoles default to cp1252
    except Exception:  # noqa: BLE001
        pass
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--phishpot", action="store_true", help="include the 229 MB Phishing Pot archive")
    ap.add_argument("--sample", type=int, default=800, help="max messages per .eml corpus (0 = all)")
    ap.add_argument("--json", help="write the full results here")
    ap.add_argument("--only", nargs="*", help="subset of corpora")
    args = ap.parse_args()
    sample = args.sample or None
    ctx = ParseContext()
    corpora = args.only or ["nazario", "easy_ham", "hard_ham"] + (["phishpot"] if args.phishpot else []) + ["tika_pst", "invictus"]
    results: dict[str, Any] = {"generatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "settings": "defaults (no internal domains, no baseline)"}
    for c in corpora:
        print(f"[{c}]", flush=True)
        try:
            if c == "tika_pst":
                results[c] = run_pst(ctx)
            elif c == "invictus":
                results[c] = run_invictus()
            else:
                results[c] = run_mail(c, sample, ctx)
        except Exception as e:  # noqa: BLE001
            results[c] = {"error": f"{type(e).__name__}: {e}"}
        print("  ", json.dumps({k: v for k, v in results[c].items() if k not in ("topFlags", "outlierFlags")}, default=str)[:400])
    print()
    print(table(results))
    for name, r in results.items():
        if isinstance(r, dict) and r.get("outlierFlags"):
            label = "missed (below medium) carry" if r["positive"] else "false positives (high or above) carry"
            print(f"{name}: {label}: " + ", ".join(f"{f} ×{n}" for f, n in r["outlierFlags"][:8]))
    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(json.dumps(results, indent=1, default=str), encoding="utf-8")
        print(f"\nwritten {args.json}")


if __name__ == "__main__":
    main()
