#!/usr/bin/env python
"""
Import the public rule collections as REMN community packs.

    python tools/import_community_rules.py all --download
    python tools/import_community_rules.py sigma --zip sigma-master.zip --sha <commit>
    python tools/import_community_rules.py sublime --zip sublime-rules-main.zip

Each source is converted with the same code the "import Sigma" / "import Sublime" buttons use
(services.rules.sigma / services.rules.mql) and written under rules/community/<pack>/ as
multi-document REMN YAML plus:

    pack.json      manifest (upstream repo, commit, licence, counts, default enabled state)
    LICENSE        the upstream licence, verbatim
    skipped.json   every upstream rule that was not converted and why

The packs are served lazily by GET /api/rules/packs[/<id>] and enabled per analyst in the
Rules view; core rules under rules/<windows|mail|m365> stay in /api/meta as before.

Re-running the script rewrites the packs in place (stable ordering, no aliases) so a refresh is
one commit. --download resolves the branch head through the GitHub API and fetches that exact
commit, so pack.json always names the commit the rules came from.
"""
from __future__ import annotations

import argparse
import datetime as dt
import io
import json
import os
import re
import sys
import tempfile
import urllib.request
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "forensic.settings")
import django  # noqa: E402

django.setup()

import yaml  # noqa: E402

from services.rules import mql, sigma  # noqa: E402
from services.store.sqlfilter import Ctx, compile_cond  # noqa: E402

COMMUNITY = ROOT / "rules" / "community"

SOURCES: dict[str, dict[str, Any]] = {
    "sigma": {
        "repo": "SigmaHQ/sigma",
        "ref": "master",
        "license": {"name": "Detection Rule License (DRL) 1.1", "spdx": "DRL-1.1", "url": "https://github.com/SigmaHQ/Detection-Rule-License"},
        "convert": sigma.convert_text,
        "source": "events",
        "windows_only": True,
        "packs": [
            {"id": "sigma-windows", "roots": ["rules"], "name": "Sigma - Windows (stable + test)", "default": True,
             "description": "The main SigmaHQ Windows rule set (process creation, registry, image load, PowerShell, network, file, DNS, built-in Security/System channels). Converted to the REMN DSL one to one; rules that would need to be weakened are listed in skipped.json."},
            {"id": "sigma-emerging-threats", "roots": ["rules-emerging-threats"], "name": "Sigma - Emerging threats (Windows)", "default": True,
             "description": "SigmaHQ emerging-threats rules for Windows: specific malware families, threat actors, exploited CVEs. Narrow by design, so they are on by default."},
            {"id": "sigma-threat-hunting", "roots": ["rules-threat-hunting"], "name": "Sigma - Threat hunting (Windows)", "default": False,
             "description": "SigmaHQ threat-hunting rules for Windows. Written to surface activity worth a look rather than confirmed malice, so they are noisy on purpose and off by default."},
        ],
    },
    "sublime": {
        "repo": "sublime-security/sublime-rules",
        "ref": "main",
        "license": {"name": "MIT License", "spdx": "MIT", "url": "https://github.com/sublime-security/sublime-rules/blob/main/LICENSE"},
        "convert": mql.convert_text,
        "source": "mails",
        "windows_only": False,
        "packs": [
            {"id": "sublime", "roots": ["detection-rules"], "name": "Sublime Security - detection rules", "default": True,
             "description": "The structural subset of the Sublime Security MQL detection rules: sender, subject, header, link and attachment logic that translates exactly to the REMN DSL. Rules that depend on Sublime-only features (ML classifiers, link analysis, sender profiles, file explosion) are listed in skipped.json."},
        ],
    },
}

_SUBLIME_GROUP_ALIASES = {"open": "open_redirect", "sus": "suspicious", "brand": "brand_impersonation"}


class _Dumper(yaml.CSafeDumper if hasattr(yaml, "CSafeDumper") else yaml.SafeDumper):  # type: ignore[misc]
    def ignore_aliases(self, data):  # noqa: D401 - PyYAML hook
        return True


_Loader = yaml.CSafeLoader if hasattr(yaml, "CSafeLoader") else yaml.SafeLoader


def _dump(rule: dict[str, Any]) -> str:
    return yaml.dump(rule, Dumper=_Dumper, sort_keys=False, allow_unicode=True, width=120)


def _github_sha(repo: str, ref: str) -> str:
    req = urllib.request.Request(f"https://api.github.com/repos/{repo}/commits/{ref}", headers={"Accept": "application/vnd.github.sha", "User-Agent": "remn-rule-import"})
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 - fixed https host
        sha = resp.read().decode("ascii").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise SystemExit(f"unexpected commit response for {repo}@{ref}: {sha[:80]!r}")
    return sha


def _download(repo: str, sha: str, cache_dir: Path) -> Path:
    cache_dir.mkdir(parents=True, exist_ok=True)
    out = cache_dir / f"{repo.replace('/', '__')}-{sha}.zip"
    if out.exists() and out.stat().st_size > 0:
        print(f"  using cached {out}")
        return out
    url = f"https://codeload.github.com/{repo}/zip/{sha}"
    print(f"  downloading {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "remn-rule-import"})
    with urllib.request.urlopen(req, timeout=300) as resp, open(out, "wb") as fh:  # noqa: S310
        while True:
            chunk = resp.read(1 << 20)
            if not chunk:
                break
            fh.write(chunk)
    print(f"  {out.stat().st_size / 1e6:.1f} MB")
    return out


def _members(zf: zipfile.ZipFile, roots: list[str]) -> list[str]:
    out = []
    for n in zf.namelist():
        parts = n.split("/")
        if len(parts) < 3 or not n.lower().endswith((".yml", ".yaml")):
            continue
        if parts[1] in roots:
            out.append(n)
    return sorted(out)


def _is_windows(text: str) -> bool:
    try:
        doc = yaml.load(text, Loader=_Loader)
    except yaml.YAMLError:
        return True  # let the converter report the problem
    if not isinstance(doc, dict):
        return False
    ls = doc.get("logsource") or {}
    return str(ls.get("product") or "").lower() == "windows"


def _sigma_group(rule: dict[str, Any]) -> str:
    ls = (rule.get("sigma") or {}).get("logsource") or {}
    cat = ls.get("category") or ls.get("service") or "other"
    return re.sub(r"[^a-z0-9]+", "_", str(cat).lower()).strip("_") or "other"


def _sublime_group(file: str) -> str:
    base = os.path.basename(file)
    token = base.split("_")[0].split(".")[0].lower()
    return _SUBLIME_GROUP_ALIASES.get(token, token) or "other"


def _core_ids() -> set[str]:
    ids: set[str] = set()
    for path in (ROOT / "rules").rglob("*.yaml"):
        if "community" in path.relative_to(ROOT / "rules").parts:
            continue
        for doc in yaml.load_all(path.read_text(encoding="utf-8"), Loader=_Loader):
            if isinstance(doc, dict) and doc.get("id"):
                ids.add(str(doc["id"]))
    return ids


def build_pack(src: dict[str, Any], pack: dict[str, Any], zf: zipfile.ZipFile, provenance: dict[str, Any], taken: set[str]) -> dict[str, Any]:
    convert = src["convert"]
    members = _members(zf, pack["roots"])
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    skipped: list[dict[str, str]] = []
    reasons: Counter[str] = Counter()
    warnings = 0
    considered = 0
    for n in members:
        text = zf.read(n).decode("utf-8", "replace")
        if src["windows_only"] and not _is_windows(text):
            continue
        considered += 1
        rel = "/".join(n.split("/")[1:])
        for r in convert(text, rel):
            if not r.get("ok"):
                reason = str(r.get("error") or "?")
                skipped.append({"file": rel, "title": str(r.get("title") or ""), "reason": reason})
                reasons[reason.split(" (")[0][:80]] += 1
                continue
            rule = r["rule"]
            rid = str(rule["id"])
            if rid in taken:
                raise SystemExit(f"duplicate rule id {rid} ({rel})")
            taken.add(rid)
            # both engines must accept the rule before it is shipped
            compile_cond(rule["where"], Ctx(source=src["source"]))
            if rule.get("exclude"):
                compile_cond(rule["exclude"], Ctx(source=src["source"]))
            warnings += len(r.get("warnings") or [])
            group = _sigma_group(rule) if src is SOURCES["sigma"] else _sublime_group(rel)
            groups[group].append(rule)
    out_dir = COMMUNITY / pack["id"]
    out_dir.mkdir(parents=True, exist_ok=True)
    for old in out_dir.glob("*.yaml"):
        old.unlink()
    files: dict[str, int] = {}
    header = (f"# {pack['name']} - generated by tools/import_community_rules.py from {src['repo']}@{provenance['sha'][:12]} "
              f"({provenance['fetched']}). Upstream licence: {src['license']['name']} (see LICENSE). Do not edit by hand: re-run the import.\n")
    for group in sorted(groups):
        rules = sorted(groups[group], key=lambda r: str(r["id"]))
        text = header + "---\n".join(_dump(r) for r in rules)
        (out_dir / f"{group}.yaml").write_text(text, encoding="utf-8", newline="\n")
        files[f"{group}.yaml"] = len(rules)
    converted = sum(files.values())
    manifest = {
        "id": pack["id"],
        "name": pack["name"],
        "description": pack["description"],
        "source": src["source"],
        "defaultEnabled": bool(pack["default"]),
        "license": {**src["license"], "file": "LICENSE"},
        "upstream": {"repo": src["repo"], "ref": src["ref"], "sha": provenance["sha"], "url": f"https://github.com/{src['repo']}/tree/{provenance['sha']}", "paths": pack["roots"], "fetched": provenance["fetched"]},
        "counts": {"upstream": considered, "converted": converted, "skipped": len(skipped), "warnings": warnings},
        "skipReasons": [[k, v] for k, v in reasons.most_common(25)],
        "files": files,
        "generator": "tools/import_community_rules.py",
    }
    (out_dir / "pack.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    (out_dir / "skipped.json").write_text(json.dumps(sorted(skipped, key=lambda s: s["file"]), indent=1, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    lic = [n for n in zf.namelist() if n.count("/") == 1 and n.split("/")[1].upper().startswith("LICENSE")]
    if lic:
        (out_dir / "LICENSE").write_bytes(zf.read(lic[0]))
    else:
        print(f"  WARNING: no LICENSE file found in the archive for {pack['id']}")
    print(f"  {pack['id']}: {converted} converted, {len(skipped)} skipped of {considered} upstream rules -> {len(files)} files")
    for why, n in reasons.most_common(6):
        print(f"      {n:5d}  {why}")
    return manifest


def run(source: str, zip_path: Path | None, sha: str | None, download: bool, cache_dir: Path) -> None:
    src = SOURCES[source]
    if download:
        sha = sha or _github_sha(src["repo"], src["ref"])
        zip_path = _download(src["repo"], sha, cache_dir)
    if zip_path is None:
        raise SystemExit("give --zip <archive> or --download")
    provenance = {"sha": sha or "unknown", "fetched": dt.date.today().isoformat()}
    print(f"{source}: {zip_path} @ {provenance['sha'][:12]}")
    taken = _core_ids()
    with zipfile.ZipFile(zip_path) as zf:
        for pack in src["packs"]:
            build_pack(src, pack, zf, provenance, taken)


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("source", choices=["sigma", "sublime", "all"])
    ap.add_argument("--zip", type=Path, help="local archive of the repository (GitHub 'Download ZIP' layout)")
    ap.add_argument("--sha", help="commit the archive corresponds to (recorded in pack.json)")
    ap.add_argument("--download", action="store_true", help="resolve the branch head on GitHub and fetch that commit")
    ap.add_argument("--cache-dir", type=Path, default=Path(tempfile.gettempdir()) / "remn-rule-import")
    a = ap.parse_args(argv)
    sources = ["sigma", "sublime"] if a.source == "all" else [a.source]
    if a.source == "all" and a.zip:
        raise SystemExit("--zip applies to one source; use --download for all")
    for s in sources:
        run(s, a.zip, a.sha, a.download, a.cache_dir)


if __name__ == "__main__":
    main()
