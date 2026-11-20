"""Write the package lists of THIRD_PARTY_NOTICES.md from the lock files.

    python tools/third_party_notices.py            # rewrite the generated parts of the file
    python tools/third_party_notices.py --check    # say what differs from the locks; exit 1 if anything does
    python tools/third_party_notices.py --fetch    # also ask PyPI and cargo for licences not known here
    python tools/third_party_notices.py --texts    # also rewrite the licence texts of the browser application

The packages are read from the files an install or a build really reads, as tools/sbom.py reads
them: backend/requirements.txt and backend/requirements-optional.txt (with uv's "# via" lines, which
say why each package is there), frontend/package-lock.json (development packages left out) and
frontend/wasm/evtx/Cargo.lock.

Licences. A Python package's licence is the one its installed metadata declares, when the version
installed is the locked one: its License-Expression, else a License field that is an SPDX
identifier, else its one licence classifier. Where the metadata is vague ("BSD", "GPL"), DECLARED
gives the licence the package's own licence file states, for as long as the metadata says what
it said when that file was read. A package not installed here (an optional parser, a Windows-only
package) keeps the licence the notices already give, or with --fetch takes the one PyPI declares
for the locked version. npm licences are the ones package-lock.json records. Crate licences come
from `cargo metadata` with --fetch or --texts (cargo downloads the crates), else stay as given.

The licence texts (--texts) are read from the installed npm packages (frontend/node_modules, after
`npm ci`) and from the crates cargo downloaded: one copy of each distinct text, with the copyright
lines of every package that carries it, and each NOTICE file whole.

Nothing here is installed to do this: the inputs are text files and the standard library.
"""

from __future__ import annotations

import argparse
import collections
import importlib.metadata
import json
import re
import subprocess
import sys
import tomllib
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NOTICES = "THIRD_PARTY_NOTICES.md"
PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)\s*(?:;\s*([^\\]*?))?\s*\\?$")
BLOCKS = ("python", "python-optional", "npm", "crates", "texts")

# metadata too vague to name a licence, and what the package's own licence file says: (metadata, licence)
DECLARED: dict[str, tuple[str, str]] = {
    "easygui": ("BSD", "BSD-3-Clause"),
    "extract-msg": ("GPL", "GPL-3.0-or-later"),
    "olefile": ("BSD", "BSD-2-Clause"),
    "oletools": ("BSD", "BSD-2-Clause"),
    "pcodedmp": ("GPL", "GPL-3.0"),
    "pycryptodomex": ("BSD, Public Domain", "BSD-2-Clause AND public domain"),
    "rtfde": ("GNU Lesser General Public License v3 (LGPLv3)", "LGPL-3.0-or-later"),
    "sqlparse": ("BSD License", "BSD-3-Clause"),
}
# spellings of a licence in metadata that name exactly one SPDX licence
ALIASES = {
    "Apache 2.0": "Apache-2.0",
    "Apache Software License": "Apache-2.0",
    "GNU Lesser General Public License v2 or later (LGPLv2+)": "LGPL-2.0-or-later",
    "ISC License (ISCL)": "ISC",
    "LGPL-2.1+": "LGPL-2.1-or-later",
    "MIT License": "MIT",
    "Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "PSFL": "PSF-2.0",
    "Python Software Foundation License": "PSF-2.0",
    "ZPL 2.1": "ZPL-2.1",
    "Zope Public License": "ZPL-2.1",
}
VAGUE = {"BSD", "BSD License", "GPL", "LGPL", "Apache", "Public Domain", "Other/Proprietary License", "UNKNOWN"}
SPDX = re.compile(r"[A-Za-z0-9.+-]+(?: (?:OR|AND|WITH) [A-Za-z0-9.+-]+)*")
COPYLEFT = re.compile(r"\b(?:A?GPL|LGPL|MPL|EUPL|CDDL|EPL)\b", re.IGNORECASE)


@dataclass
class Package:
    name: str
    versions: list[str]
    licence: str = ""
    why: list[str] = field(default_factory=list)
    where: str = ""
    # the directories holding each version's files, for the licence texts
    dirs: list[Path] = field(default_factory=list)


# ---- the locks


def python_lock(path: Path) -> dict[str, Package]:
    out: dict[str, Package] = {}
    current: Package | None = None
    collecting = False
    for line in path.read_text(encoding="utf-8").splitlines():
        m = PIN.match(line)
        if m:
            current = Package(re.sub(r"[-_.]+", "-", m.group(1)).lower(), [m.group(2)], where=_platform(m.group(3) or ""))
            out[current.name] = current
            collecting = False
            continue
        text = line.strip()
        if current is None or not text.startswith("#"):
            collecting = False
            continue
        if text.startswith("# via"):
            rest = text[5:].strip()
            if rest:
                current.why.append(rest)
            collecting = not rest
        elif collecting and text.startswith("#   "):
            current.why.append(text[1:].strip())
    for package in out.values():
        package.why = _requirers([_why(w) for w in package.why if not w.startswith("-c ")])
    return out


def _why(via: str) -> str:
    return "REMN" if via.startswith("-r ") else via


def _requirers(names: list[str]) -> list[str]:
    """Sorted, with REMN (or the decoder itself) first."""
    first = [n for n in ("REMN", "the decoder") if n in names]
    return first + sorted(set(names) - set(first))


def _platform(marker: str) -> str:
    # a marker with "or" in it covers several platforms; uv writes a single platform as one clause
    if " or " in marker:
        return ""
    if "sys_platform == 'win32'" in marker:
        return "Windows only"
    if "platform_python_implementation == 'PyPy'" in marker:
        return "PyPy only"
    return ""


def python_packages(root: Path = ROOT) -> tuple[dict[str, Package], dict[str, Package]]:
    """The main set, and the packages the optional set adds to it."""
    main = python_lock(root / "backend" / "requirements.txt")
    optional = {n: p for n, p in python_lock(root / "backend" / "requirements-optional.txt").items() if n not in main}
    return main, optional


def npm_packages(root: Path = ROOT) -> dict[str, Package]:
    packages = json.loads((root / "frontend" / "package-lock.json").read_text(encoding="utf-8")).get("packages", {})
    shipped = {p: m for p, m in packages.items() if p and not m.get("dev") and not m.get("link") and "version" in m}
    out: dict[str, Package] = {}
    for path, meta in sorted(shipped.items()):
        name = meta.get("name") or path.rsplit("node_modules/", 1)[-1]
        package = out.setdefault(name, Package(name, []))
        package.versions.append(meta["version"])
        package.dirs.append(root / "frontend" / path)
        if meta.get("license") and meta["license"] not in package.licence.split(" / "):
            package.licence = " / ".join(x for x in (package.licence, meta["license"]) if x)
    for path, meta in [("", packages.get("", {}))] + sorted(shipped.items()):
        requirer = "REMN" if not path else (meta.get("name") or path.rsplit("node_modules/", 1)[-1])
        for kind in ("dependencies", "optionalDependencies", "peerDependencies"):
            for dep in meta.get(kind, {}):
                if dep in out and requirer != dep:
                    out[dep].why.append(requirer)
    for package in out.values():
        package.why = _requirers(package.why)
    return out


def crate_packages(root: Path = ROOT) -> dict[str, Package]:
    lock = tomllib.loads((root / "frontend" / "wasm" / "evtx" / "Cargo.lock").read_text(encoding="utf-8"))
    out: dict[str, Package] = {}
    for crate in lock.get("package", []):
        if "source" in crate:
            out.setdefault(crate["name"], Package(crate["name"], [])).versions.append(crate["version"])
    for crate in lock.get("package", []):
        requirer = crate["name"] if "source" in crate else "the decoder"
        for dep in crate.get("dependencies", []):
            name = dep.split(" ", 1)[0]
            if name in out and name != requirer:
                out[name].why.append(requirer)
    for package in out.values():
        package.why = _requirers(package.why)
    return out


# ---- licences


def licence_from_metadata(name: str, expression: str | None, text: str | None, classifiers: list[str]) -> str | None:
    """The SPDX licence a package's metadata declares, or None when it is too vague to say."""
    raw = metadata_licence(expression, text, classifiers)
    if name in DECLARED and DECLARED[name][0] == raw:
        return DECLARED[name][1]
    if expression:
        return expression.strip()
    value = ALIASES.get(raw, raw)
    if value and value not in VAGUE and SPDX.fullmatch(value):
        return value
    return None


def metadata_licence(expression: str | None, text: str | None, classifiers: list[str]) -> str:
    """What the metadata says about the licence, in the words it uses."""
    if expression:
        return expression.strip()
    text = (text or "").strip()
    if text and "\n" not in text and len(text) <= 80:
        return text
    return "; ".join(c.split(" :: ")[-1] for c in classifiers if c.startswith("License ::"))


def installed_licence(package: Package) -> tuple[str | None, str] | None:
    """(licence, what the metadata says) of the installed distribution, when it is the locked version."""
    try:
        dist = importlib.metadata.distribution(package.name)
    except importlib.metadata.PackageNotFoundError:
        return None
    if dist.version not in package.versions:
        return None
    meta = dist.metadata
    args = (meta.get("License-Expression"), meta.get("License"), meta.get_all("Classifier") or [])
    return licence_from_metadata(package.name, *args), metadata_licence(*args)


def pypi_licence(package: Package) -> tuple[str | None, str]:
    url = f"https://pypi.org/pypi/{package.name}/{package.versions[0]}/json"
    with urllib.request.urlopen(url, timeout=30) as response:
        info = json.load(response)["info"]
    args = (info.get("license_expression"), info.get("license"), info.get("classifiers") or [])
    return licence_from_metadata(package.name, *args), metadata_licence(*args)


def cargo_metadata(root: Path = ROOT) -> dict[tuple[str, str], dict]:
    """Each locked crate's metadata, from cargo (which downloads the crates it does not have)."""
    manifest = root / "frontend" / "wasm" / "evtx" / "Cargo.toml"
    result = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--locked", "--manifest-path", str(manifest)],
        capture_output=True,
        text=True,
        check=True,
        cwd=manifest.parent,
    )
    return {(p["name"], p["version"]): p for p in json.loads(result.stdout)["packages"]}


def copyleft_only(expression: str) -> bool:
    """Whether a licence leaves no permissive choice: a copyleft licence, or an OR of copyleft licences only."""
    for term in re.split(r"\s+AND\s+", expression.replace("(", " ").replace(")", " ")):
        options = [o for o in re.split(r"\s+OR\s+|/", term) if o.strip()]
        if options and all(COPYLEFT.search(o) for o in options):
            return True
    return False


# ---- the file


def blocks(text: str) -> dict[str, str]:
    out = {}
    for name in BLOCKS:
        m = re.search(rf"<!-- BEGIN generated: {name} -->\n(.*?)<!-- END generated: {name} -->", text, re.DOTALL)
        if m:
            out[name] = m.group(1)
    return out


def replace_block(text: str, name: str, body: str) -> str:
    begin, end = f"<!-- BEGIN generated: {name} -->\n", f"<!-- END generated: {name} -->"
    head, rest = text.split(begin, 1)
    return head + begin + body + end + rest.split(end, 1)[1]


def table_rows(block: str) -> dict[str, list[str]]:
    """{package: [the row's cells after the name]} of a generated table."""
    out = {}
    for line in block.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if line.startswith("| `") and len(cells) >= 2:
            out[cells[0].strip("`")] = cells[1:]
    return out


def table(packages: dict[str, Package], first: str, why: str) -> str:
    lines = [f"| {first} | Licence | {why} |", "| --- | --- | --- |"]
    for name in sorted(packages):
        p = packages[name]
        reasons = ", ".join(p.why) or "REMN"
        if p.where:
            reasons += f"; {p.where}"
        lines.append(f"| `{name}` | {p.licence or 'not known'} | {reasons} |")
    return "\n".join(lines) + "\n"


# ---- the licence texts

LICENCE_FILE = re.compile(r"^(?:licen[cs]e|copying|unlicen[cs]e|notice|copyright)(?:[-_.].*)?$", re.IGNORECASE)
# "Copyright (c) 2019 Someone", "Copyright 2016 The Project Authors", "© 1991-2023 Unicode, Inc.": a notice, not a
# sentence of the licence about copyright, and not the "[yyyy] [name of copyright owner]" of a template
COPYRIGHT_LINE = re.compile(r"^\s*(?:copyright\s*(?:\(c\)|©|\d{4}|by\s)|\(c\)\s*\d{4}|©\s*\d{4})", re.IGNORECASE)
# the lines at the top of a licence file where its copyright lines are looked for
HEAD = 12
APACHE_TEXT = "[The terms of the Apache License 2.0, as in LICENSE at the root of this repository.]"
PREFERRED = ("MIT", "Apache-2.0", "BSD-3-Clause", "BSD-2-Clause", "ISC", "Zlib", "0BSD", "Unlicense", "CC0-1.0", "Unicode-3.0")


def licence_files(directory: Path, expression: str) -> list[Path]:
    """The licence files of a package: those at its top, less the ones of a licence not taken, and every file
    of its licenses/ folder, which holds the licences of code it includes from elsewhere."""
    top = pick([f for f in directory.iterdir() if f.is_file() and LICENCE_FILE.match(f.name)], expression)
    sub = directory / "licenses"
    return top + (sorted(f for f in sub.rglob("*") if f.is_file()) if sub.is_dir() else [])


def _tag(path: Path) -> str:
    """LICENSE-MIT is "mit", LICENSE-APACHE "apache", UNLICENSE "unlicense"; LICENSE, COPYING and NOTICE have none."""
    stem = path.name.lower()
    if stem.startswith("unlicen"):
        return "unlicense"
    m = re.match(r"^(?:licen[cs]e|copying)[-_.](.+?)(?:\.(?:txt|md|markdown))?$", stem)
    return m.group(1) if m and m.group(1) not in ("txt", "md", "markdown") else ""


def chosen(expression: str) -> list[str]:
    """The licences taken where the package offers a choice: one of each OR, every term of an AND."""
    out = []
    for term in re.split(r"\s+AND\s+", expression.replace("(", " ").replace(")", " ").strip()):
        options = [o.strip() for o in re.split(r"\s+OR\s+|/", term) if o.strip()]
        options = [o.split(" WITH ")[0] for o in options]
        out.append(next((p for p in PREFERRED if p in options), options[0] if options else ""))
    return out


def pick(files: list[Path], expression: str) -> list[Path]:
    wanted = [c.lower().split("-")[0] for c in chosen(expression)]
    tagged = [f for f in files if _tag(f)]
    keep = [f for f in tagged if any(_tag(f).startswith(w) or w.startswith(_tag(f)) for w in wanted)]
    untagged = [f for f in files if not _tag(f)]
    # a LICENSE-MPL beside a LICENSE that holds the licence taken is left out; with nothing else, it is all there is
    return sorted(untagged + keep) if untagged or keep else sorted(tagged)


def _apache(root: Path = ROOT) -> str:
    """The terms of the Apache License 2.0 as REMN's own LICENSE gives them, whitespace folded."""
    lines = (root / "LICENSE").read_text(encoding="utf-8").splitlines()
    end = next(i for i, ln in enumerate(lines) if "END OF TERMS AND CONDITIONS" in ln)
    return " ".join(" ".join(lines[: end + 1]).split())


def _without_apache(lines: list[str], terms: str) -> tuple[list[str], list[str]]:
    """The lines of a licence file with the Apache License's terms taken out, when they are the ones in LICENSE,
    and its appendix on how to apply the licence with them; and the copyright lines that appendix was filled in
    with. What else the file says stays. No copyright lines and the lines unchanged: not the Apache terms."""
    starts = [i for i, ln in enumerate(lines) if ln.strip() == "Apache License"]
    ends = [i for i, ln in enumerate(lines) if "END OF TERMS AND CONDITIONS" in ln]
    for start in starts:
        end = next((e for e in ends if e > start), None)
        if end is None or " ".join(" ".join(lines[start : end + 1]).split()) != terms:
            continue
        rest, holders = lines[end + 1 :], []
        first = next((i for i, ln in enumerate(rest) if ln.strip()), None)
        if first is not None and rest[first].strip().startswith("APPENDIX: How to apply the Apache License"):
            last = next((i for i, ln in enumerate(rest) if "limitations under the License." in ln), None)
            if last is not None:
                holders = [ln.strip() for ln in rest[: last + 1] if COPYRIGHT_LINE.match(ln)]
                rest = rest[last + 1 :]
        return lines[:start] + rest, holders or [""]
    return lines, []


def _split(text: str, terms: str = "") -> tuple[list[str], str]:
    """(the copyright lines at the head of a licence file, the rest of it). A copyright line further down is
    part of the text (the history in the Python licence, a component's notice in an appended section)."""
    lines = text.replace("\r\n", "\n").split("\n")
    lines, appendix = _without_apache(lines, terms) if terms else (lines, [])
    apache = bool(appendix)
    head = [i for i, ln in enumerate(lines[:HEAD]) if COPYRIGHT_LINE.match(ln)]
    holders = [lines[i].strip() for i in head] + [h for h in appendix if h]
    body = "\n".join(ln for i, ln in enumerate(lines) if i not in head).strip("\n")
    if apache:
        body = (APACHE_TEXT + "\n\n" + body).strip("\n")
    return holders, body


def texts(groups: list[tuple[str, dict[str, Package]]]) -> str:
    """One copy of each distinct licence text, with the copyright lines of each package carrying it."""
    terms = _apache()
    by_body: dict[str, dict] = {}
    notices: dict[str, str] = {}
    bare: list[str] = []
    for kind, packages in groups:
        for name in sorted(packages):
            p = packages[name]
            label = f"{kind} `{name}`"
            files = [f for d in p.dirs if d.is_dir() for f in licence_files(d, p.licence)]
            if not files:
                bare.append(f"- {label} ({p.licence}): the package carries no licence file")
                continue
            for f in files:
                text = f.read_text(encoding="utf-8", errors="replace")
                if f.name.lower().startswith("notice"):
                    notices.setdefault(f"{label}, {f.name}", text.strip("\n"))
                    continue
                holders, body = _split(text, terms)
                key = " ".join(body.split())
                if key:
                    group = by_body.setdefault(key, {"body": body, "label": chosen(p.licence)[0] if p.licence else "", "holders": {}})
                    lines = group["holders"].setdefault(label, [])
                    lines += [h for h in holders if h not in lines]
    out = [
        "Each licence text below is given once, after the copyright lines of the packages that carry it, as",
        "their licence files state them. Where a package offers a choice of licences, the text given is the one",
        "REMN takes (MIT before Apache-2.0, then the others). Where a file holds the terms of the Apache License",
        "2.0 word for word, they are not repeated: they are the terms in `LICENSE` at the root of this",
        "repository, and only what the file adds to them is given. NOTICE files, which the Apache License asks",
        "to be passed on, follow whole.",
        "",
    ]
    counts: collections.Counter[str] = collections.Counter()
    for group in sorted(by_body.values(), key=lambda g: (g["label"], min(g["holders"]))):
        counts[group["label"]] += 1
        out += [f"### {group['label'] or 'Licence'}, text {counts[group['label']]}", ""]
        # the packages whose copyright lines are the same, on one line
        same: dict[tuple[str, ...], list[str]] = {}
        for label, holders in group["holders"].items():
            same.setdefault(tuple(holders), []).append(label)
        for holders, labels in sorted(same.items(), key=lambda kv: kv[1]):
            out.append(f"- {', '.join(labels)}: " + ("; ".join(holders) if holders else "no copyright line at the top of the licence file"))
        out += ["", "```text", group["body"], "```", ""]
    if notices:
        out += ["### NOTICE files", ""]
        for label, text in notices.items():
            out += [f"{label}:", "", "```text", text, "```", ""]
    if bare:
        out += ["### Packages without a licence file", ""] + bare + [""]
    return "\n".join(out)


# ---- putting it together


def resolve(root: Path = ROOT, fetch: bool = False, with_texts: bool = False) -> tuple[dict[str, str], list[str]]:
    """The generated blocks for the current locks, and what could not be resolved."""
    current = blocks((root / NOTICES).read_text(encoding="utf-8"))
    problems: list[str] = []
    main, optional = python_packages(root)
    for block, packages in (("python", main), ("python-optional", optional)):
        known = table_rows(current.get(block, ""))
        for p in packages.values():
            found = installed_licence(p)
            if found is None and fetch:
                found = pypi_licence(p)
            if found is not None and found[0] is None:
                problems.append(f"{p.name}: the metadata says {found[1]!r}; read its licence file and add it to DECLARED")
            p.licence = (found[0] if found and found[0] else None) or known.get(p.name, [""])[0]
            if not p.licence:
                problems.append(f"{p.name}: no licence known; run with --fetch")
    npm = npm_packages(root)
    crates = crate_packages(root)
    known = table_rows(current.get("crates", ""))
    meta = cargo_metadata(root) if fetch or with_texts else {}
    for p in crates.values():
        declared = {meta[(p.name, v)].get("license") or "" for v in p.versions if (p.name, v) in meta}
        p.licence = " / ".join(sorted(x for x in declared if x)) or known.get(p.name, [""])[0]
        p.dirs = [Path(meta[(p.name, v)]["manifest_path"]).parent for v in p.versions if (p.name, v) in meta]
        if not p.licence:
            problems.append(f"crate {p.name}: no licence known; run with --fetch")
    for p in npm.values():
        if not p.licence:
            problems.append(f"npm {p.name}: package-lock.json records no licence")
    out = {
        "python": table(main, "Package", "Installed because of"),
        "python-optional": table(optional, "Package", "Installed because of"),
        "npm": table(npm, "Package", "Required by"),
        "crates": table(crates, "Crate", "Required by"),
    }
    if with_texts:
        missing = [p.name for p in npm.values() if not any(d.is_dir() for d in p.dirs)]
        if missing:
            problems.append(f"no installed npm packages for {', '.join(missing[:5])}: run npm ci in frontend/ first")
        out["texts"] = texts([("npm", npm), ("crate", crates)])
    return out, problems


def check(root: Path = ROOT) -> list[str]:
    """What the notices say that the locks, or the installed packages, do not."""
    text = (root / NOTICES).read_text(encoding="utf-8")
    current = blocks(text)
    fresh, problems = resolve(root)
    for name in ("python", "python-optional", "npm", "crates"):
        if name not in current:
            problems.append(f"{NOTICES} has no generated {name} block")
            continue
        have, want = table_rows(current[name]), table_rows(fresh[name])
        for package in sorted(set(have) | set(want)):
            if have.get(package) != want.get(package):
                problems.append(f"{name}: {package} reads {have.get(package)} where the locks give {want.get(package)}")
    for kind, packages in (("npm", npm_packages(root)), ("crate", crate_packages(root))):
        listed = set(re.findall(rf"\b{kind} `([^`]+)`", current.get("texts", "")))
        for name in sorted(set(packages) - listed):
            problems.append(f"texts: no licence text or copyright line for {kind} {name}; run with --texts")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--check", action="store_true", help="compare only, exit 1 on a difference")
    parser.add_argument("--fetch", action="store_true", help="ask PyPI and cargo for licences not known here")
    parser.add_argument("--texts", action="store_true", help="rewrite the licence texts too (needs npm ci and cargo)")
    args = parser.parse_args()
    if args.check:
        problems = check()
        print("\n".join(problems) or f"{NOTICES} agrees with the locks")
        return 1 if problems else 0
    fresh, problems = resolve(fetch=args.fetch, with_texts=args.texts)
    if problems:
        print("\n".join(problems), file=sys.stderr)
        return 1
    path = ROOT / NOTICES
    text = path.read_text(encoding="utf-8")
    for name, body in fresh.items():
        text = replace_block(text, name, body)
    path.write_text(text, encoding="utf-8")
    print(f"{NOTICES}: " + ", ".join(f"{name} written" for name in fresh))
    return 0


if __name__ == "__main__":
    sys.exit(main())
