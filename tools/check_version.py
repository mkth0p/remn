"""One version, said the same way everywhere a release reads it.

    python tools/check_version.py              the files agree with each other
    python tools/check_version.py --tag v0.2.0 and with the tag being released

backend/forensic/build.py is the version the server reports; frontend/package.json and its lock
carry the same number, and CHANGELOG.md has a dated section for it. The release workflow runs
this against the tag before it builds anything, and the test suite runs it on every change, so a
tag that does not match the code fails in the first minute and not after an archive is published.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = re.compile(r"^\d+\.\d+\.\d+$")
SECTION = re.compile(r"^## (\d+\.\d+\.\d+) \((\d{4}-\d{2}-\d{2})\)\s*$", re.MULTILINE)


def code_version(root: Path = ROOT) -> str:
    text = (root / "backend" / "forensic" / "build.py").read_text(encoding="utf-8")
    m = re.search(r'^VERSION = "([^"]+)"', text, re.MULTILINE)
    return m.group(1) if m else ""


def changelog_sections(root: Path = ROOT) -> dict[str, str]:
    """Released version -> its date, from the section headings."""
    return dict(SECTION.findall((root / "CHANGELOG.md").read_text(encoding="utf-8")))


def changelog_notes(version: str, root: Path = ROOT) -> str:
    """The text under a version's heading, up to the next one: the release notes."""
    lines = (root / "CHANGELOG.md").read_text(encoding="utf-8").splitlines()
    out: list[str] = []
    inside = False
    for line in lines:
        if line.startswith("## "):
            if inside:
                break
            m = SECTION.match(line)
            inside = bool(m and m.group(1) == version)
            continue
        if inside:
            out.append(line)
    return "\n".join(out).strip() + "\n" if inside or out else ""


def problems(tag: str | None = None, root: Path = ROOT) -> list[str]:
    found: list[str] = []
    code = code_version(root)
    if not VERSION.match(code):
        found.append(f"backend/forensic/build.py: VERSION is {code!r}, expected three numbers")
    package = json.loads((root / "frontend" / "package.json").read_text(encoding="utf-8")).get("version", "")
    if package != code:
        found.append(f"frontend/package.json says {package}, backend/forensic/build.py says {code}")
    lock = json.loads((root / "frontend" / "package-lock.json").read_text(encoding="utf-8"))
    for where, value in (("version", lock.get("version", "")), ('packages[""].version', lock.get("packages", {}).get("", {}).get("version", ""))):
        if value != code:
            found.append(f"frontend/package-lock.json {where} says {value}, backend/forensic/build.py says {code}")
    if code not in changelog_sections(root):
        found.append(f"CHANGELOG.md has no section '## {code} (YYYY-MM-DD)'")
    if tag is not None:
        if tag != f"v{code}":
            found.append(f"the tag is {tag}, the code is version {code}: the tag must be v{code}")
        elif not changelog_notes(code, root).strip():
            found.append(f"CHANGELOG.md has nothing under '## {code}'")
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--tag", help="the tag being released, e.g. v0.2.0")
    parser.add_argument("--notes", type=Path, help="write the changelog section of this version to a file")
    args = parser.parse_args()
    found = problems(args.tag)
    for line in found:
        print(line, file=sys.stderr)
    if found:
        return 1
    version = code_version()
    if args.notes:
        args.notes.write_text(changelog_notes(version), encoding="utf-8")
    print(version)
    return 0


if __name__ == "__main__":
    sys.exit(main())
