"""THIRD_PARTY_NOTICES.md lists what the lock files ship, under the licences the packages declare, and names
every copyleft package where it says what copyleft means for an install. A package added to a lock without its
notice, or a licence that changes with a new version, fails here; tools/third_party_notices.py rewrites the lists.
"""

import importlib.util
import re
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LOCKS = (
    "THIRD_PARTY_NOTICES.md",
    "backend/requirements.txt",
    "backend/requirements-optional.txt",
    "frontend/package-lock.json",
    "frontend/wasm/evtx/Cargo.lock",
)


def _tool(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


notices = _tool("third_party_notices")


def _text() -> str:
    return (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")


def _section(text: str, heading: str) -> str:
    return text.split(f"\n## {heading}\n", 1)[1].split("\n## ", 1)[0]


def _normal(text: str) -> str:
    # dissect.target in prose is dissect-target in a lock
    return re.sub(r"[-_.]+", "-", text.lower())


@pytest.fixture
def copy(tmp_path):
    """The notices and the locks, in a directory of their own, to be changed."""
    for name in LOCKS:
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / name, tmp_path / name)
    return tmp_path


def test_the_notices_agree_with_the_lock_files_and_the_installed_packages():
    assert notices.check() == []


def test_every_copyleft_package_is_named_where_the_notices_explain_copyleft():
    text = _text()
    explained = _normal(_section(text, "Copyleft components"))
    generated = notices.blocks(text)
    copyleft = [
        package
        for block in ("python", "python-optional", "npm", "crates")
        for package, cells in notices.table_rows(generated[block]).items()
        if notices.copyleft_only(cells[0])
    ]
    assert {"extract-msg", "dissect-target", "libpff-python"} <= set(copyleft)
    assert [p for p in copyleft if _normal(p) not in explained] == []


def test_a_package_added_to_a_lock_without_its_notice_is_caught(copy):
    requirements = copy / "backend" / "requirements.txt"
    requirements.write_text(
        requirements.read_text(encoding="utf-8")
        + "an-invented-package==1.0 \\\n    --hash=sha256:"
        + "0" * 64
        + "\n    # via -r backend/requirements.ranges\n",
        encoding="utf-8",
    )
    lock = copy / "frontend" / "package-lock.json"
    lock.write_text(
        lock.read_text(encoding="utf-8").replace(
            '"packages": {', '"packages": {\n    "node_modules/an-invented-module": {"version": "1.0.0", "license": "MIT"},', 1
        ),
        encoding="utf-8",
    )
    cargo = copy / "frontend" / "wasm" / "evtx" / "Cargo.lock"
    cargo.write_text(
        cargo.read_text(encoding="utf-8")
        + '\n[[package]]\nname = "an-invented-crate"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n',
        encoding="utf-8",
    )
    problems = "\n".join(notices.check(copy))
    for name in ("an-invented-package", "an-invented-module", "an-invented-crate"):
        assert name in problems


def test_a_licence_the_installed_package_does_not_declare_is_caught(copy):
    path = copy / "THIRD_PARTY_NOTICES.md"
    path.write_text(path.read_text(encoding="utf-8").replace("| `django` | BSD-3-Clause |", "| `django` | MIT |"), encoding="utf-8")
    assert any(line.startswith("python: django") for line in notices.check(copy))


def test_vague_metadata_names_no_licence_until_the_licence_file_has_been_read():
    assert notices.licence_from_metadata("an-invented-package", None, "BSD", []) is None
    assert notices.licence_from_metadata("an-invented-package", None, "GPL", ["License :: OSI Approved :: GNU General Public License v3 (GPLv3)"]) is None
    assert notices.licence_from_metadata("oletools", None, "BSD", []) == "BSD-2-Clause"
    # a new version that says something else about its licence is read again, not taken on the old reading
    assert notices.licence_from_metadata("oletools", None, "GPL", []) is None
    assert notices.licence_from_metadata("an-invented-package", None, "MIT License", []) == "MIT"
    assert notices.licence_from_metadata("an-invented-package", "Apache-2.0 OR MIT", "BSD", []) == "Apache-2.0 OR MIT"


def test_a_licence_with_a_permissive_choice_is_not_copyleft_only():
    assert notices.copyleft_only("GPL-3.0-or-later") and notices.copyleft_only("AGPL-3.0-or-later")
    assert notices.copyleft_only("LGPL-2.1-or-later") and notices.copyleft_only("MPL-2.0")
    assert not notices.copyleft_only("(MPL-2.0 OR Apache-2.0)")
    assert not notices.copyleft_only("MIT OR Apache-2.0 OR LGPL-2.1-or-later")
    assert not notices.copyleft_only("BSD-2-Clause AND public domain")


def test_the_hayabusa_the_image_downloads_is_the_one_the_notices_name():
    version = re.search(r"^ARG HAYABUSA_VERSION=(\S+)", (ROOT / "Dockerfile").read_text(encoding="utf-8"), re.MULTILINE).group(1)
    section = " ".join(_section(_text(), "Hayabusa, in the Docker image").split())
    assert f"Hayabusa {version} " in section
    assert f"hayabusa/tree/v{version}" in section and f"hayabusa/blob/v{version}/LICENSE.txt" in section
