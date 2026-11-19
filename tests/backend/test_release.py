"""What a release is made from: one version said everywhere, and a list of what it contains."""

import importlib.util
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _tool(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


check_version = _tool("check_version")
sbom = _tool("sbom")


def test_the_repository_states_one_version():
    assert check_version.problems() == []


def test_a_tag_that_is_not_the_code_version_is_refused():
    version = check_version.code_version()
    assert check_version.problems(tag=f"v{version}") == []
    wrong = check_version.problems(tag="v99.0.0")
    assert wrong and "v99.0.0" in wrong[0]
    assert check_version.problems(tag=version), "a tag without the leading v is not a release tag"


def test_the_release_notes_are_the_changelog_section_of_the_version():
    version = check_version.code_version()
    notes = check_version.changelog_notes(version)
    assert notes.strip()
    assert "\n## " not in notes and not notes.startswith("## ")


def _copy_tree_for_version(tmp_path: Path, version_in_package: str) -> Path:
    (tmp_path / "backend" / "forensic").mkdir(parents=True)
    (tmp_path / "frontend").mkdir()
    (tmp_path / "backend" / "forensic" / "build.py").write_text('VERSION = "1.2.3"\n', encoding="utf-8")
    (tmp_path / "frontend" / "package.json").write_text(json.dumps({"version": version_in_package}), encoding="utf-8")
    (tmp_path / "frontend" / "package-lock.json").write_text(json.dumps({"version": "1.2.3", "packages": {"": {"version": "1.2.3"}}}), encoding="utf-8")
    (tmp_path / "CHANGELOG.md").write_text(
        "# Changelog\n\n## Unreleased\n\n- next\n\n## 1.2.3 (2026-01-02)\n\n- done\n\n## 1.2.2 (2026-01-01)\n\n- before\n", encoding="utf-8"
    )
    return tmp_path


def test_a_version_that_differs_between_the_server_and_the_frontend_is_named(tmp_path):
    root = _copy_tree_for_version(tmp_path, "1.2.4")
    found = check_version.problems(root=root)
    assert len(found) == 1 and "package.json says 1.2.4" in found[0]


def test_a_version_without_a_dated_changelog_section_is_named(tmp_path):
    root = _copy_tree_for_version(tmp_path, "1.2.3")
    assert check_version.problems(tag="v1.2.3", root=root) == []
    assert check_version.changelog_notes("1.2.3", root) == "- done\n"
    (root / "CHANGELOG.md").write_text("# Changelog\n\n## Unreleased\n\n- next\n", encoding="utf-8")
    assert any("no section" in line for line in check_version.problems(root=root))


def test_the_bill_of_materials_lists_every_pinned_package_once():
    bom = sbom.build("0.0.0")
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.5"
    refs = [c["bom-ref"] for c in bom["components"]]
    assert len(refs) == len(set(refs))
    by_group: dict[str, set[str]] = {}
    for component in bom["components"]:
        assert component["name"] and component["version"]
        assert component["purl"].endswith("@" + component["version"].removeprefix("v")) or component["purl"].endswith("@v" + component["version"])
        by_group.setdefault(component["group"], set()).add(component["name"])
    pin = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==", re.MULTILINE)
    runtime = {re.sub(r"[-_.]+", "-", n).lower() for n in pin.findall((ROOT / "backend" / "requirements.txt").read_text(encoding="utf-8"))}
    assert by_group["backend"] == runtime
    assert {"libpff-python", "yara-python", "py7zr"} <= by_group["backend-optional"]
    assert "react" in by_group["frontend"] and "typescript" not in by_group["frontend"], "packages of the build, not of the toolchain"
    assert "evtx" in by_group["evtx-decoder"]
    assert by_group["image"] == {"hayabusa"}


def test_a_release_archive_reports_the_commit_it_was_packed_from(tmp_path, monkeypatch):
    from forensic import build

    commit = "0123456789abcdef0123456789abcdef01234567"
    (tmp_path / "BUILD_ID").write_text(commit + "\n", encoding="utf-8")
    assert build._packed_commit(tmp_path) == commit
    (tmp_path / "BUILD_ID").write_text("not a commit\n", encoding="utf-8")
    assert build._packed_commit(tmp_path) == ""
    assert build._packed_commit(tmp_path / "missing") == ""
    # the environment and a checkout still come first
    monkeypatch.setenv("REMN_BUILD_ID", "f" * 40)
    build.commit.cache_clear()
    try:
        assert build.commit() == "f" * 40
    finally:
        build.commit.cache_clear()
