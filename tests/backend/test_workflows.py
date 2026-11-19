"""What the workflows may do, and what they run, is fixed in the files and not left to defaults.

A workflow without a permissions block gets whatever the repository's default token is allowed,
and an action named by tag runs whatever that tag points at on the day. Both are decided here
instead: read-only unless a job says otherwise, and every action at a commit.
"""

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
USES = re.compile(r"^\s*(?:-\s+)?uses:\s*(\S+)(?:\s+#\s*(\S+))?\s*$", re.MULTILINE)
WRITE_SCOPES = {
    # workflow file -> job -> the write permissions that job may hold
    "release.yml": {
        "image": {"packages", "id-token", "attestations"},
        "publish": {"contents", "id-token", "attestations"},
    },
    "scheduled-report.yml": {"report": {"issues"}},
}


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_there_are_workflows_to_check():
    assert {p.name for p in WORKFLOWS} >= {"ci.yml", "measure-rules.yml", "release.yml", "scheduled-report.yml"}


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_a_workflow_starts_from_read_only(path):
    permissions = _load(path).get("permissions")
    assert permissions == {"contents": "read"}, f"{path.name}: the top-level permissions are {permissions!r}, expected contents: read only"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_only_the_named_jobs_may_write_and_only_what_is_named(path):
    allowed = WRITE_SCOPES.get(path.name, {})
    for job, body in _load(path)["jobs"].items():
        writes = {scope for scope, level in (body.get("permissions") or {}).items() if level == "write"}
        assert writes <= allowed.get(job, set()), f"{path.name}: job {job} asks to write {sorted(writes - allowed.get(job, set()))}"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_every_action_is_pinned_to_a_commit_with_its_version_beside_it(path):
    used = USES.findall(path.read_text(encoding="utf-8"))
    for reference, comment in used:
        if reference.startswith("./"):
            # a workflow of this repository, at the commit being run
            continue
        action, _, ref = reference.partition("@")
        assert re.fullmatch(r"[0-9a-f]{40}", ref), f"{path.name}: {action} is pinned to {ref!r}, not to a commit"
        assert re.fullmatch(r"v\d+(\.\d+){0,2}", comment), f"{path.name}: {action} has no version comment for Dependabot to raise"


def test_one_action_is_pinned_at_one_commit_everywhere():
    seen: dict[str, set[str]] = {}
    for path in WORKFLOWS:
        for reference, _ in USES.findall(path.read_text(encoding="utf-8")):
            if not reference.startswith("./"):
                action, _, ref = reference.partition("@")
                seen.setdefault(action, set()).add(ref)
    split = {action: refs for action, refs in seen.items() if len(refs) > 1}
    assert not split, f"pinned at more than one commit: {split}"


def test_a_checkout_does_not_leave_the_job_token_in_the_working_copy():
    for path in WORKFLOWS:
        for job, body in _load(path)["jobs"].items():
            for step in body.get("steps") or []:
                if str(step.get("uses", "")).startswith("actions/checkout@"):
                    assert (step.get("with") or {}).get("persist-credentials") is False, f"{path.name}: job {job} checks out with the token persisted"


def test_only_a_tag_publishes():
    release = _load(ROOT / ".github" / "workflows" / "release.yml")
    # PyYAML reads the key "on" as the boolean True
    triggers = release.get("on", release.get(True))
    assert triggers == {"push": {"tags": ["v*"]}}
