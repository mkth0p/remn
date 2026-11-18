"""An install reads the lock, so the lock has to be whole and has to be what the ranges ask for.

backend/requirements.txt, requirements-dev.txt and requirements-optional.txt are written by
tools/lock_requirements.sh from the three .ranges files. A bump that edits a pin by hand, or by a
bot, can leave them apart: these tests say so before a fresh install does.
"""

import re
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

BACKEND = Path(__file__).resolve().parents[2] / "backend"
PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)")


def _ranges(name: str) -> list[Requirement]:
    lines = (BACKEND / name).read_text(encoding="utf-8").splitlines()
    return [Requirement(line) for line in lines if line.strip() and not line.lstrip().startswith(("#", "-c "))]


def _lock(name: str) -> dict[str, tuple[Version, int]]:
    """Package -> (pinned version, number of hashes), from a lock file."""
    out: dict[str, tuple[Version, int]] = {}
    current = None
    for line in (BACKEND / name).read_text(encoding="utf-8").splitlines():
        m = PIN.match(line)
        if m:
            current = canonicalize_name(m.group(1))
            out[current] = (Version(m.group(2)), 0)
        elif current and "--hash=sha256:" in line:
            version, hashes = out[current]
            out[current] = (version, hashes + 1)
    return out


@pytest.mark.parametrize(
    ("ranges", "locks"),
    [
        ("requirements.ranges", ["requirements.txt"]),
        ("requirements-dev.ranges", ["requirements-dev.txt", "requirements.txt"]),
        ("requirements-optional.ranges", ["requirements-optional.txt"]),
    ],
)
def test_every_range_is_met_by_the_version_the_lock_pins(ranges, locks):
    pinned: dict[str, tuple[Version, int]] = {}
    for lock in locks:
        pinned.update(_lock(lock))
    for req in _ranges(ranges):
        name = canonicalize_name(req.name)
        assert name in pinned, f"{req.name} is in {ranges} and not in {locks[0]}: run tools/lock_requirements.sh"
        version = pinned[name][0]
        assert req.specifier.contains(version, prereleases=True), (
            f"{locks[0]} pins {req.name} {version}, outside {req.specifier} in {ranges}: change the range and run tools/lock_requirements.sh"
        )


@pytest.mark.parametrize("lock", ["requirements.txt", "requirements-dev.txt", "requirements-optional.txt"])
def test_every_pin_carries_a_hash(lock):
    pinned = _lock(lock)
    assert pinned, f"{lock} pins nothing"
    bare = sorted(name for name, (_, hashes) in pinned.items() if hashes == 0)
    assert not bare, f"{lock} has pins without a hash: {bare}"


def test_the_ranges_all_have_an_upper_bound():
    """A range without one is how a release upstream broke every fresh install."""
    for name in ("requirements.ranges", "requirements-dev.ranges", "requirements-optional.ranges"):
        for req in _ranges(name):
            bounded = any(s.operator in ("<", "<=", "==", "~=") for s in req.specifier)
            assert bounded, f"{req.name} in {name} has no upper bound"


@pytest.mark.parametrize("other", ["requirements-dev.txt", "requirements-optional.txt"])
def test_the_other_locks_do_not_contradict_the_runtime_lock(other):
    """They are installed into the same environment, so a package in two of them has one version."""
    runtime, second = _lock("requirements.txt"), _lock(other)
    for name in runtime.keys() & second.keys():
        assert runtime[name][0] == second[name][0], f"{name} is pinned at two versions"


def test_the_optional_lock_names_what_the_code_imports_optionally():
    """PST, YARA and 7z support are imported inside a try: each has to be installable from the lock."""
    optional = _lock("requirements-optional.txt")
    for package in ("libpff-python", "yara-python", "py7zr"):
        assert package in optional, f"{package} is not in requirements-optional.txt"
