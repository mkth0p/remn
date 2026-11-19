"""backend/run.py does not start where other machines can reach it without an access token, unless
the operator says that this is intended. In a container it judges the address the port is
published on, which the compose files pass in. Every address below is invented or a loopback."""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

import pytest
import yaml
from django.test import override_settings

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

import run  # noqa: E402


@pytest.mark.parametrize("address", ["127.0.0.1", "127.8.9.10", "::1", "[::1]", "localhost", "LocalHost"])
def test_a_loopback_address_is_recognised(address):
    assert run._loopback(address)


@pytest.mark.parametrize("address", ["0.0.0.0", "::", "192.0.2.10", "2001:db8::10", "remn.example", ""])
def test_any_other_address_is_reachable_from_elsewhere(address):
    assert not run._loopback(address)


@override_settings(FORENSIC_AUTH_TOKEN="", FORENSIC_ALLOW_NO_TOKEN=False, FORENSIC_PUBLISHED_ON="", FORENSIC_BROWSER_ONLY=False)
def test_without_a_token_the_server_refuses_an_address_others_reach_and_names_the_choices():
    said = run.refusal("0.0.0.0")
    assert said is not None and said.startswith("[!] Not starting: the server would be reachable on 0.0.0.0 without an access token.")
    for choice in ("FORENSIC_AUTH_TOKEN", "REMN_TOKEN", "FORENSIC_PUBLISHED_ON=127.0.0.1", "FORENSIC_ALLOW_NO_TOKEN=1", "REMN_NO_TOKEN=1", "docs/setup.md"):
        assert choice in said
    assert "read and delete every case" in said
    assert run.refusal("127.0.0.1") is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"FORENSIC_AUTH_TOKEN": "invented-token"},
        {"FORENSIC_ALLOW_NO_TOKEN": True},
        {"FORENSIC_PUBLISHED_ON": "127.0.0.1"},
    ],
)
def test_a_token_a_stated_choice_or_a_loopback_publication_lets_it_start(overrides):
    base = {"FORENSIC_AUTH_TOKEN": "", "FORENSIC_ALLOW_NO_TOKEN": False, "FORENSIC_PUBLISHED_ON": ""}
    with override_settings(**{**base, **overrides}):
        assert run.refusal("0.0.0.0") is None


@override_settings(FORENSIC_AUTH_TOKEN="", FORENSIC_ALLOW_NO_TOKEN=False, FORENSIC_PUBLISHED_ON="0.0.0.0")
def test_in_a_container_the_published_address_is_judged_not_the_one_listened_on():
    said = run.refusal("127.0.0.1")
    assert said is not None and "reachable on 0.0.0.0" in said


@override_settings(FORENSIC_AUTH_TOKEN="", FORENSIC_ALLOW_NO_TOKEN=False, FORENSIC_PUBLISHED_ON="", FORENSIC_BROWSER_ONLY=True)
def test_a_browser_only_instance_has_to_say_it_is_open_on_purpose():
    said = run.refusal("0.0.0.0")
    assert said is not None and "keeps no cases" in said


@pytest.fixture
def started(monkeypatch):
    """main() with waitress replaced, and the process state it changes put back."""
    import waitress

    calls: list[dict] = []
    monkeypatch.setattr(waitress, "serve", lambda app, **kw: calls.append(kw))
    monkeypatch.setattr(tempfile, "tempdir", tempfile.tempdir)
    monkeypatch.setenv("FORENSIC_THREADS", "8")
    return calls


def test_run_exits_with_code_2_before_it_listens(started, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["run.py", "--host", "0.0.0.0", "--port", "8000"])
    with override_settings(FORENSIC_AUTH_TOKEN="", FORENSIC_ALLOW_NO_TOKEN=False, FORENSIC_PUBLISHED_ON=""):
        with pytest.raises(SystemExit) as stopped:
            run.main()
    assert stopped.value.code == 2 and started == []
    assert "Not starting" in capsys.readouterr().err


def test_run_listens_when_running_open_is_stated_and_says_so(started, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["run.py", "--host", "0.0.0.0", "--port", "8000"])
    with override_settings(FORENSIC_AUTH_TOKEN="", FORENSIC_ALLOW_NO_TOKEN=True, FORENSIC_PUBLISHED_ON=""):
        run.main()
    assert [c["host"] for c in started] == ["0.0.0.0"]
    assert "as FORENSIC_ALLOW_NO_TOKEN says is intended" in capsys.readouterr().out


def _compose(name: str) -> dict:
    return yaml.safe_load((ROOT / name).read_text(encoding="utf-8"))


def test_the_default_compose_file_tells_the_server_where_its_port_is_published():
    service = _compose("docker-compose.yml")["services"]["remn"]
    (published,) = service["ports"]
    env = service["environment"]
    # the same variable, with the same default, decides both
    assert published.startswith("${REMN_BIND:-127.0.0.1}:")
    assert env["FORENSIC_PUBLISHED_ON"] == "${REMN_BIND:-127.0.0.1}"
    assert env["FORENSIC_AUTH_TOKEN"] == "${REMN_TOKEN:-}" and env["FORENSIC_ALLOW_NO_TOKEN"] == "${REMN_NO_TOKEN:-}"


@pytest.mark.parametrize("name", ["docker-compose.open.yml", "docker-compose.public.yml"])
def test_the_compose_files_that_run_open_by_design_say_so(name):
    env = _compose(name)["services"]["remn"]["environment"]
    assert env["FORENSIC_AUTH_TOKEN"] == "" and env["FORENSIC_ALLOW_NO_TOKEN"] == "1"


def test_the_image_listens_on_every_interface_of_the_container():
    cmd = [line for line in (ROOT / "Dockerfile").read_text(encoding="utf-8").splitlines() if line.startswith("CMD ")]
    assert cmd == ['CMD ["python", "backend/run.py", "--host", "0.0.0.0", "--port", "8000"]']


def _docker_runs_of_the_image() -> list[tuple[str, str]]:
    """Every documented `docker run` of the application image that publishes a port."""
    sources = [ROOT / "Dockerfile", ROOT / "README.md", ROOT / ".github" / "workflows" / "ci.yml", *sorted((ROOT / "docs").glob("*.md"))]
    found = []
    for path in sources:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip().lstrip("#").strip()
            if not line.startswith("docker run") or " -p " not in f" {line} ":
                continue
            words = line.split("|")[0].split()
            image = next((w for w in reversed(words) if not w.startswith("-") and re.fullmatch(r"remn(:\w+)?", w)), None)
            if image:
                found.append((path.name, line))
    return found


def test_a_documented_docker_run_of_the_image_says_how_its_port_is_published():
    runs = _docker_runs_of_the_image()
    assert {name for name, _ in runs} >= {"Dockerfile", "ci.yml"}
    for name, line in runs:
        assert "-p 127.0.0.1:" in line and "-e FORENSIC_PUBLISHED_ON=127.0.0.1" in line, (name, line)
