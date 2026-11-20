"""docs/api.md lists every route under /api/, and only routes that exist. The route index on that page is
read as a table of method, route, what an account needs and whether a browser-only instance answers it,
and compared with the URL configuration: a route added without its line, a line left for a route that was
removed, or a method, a level or a mode that differs from the code fails here. Every /api/ path the other
pages name has to reach a route too.
"""

from __future__ import annotations

import re
from pathlib import Path

from django.test import RequestFactory
from django.urls import Resolver404, URLPattern, URLResolver, get_resolver, resolve

from forensic.access import declared
from forensic.middleware import BROWSER_ONLY_CLOSED

ROOT = Path(__file__).resolve().parents[2]
API_PAGE = ROOT / "docs" / "api.md"
METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
# one line of the route index: | GET | `/api/health` | signed-in | open |
INDEX_LINE = re.compile(r"^\| (GET|POST|PUT|PATCH|DELETE) \| `(/api/[^`]*)` \| ([a-z-]+) \| (open|closed) \|\s*$")
# the heading of a route's entry: **`GET /api/store/<key>/row?source=&id=`.**
ENTRY = re.compile(r"\*\*`(?:GET|POST|PUT|PATCH|DELETE) (/api/[^`?]*)")
# a path a page names, not one of another program (Ollama's http://127.0.0.1:11434/api/ps)
MENTION = re.compile(r"(?<![\w.:/-])/api/[A-Za-z0-9_<>/.-]*")


def _doc_route(pattern: str) -> str:
    """A Django route as the pages write it: /api/store/<key>/evidence/<evidence_id>."""
    return "/" + re.sub(r"<(?:\w+:)?(\w+)>", r"<\1>", pattern)


def _allowed(view) -> tuple[str, ...]:
    """The methods a view answers, read from the 405 its method decorator gives any other method:
    the decorator answers before the view runs, so nothing is read or written."""
    resp = view(RequestFactory().generic("PROPFIND", "/api/x"))
    assert resp.status_code == 405, f"{view.__module__}.{view.__name__} answers a method it does not name"
    return tuple(m.strip() for m in resp["Allow"].split(","))


def code_routes() -> dict[tuple[str, str], tuple[str, str]]:
    """(method, route) -> (the level an account needs, "open" or "closed" in browser-only mode)."""
    found: list[tuple[str, object]] = []

    def walk(patterns, prefix: str) -> None:
        for p in patterns:
            if isinstance(p, URLResolver):
                walk(p.url_patterns, prefix + str(p.pattern))
            elif isinstance(p, URLPattern):
                found.append((prefix + str(p.pattern), p.callback))

    walk(get_resolver().url_patterns, "")
    out: dict[tuple[str, str], tuple[str, str]] = {}
    for pattern, view in found:
        if not pattern.startswith("api/"):
            continue
        route = _doc_route(pattern)
        need = declared(view)
        mode = "closed" if route.startswith(BROWSER_ONLY_CLOSED) else "open"
        for method in _allowed(view):
            out[(method, route)] = (need.level(method) if need else "none", mode)
    return out


def documented_routes(text: str) -> dict[tuple[str, str], tuple[str, str]]:
    out: dict[tuple[str, str], tuple[str, str]] = {}
    for line in text.splitlines():
        if m := INDEX_LINE.match(line):
            out[(m.group(1), m.group(2))] = (m.group(3), m.group(4))
    return out


def differences(text: str, code: dict[tuple[str, str], tuple[str, str]]) -> list[str]:
    """What the page says that the code does not, in sentences."""
    doc = documented_routes(text)
    out = [f"{m} {r} is a route of the server and is missing from the route index of docs/api.md" for m, r in sorted(code.keys() - doc.keys())]
    out += [f"{m} {r} is in the route index of docs/api.md and is no route of the server" for m, r in sorted(doc.keys() - code.keys())]
    for key in sorted(doc.keys() & code.keys()):
        (said_level, said_mode), (level, mode) = doc[key], code[key]
        if said_level != level:
            out.append(f"{key[0]} {key[1]}: docs/api.md says it needs {said_level}, the route declares {level}")
        if said_mode != mode:
            out.append(f"{key[0]} {key[1]}: docs/api.md says it is {said_mode} in browser-only mode, the server has it {mode}")
    described = set(ENTRY.findall(text))
    out += [f"{r} has no entry of its own in docs/api.md" for r in sorted({r for _, r in code} - described)]
    return out


def dead_mentions(text: str) -> list[str]:
    """The /api/ paths a page names that reach no route."""
    out = []
    for path in MENTION.findall(text):
        path = path.rstrip(".")
        if path == "/api/":
            continue  # the prefix itself
        try:
            match = resolve(re.sub(r"<[^>]*>", "1", path))
        except Resolver404:
            out.append(path)
            continue
        if not match.route.startswith("api/"):
            out.append(path)
    return out


def _pages() -> list[Path]:
    # the dated reviews under docs/reviews/ describe the code of their day and are left as written
    return [ROOT / "README.md", ROOT / "SECURITY.md", ROOT / "CONTRIBUTING.md", *sorted((ROOT / "docs").glob("*.md"))]


def test_the_route_index_lists_every_route_with_its_methods_level_and_mode():
    code = code_routes()
    assert len({r for _, r in code}) > 50
    assert differences(API_PAGE.read_text(encoding="utf-8"), code) == []


def test_a_route_missing_from_the_page_or_named_after_it_is_gone_is_caught():
    code = code_routes()
    text = API_PAGE.read_text(encoding="utf-8")
    without = "\n".join(line for line in text.splitlines() if "`/api/store/<key>/stack`" not in line)
    assert "POST /api/store/<key>/stack is a route of the server and is missing from the route index of docs/api.md" in differences(without, code)
    gone = text + "\n| POST | `/api/store/<key>/vacuum` | write | closed |\n"
    assert "POST /api/store/<key>/vacuum is in the route index of docs/api.md and is no route of the server" in differences(gone, code)
    wrong = text.replace("| DELETE | `/api/store/<key>` | own | closed |", "| DELETE | `/api/store/<key>` | write | closed |")
    assert any("needs write, the route declares own" in line for line in differences(wrong, code))


def test_every_api_path_the_pages_name_reaches_a_route():
    dead = {page.relative_to(ROOT).as_posix(): found for page in _pages() if (found := dead_mentions(page.read_text(encoding="utf-8")))}
    assert dead == {}


def test_a_path_that_reaches_no_route_is_named():
    assert dead_mentions("call `/api/store/<key>/vacuum`, then `/api/jobs?case=<key>`") == ["/api/store/<key>/vacuum"]
    assert dead_mentions("Ollama answers on http://127.0.0.1:11434/api/ps.") == []
