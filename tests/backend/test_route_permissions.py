"""Every API route declares what it needs, so that with accounts on no route answers without the
access check. A new route without a declaration fails here, and is refused by the server."""

from __future__ import annotations

from django.http import JsonResponse
from django.test import Client, override_settings
from django.urls import URLPattern, URLResolver, get_resolver, path
from team_server import team  # noqa: F401 - the fixture

from forensic.access import CASE_LEVELS, LEVELS, declared


def _api_routes() -> list[tuple[str, object]]:
    """(route, view) for every pattern under /api/."""
    out: list[tuple[str, object]] = []

    def walk(patterns, prefix: str) -> None:
        for p in patterns:
            if isinstance(p, URLResolver):
                walk(p.url_patterns, prefix + str(p.pattern))
            elif isinstance(p, URLPattern):
                out.append((prefix + str(p.pattern), p.callback))

    walk(get_resolver().url_patterns, "")
    return [(route, view) for route, view in out if route.startswith("api/")]


def test_every_api_route_declares_what_it_needs():
    routes = _api_routes()
    assert len(routes) > 50
    undeclared = [route for route, view in routes if declared(view) is None]
    assert not undeclared, f"routes with no @permission: {undeclared}"
    for route, view in routes:
        need = declared(view)
        assert set(need.levels.values()) <= set(LEVELS), route


def test_a_route_that_names_a_case_checks_access_to_that_case():
    # the case key alone does not open a store: every route with one in its path checks the case
    for route, view in _api_routes():
        if "<str:key>" in route:
            need = declared(view)
            assert need.case == "url" and set(need.levels.values()) <= set(CASE_LEVELS), route
    # the routes that take the key in the query or the body check it too
    by_route = dict(_api_routes())
    for route in ("api/jobs", "api/jobs/<str:job_id>", "api/jobs/<str:job_id>/events"):
        assert declared(by_route[route]).case == "query"
    for route in ("api/stories/build", "api/relationships/build", "api/enrich/mails", "api/enrich/mails/rescore"):
        assert declared(by_route[route]).case == "body"


def test_evidence_coming_in_needs_an_analyst_and_the_audit_log_is_admin_only():
    by_route = dict(_api_routes())
    for route in ("api/ingest/evtx", "api/ingest/mail", "api/ingest/package", "api/analyze/attachment", "api/upload/init", "api/reputation/lookup"):
        assert declared(by_route[route]).levels == {"*": "work"}, route
    for route in ("api/audit", "api/audit/verify"):
        assert declared(by_route[route]).levels == {"*": "admin"}, route


def _undeclared(request):
    return JsonResponse({"answered": True})


urlpatterns = [path("api/undeclared", _undeclared)]


@override_settings(ROOT_URLCONF=__name__)
def test_a_route_without_a_declaration_is_refused_while_accounts_are_on(team):  # noqa: F811
    r = Client().get("/api/undeclared", **team.headers("root"))
    assert r.status_code == 403 and r.json()["code"] == "undeclared"


@override_settings(ROOT_URLCONF=__name__, FORENSIC_ACCOUNTS_FILE="/nonexistent/accounts.json")
def test_without_accounts_an_undeclared_route_answers_as_before():
    r = Client().get("/api/undeclared", HTTP_X_FORENSIC_CLIENT="remn")
    assert r.status_code == 200 and r.json() == {"answered": True}
