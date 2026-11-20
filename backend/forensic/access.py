"""
What each API route needs, and whether a request's account has it.

Every view under /api/ declares its need with @permission. With accounts on, AccessMiddleware
refuses a request whose account lacks it before the view runs, and refuses every request to a view
that declares nothing, so a new route cannot skip the check (tests/backend/test_route_permissions.py
also fails on one). With accounts off nothing here is consulted and the server behaves as before.

The levels:
- "signed-in": any account, whatever its role;
- "work": an analyst or an admin (adds evidence, sends indicators to providers);
- "admin": an admin only;
- "read": a member of the case, of any role, its owner, or an admin;
- "write": an analyst who owns the case or is a member of it, or an admin;
- "own": the case's owner, while an analyst, or an admin (membership, deleting the case).

The case is named in the URL (`key`), in the query (`?case=`, the job routes) or in the JSON body
(`storeKey`, the routes that also build from rows the page posts; without one they read no case and
need "signed-in"). A route declared with create=True registers a case nobody has recorded yet, and
that has no store on disk, with the account that writes to it first as its owner. A store written
before accounts were turned on has no record: only an admin opens it until an owner is given.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from django.http import HttpRequest, JsonResponse

from forensic.accounts import Account, store

LEVELS = ("signed-in", "work", "admin", "read", "write", "own")
CASE_LEVELS = ("read", "write", "own")
CASE_SOURCES = ("url", "query", "body")
SAFE_METHODS = ("GET", "HEAD")


@dataclass(frozen=True)
class Need:
    """A route's declared need: the level per method ("*" for any), where its case is named, whether
    a write registers a new case, and which of its requests go to the audit log: True or False for
    all of them, a tuple of methods, or None for those that change something, by method and level."""

    levels: dict[str, str]
    case: str | None
    create: bool
    record: bool | tuple[str, ...] | None

    def level(self, method: str) -> str | None:
        return self.levels.get(method, self.levels.get("*"))


def permission(level: str | dict[str, str], *, case: str | None = None, create: bool = False, record: bool | tuple[str, ...] | None = None) -> Callable:
    """Declare what a view needs. `level` is one of LEVELS, or {method: level}."""
    levels = dict(level) if isinstance(level, dict) else {"*": level}
    if any(v not in LEVELS for v in levels.values()):
        raise ValueError(f"unknown level in {levels}; the levels are {LEVELS}")
    if case is not None and case not in CASE_SOURCES:
        raise ValueError(f"case is one of {CASE_SOURCES}")
    if any(v in CASE_LEVELS for v in levels.values()) and case is None:
        raise ValueError("a case level needs the place the case is named (case=...)")
    need = Need(levels=levels, case=case, create=create, record=record)

    def mark(view: Callable) -> Callable:
        view.remn_permission = need  # type: ignore[attr-defined]
        return view

    return mark


def declared(view: Callable | None) -> Need | None:
    return getattr(view, "remn_permission", None)


def case_key(request: HttpRequest, need: Need, kwargs: dict[str, Any]) -> str | None:
    """The case a request names, read as its view reads it."""
    cached = getattr(request, "_remn_case", False)
    if cached is not False:
        return cached
    key: str | None = None
    if need.case == "url":
        key = str(kwargs.get("key") or "") or None
    elif need.case == "query":
        key = request.GET.get("case") or None
    elif need.case == "body":
        try:
            raw = request.body
        except Exception:  # noqa: BLE001 - a body already read as a stream names no case here
            raw = b""
        # a body of posted rows can be large: it is parsed only when it may name a case at all
        if b'"storeKey"' in raw:
            try:
                body = json.loads(raw)
            except ValueError:
                body = None
            if isinstance(body, dict) and body.get("storeKey"):
                key = str(body["storeKey"])
    request._remn_case = key  # type: ignore[attr-defined]
    return key


def level_of(request: HttpRequest, need: Need, key: str | None) -> str | None:
    """The level this request needs: the method's, or "signed-in" for a body that names no case."""
    level = need.level(request.method or "GET")
    if level is not None and need.case == "body" and not key:
        return "signed-in"
    return level


def recorded(request: HttpRequest, need: Need, level: str | None) -> bool:
    """Whether the audit log records this request when it is answered."""
    method = request.method or "GET"
    if isinstance(need.record, tuple):
        return method in need.record
    if need.record is not None:
        return need.record
    return method not in SAFE_METHODS and level not in (None, "signed-in", "read")


def may(account: Account, level: str, record: dict[str, Any] | None) -> bool:
    """Whether `account` has `level` on a case with this record (None: no case, or none recorded)."""
    if account.role == "admin":
        return True
    if level == "signed-in":
        return True
    if level == "work":
        return account.role == "analyst"
    if level == "admin" or record is None:
        return False
    owner = record.get("owner") == account.name
    if not owner and account.name not in (record.get("members") or []):
        return False
    if level == "read":
        return True
    if level == "write":
        return account.role == "analyst"
    return level == "own" and owner and account.role == "analyst"


def unknown_case() -> JsonResponse:
    # the same answer for a key nobody uses and for a case of other accounts, so neither is told apart
    return JsonResponse({"error": "unknown case, or one this account is not a member of", "code": "caseAccess"}, status=404)


def refused(account: Account, level: str) -> JsonResponse:
    if level == "admin":
        why = "this needs an admin account"
    elif account.role == "viewer":
        why = "this account is a viewer: it reads the cases it is a member of and changes nothing"
    elif level == "own":
        why = "only the case's owner or an admin may do this"
    else:
        why = "this needs an analyst or an admin account"
    return JsonResponse({"error": why, "code": "role", "role": account.role}, status=403)


def check(request: HttpRequest, need: Need, kwargs: dict[str, Any]) -> JsonResponse | None:
    """None when the request's account may make it, else the answer that refuses it. A case new to
    the server is registered here, before its view runs, when the route creates cases."""
    account: Account | None = getattr(request, "account", None)
    if account is None:
        return JsonResponse({"error": "this server has accounts: a personal access token is required", "code": "auth", "accounts": True}, status=401)
    key = case_key(request, need, kwargs)
    level = level_of(request, need, key)
    if level is None:
        return None  # a method the view does not answer; the view says so
    if level not in CASE_LEVELS:
        return None if may(account, level, None) else refused(account, level)
    if level != "read" and not may(account, "work", None):
        # a viewer changes no case: the same answer for every key, so it tells nothing about one
        return refused(account, level)
    from services.store.casestore import KEY_RE, registry

    if not key or not KEY_RE.match(key):
        return None  # the view answers a malformed key; nothing can be opened with it
    accounts = store()
    record = accounts.case(key)
    if record is None and need.create and level in ("write", "own") and may(account, "work", None) and not registry.exists(key):
        record = accounts.register_case(key, account.name)
    if may(account, level, record):
        return None
    if record is not None and may(account, "read", record):
        return refused(account, level)
    return unknown_case()
