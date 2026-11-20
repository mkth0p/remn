"""Who may open a case, and the audit log, on a server with accounts (forensic/accounts.py, forensic/audit.py)."""

from __future__ import annotations

import json
from typing import Any

from django.http import HttpRequest, JsonResponse
from django.views.decorators.http import require_GET, require_http_methods

from api.params import BadParameter, whole_number
from forensic import audit
from forensic.access import may, permission
from forensic.accounts import AccountError, accounts_on, store


def _no_accounts() -> JsonResponse:
    return JsonResponse({"error": "this server has no accounts: every case is open to whoever reaches the server", "code": "noAccounts"}, status=404)


def _describe(key: str, rec: dict[str, Any] | None, account) -> dict[str, Any]:
    rec = rec or {}
    return {
        "key": key,
        "name": rec.get("name") or "",
        "owner": rec.get("owner"),
        "members": list(rec.get("members") or []),
        "may": {"read": True, "write": may(account, "write", rec or None), "own": may(account, "own", rec or None)},
    }


# the owner, or an admin, changes who may open the case; the first account to set it up on a new
# key becomes its owner, as the first write to it would
@permission({"GET": "read", "POST": "own"}, case="url", create=True)
@require_http_methods(["GET", "POST"])
def case_access(request: HttpRequest, key: str):
    """GET: the case's name, owner and members, and what the asking account may do with it.
    POST {members?: [names], name?: str, owner?: name}: the members replace the list; only an
    admin gives the case another owner."""
    account = getattr(request, "account", None)
    if account is None or not accounts_on():
        return _no_accounts()
    accounts = store()
    if request.method == "GET":
        return JsonResponse(_describe(key, accounts.case(key), account))
    try:
        body = json.loads(request.body or b"{}")
    except ValueError:
        return JsonResponse({"error": "invalid JSON"}, status=400)
    if not isinstance(body, dict):
        return JsonResponse({"error": "expected a JSON object"}, status=400)
    members, owner, name = body.get("members"), body.get("owner"), body.get("name")
    if members is not None and (not isinstance(members, list) or not all(isinstance(m, str) for m in members) or len(members) > 200):
        return JsonResponse({"error": "members is a list of account names"}, status=400)
    if (owner is not None and not isinstance(owner, str)) or (name is not None and not isinstance(name, str)):
        return JsonResponse({"error": "owner and name are strings"}, status=400)
    if owner is not None and account.role != "admin":
        return JsonResponse({"error": "only an admin gives a case another owner", "code": "role", "role": account.role}, status=403)
    try:
        rec = accounts.update_case(key, owner=owner, members=[m.strip() for m in members] if members is not None else None, name=name)
    except AccountError as exc:
        return JsonResponse({"error": str(exc)}, status=400)
    return JsonResponse(_describe(key, rec, account))


@permission("admin")
@require_GET
def audit_entries(request: HttpRequest):
    """GET ?after=<seq>&limit=<n>&case=<key>&account=<name>: entries of the audit log, oldest first."""
    if not accounts_on():
        return _no_accounts()
    try:
        after = whole_number(request.GET.get("after"), "after", 0, minimum=0)
        limit = whole_number(request.GET.get("limit"), "limit", 200, minimum=1)
    except BadParameter as exc:
        return JsonResponse({"error": str(exc)}, status=400)
    limit = min(limit, 1000)
    entries = audit.log().entries(after=after, limit=limit, case=request.GET.get("case") or None, account=request.GET.get("account") or None)
    return JsonResponse({"entries": entries, "next": entries[-1]["seq"] if len(entries) == limit else None})


@permission("admin")
@require_GET
def audit_verify(request: HttpRequest):
    """GET ?head=<code>[&head=...]: check the chain of the audit log. Each head noted earlier must
    still be in it; the entry this server wrote last is checked the same way."""
    if not accounts_on():
        return _no_accounts()
    log = audit.log()
    heads = [h for h in request.GET.getlist("head") if h]
    if log.last_written:
        heads.append(log.last_written["mac"])
    return JsonResponse(log.verify(heads))
