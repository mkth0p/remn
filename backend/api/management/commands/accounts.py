"""
`manage.py accounts`: the accounts of a server shared by a team, and the cases each may open.

    manage.py accounts create <name> --role admin|analyst|viewer   a new account; prints its token once
    manage.py accounts list                                        accounts, roles and token ids
    manage.py accounts rotate <name>                               revokes its tokens; prints a new one once
    manage.py accounts revoke <name> [--token <id>]                one token, or all of them
    manage.py accounts disable <name> | enable <name>
    manage.py accounts role <name> <role>
    manage.py accounts cases                                       case records, and stores no record covers
    manage.py accounts case <key> [--owner <name>] [--members a,b] [--name <text>]

The first account created turns accounts on: from then on every API request needs a personal
token. Run it as the account the server runs as (with Docker: docker compose exec remn python
backend/manage.py accounts ...), so the files it writes are the server's. Every change is recorded
in the audit log.
"""

from __future__ import annotations

import getpass
from typing import Any

from django.core.management.base import BaseCommand, CommandError

from forensic import audit
from forensic.accounts import ROLES, AccountError, store


class Command(BaseCommand):
    help = "Create, list, disable and rotate the accounts of a shared server, and set who may open a case."

    def add_arguments(self, parser) -> None:
        sub = parser.add_subparsers(dest="action", required=True)
        p = sub.add_parser("create", help="a new account; its token is printed once")
        p.add_argument("name")
        p.add_argument("--role", required=True, choices=ROLES)
        sub.add_parser("list", help="every account, its role and its tokens' ids")
        p = sub.add_parser("rotate", help="revoke every token of the account and print a new one once")
        p.add_argument("name")
        p = sub.add_parser("revoke", help="revoke one token of the account, or all of them")
        p.add_argument("name")
        p.add_argument("--token", help="the token's id, as `list` shows it; all of them when left out")
        p = sub.add_parser("disable", help="refuse every token of the account until it is enabled again")
        p.add_argument("name")
        p = sub.add_parser("enable", help="accept the account's tokens again")
        p.add_argument("name")
        p = sub.add_parser("role", help="give the account another role")
        p.add_argument("name")
        p.add_argument("role", choices=ROLES)
        sub.add_parser("cases", help="the case records, and the stores no record covers (only an admin opens those)")
        p = sub.add_parser("case", help="set a case's owner, members or name")
        p.add_argument("key")
        p.add_argument("--owner")
        p.add_argument("--members", help="comma-separated account names; replaces the list")
        p.add_argument("--name")

    def handle(self, *args: Any, **opts: Any) -> None:
        action = opts["action"]
        accounts = store()
        try:
            if action == "create":
                token = accounts.create(opts["name"], opts["role"])
                self._record(f"accounts create {opts['name']} --role {opts['role']}")
                self._token(opts["name"], token)
            elif action == "list":
                self._list(accounts.accounts())
            elif action == "rotate":
                token = accounts.rotate(opts["name"])
                self._record(f"accounts rotate {opts['name']}")
                self._token(opts["name"], token)
            elif action == "revoke":
                n = accounts.revoke(opts["name"], opts.get("token"))
                self._record(f"accounts revoke {opts['name']}" + (f" --token {opts['token']}" if opts.get("token") else ""))
                self.stdout.write(f"{n} token(s) of {opts['name']} revoked")
            elif action in ("disable", "enable"):
                accounts.set_disabled(opts["name"], action == "disable")
                self._record(f"accounts {action} {opts['name']}")
                self.stdout.write(f"{opts['name']} {action}d")
            elif action == "role":
                accounts.set_role(opts["name"], opts["role"])
                self._record(f"accounts role {opts['name']} {opts['role']}")
                self.stdout.write(f"{opts['name']} is now {opts['role']}")
            elif action == "cases":
                self._cases(accounts.cases())
            elif action == "case":
                self._case(opts)
        except AccountError as exc:
            raise CommandError(str(exc)) from None

    def _record(self, what: str, case: str | None = None) -> None:
        """An entry in the audit log for a change made here; the account is the system user who ran it."""
        try:
            user = getpass.getuser()
        except Exception:  # noqa: BLE001 - no user name on this system
            user = "?"
        audit.log().append(
            account=f"manage.py ({user})", role=None, address="local", method="COMMAND", route=what, path=None, case=case, status=0, outcome="ok"
        )

    def _token(self, name: str, token: str) -> None:
        self.stdout.write(f"token of {name} (shown once, keep it like a password; only its digest is stored):")
        self.stdout.write(token)

    def _list(self, rows: list[dict[str, Any]]) -> None:
        if not rows:
            self.stdout.write("no accounts: the server runs without them (no token, or the one shared FORENSIC_AUTH_TOKEN)")
            return
        for acc in rows:
            active = [t["id"] for t in acc["tokens"] if not t["revoked"]]
            state = "disabled" if acc["disabled"] else "enabled"
            self.stdout.write(f"{acc['name']:<24} {acc['role']:<8} {state:<9} tokens: {', '.join(active) or 'none'} (created {acc['created']})")

    def _cases(self, records: dict[str, dict[str, Any]]) -> None:
        # the registry is on the cases folder since the app started (api/apps.py)
        from services.store.casestore import registry

        stored = {s["key"] for s in registry.list()}
        for key in sorted(set(records) | stored):
            rec = records.get(key)
            if rec is None:
                self.stdout.write(f"{key}  no owner: only an admin opens it (accounts case {key} --owner <name>)")
                continue
            where = "" if key in stored else "  (no store yet)"
            self.stdout.write(f"{key}  owner {rec.get('owner') or '-'}  members {', '.join(rec.get('members') or []) or '-'}  {rec.get('name') or ''}{where}")

    def _case(self, opts: dict[str, Any]) -> None:
        from services.store.casestore import KEY_RE

        key = opts["key"]
        if not KEY_RE.match(key):
            raise CommandError("a case key is a UUID, as `accounts cases` lists it")
        members = [m.strip() for m in opts["members"].split(",") if m.strip()] if opts.get("members") is not None else None
        if opts.get("owner") is None and members is None and opts.get("name") is None:
            raise CommandError("say what to set: --owner, --members or --name")
        rec = store().update_case(key, owner=opts.get("owner"), members=members, name=opts.get("name"))
        said = " ".join(f"--{k} {v}" for k, v in (("owner", opts.get("owner")), ("members", opts.get("members")), ("name", opts.get("name"))) if v is not None)
        self._record(f"accounts case {said}", case=key)
        self.stdout.write(f"{key}  owner {rec.get('owner') or '-'}  members {', '.join(rec.get('members') or []) or '-'}")
