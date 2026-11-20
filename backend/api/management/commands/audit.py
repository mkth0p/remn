"""
`manage.py audit`: read and check the audit log of a server with accounts.

    manage.py audit verify [--head <code> ...]     check the chain; exit code 1 when it does not hold
    manage.py audit show [--after N] [--limit N] [--case <key>] [--account <name>]

`verify` ends with the newest entry's code. Noting it somewhere the server cannot write, and giving
it back with --head next time, is what finds entries removed from the end of the log, which the
chain alone cannot show.
"""

from __future__ import annotations

import json
from typing import Any

from django.core.management.base import BaseCommand, CommandError

from forensic import audit


class Command(BaseCommand):
    help = "Read and check the audit log of a server with accounts."

    def add_arguments(self, parser) -> None:
        sub = parser.add_subparsers(dest="action", required=True)
        p = sub.add_parser("verify", help="check every entry against the audit key and the entry before it")
        p.add_argument("--head", action="append", default=[], help="the code of an entry noted earlier, which must still be in the log")
        p = sub.add_parser("show", help="print entries, oldest first, one JSON object a line")
        p.add_argument("--after", type=int, default=0, help="only entries after this sequence number")
        p.add_argument("--limit", type=int, default=200)
        p.add_argument("--case")
        p.add_argument("--account")

    def handle(self, *args: Any, **opts: Any) -> None:
        log = audit.log()
        if opts["action"] == "show":
            for entry in log.entries(after=opts["after"], limit=max(1, opts["limit"]), case=opts.get("case"), account=opts.get("account")):
                self.stdout.write(json.dumps(entry, ensure_ascii=False))
            return
        result = log.verify(opts["head"])
        for problem in result["problems"]:
            self.stdout.write(problem)
        if result["problemCount"] > len(result["problems"]):
            self.stdout.write(f"... and {result['problemCount'] - len(result['problems'])} more")
        head = result["head"]
        self.stdout.write(
            f"{result['entries']} entries; " + (f"newest: entry {head['seq']} at {head['time']}, code {head['mac']}" if head else "the log is empty")
        )
        if not result["ok"]:
            raise CommandError(f"the audit log does not verify: {result['problemCount']} problem(s)")
        self.stdout.write("the chain holds")
