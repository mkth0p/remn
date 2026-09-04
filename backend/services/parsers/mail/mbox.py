"""MBOX parsing (Thunderbird, Google Takeout, Apple Mail exports)."""
from __future__ import annotations

import logging
import mailbox
import re
from typing import Any, Iterator

from services.parsers.mail.common import ParseContext, parse_message_bytes

log = logging.getLogger(__name__)
_FROM_LINE = re.compile(rb"^From .*\d{4}\r?\n", re.M)


def iter_mbox(path: str, ctx: ParseContext, folder: str = "mbox") -> Iterator[dict[str, Any]]:
    box = mailbox.mbox(path, create=False)
    try:
        keys = box.keys()
        for i, key in enumerate(keys):
            try:
                data = box.get_bytes(key)
            except Exception as exc:  # noqa: BLE001
                log.warning("mbox message %d unreadable: %s", i, exc)
                continue
            try:
                row = parse_message_bytes(data, ctx, folder=folder)
            except Exception as exc:  # noqa: BLE001
                log.warning("mbox message %d failed: %s", i, exc)
                row = {"folder": folder, "subject": "(unparseable message)", "flags": ["parse_error"], "risk": 10,
                       "error": str(exc)[:200], "attachments": [], "urls": []}
            row["sourceIndex"] = i
            row["sourceFormat"] = "mbox"
            # Gmail Takeout labels
            labels = None
            try:
                msg = box.get_message(key)
                labels = msg.get("X-Gmail-Labels")
            except Exception:  # noqa: BLE001
                pass
            if labels:
                row["labels"] = [x.strip() for x in str(labels).split(",") if x.strip()][:20]
            yield row
    finally:
        box.close()


def looks_like_mbox(head: bytes) -> bool:
    return head.startswith(b"From ") and bool(_FROM_LINE.match(head[:400]))
