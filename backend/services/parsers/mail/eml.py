"""EML (RFC 822) parsing."""
from __future__ import annotations

from typing import Any, Iterator

from services.parsers.mail.common import ParseContext, parse_message_bytes


def parse_eml(data: bytes, ctx: ParseContext, folder: str = "", index: int = 0) -> dict[str, Any]:
    row = parse_message_bytes(data, ctx, folder=folder)
    row["sourceIndex"] = index
    row["sourceFormat"] = "eml"
    return row


def iter_eml_files(items: Iterator[tuple[str, bytes]], ctx: ParseContext) -> Iterator[dict[str, Any]]:
    for i, (name, data) in enumerate(items):
        row = parse_eml(data, ctx, folder=name, index=i)
        row["sourceName"] = name
        yield row
