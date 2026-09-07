"""
PST / OST parsing with libpff (pypff). Optional dependency: install
``libpff-python`` (build) or ``libpff-python-windows`` (community wheel).
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from email.utils import format_datetime
from typing import Any

from services.parsers.mail.common import Header, ParseContext, RawAttachment, build_row

log = logging.getLogger(__name__)

# MAPI property identifiers we read from record sets when transport headers are missing
PR_SENDER_NAME = 0x0C1A
PR_SENDER_EMAIL_ADDRESS = 0x0C1F
PR_SENDER_SMTP_ADDRESS = 0x5D01
PR_SENT_REPRESENTING_NAME = 0x0042
PR_SENT_REPRESENTING_EMAIL = 0x0065
PR_SENT_REPRESENTING_SMTP = 0x5D02
PR_DISPLAY_TO = 0x0E04
PR_DISPLAY_CC = 0x0E03
PR_DISPLAY_BCC = 0x0E02
PR_INTERNET_MESSAGE_ID = 0x1035
PR_IN_REPLY_TO_ID = 0x1042
PR_MESSAGE_CLASS = 0x001A
PR_IMPORTANCE = 0x0017
PR_INTERNET_REFERENCES = 0x1039
PR_TRANSPORT_MESSAGE_HEADERS = 0x007D


def available() -> bool:
    try:
        import pypff  # noqa: F401

        return True
    except Exception:  # noqa: BLE001
        return False


def _props(message: Any) -> dict[int, Any]:
    out: dict[int, Any] = {}
    try:
        n = message.number_of_record_sets
    except Exception:  # noqa: BLE001
        return out
    for i in range(min(n, 4)):
        try:
            rs = message.get_record_set(i)
            for j in range(rs.number_of_entries):
                entry = rs.get_entry(j)
                et = entry.entry_type
                if et in out:
                    continue
                vt = getattr(entry, "value_type", None)
                try:
                    if vt in (0x001E, 0x001F):  # string8 / unicode
                        out[et] = entry.get_data_as_string()
                    elif vt in (0x0002, 0x0003, 0x0014):
                        out[et] = entry.get_data_as_integer()
                    elif vt == 0x000B:
                        out[et] = entry.get_data_as_boolean()
                    elif vt == 0x0040:
                        out[et] = entry.get_data_as_floatingtime() if hasattr(entry, "get_data_as_floatingtime") else entry.get_data()
                except Exception:  # noqa: BLE001
                    continue
        except Exception:  # noqa: BLE001
            continue
    return out


def _headers_from_message(message: Any, props: dict[int, Any]) -> tuple[list[Header], dict[str, Any]]:
    headers: list[Header] = []
    extra: dict[str, Any] = {}
    transport = None
    try:
        transport = message.transport_headers
    except Exception:  # noqa: BLE001
        transport = props.get(PR_TRANSPORT_MESSAGE_HEADERS)
    if transport:
        import email
        from email import policy

        try:
            parsed = email.message_from_string(transport if isinstance(transport, str) else transport.decode("utf-8", "replace"), policy=policy.compat32)
            for k, v in parsed.items():
                headers.append((k, str(v)))
        except Exception as exc:  # noqa: BLE001
            log.debug("transport headers parse failed: %s", exc)
    extra["syntheticHeaders"] = not headers
    names = {k.lower() for k, _ in headers}

    def add(name: str, value: Any) -> None:
        if value and name.lower() not in names:
            headers.append((name, str(value)))
            names.add(name.lower())

    sender_name = props.get(PR_SENT_REPRESENTING_NAME) or props.get(PR_SENDER_NAME)
    if not sender_name:
        try:
            sender_name = message.sender_name
        except Exception:  # noqa: BLE001
            sender_name = None
    sender_addr = (
        props.get(PR_SENT_REPRESENTING_SMTP) or props.get(PR_SENDER_SMTP_ADDRESS) or props.get(PR_SENT_REPRESENTING_EMAIL) or props.get(PR_SENDER_EMAIL_ADDRESS)
    )
    if sender_addr and "@" not in str(sender_addr):
        # X.500 / EX address: keep it as the name, no SMTP address
        extra["senderExchangeAddress"] = str(sender_addr)[:300]
        sender_addr = None
    if sender_name or sender_addr:
        add("From", f'"{sender_name}" <{sender_addr}>' if sender_name and sender_addr else (sender_addr or sender_name))
    add("To", props.get(PR_DISPLAY_TO))
    add("Cc", props.get(PR_DISPLAY_CC))
    add("Bcc", props.get(PR_DISPLAY_BCC))
    try:
        add("Subject", message.subject)
    except Exception:  # noqa: BLE001
        pass
    add("Message-ID", props.get(PR_INTERNET_MESSAGE_ID))
    add("In-Reply-To", props.get(PR_IN_REPLY_TO_ID))
    add("References", props.get(PR_INTERNET_REFERENCES))
    date = None
    for attr in ("delivery_time", "client_submit_time", "creation_time"):
        try:
            date = getattr(message, attr)
        except Exception:  # noqa: BLE001
            date = None
        if date:
            break
    if date:
        try:
            add("Date", format_datetime(date))
        except Exception:  # noqa: BLE001
            add("Date", str(date))
        extra["dateFallback"] = str(date)
    extra["messageClass"] = props.get(PR_MESSAGE_CLASS)
    extra["importance"] = props.get(PR_IMPORTANCE)
    return headers, extra


def _attachments(message: Any) -> list[RawAttachment]:
    out: list[RawAttachment] = []
    try:
        n = message.number_of_attachments
    except Exception:  # noqa: BLE001
        return out
    for i in range(min(n, 60)):
        try:
            att = message.get_attachment(i)
            name = None
            for attr in ("name", "long_filename", "filename", "display_name"):
                try:
                    name = getattr(att, attr)
                except Exception:  # noqa: BLE001
                    name = None
                if name:
                    break
            size = 0
            try:
                size = att.get_size()
            except Exception:  # noqa: BLE001
                try:
                    size = att.size
                except Exception:  # noqa: BLE001
                    size = 0
            data = b""
            if size and size <= 60 * 1024 * 1024:
                try:
                    data = att.read_buffer(size)
                except Exception:  # noqa: BLE001
                    try:
                        att.seek(0)
                        data = att.read(size)
                    except Exception:  # noqa: BLE001
                        data = b""
            out.append(RawAttachment(name or f"attachment-{i}", data or b"", None, False, None))
        except Exception as exc:  # noqa: BLE001
            log.debug("pst attachment %d failed: %s", i, exc)
    return out


def _bodies(message: Any) -> tuple[str | None, str | None]:
    text = html = None
    try:
        t = message.plain_text_body
        if t:
            text = t.decode("utf-8", "replace") if isinstance(t, bytes) else str(t)
    except Exception:  # noqa: BLE001
        pass
    try:
        h = message.html_body
        if h:
            html = h.decode("utf-8", "replace") if isinstance(h, bytes) else str(h)
    except Exception:  # noqa: BLE001
        pass
    if not text and not html:
        try:
            r = message.rtf_body
            if r:
                from services.parsers.mail.msg import _rtf_to_text

                text = _rtf_to_text(r)
        except Exception:  # noqa: BLE001
            pass
    # never hand bytes to the analyzers (RTF-only messages used to slip through as bytes)
    if isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
    if isinstance(html, bytes):
        html = html.decode("utf-8", "replace")
    return text, html


def _walk(folder: Any, path: str) -> Iterator[tuple[str, Any]]:
    try:
        name = folder.name or ""
    except Exception:  # noqa: BLE001
        name = ""
    current = f"{path}/{name}".strip("/") if name else path
    try:
        for i in range(folder.number_of_sub_messages):
            try:
                yield current, folder.get_sub_message(i)
            except Exception as exc:  # noqa: BLE001
                log.debug("pst message %d in %s failed: %s", i, current, exc)
    except Exception as exc:  # noqa: BLE001
        log.debug("pst folder %s messages failed: %s", current, exc)
    try:
        for i in range(folder.number_of_sub_folders):
            try:
                yield from _walk(folder.get_sub_folder(i), current)
            except Exception as exc:  # noqa: BLE001
                log.debug("pst subfolder %d in %s failed: %s", i, current, exc)
    except Exception:  # noqa: BLE001
        pass


# Folders whose content the user (or an attacker) deleted: Outlook's Deleted Items in the common
# locales, and the Exchange Recoverable Items dumpster subtree of an OST/PST export.
_DELETED_FOLDER_RE = re.compile(
    r"(?i)(deleted items|éléments supprimés|elements supprimes|gelöschte elemente|elementos eliminados|posta eliminata|"
    r"recoverable items|éléments récupérables|purges|deletions|versions|discoveryholds|substrateholds|calendar logging)"
)
ORPHAN_FOLDER = "(orphaned - deleted item not attached to any folder)"


def _message_row(message: Any, folder: str, ctx: ParseContext, index: int) -> dict[str, Any]:
    try:
        props = _props(message)
        headers, extra = _headers_from_message(message, props)
        text, html = _bodies(message)
        attachments = _attachments(message) if ctx.analyze_attachments else []
        extra["sourceFormat"] = "pst"
        row = build_row(headers, text, html, attachments, ctx, folder=folder, size=None, extra=extra)
    except Exception as exc:  # noqa: BLE001
        log.warning("pst message %d failed: %s", index, exc)
        row = {
            "folder": folder,
            "subject": "(unparseable message)",
            "flags": ["parse_error"],
            "risk": 10,
            "error": str(exc)[:200],
            "attachments": [],
            "urls": [],
            "sourceFormat": "pst",
        }
    row["sourceIndex"] = index
    try:
        row["pstIdentifier"] = message.identifier
    except Exception:  # noqa: BLE001
        pass
    return row


def _add_flag(row: dict[str, Any], flag: str) -> None:
    row["flags"] = sorted(set(row.get("flags") or []) | {flag})


def _looks_like_message(item: Any) -> bool:
    return hasattr(item, "get_transport_headers") or hasattr(item, "transport_headers") or hasattr(item, "plain_text_body")


def iter_pst_file(pst: Any, ctx: ParseContext) -> Iterator[dict[str, Any]]:
    """Rows of an opened pypff file: the folder tree, then the orphan items (messages that lost
    their folder link when they were deleted - libpff keeps them reachable through the item tree)."""
    root = pst.get_root_folder()
    index = 0
    for folder, message in _walk(root, ""):
        index += 1
        row = _message_row(message, folder, ctx, index)
        if _DELETED_FOLDER_RE.search(folder or ""):
            _add_flag(row, "deleted_item")
        yield row
    try:
        n_orphans = int(pst.number_of_orphan_items)
    except Exception:  # noqa: BLE001
        n_orphans = 0
    for i in range(n_orphans):
        try:
            item = pst.get_orphan_item(i)
        except Exception as exc:  # noqa: BLE001
            log.debug("pst orphan %d failed: %s", i, exc)
            continue
        if item is None or not _looks_like_message(item):
            continue
        index += 1
        row = _message_row(item, ORPHAN_FOLDER, ctx, index)
        _add_flag(row, "orphan_item")
        _add_flag(row, "deleted_item")
        row["orphan"] = True
        yield row


def iter_pst(path: str, ctx: ParseContext) -> Iterator[dict[str, Any]]:
    import pypff

    pst = pypff.file()
    pst.open(path)
    try:
        yield from iter_pst_file(pst, ctx)
    finally:
        try:
            pst.close()
        except Exception:  # noqa: BLE001
            pass
