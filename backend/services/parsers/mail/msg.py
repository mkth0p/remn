"""Outlook .msg parsing with extract-msg."""

from __future__ import annotations

import logging
from typing import Any

from services.parsers.mail.common import Header, ParseContext, RawAttachment, build_row

log = logging.getLogger(__name__)


def _headers_from_msg(msg: Any) -> tuple[list[Header], bool]:
    """Returns (headers, synthetic): synthetic is True when the .msg carried no transport
    headers and everything below is reconstructed from MAPI properties."""
    headers: list[Header] = []
    try:
        hdr = msg.header  # email.message.Message built from the transport headers property
        if hdr is not None:
            for k, v in hdr.items():
                headers.append((k, str(v)))
    except Exception as exc:  # noqa: BLE001
        log.debug("msg.header failed: %s", exc)
    synthetic = not headers
    names = {k.lower() for k, _ in headers}

    def add(name: str, value: Any) -> None:
        if value and name.lower() not in names:
            headers.append((name, str(value)))
            names.add(name.lower())

    try:
        sender = msg.sender
    except Exception:  # noqa: BLE001
        sender = None
    add("From", sender)
    for attr, name in (("to", "To"), ("cc", "Cc"), ("bcc", "Bcc"), ("subject", "Subject"), ("messageId", "Message-ID"), ("inReplyTo", "In-Reply-To")):
        try:
            add(name, getattr(msg, attr, None))
        except Exception:  # noqa: BLE001
            pass
    try:
        d = msg.date
        if d is not None:
            from email.utils import format_datetime

            add("Date", format_datetime(d) if hasattr(d, "tzinfo") else str(d))
    except Exception:  # noqa: BLE001
        pass
    return headers, synthetic


def _internet_encoding(msg: Any) -> str | None:
    """The encoding of a message's 8-bit strings when only its internet code page names it.

    extract-msg reads such strings in the message code page (PR_MESSAGE_CODEPAGE) and, without
    one, as ISO-8859-15. Outlook does not always write that property: a message in Chinese saved
    with only PR_INTERNET_CPID set came out with its subject and sender in mojibake.
    """
    try:
        if msg.areStringsUnicode or "3FFD0003" in msg.props or "3FDE0003" not in msg.props:
            return None
        from extract_msg.encoding import lookupCodePage

        return lookupCodePage(int(msg.getPropertyVal("3FDE0003")))
    except Exception:  # noqa: BLE001
        return None


def parse_msg_bytes(data: bytes, ctx: ParseContext, folder: str = "", depth: int = 0) -> dict[str, Any]:
    import extract_msg

    def open_msg(**encoding: str) -> Any:
        if not hasattr(extract_msg, "enums"):
            return extract_msg.openMsg(data, **encoding)
        return extract_msg.openMsg(
            data,
            delayAttachments=False,
            attachmentErrorBehavior=getattr(extract_msg.enums, "ErrorBehavior", None) and extract_msg.enums.ErrorBehavior.SUPPRESS_ALL,
            **encoding,
        )

    msg = open_msg()
    encoding = _internet_encoding(msg)
    if encoding:
        msg.close()
        msg = open_msg(overrideEncoding=encoding)
    try:
        headers, synthetic = _headers_from_msg(msg)
        try:
            text = msg.body
        except Exception:  # noqa: BLE001
            text = None
        html = None
        try:
            hb = msg.htmlBody
            if hb:
                html = hb.decode("utf-8", "replace") if isinstance(hb, bytes) else str(hb)
        except Exception:  # noqa: BLE001
            html = None
        if not text and not html:
            try:
                rtf = msg.rtfBody
                if rtf:
                    text = _rtf_to_text(rtf)
            except Exception:  # noqa: BLE001
                pass
        attachments: list[RawAttachment] = []
        try:
            for att in msg.attachments:
                try:
                    name = getattr(att, "longFilename", None) or getattr(att, "shortFilename", None) or getattr(att, "name", None)
                    payload = att.data
                    mime = getattr(att, "mimetype", None)
                    cid = getattr(att, "cid", None) or getattr(att, "contentId", None)
                    if isinstance(payload, (bytes, bytearray)):
                        attachments.append(RawAttachment(name, bytes(payload), mime, False, cid))
                    elif payload is not None and hasattr(payload, "export") or hasattr(payload, "asBytes") or hasattr(payload, "exportBytes"):
                        # embedded message
                        try:
                            blob = payload.exportBytes() if hasattr(payload, "exportBytes") else payload.asBytes()
                        except Exception:  # noqa: BLE001
                            blob = b""
                        attachments.append(
                            RawAttachment(
                                (name or "embedded") + (".msg" if not str(name or "").lower().endswith((".msg", ".eml")) else ""),
                                blob,
                                "application/vnd.ms-outlook",
                                False,
                                cid,
                            )
                        )
                except Exception as exc:  # noqa: BLE001
                    log.debug("msg attachment failed: %s", exc)
        except Exception as exc:  # noqa: BLE001
            log.debug("msg attachments failed: %s", exc)
        extra: dict[str, Any] = {"sourceFormat": "msg", "syntheticHeaders": synthetic}
        try:
            extra["importance"] = str(msg.importance) if msg.importance is not None else None
        except Exception:  # noqa: BLE001
            pass
        try:
            extra["classType"] = msg.classType
        except Exception:  # noqa: BLE001
            pass
        return build_row(headers, text, html, attachments, ctx, folder=folder, size=len(data), extra=extra, depth=depth)
    finally:
        try:
            msg.close()
        except Exception:  # noqa: BLE001
            pass


def _as_str(value: object) -> str:
    """RTFDE 0.1.x hands back the de-encapsulated content as UTF-8 bytes."""
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace")
    return str(value)


def _rtf_to_text(rtf: bytes | str) -> str:
    raw = rtf if isinstance(rtf, bytes) else rtf.encode("latin-1", "replace")
    try:
        from RTFDE.deencapsulate import DeEncapsulator

        de = DeEncapsulator(raw)
        de.deencapsulate()
        if de.content_type == "html":
            from services.analysis.body import html_to_text

            return html_to_text(_as_str(de.html))[0]
        return _as_str(de.text)
    except Exception:  # noqa: BLE001
        import re

        s = raw.decode("latin-1", "replace")
        s = re.sub(r"\\par[d]?", "\n", s)
        s = re.sub(r"\\'[0-9a-f]{2}", "", s)
        s = re.sub(r"\\[a-z]+-?\d* ?", "", s)
        s = re.sub(r"[{}]", "", s)
        return s.strip()[:200000]
