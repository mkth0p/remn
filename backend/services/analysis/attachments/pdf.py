"""PDF attachment analysis: pdfid-style keyword scan + pypdf structural checks."""

from __future__ import annotations

import io
import logging
import re
from typing import Any

log = logging.getLogger(__name__)

# Keywords are matched after normalising #xx hex escapes in names (/J#61vaScript).
KEYWORDS = (
    "/JS",
    "/JavaScript",
    "/AA",
    "/OpenAction",
    "/Launch",
    "/EmbeddedFile",
    "/EmbeddedFiles",
    "/RichMedia",
    "/XFA",
    "/AcroForm",
    "/URI",
    "/SubmitForm",
    "/GoToR",
    "/GoToE",
    "/ObjStm",
    "/Encrypt",
    "/JBIG2Decode",
    "/Names",
    "/Annots",
    "/Sound",
    "/Movie",
    "/ImportData",
    "/RenditionAction",
    "/Win",
    "/FileAttachment",
)
_NAME_ESC = re.compile(rb"#([0-9A-Fa-f]{2})")
_URI_RE = re.compile(rb"/URI\s*\(\s*([^)]{1,600})\)|/URI\s*<([0-9A-Fa-f]{2,1200})>")
_URL_IN_TEXT = re.compile(rb"(?i)\b(?:https?://|www\.)[^\s\"'<>)]{4,300}")


def _normalise(data: bytes) -> bytes:
    return _NAME_ESC.sub(lambda m: bytes([int(m.group(1), 16)]), data)


def analyze_pdf(data: bytes, max_pypdf_bytes: int = 25 * 1024 * 1024) -> dict[str, Any]:
    flags: set[str] = set()
    out: dict[str, Any] = {
        "flags": [],
        "keywords": {},
        "objects": 0,
        "streams": 0,
        "eofs": 0,
        "pages": None,
        "encrypted": False,
        "metadata": None,
        "uris": [],
        "embeddedFiles": [],
        "formFields": 0,
        "header": None,
        "trailingData": 0,
        "version": None,
    }
    if not data.startswith(b"%PDF"):
        # PDF magic elsewhere (prepended junk to evade filters)
        idx = data.find(b"%PDF", 0, 4096)
        if idx > 0:
            flags.add("pdf_header_offset")
            out["header"] = f"%PDF at offset {idx}"
    else:
        out["header"] = data[:8].decode("ascii", "replace")
        m = re.match(rb"%PDF-(\d\.\d)", data[:10])
        if m:
            out["version"] = m.group(1).decode()
    norm = _normalise(data)
    counts: dict[str, int] = {}
    for kw in KEYWORDS:
        n = len(re.findall(re.escape(kw.encode()) + rb"(?![A-Za-z])", norm))
        if n:
            counts[kw] = n
    out["keywords"] = counts
    out["objects"] = len(re.findall(rb"\bobj\b", norm))
    out["streams"] = len(re.findall(rb"\bstream\b", norm))
    out["eofs"] = norm.count(b"%%EOF")
    if norm.count(b"#") > 50 and re.search(rb"/[A-Za-z]*#[0-9A-Fa-f]{2}", data):
        flags.add("pdf_obfuscated_names")
    if counts.get("/JS") or counts.get("/JavaScript"):
        flags.add("pdf_javascript")
    if counts.get("/OpenAction") or counts.get("/AA"):
        flags.add("pdf_auto_action")
    if counts.get("/Launch") or counts.get("/Win"):
        flags.add("pdf_launch")
    if counts.get("/EmbeddedFile") or counts.get("/EmbeddedFiles") or counts.get("/FileAttachment"):
        flags.add("pdf_embedded_file")
    if counts.get("/RichMedia") or counts.get("/Movie") or counts.get("/Sound") or counts.get("/RenditionAction"):
        flags.add("pdf_rich_media")
    if counts.get("/XFA"):
        flags.add("pdf_xfa")
    if counts.get("/SubmitForm") or counts.get("/ImportData"):
        flags.add("pdf_submit_form")
    if counts.get("/GoToR") or counts.get("/GoToE"):
        flags.add("pdf_remote_goto")
    if counts.get("/Encrypt"):
        flags.add("pdf_encrypted")
        out["encrypted"] = True
    if counts.get("/JBIG2Decode"):
        flags.add("pdf_jbig2")
    if out["eofs"] > 1:
        flags.add("pdf_incremental_updates")
    if counts.get("/ObjStm") and not counts.get("/URI") and not counts.get("/JS"):
        # keywords may be hidden inside object streams; pypdf below will decompress them
        out["objStmHidden"] = True
    tail = data.rstrip()
    if tail and not tail.endswith(b"%%EOF"):
        last = data.rfind(b"%%EOF")
        if last != -1:
            out["trailingData"] = len(data) - last - 5
            if out["trailingData"] > 1024:
                flags.add("pdf_trailing_data")
    # Raw URI extraction (works even when pypdf fails)
    uris: set[str] = set()
    for lit, hexs in _URI_RE.findall(norm):
        if lit:
            uris.add(lit.decode("utf-8", "replace").replace("\\", "")[:400])
        elif hexs:
            try:
                uris.add(bytes.fromhex(hexs.decode()).decode("utf-8", "replace")[:400])
            except ValueError:
                pass
    for u in _URL_IN_TEXT.findall(norm[:3_000_000]):
        uris.add(u.decode("utf-8", "replace")[:400])

    if len(data) <= max_pypdf_bytes:
        try:
            from pypdf import PdfReader

            reader = PdfReader(io.BytesIO(data), strict=False)
            if reader.is_encrypted:
                out["encrypted"] = True
                flags.add("pdf_encrypted")
                try:
                    reader.decrypt("")
                    flags.add("pdf_encrypted_empty_password")
                except Exception:  # noqa: BLE001
                    pass
            try:
                out["pages"] = len(reader.pages)
            except Exception:  # noqa: BLE001
                pass
            try:
                meta = reader.metadata
                if meta:
                    out["metadata"] = {k.lstrip("/"): str(v)[:200] for k, v in meta.items()}
            except Exception:  # noqa: BLE001
                pass
            # Decompressed catalog checks (object streams)
            try:
                root = reader.trailer.get("/Root", {})
                root = root.get_object() if hasattr(root, "get_object") else root
                for key in ("/OpenAction", "/AA", "/AcroForm", "/Names"):
                    if key in root:
                        if key == "/OpenAction":
                            flags.add("pdf_auto_action")
                            action = root[key]
                            action = action.get_object() if hasattr(action, "get_object") else action
                            s = str(action.get("/S", "")) if hasattr(action, "get") else ""
                            if "JavaScript" in s:
                                flags.add("pdf_javascript")
                            if "Launch" in s:
                                flags.add("pdf_launch")
                        elif key == "/Names":
                            names = root[key]
                            names = names.get_object() if hasattr(names, "get_object") else names
                            if hasattr(names, "get"):
                                if "/JavaScript" in names:
                                    flags.add("pdf_javascript")
                                if "/EmbeddedFiles" in names:
                                    flags.add("pdf_embedded_file")
                                    try:
                                        ef = names["/EmbeddedFiles"].get_object()
                                        arr = ef.get("/Names", [])
                                        for i in range(0, len(arr), 2):
                                            out["embeddedFiles"].append(str(arr[i])[:120])
                                    except Exception:  # noqa: BLE001
                                        pass
                        elif key == "/AcroForm":
                            try:
                                fields = reader.get_fields() or {}
                                out["formFields"] = len(fields)
                                if fields:
                                    flags.add("pdf_form")
                            except Exception:  # noqa: BLE001
                                pass
            except Exception:  # noqa: BLE001
                pass
            # Link annotations on the first pages
            try:
                for page in list(reader.pages)[:40]:
                    annots = page.get("/Annots")
                    if not annots:
                        continue
                    annots = annots.get_object() if hasattr(annots, "get_object") else annots
                    for a in annots:
                        try:
                            a = a.get_object()
                            act = a.get("/A")
                            if not act:
                                continue
                            act = act.get_object()
                            s = str(act.get("/S", ""))
                            if s == "/URI":
                                uris.add(str(act.get("/URI", ""))[:400])
                            elif s == "/JavaScript":
                                flags.add("pdf_javascript")
                            elif s == "/Launch":
                                flags.add("pdf_launch")
                            elif s in ("/GoToR", "/GoToE"):
                                flags.add("pdf_remote_goto")
                            elif s == "/SubmitForm":
                                flags.add("pdf_submit_form")
                        except Exception:  # noqa: BLE001
                            continue
            except Exception:  # noqa: BLE001
                pass
            # Text of the first page for lure detection (short)
            try:
                if reader.pages:
                    txt = reader.pages[0].extract_text() or ""
                    out["firstPageText"] = txt[:1500]
                    if len(txt.strip()) < 30 and out["pages"] == 1:
                        flags.add("pdf_image_only")
            except Exception:  # noqa: BLE001
                pass
        except Exception as exc:  # noqa: BLE001
            log.debug("pypdf failed: %s", exc)
            out["pypdfError"] = str(exc)[:200]
            flags.add("pdf_parse_error")
    else:
        out["pypdfSkipped"] = "too large"

    if len(uris) >= 1 and (out.get("pages") == 1 or (out.get("pages") or 0) <= 2) and (len((out.get("firstPageText") or "").strip()) < 300):
        flags.add("pdf_link_lure")
    out["uris"] = sorted(u for u in uris if u)[:100]
    out["flags"] = sorted(flags)
    return out
