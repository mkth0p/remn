"""
Attachment orchestrator: identifies the real type, runs the specialised
analyzers and produces flags + a 0-100 risk score. Bytes are never returned.
"""
from __future__ import annotations

import logging
from typing import Any

from services.analysis.attachments import archive as _archive
from services.analysis.attachments import html as _html
from services.analysis.attachments import office as _office
from services.analysis.attachments import pdf as _pdf
from services.analysis.attachments import yara_scan
from services.analysis.attachments.magic import DANGEROUS_EXT, EXEC_CATEGORIES, analyze_name, extension_matches, identify
from services.common import md5_bytes, sha256_bytes

log = logging.getLogger(__name__)

MAX_ANALYZE_BYTES = 60 * 1024 * 1024

# Flag -> weight used for the risk score (max of weights + small bonus per extra flag)
WEIGHTS: dict[str, int] = {
    "executable": 95, "installer": 85, "script": 90, "shortcut": 85, "help": 80, "onenote": 75, "disk_image": 80,
    "xll": 90, "double_extension": 60, "rtlo_filename": 85, "padded_filename": 50, "extension_mismatch": 45,
    "extension_mismatch_executable": 95, "zero_width_filename": 40, "mixed_script_filename": 35,
    "office_macro": 70, "macro_autoexec": 80, "macro_suspicious": 82, "macro_ioc": 85, "macro_obfuscated": 85,
    "macro_vba_stomping": 90, "office_xlm": 85, "office_dde": 85, "office_external_template": 85,
    "office_external_object": 80, "office_external_relation": 45, "office_remote_image": 30, "office_ole_object": 60,
    "office_activex": 50, "office_encrypted": 55, "office_iqy_remote": 85, "csv_formula_injection": 70,
    "rtf_object": 65, "rtf_equation_editor": 95, "rtf_objupdate": 85, "rtf_package": 80,
    "pdf_javascript": 70, "pdf_auto_action": 55, "pdf_launch": 90, "pdf_embedded_file": 65, "pdf_rich_media": 55,
    "pdf_xfa": 40, "pdf_submit_form": 50, "pdf_remote_goto": 55, "pdf_encrypted": 35, "pdf_encrypted_empty_password": 45,
    "pdf_obfuscated_names": 35, "pdf_header_offset": 45, "pdf_trailing_data": 30, "pdf_link_lure": 45,
    "pdf_image_only": 25, "pdf_form": 20, "pdf_parse_error": 25, "pdf_jbig2": 30, "pdf_incremental_updates": 10,
    "encrypted_archive": 70, "archive_contains_executable": 90, "archive_contains_script": 88,
    "archive_contains_shortcut": 85, "archive_contains_disk_image": 80, "archive_contains_office_macro": 70,
    "archive_contains_legacy_office": 40, "archive_contains_html": 55, "archive_contains_onenote": 75,
    "nested_archive": 50, "archive_single_executable": 92, "archive_single_lure": 55, "zip_bomb": 80,
    "archive_path_traversal": 70, "archive_many_entries": 20, "archive_corrupt": 30, "unsupported_archive_format": 35,
    "disk_image_contains_executable": 90, "disk_image_contains_shortcut": 90, "archive_partially_analyzed": 5,
    "html_smuggling": 90, "html_smuggling_possible": 60, "html_embedded_payload": 85, "html_obfuscated": 60,
    "html_dynamic_code": 50, "html_script": 35, "html_event_handler": 30, "html_password_form": 70,
    "html_credential_harvest": 90, "html_email_form": 45, "html_brand_lure": 40, "html_prefilled_email": 60,
    "html_meta_refresh": 55, "html_js_redirect": 55, "html_hidden_iframe": 65, "svg_script": 80,
    "html_redirect_only": 70, "html_script_only": 60, "html_callback_lure": 60, "html_attachment": 30,
    "nested_mail": 25, "empty_file": 15, "yara_match": 90, "calendar_lure": 20, "archive": 25, "office_legacy": 30,
    "rtf": 25, "mail": 15, "vcard": 5, "large_attachment": 5, "office_parse_error": 20,
}


def _score(flags: list[str]) -> int:
    if not flags:
        return 0
    weights = sorted((WEIGHTS.get(f, 10) for f in flags), reverse=True)
    score = weights[0] + sum(min(w, 25) // 5 for w in weights[1:6])
    return max(0, min(100, score))


def analyze_attachment(name: str | None, data: bytes, declared_mime: str | None = None,
                       depth: int = 0, inline: bool = False, content_id: str | None = None) -> dict[str, Any]:
    name = name or "(unnamed)"
    size = len(data)
    flags: set[str] = set()
    details: dict[str, Any] = {}
    name_info = analyze_name(name)
    ext = name_info["ext"]
    flags.update(name_info["flags"])
    real = identify(data, name) if data else {"ext": "", "mime": "", "description": "", "confidence": 0.0}
    real_ext = real["ext"]
    category = DANGEROUS_EXT.get(ext) or DANGEROUS_EXT.get(real_ext)
    real_category = DANGEROUS_EXT.get(real_ext)

    result: dict[str, Any] = {
        "name": name[:300], "ext": ext, "size": size, "declaredMime": (declared_mime or "")[:120],
        "realExt": real_ext, "realMime": real["mime"], "realType": real["description"], "category": category,
        "sha256": sha256_bytes(data) if data else None, "md5": md5_bytes(data) if data else None,
        "inline": inline, "contentId": content_id, "depth": depth, "flags": [], "risk": 0, "details": details,
    }
    if size == 0:
        flags.add("empty_file")
        result["flags"] = sorted(flags)
        result["risk"] = _score(result["flags"])
        return result
    if size > 25 * 1024 * 1024:
        flags.add("large_attachment")

    if ext and real_ext and not extension_matches(ext, real_ext):
        if real_category in EXEC_CATEGORIES or real_ext in ("exe", "lnk", "html", "hta", "js"):
            flags.add("extension_mismatch_executable")
        elif real["confidence"] >= 0.8:
            flags.add("extension_mismatch")
    if category in EXEC_CATEGORIES:
        flags.add(category)
    if real_category in EXEC_CATEGORIES and real_category != category:
        flags.add(real_category)
    if ext in ("xll", "wll"):
        flags.add("xll")

    if size > MAX_ANALYZE_BYTES:
        details["skipped"] = "too large for deep analysis"
    else:
        try:
            kind = real_ext or ext
            if kind in ("docx", "xlsx", "pptx", "ooxml", "vsdx", "doc", "xls", "ppt", "ole", "rtf", "docm", "xlsm", "pptm",
                        "dotm", "xlam", "xlsb", "office_encrypted", "odt", "ods", "odp", "odf", "pub", "mdb", "slk", "iqy", "csv",
                        "mht", "mhtml", "xml") and (category in ("office", "office_macro", "office_legacy", "rtf", "data", "text", "html") or real_category in ("office", "office_macro", "office_legacy", "rtf")):
                if kind in ("mht", "mhtml", "html", "xml") and not (data[:2] == b"PK" or data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" or data[:5].lower() == b"{\\rtf"):
                    pass
                else:
                    off = _office.analyze_office(data, ext, real_ext)
                    details["office"] = off
                    flags.update(off["flags"])
                    if off.get("encrypted"):
                        flags.add("office_encrypted")
                    if category == "office_legacy" or real_category == "office_legacy":
                        flags.add("office_legacy")
                    if kind == "rtf" or real_ext == "rtf":
                        flags.add("rtf")
            if kind == "pdf" or real_ext == "pdf":
                pdf = _pdf.analyze_pdf(data)
                details["pdf"] = pdf
                flags.update(pdf["flags"])
            if real_ext in ("zip", "jar", "apk", "appx", "gz", "tgz", "tar", "bz2", "xz", "rar", "7z", "cab", "iso", "img", "vhd", "vhdx", "one") and real_ext not in ("docx", "xlsx", "pptx"):
                if real_ext == "one":
                    flags.add("onenote")
                    details["onenote"] = _onenote(data)
                    flags.update(details["onenote"]["flags"])
                else:
                    arc = _archive.analyze_archive(data, ext, real_ext, analyze_nested=_nested, depth=depth)
                    details["archive"] = arc
                    flags.update(arc["flags"])
                    if real_category == "archive" or category == "archive":
                        flags.add("archive")
            elif category == "archive" and real_ext not in ("zip", "jar"):
                arc = _archive.analyze_archive(data, ext, real_ext or ext, analyze_nested=_nested, depth=depth)
                details["archive"] = arc
                flags.update(arc["flags"])
                flags.add("archive")
            if real_ext in ("html", "svg", "xhtml", "mht", "mhtml") or ext in ("html", "htm", "shtml", "xhtml", "svg", "mht", "mhtml"):
                if not (data[:2] == b"PK" or data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
                    h = _html.analyze_html(data, ext or real_ext)
                    details["html"] = h
                    flags.update(h["flags"])
                    flags.add("html_attachment")
            if real_ext == "lnk" or ext == "lnk":
                details["lnk"] = _lnk(data)
                flags.add("shortcut")
            if real_ext == "exe":
                details["pe"] = _pe(data)
            if real_ext == "eml" or ext == "eml" or (declared_mime or "").lower() == "message/rfc822" or real_ext == "msg" or ext == "msg":
                flags.add("nested_mail")
                if depth < 2:
                    try:
                        from services.parsers.mail.common import parse_nested_mail

                        details["mail"] = parse_nested_mail(name, data, depth + 1)
                        for f in details["mail"].get("flags", []):
                            flags.add("nested_" + f)
                        for att in details["mail"].get("attachments", []):
                            for f in att.get("flags", []):
                                flags.add("nested_" + f)
                    except Exception as exc:  # noqa: BLE001
                        details["mailError"] = str(exc)[:200]
            if ext == "ics" or real_ext == "ics":
                if b"ATTENDEE" in data[:200000] or b"http" in data[:200000].lower():
                    flags.add("calendar_lure")
            if ext == "vcf":
                flags.add("vcard")
        except Exception as exc:  # noqa: BLE001
            log.warning("attachment analysis error for %s: %s", name, exc)
            details["error"] = str(exc)[:300]
            flags.add("office_parse_error" if category in ("office", "office_macro", "office_legacy") else "analysis_error")
        try:
            ym = yara_scan.scan(data)
            if ym:
                details["yara"] = ym
                flags.add("yara_match")
        except Exception:  # noqa: BLE001
            pass

    result["flags"] = sorted(flags)
    result["risk"] = _score(result["flags"])
    return result


def _nested(name: str, data: bytes, depth: int) -> dict[str, Any]:
    res = analyze_attachment(name, data, None, depth=depth)
    # keep nested entries compact
    res.pop("details", None)
    return res


def _onenote(data: bytes) -> dict[str, Any]:
    """OneNote sections can embed arbitrary files (FileDataStoreObject GUID)."""
    guid = b"\xe7\x16\xe3\xbd\x65\x26\x11\x45\xa4\xc4\x8d\x4d\x0b\x7a\x9e\xac"
    flags: set[str] = set()
    embedded: list[str] = []
    pos = 0
    count = 0
    while True:
        idx = data.find(guid, pos)
        if idx == -1 or count > 50:
            break
        count += 1
        start = idx + 36
        head = data[start:start + 16]
        if head.startswith(b"MZ"):
            embedded.append("exe")
        elif head.startswith(b"PK"):
            embedded.append("zip")
        elif head.startswith(b"%PDF"):
            embedded.append("pdf")
        elif head.startswith(b"\xd0\xcf\x11\xe0"):
            embedded.append("ole")
        elif head.lstrip().lower().startswith((b"<html", b"<!doc", b"<script", b"<hta", b"<?xml")):
            embedded.append("html")
        elif head.startswith(b"L\x00\x00\x00"):
            embedded.append("lnk")
        elif head[:2] in (b"\xff\xd8",) or head.startswith(b"\x89PNG"):
            embedded.append("image")
        else:
            txt = head.lower()
            if any(k in data[start:start + 4096].lower() for k in (b"powershell", b"cmd.exe", b"wscript", b"cscript", b"mshta", b"createobject", b"@echo off")):
                embedded.append("script")
            else:
                embedded.append("unknown")
        pos = idx + 16
    if any(e in ("exe", "html", "lnk", "script", "zip", "ole") for e in embedded):
        flags.add("archive_contains_executable" if "exe" in embedded else "archive_contains_script")
    return {"embedded": embedded, "count": count, "flags": sorted(flags)}


def _lnk(data: bytes) -> dict[str, Any]:
    """Very small LNK parser: flags, target/args strings (UTF-16 or ANSI)."""
    out: dict[str, Any] = {"strings": []}
    try:
        import struct

        if len(data) < 0x4C:
            return out
        link_flags = struct.unpack_from("<I", data, 0x14)[0]
        out["hasArguments"] = bool(link_flags & 0x20)
        out["hasIconLocation"] = bool(link_flags & 0x40)
        out["isUnicode"] = bool(link_flags & 0x80)
        out["hasEnvironmentBlock"] = bool(link_flags & 0x200)
        # crude string harvesting
        import re as _re

        for m in _re.finditer(rb"(?:[\x20-\x7e]\x00){6,}", data):
            s = m.group(0).decode("utf-16-le", "ignore")
            if s.strip():
                out["strings"].append(s[:300])
        for m in _re.finditer(rb"[\x20-\x7e]{8,}", data):
            s = m.group(0).decode("ascii", "ignore")
            if s not in out["strings"]:
                out["strings"].append(s[:300])
        joined = " ".join(out["strings"]).lower()
        out["suspicious"] = [k for k in ("powershell", "cmd.exe", "mshta", "wscript", "cscript", "rundll32", "regsvr32",
                                          "certutil", "bitsadmin", "curl", "http", "-enc", "-w hidden", "iex", "invoke",
                                          "downloadstring", "\\\\", "conhost", "forfiles", "msiexec", "explorer.exe ")
                             if k in joined]
    except Exception as exc:  # noqa: BLE001
        out["error"] = str(exc)[:100]
    out["strings"] = out["strings"][:40]
    return out


def _pe(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {}
    try:
        import struct

        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] == b"PE\x00\x00":
            machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
            characteristics = struct.unpack_from("<H", data, e_lfanew + 22)[0]
            timestamp = struct.unpack_from("<I", data, e_lfanew + 8)[0]
            out["machine"] = {0x14C: "x86", 0x8664: "x64", 0x1C0: "ARM", 0xAA64: "ARM64"}.get(machine, hex(machine))
            out["dll"] = bool(characteristics & 0x2000)
            out["compileTimestamp"] = timestamp
            magic = struct.unpack_from("<H", data, e_lfanew + 24)[0]
            out["pe32plus"] = magic == 0x20B
            subsystem_off = e_lfanew + 24 + (68 if magic == 0x20B else 68)
            subsystem = struct.unpack_from("<H", data, subsystem_off)[0]
            out["subsystem"] = {2: "GUI", 3: "console", 1: "native"}.get(subsystem, subsystem)
        if b"This program cannot be run in DOS mode" not in data[:1024]:
            out["dosStubMissing"] = True
        if b"UPX" in data[:4096]:
            out["packer"] = "UPX"
        out["hasSignature"] = b"wintrust" in data.lower() or b"\x30\x82" in data[-65536:]
    except Exception as exc:  # noqa: BLE001
        out["error"] = str(exc)[:100]
    return out
