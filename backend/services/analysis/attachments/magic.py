"""Real file-type identification (puremagic + container sniffing) and filename tricks."""
from __future__ import annotations

import io
import re
import zipfile
from typing import Any

import puremagic

# Extension -> category. Categories drive the risk scoring.
DANGEROUS_EXT: dict[str, str] = {
    # native executables
    "exe": "executable", "scr": "executable", "com": "executable", "pif": "executable", "cpl": "executable",
    "dll": "executable", "sys": "executable", "drv": "executable", "ocx": "executable", "msi": "installer",
    "msp": "installer", "mst": "installer", "appx": "installer", "msix": "installer", "appxbundle": "installer",
    "msixbundle": "installer", "apk": "installer", "deb": "installer", "rpm": "installer", "dmg": "installer",
    "pkg": "installer", "xll": "executable", "wll": "executable",
    # scripts
    "bat": "script", "cmd": "script", "vbs": "script", "vbe": "script", "js": "script", "jse": "script",
    "wsf": "script", "wsh": "script", "hta": "script", "ps1": "script", "psm1": "script", "psd1": "script",
    "ps1xml": "script", "sct": "script", "reg": "script", "inf": "script", "py": "script", "pyw": "script",
    "jar": "script", "jnlp": "script", "class": "script", "sh": "script", "vb": "script", "vbscript": "script",
    "applescript": "script", "scpt": "script", "cs": "script", "csproj": "script", "msc": "script", "url": "shortcut",
    "website": "shortcut", "lnk": "shortcut", "desktop": "shortcut", "scf": "shortcut", "library-ms": "shortcut",
    "search-ms": "shortcut", "settingcontent-ms": "shortcut", "theme": "shortcut", "themepack": "shortcut",
    "diagcab": "shortcut", "chm": "help", "hlp": "help", "wim": "disk_image", "one": "onenote", "onepkg": "onenote",
    # disk images / containers that bypass Mark-of-the-Web
    "iso": "disk_image", "img": "disk_image", "vhd": "disk_image", "vhdx": "disk_image", "udf": "disk_image",
    "daa": "disk_image", "bin": "disk_image",
    # archives
    "zip": "archive", "rar": "archive", "7z": "archive", "ace": "archive", "arj": "archive", "cab": "archive",
    "gz": "archive", "tgz": "archive", "bz2": "archive", "xz": "archive", "tar": "archive", "z": "archive",
    "lz": "archive", "lzh": "archive", "lha": "archive", "zipx": "archive", "jar_": "archive", "uue": "archive",
    "tbz2": "archive", "txz": "archive", "gzip": "archive",
    # macro-enabled office
    "docm": "office_macro", "dotm": "office_macro", "xlsm": "office_macro", "xltm": "office_macro",
    "xlam": "office_macro", "pptm": "office_macro", "potm": "office_macro", "ppam": "office_macro",
    "ppsm": "office_macro", "sldm": "office_macro", "xlsb": "office_macro",
    # legacy office (can carry macros)
    "doc": "office_legacy", "dot": "office_legacy", "xls": "office_legacy", "xlt": "office_legacy",
    "ppt": "office_legacy", "pot": "office_legacy", "pps": "office_legacy", "rtf": "rtf", "wiz": "office_legacy",
    "pub": "office_legacy", "mdb": "office_legacy", "accdb": "office_legacy", "accde": "office_legacy",
    # modern office / pdf / html
    "docx": "office", "dotx": "office", "xlsx": "office", "xltx": "office", "pptx": "office", "potx": "office",
    "ppsx": "office", "odt": "office", "ods": "office", "odp": "office", "pdf": "pdf",
    "html": "html", "htm": "html", "xhtml": "html", "shtml": "html", "mht": "html", "mhtml": "html", "svg": "html",
    "eml": "mail", "msg": "mail", "ics": "calendar", "vcf": "contact", "xml": "data", "json": "data", "csv": "data",
    "txt": "text",
}
EXEC_CATEGORIES = {"executable", "installer", "script", "shortcut", "help", "onenote", "disk_image"}

_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_RTLO_CHARS = "‮‭‫‪⁦⁧⁨"


def extension_of(name: str | None) -> str:
    if not name:
        return ""
    n = name.strip().lower()
    n = n.rstrip(". ")
    if "." not in n:
        return ""
    return n.rsplit(".", 1)[1][:16]


def analyze_name(name: str | None) -> dict[str, Any]:
    n = name or ""
    flags: list[str] = []
    ext = extension_of(n)
    parts = [p for p in n.lower().split(".") if p]
    if len(parts) >= 3 and parts[-1] in DANGEROUS_EXT and parts[-2] in DANGEROUS_EXT and DANGEROUS_EXT.get(parts[-1]) in EXEC_CATEGORIES:
        flags.append("double_extension")
    elif len(parts) >= 3 and DANGEROUS_EXT.get(parts[-1]) in EXEC_CATEGORIES and parts[-2] in ("pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt", "html", "ppt", "pptx"):
        flags.append("double_extension")
    if any(c in n for c in _RTLO_CHARS):
        flags.append("rtlo_filename")
    if re.search(r"\s{5,}\.", n):
        flags.append("padded_filename")
    if len(n) > 120:
        flags.append("long_filename")
    if re.search(r"[​-‏⁠﻿]", n):
        flags.append("zero_width_filename")
    if re.search(r"[Ѐ-ӿͰ-Ͽ]", n) and re.search(r"[A-Za-z]", n):
        flags.append("mixed_script_filename")
    category = DANGEROUS_EXT.get(ext)
    return {"ext": ext, "category": category, "flags": flags}


def _sniff_zip(data: bytes) -> tuple[str, str] | None:
    """Look inside a ZIP container to tell OOXML / ODF / JAR / APK apart."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = set(zf.namelist()[:400])
    except Exception:  # noqa: BLE001
        return None
    if "[Content_Types].xml" in names:
        if any(n.startswith("word/") for n in names):
            return ("docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        if any(n.startswith("xl/") for n in names):
            return ("xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        if any(n.startswith("ppt/") for n in names):
            return ("pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation")
        if any(n.startswith("visio/") for n in names):
            return ("vsdx", "application/vnd.ms-visio.drawing")
        return ("ooxml", "application/vnd.openxmlformats-officedocument")
    if "mimetype" in names:
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                mt = zf.read("mimetype")[:100].decode("ascii", "replace")
            ext = {"application/vnd.oasis.opendocument.text": "odt",
                   "application/vnd.oasis.opendocument.spreadsheet": "ods",
                   "application/vnd.oasis.opendocument.presentation": "odp"}.get(mt, "odf")
            return (ext, mt)
        except Exception:  # noqa: BLE001
            return None
    if "META-INF/MANIFEST.MF" in names:
        if "AndroidManifest.xml" in names:
            return ("apk", "application/vnd.android.package-archive")
        return ("jar", "application/java-archive")
    if "AppxManifest.xml" in names:
        return ("appx", "application/vnd.ms-appx")
    return ("zip", "application/zip")


def _sniff_ole(data: bytes) -> tuple[str, str]:
    try:
        import olefile

        with olefile.OleFileIO(io.BytesIO(data)) as ole:
            streams = ["/".join(s) for s in ole.listdir(streams=True, storages=True)]
    except Exception:  # noqa: BLE001
        return ("ole", "application/x-ole-storage")
    low = [s.lower() for s in streams]
    if any(s.startswith("__substg1.0_") for s in low):
        return ("msg", "application/vnd.ms-outlook")
    if "encryptedpackage" in low:
        return ("office_encrypted", "application/encrypted")
    if "worddocument" in low:
        return ("doc", "application/msword")
    if "workbook" in low or "book" in low:
        return ("xls", "application/vnd.ms-excel")
    if "powerpoint document" in low:
        return ("ppt", "application/vnd.ms-powerpoint")
    if "\x01ole10native" in low or "ole10native" in "".join(low):
        return ("ole_package", "application/x-ole-package")
    return ("ole", "application/x-ole-storage")


def identify(data: bytes, filename: str | None = None) -> dict[str, Any]:
    """Return {'ext', 'mime', 'description', 'confidence'} for the real content."""
    head = data[:4096]
    result: dict[str, Any] = {"ext": "", "mime": "", "description": "", "confidence": 0.0}
    if not data:
        return result
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06") or head.startswith(b"PK\x07\x08"):
        z = _sniff_zip(data)
        if z:
            result.update({"ext": z[0], "mime": z[1], "description": f"ZIP container ({z[0]})", "confidence": 0.95})
            return result
    if head.startswith(_OLE_MAGIC):
        ext, mime = _sniff_ole(data)
        result.update({"ext": ext, "mime": mime, "description": f"OLE2 compound file ({ext})", "confidence": 0.95})
        return result
    if head.startswith(b"%PDF"):
        result.update({"ext": "pdf", "mime": "application/pdf", "description": "PDF document", "confidence": 0.99})
        return result
    if head.startswith(b"MZ"):
        result.update({"ext": "exe", "mime": "application/x-msdownload", "description": "Windows PE executable", "confidence": 0.99})
        return result
    if head.startswith(b"{\\rtf"):
        result.update({"ext": "rtf", "mime": "application/rtf", "description": "Rich Text Format", "confidence": 0.99})
        return result
    if head.startswith(b"L\x00\x00\x00\x01\x14\x02\x00"):
        result.update({"ext": "lnk", "mime": "application/x-ms-shortcut", "description": "Windows shortcut (LNK)", "confidence": 0.99})
        return result
    if head.startswith(b"Rar!\x1a\x07"):
        result.update({"ext": "rar", "mime": "application/vnd.rar", "description": "RAR archive", "confidence": 0.99})
        return result
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        result.update({"ext": "7z", "mime": "application/x-7z-compressed", "description": "7-Zip archive", "confidence": 0.99})
        return result
    if head.startswith(b"MSCF"):
        result.update({"ext": "cab", "mime": "application/vnd.ms-cab-compressed", "description": "Microsoft Cabinet", "confidence": 0.99})
        return result
    if len(data) > 0x8006 and data[0x8001:0x8006] == b"CD001":
        result.update({"ext": "iso", "mime": "application/x-iso9660-image", "description": "ISO 9660 disk image", "confidence": 0.99})
        return result
    if head.startswith(b"\xe4\x52\x5c\x7b\x8c\xd8\xa7\x4d\xae\xb1\x53\x78\xd0\x29\x96\xd3"):
        result.update({"ext": "one", "mime": "application/onenote", "description": "OneNote section", "confidence": 0.99})
        return result
    if head.startswith(b"\x1f\x8b"):
        result.update({"ext": "gz", "mime": "application/gzip", "description": "gzip", "confidence": 0.99})
        return result
    if head.startswith(b"BZh"):
        result.update({"ext": "bz2", "mime": "application/x-bzip2", "description": "bzip2", "confidence": 0.95})
        return result
    if head.startswith(b"\xfd7zXZ\x00"):
        result.update({"ext": "xz", "mime": "application/x-xz", "description": "xz", "confidence": 0.99})
        return result
    if head.startswith(b"MIME-Version") or head.startswith(b"From ") or head.startswith(b"Received:") or head.startswith(b"Return-Path:"):
        result.update({"ext": "eml", "mime": "message/rfc822", "description": "RFC 822 message", "confidence": 0.8})
        return result
    low = head[:1024].lower().lstrip()
    if low.startswith((b"<!doctype html", b"<html", b"<head", b"<body", b"<script", b"<?xml")) or (b"<html" in low[:512]):
        if b"<svg" in low[:600]:
            result.update({"ext": "svg", "mime": "image/svg+xml", "description": "SVG (XML, can carry scripts)", "confidence": 0.9})
        elif low.startswith(b"<?xml") and b"<html" not in low:
            result.update({"ext": "xml", "mime": "application/xml", "description": "XML", "confidence": 0.8})
        else:
            result.update({"ext": "html", "mime": "text/html", "description": "HTML document", "confidence": 0.9})
        return result
    if low.startswith(b"<svg"):
        result.update({"ext": "svg", "mime": "image/svg+xml", "description": "SVG (XML, can carry scripts)", "confidence": 0.9})
        return result
    try:
        matches = puremagic.magic_string(data, filename=filename or "")
    except puremagic.PureError:
        matches = []
    except Exception:  # noqa: BLE001
        matches = []
    if matches:
        best = max(matches, key=lambda m: m.confidence)
        ext = (best.extension or "").lstrip(".").lower()
        result.update({"ext": ext, "mime": best.mime_type or "", "description": best.name or "", "confidence": float(best.confidence)})
        return result
    # text vs binary heuristic
    sample = head[:2048]
    if sample and all(32 <= b < 127 or b in (9, 10, 13) for b in sample):
        result.update({"ext": "txt", "mime": "text/plain", "description": "Plain text", "confidence": 0.5})
    elif sample:
        try:
            sample.decode("utf-8")
            result.update({"ext": "txt", "mime": "text/plain", "description": "UTF-8 text", "confidence": 0.4})
        except UnicodeDecodeError:
            result.update({"ext": "", "mime": "application/octet-stream", "description": "Unknown binary", "confidence": 0.1})
    return result


_EQUIVALENT: dict[str, set[str]] = {
    "jpg": {"jpeg", "jpg", "jpe"}, "jpeg": {"jpeg", "jpg"}, "tif": {"tif", "tiff"}, "tiff": {"tif", "tiff"},
    "htm": {"htm", "html"}, "html": {"htm", "html", "xhtml", "shtml"}, "docx": {"docx", "docm", "dotx", "dotm", "ooxml"},
    "xlsx": {"xlsx", "xlsm", "xltx", "xltm", "xlam", "xlsb", "ooxml"}, "pptx": {"pptx", "pptm", "potx", "potm", "ppsx", "ppsm", "ooxml"},
    "doc": {"doc", "dot", "wiz"}, "xls": {"xls", "xlt", "xla"}, "ppt": {"ppt", "pot", "pps"}, "zip": {"zip", "zipx"},
    "txt": {"txt", "text", "log", "csv", "ini", "cfg", "md", "json", "xml", "eml", "vcf", "ics", "rtf", "svg", "htm", "html", "js", "vbs", "bat", "cmd", "ps1", "hta", "reg", "url", "inf", "sct", "wsf", "py", "sh"},
    "eml": {"eml", "txt", "mht", "mhtml"}, "msg": {"msg", "ole"}, "ole": {"doc", "xls", "ppt", "msg", "ole", "pub", "mdb"},
    "gz": {"gz", "tgz", "gzip"}, "exe": {"exe", "dll", "scr", "com", "pif", "cpl", "sys", "ocx", "xll", "drv"},
    "tar": {"tar"}, "jar": {"jar", "zip"}, "apk": {"apk"}, "svg": {"svg", "xml"}, "xml": {"xml", "svg", "xhtml", "rels", "config", "ps1xml"},
    "mp3": {"mp3"}, "mp4": {"mp4", "m4v", "mov"}, "png": {"png"}, "gif": {"gif"}, "bmp": {"bmp"}, "webp": {"webp"},
    "ics": {"ics", "txt"}, "pdf": {"pdf"}, "iso": {"iso", "img"}, "img": {"img", "iso"}, "cab": {"cab"}, "one": {"one"},
}


def extension_matches(declared: str, real: str) -> bool:
    if not declared or not real:
        return True
    if declared == real:
        return True
    if real in _EQUIVALENT.get(declared, set()) or declared in _EQUIVALENT.get(real, set()):
        return True
    # text-like real type is compatible with any text-ish declared extension
    if real == "txt" and declared in _EQUIVALENT["txt"]:
        return True
    return False
