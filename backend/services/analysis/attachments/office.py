"""Office / RTF document analysis with oletools (macros, XLM, DDE, external templates, OLE objects)."""
from __future__ import annotations

import io
import logging
import re
import zipfile
from typing import Any

log = logging.getLogger(__name__)

_DDE_RE = re.compile(rb"(?i)DDE(?:AUTO)?\b|\\ddeauto|\\dde\b|\bDDE\x00(?:A\x00U\x00T\x00O\x00)?")
_DDE_FIELD_RE = re.compile(rb"(?i)(?:<w:instrText[^>]*>\s*)?DDE(?:AUTO)?[\s\"'\\][^<]{0,200}")
_EXT_REL_RE = re.compile(rb'(?is)<Relationship\b[^>]*?/?>')
_ATTR_RE = re.compile(rb'(?is)\b(Type|Target|TargetMode|Id)="([^"]*)"')
_MSO_RE = re.compile(rb"(?i)mso-?script|vbscript:|javascript:")
_RTF_OBJ_RE = re.compile(rb"(?i)\\object|\\objdata|\\objupdate|\\objocx|\\objemb|\\objautlink|\\objclass\s*([A-Za-z0-9._]+)")
_RTF_OVERLAY_RE = re.compile(rb"\\bin\d|\\pict")
_RTF_EQN_RE = re.compile(rb"(?i)equation\.?3|0002ce02-0000-0000-c000-000000000046|0002CE02")
_URL_RE = re.compile(rb"(?i)\b(?:https?|ftp|file|\\\\)[^\s\"'<>]{4,300}")


def _rels_external(data: bytes) -> list[dict[str, Any]]:
    """Scan every *.rels inside an OOXML zip for external relationships."""
    out: list[dict[str, Any]] = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for name in zf.namelist():
                if not name.lower().endswith(".rels"):
                    continue
                try:
                    content = zf.read(name)
                except Exception:  # noqa: BLE001
                    continue
                for rel in _EXT_REL_RE.findall(content):
                    attrs = {k.decode().lower(): v.decode("utf-8", "replace") for k, v in _ATTR_RE.findall(rel)}
                    target = attrs.get("target", "")
                    mode = attrs.get("targetmode", "")
                    rtype = attrs.get("type", "").rsplit("/", 1)[-1]
                    if mode.lower() == "external" or target.lower().startswith(("http://", "https://", "file://", "\\\\", "ftp://", "mhtml:")):
                        if rtype.lower() == "hyperlink":
                            continue  # ordinary links are collected as URLs elsewhere
                        out.append({"rels": name, "type": rtype, "target": target[:500], "mode": mode})
    except zipfile.BadZipFile:
        pass
    except Exception as exc:  # noqa: BLE001
        log.debug("rels scan failed: %s", exc)
    return out


def _ooxml_inventory(data: bytes) -> dict[str, Any]:
    inv: dict[str, Any] = {"vbaProject": False, "embeddings": [], "activeX": 0, "xlmSheets": 0, "customXml": 0,
                           "settingsDde": False, "macroSheets": 0, "oleObjects": 0, "names": 0}
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()
            inv["names"] = len(names)
            for n in names:
                low = n.lower()
                if low.endswith("vbaproject.bin") or "/vbaproject" in low:
                    inv["vbaProject"] = True
                elif "/embeddings/" in low:
                    inv["embeddings"].append(n.rsplit("/", 1)[-1][:120])
                elif "/activex/" in low and low.endswith(".bin"):
                    inv["activeX"] += 1
                elif "/macrosheets/" in low:
                    inv["macroSheets"] += 1
                elif "customxml/" in low:
                    inv["customXml"] += 1
            for n in names:
                low = n.lower()
                if low in ("word/document.xml", "word/settings.xml", "xl/workbook.xml") or low.startswith("word/header") or low.startswith("word/footer") or low.startswith("xl/worksheets/"):
                    try:
                        content = zf.read(n)
                    except Exception:  # noqa: BLE001
                        continue
                    if _DDE_RE.search(content):
                        inv["settingsDde"] = True
                    inv["oleObjects"] += len(re.findall(rb"(?i)<o:OLEObject|<oleObj\b|<w:object\b", content))
    except Exception as exc:  # noqa: BLE001
        log.debug("ooxml inventory failed: %s", exc)
    return inv


def analyze_office(data: bytes, ext: str, real_ext: str) -> dict[str, Any]:
    """
    Returns a dict with keys: flags (list), macros (dict|None), externalRelations,
    ooxml (inventory), ole (streams), dde (bool), encrypted (bool), rtf (dict|None).
    """
    flags: set[str] = set()
    out: dict[str, Any] = {"flags": [], "macros": None, "externalRelations": [], "ooxml": None,
                           "ole": None, "dde": False, "encrypted": False, "rtf": None, "xlm": None, "urls": []}
    is_zip = data[:2] == b"PK"
    is_ole = data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    is_rtf = data[:5].lower() == b"{\\rtf"

    if is_zip:
        inv = _ooxml_inventory(data)
        out["ooxml"] = inv
        if inv["vbaProject"]:
            flags.add("office_macro")
        if inv["embeddings"]:
            flags.add("office_ole_object")
        if inv["activeX"]:
            flags.add("office_activex")
        if inv["macroSheets"]:
            flags.add("office_xlm")
        if inv["settingsDde"]:
            flags.add("office_dde")
            out["dde"] = True
        rels = _rels_external(data)
        out["externalRelations"] = rels
        for r in rels:
            t = r["type"].lower()
            if "attachedtemplate" in t or "template" in t:
                flags.add("office_external_template")
            elif "oleobject" in t or "package" in t or "frame" in t or "subdocument" in t:
                flags.add("office_external_object")
            elif "image" in t and r["target"].lower().startswith("http"):
                flags.add("office_remote_image")
            else:
                flags.add("office_external_relation")

    if is_ole:
        try:
            import olefile

            with olefile.OleFileIO(io.BytesIO(data)) as ole:
                streams = ["/".join(s) for s in ole.listdir(streams=True, storages=True)]
                out["ole"] = {"streams": streams[:80], "count": len(streams)}
                low = [s.lower() for s in streams]
                if "encryptedpackage" in low or ole.exists("EncryptionInfo"):
                    out["encrypted"] = True
                    flags.add("office_encrypted")
                if any("macros" in s or "_vba_project" in s or s.startswith("vba") for s in low):
                    flags.add("office_macro")
                if any("objectpool" in s or "ole10native" in s or s.startswith("\x01ole") for s in low):
                    flags.add("office_ole_object")
                if any(s.endswith("word/document") or s == "worddocument" for s in low):
                    pass
                try:
                    meta = ole.get_metadata()
                    out["metadata"] = {
                        "author": (meta.author or b"").decode("utf-8", "replace") if isinstance(meta.author, bytes) else meta.author,
                        "lastSavedBy": (meta.last_saved_by or b"").decode("utf-8", "replace") if isinstance(meta.last_saved_by, bytes) else meta.last_saved_by,
                        "created": str(meta.create_time) if meta.create_time else None,
                        "modified": str(meta.last_saved_time) if meta.last_saved_time else None,
                        "creatingApp": (meta.creating_application or b"").decode("utf-8", "replace") if isinstance(meta.creating_application, bytes) else meta.creating_application,
                    }
                except Exception:  # noqa: BLE001
                    pass
        except Exception as exc:  # noqa: BLE001
            log.debug("olefile failed: %s", exc)
        if _DDE_RE.search(data):
            # Legacy .doc: DDE fields are stored as text in the WordDocument stream (UTF-16 or ANSI)
            if re.search(rb"(?i)D\x00D\x00E\x00A\x00U\x00T\x00O\x00|DDEAUTO", data):
                flags.add("office_dde")
                out["dde"] = True

    if is_rtf:
        rtf: dict[str, Any] = {"objects": 0, "classes": [], "equation": False, "objupdate": False, "objocx": False, "packages": 0}
        try:
            from oletools import rtfobj

            parser = rtfobj.RtfObjParser(data)
            parser.parse()
            rtf["objects"] = len(parser.objects)
            for obj in parser.objects:
                cls = getattr(obj, "class_name", None)
                if cls:
                    cls = cls.decode("utf-8", "replace") if isinstance(cls, bytes) else str(cls)
                    rtf["classes"].append(cls[:80])
                if getattr(obj, "is_package", False):
                    rtf["packages"] += 1
                    pkg = getattr(obj, "filename", None)
                    if pkg:
                        rtf.setdefault("packageNames", []).append(str(pkg)[:120])
        except Exception as exc:  # noqa: BLE001
            log.debug("rtfobj failed: %s", exc)
            rtf["objects"] = len(re.findall(rb"(?i)\\object", data))
        if _RTF_EQN_RE.search(data) or any("equation" in c.lower() for c in rtf["classes"]):
            rtf["equation"] = True
            flags.add("rtf_equation_editor")
        if re.search(rb"(?i)\\objupdate", data):
            rtf["objupdate"] = True
            flags.add("rtf_objupdate")
        if re.search(rb"(?i)\\objocx", data):
            rtf["objocx"] = True
        if rtf["objects"]:
            flags.add("rtf_object")
        if rtf["packages"]:
            flags.add("rtf_package")
        if re.search(rb"(?i)\\object[^{}]*\\objautlink", data) or _DDE_RE.search(data):
            flags.add("office_dde")
            out["dde"] = True
        out["rtf"] = rtf

    # VBA macro extraction and static analysis (all container types)
    if is_zip or is_ole or is_rtf or ext in ("xml", "mht", "mhtml", "slk", "csv", "iqy"):
        out["macros"] = _analyze_vba(data, ext or real_ext)
        m = out["macros"]
        if m and m.get("hasMacros"):
            flags.add("office_macro")
            if m.get("autoExec"):
                flags.add("macro_autoexec")
            if m.get("suspicious"):
                flags.add("macro_suspicious")
            if m.get("iocs"):
                flags.add("macro_ioc")
            if m.get("obfuscation"):
                flags.add("macro_obfuscated")
            if m.get("stomped"):
                flags.add("macro_vba_stomping")
        if m and m.get("xlm"):
            flags.add("office_xlm")
            out["xlm"] = m.get("xlm")

    # SLK / IQY / CSV injection-style files
    if ext in ("slk", "iqy", "csv", "txt"):
        low = data[:20000].lower()
        if ext == "iqy" and b"web" in low and (b"http" in low or b"\\\\" in low):
            flags.add("office_iqy_remote")
        if ext == "slk" and (b"exec(" in low or b"call(" in low or b"register(" in low):
            flags.add("office_xlm")
        if ext == "csv" and re.search(rb"(?m)^\s*[=+\-@].*(?:cmd|powershell|mshta|http|dde)", data[:200000], re.I):
            flags.add("csv_formula_injection")

    urls = sorted({u.decode("utf-8", "replace")[:300] for u in _URL_RE.findall(data[:2_000_000])})
    out["urls"] = urls[:50]
    out["flags"] = sorted(flags)
    return out


def _analyze_vba(data: bytes, ext: str) -> dict[str, Any] | None:
    try:
        from oletools.olevba import VBA_Parser
    except Exception as exc:  # noqa: BLE001
        log.warning("oletools unavailable: %s", exc)
        return None
    fname = f"attachment.{ext or 'bin'}"
    result: dict[str, Any] = {"hasMacros": False, "modules": [], "autoExec": [], "suspicious": [], "iocs": [],
                              "obfuscation": [], "stomped": False, "xlm": None, "codePreview": None, "error": None}
    vba = None
    try:
        vba = VBA_Parser(fname, data=data)
        result["type"] = getattr(vba, "type", None)
        if vba.detect_vba_macros():
            result["hasMacros"] = True
            code_all: list[str] = []
            for (_fn, stream_path, vba_filename, vba_code) in vba.extract_all_macros():
                code = vba_code if isinstance(vba_code, str) else (vba_code or b"").decode("utf-8", "replace")
                result["modules"].append({"stream": str(stream_path)[:120], "name": str(vba_filename)[:120],
                                          "lines": code.count("\n") + 1, "size": len(code)})
                code_all.append(code)
            joined = "\n".join(code_all)
            result["codePreview"] = joined[:4000]
            try:
                for kw_type, keyword, desc in vba.analyze_macros(show_decoded_strings=True, deobfuscate=True):
                    entry = {"keyword": str(keyword)[:200], "description": str(desc)[:200]}
                    t = str(kw_type).lower()
                    if t == "autoexec":
                        result["autoExec"].append(entry)
                    elif t == "suspicious":
                        result["suspicious"].append(entry)
                    elif t == "ioc":
                        result["iocs"].append(entry)
                    elif t in ("hex string", "base64 string", "dridex string", "vba string", "obfuscation"):
                        result["obfuscation"].append(entry)
            except Exception as exc:  # noqa: BLE001
                result["error"] = f"analyze_macros: {exc}"[:200]
            # VBA stomping: p-code present but source is empty / trivial
            try:
                if joined.strip() == "" or all(len(c.strip()) < 30 for c in code_all):
                    result["stomped"] = True
            except Exception:  # noqa: BLE001
                pass
        # Excel 4.0 (XLM) macros
        try:
            if vba.detect_xlm_macros():
                xlm_code = []
                try:
                    for (_fn, stream_path, vba_filename, vba_code) in vba.extract_all_macros():
                        if "xlm" in str(stream_path).lower() or "macro" in str(vba_filename).lower():
                            xlm_code.append(vba_code if isinstance(vba_code, str) else str(vba_code))
                except Exception:  # noqa: BLE001
                    pass
                result["xlm"] = {"present": True, "preview": "\n".join(xlm_code)[:2000]}
        except Exception:  # noqa: BLE001
            pass
    except Exception as exc:  # noqa: BLE001
        result["error"] = str(exc)[:200]
    finally:
        if vba is not None:
            try:
                vba.close()
            except Exception:  # noqa: BLE001
                pass
    # Trim to keep the payload reasonable
    for k in ("autoExec", "suspicious", "iocs", "obfuscation"):
        result[k] = result[k][:60]
    result["modules"] = result["modules"][:40]
    return result
