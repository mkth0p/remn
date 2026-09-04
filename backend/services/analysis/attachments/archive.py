"""Archive and disk-image attachment analysis (zip/tar/gz + heuristics for rar/7z/iso)."""
from __future__ import annotations

import gzip
import io
import logging
import re
import tarfile
import zipfile
from typing import Any, Callable

from services.analysis.attachments.magic import DANGEROUS_EXT, EXEC_CATEGORIES, analyze_name, extension_of

log = logging.getLogger(__name__)

MAX_NESTED_BYTES = 15 * 1024 * 1024
MAX_ENTRIES_ANALYZED = 40
_UTF16_EXE_RE = re.compile(rb"(?i)\.\x00(?:e\x00x\x00e|l\x00n\x00k|d\x00l\x00l|j\x00s|v\x00b\x00s|b\x00a\x00t|c\x00m\x00d|h\x00t\x00a|p\x00s\x001|s\x00c\x00r|m\x00s\x00i|w\x00s\x00f|c\x00p\x00l)\x00")
_ASCII_EXE_RE = re.compile(rb"(?i)[A-Z0-9_\-. ]{1,60}\.(exe|lnk|dll|js|vbs|bat|cmd|hta|ps1|scr|msi|wsf|cpl)\b")


def _entry_flags(names: list[str]) -> set[str]:
    flags: set[str] = set()
    for n in names:
        info = analyze_name(n)
        cat = info["category"]
        if cat in ("executable", "installer"):
            flags.add("archive_contains_executable")
        elif cat == "script":
            flags.add("archive_contains_script")
        elif cat == "shortcut":
            flags.add("archive_contains_shortcut")
        elif cat == "disk_image":
            flags.add("archive_contains_disk_image")
        elif cat == "archive":
            flags.add("nested_archive")
        elif cat in ("office_macro",):
            flags.add("archive_contains_office_macro")
        elif cat == "office_legacy":
            flags.add("archive_contains_legacy_office")
        elif cat == "html":
            flags.add("archive_contains_html")
        elif cat == "onenote":
            flags.add("archive_contains_onenote")
        elif cat == "help":
            flags.add("archive_contains_executable")
        for f in info["flags"]:
            flags.add("archive_entry_" + f)
        if ".." in n.replace("\\", "/").split("/") or n.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", n):
            flags.add("archive_path_traversal")
    return flags


def analyze_archive(data: bytes, ext: str, real_ext: str,
                    analyze_nested: Callable[[str, bytes, int], dict[str, Any]] | None = None,
                    depth: int = 0) -> dict[str, Any]:
    flags: set[str] = set()
    out: dict[str, Any] = {"flags": [], "format": real_ext or ext, "entries": [], "entryCount": 0,
                           "encrypted": False, "uncompressedSize": 0, "ratio": None, "nested": []}
    fmt = real_ext or ext
    entries: list[dict[str, Any]] = []

    def add_entry(name: str, size: int, csize: int | None, encrypted: bool, is_dir: bool) -> None:
        entries.append({"name": name[:300], "size": size, "compressedSize": csize, "encrypted": encrypted,
                        "dir": is_dir, "ext": extension_of(name), "category": DANGEROUS_EXT.get(extension_of(name))})

    try:
        if fmt in ("zip", "jar", "apk", "docx", "xlsx", "pptx", "ooxml", "zipx", "appx"):
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                infos = zf.infolist()
                out["entryCount"] = len(infos)
                total = 0
                for zi in infos[:2000]:
                    enc = bool(zi.flag_bits & 0x1)
                    if enc:
                        out["encrypted"] = True
                    total += zi.file_size
                    add_entry(zi.filename, zi.file_size, zi.compress_size, enc, zi.is_dir())
                out["uncompressedSize"] = total
                if data and total:
                    out["ratio"] = round(total / max(len(data), 1), 1)
                    if out["ratio"] > 100 and total > 50 * 1024 * 1024:
                        flags.add("zip_bomb")
                if out["encrypted"]:
                    flags.add("encrypted_archive")
                # Look inside (non-encrypted) small entries
                if analyze_nested and depth < 2:
                    analyzed = 0
                    for zi in infos:
                        if zi.is_dir() or zi.flag_bits & 0x1 or zi.file_size > MAX_NESTED_BYTES or zi.file_size == 0:
                            continue
                        cat = DANGEROUS_EXT.get(extension_of(zi.filename))
                        if cat is None and extension_of(zi.filename) in ("png", "jpg", "jpeg", "gif", "bmp", "xml", "rels"):
                            continue
                        if analyzed >= MAX_ENTRIES_ANALYZED:
                            flags.add("archive_partially_analyzed")
                            break
                        try:
                            blob = zf.read(zi)
                        except Exception:  # noqa: BLE001
                            continue
                        analyzed += 1
                        nested = analyze_nested(zi.filename, blob, depth + 1)
                        out["nested"].append(nested)
                        for f in nested.get("flags", []):
                            flags.add("nested_" + f if not f.startswith("archive_") else f)
        elif fmt in ("gz", "tgz", "gzip"):
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
                inner = gz.read(MAX_NESTED_BYTES + 1)
            name = ""
            # gzip header may contain the original file name (FNAME flag)
            if len(data) > 10 and data[3] & 0x08:
                end = data.find(b"\x00", 10)
                if end != -1:
                    name = data[10:end].decode("latin-1", "replace")
            if inner[:262].find(b"ustar") != -1 or (ext in ("tgz",)):
                return _analyze_tar(inner, out, flags, analyze_nested, depth)
            add_entry(name or "(gzip member)", len(inner), len(data), False, False)
            out["entryCount"] = 1
            if analyze_nested and depth < 2 and len(inner) <= MAX_NESTED_BYTES:
                nested = analyze_nested(name or "member", inner, depth + 1)
                out["nested"].append(nested)
                for f in nested.get("flags", []):
                    flags.add("nested_" + f)
        elif fmt in ("tar",):
            return _analyze_tar(data, out, flags, analyze_nested, depth)
        elif fmt in ("bz2", "xz"):
            try:
                import bz2 as _bz2
                import lzma as _lzma

                inner = _bz2.decompress(data[:MAX_NESTED_BYTES]) if fmt == "bz2" else _lzma.decompress(data[:MAX_NESTED_BYTES])
                if inner[:262].find(b"ustar") != -1:
                    return _analyze_tar(inner, out, flags, analyze_nested, depth)
                add_entry("(compressed member)", len(inner), len(data), False, False)
                out["entryCount"] = 1
                if analyze_nested and depth < 2 and len(inner) <= MAX_NESTED_BYTES:
                    nested = analyze_nested("member", inner, depth + 1)
                    out["nested"].append(nested)
                    for f in nested.get("flags", []):
                        flags.add("nested_" + f)
            except Exception as exc:  # noqa: BLE001
                out["error"] = str(exc)[:200]
        elif fmt == "rar":
            flags.add("unsupported_archive_format")
            # RAR: file headers store names in plain text; encrypted headers hide them.
            names = [m.group(0).decode("latin-1", "replace") for m in _ASCII_EXE_RE.finditer(data[:5_000_000])]
            if names:
                for n in sorted(set(names))[:50]:
                    add_entry(n.strip(), 0, None, False, False)
            if data[:8] == b"Rar!\x1a\x07\x01\x00":
                out["format"] = "rar5"
            # RAR4 header-encryption flag (0x0080 in main header flags) / RAR5 encryption header type 4
            if (len(data) > 12 and data[:7] == b"Rar!\x1a\x07\x00" and data[10] & 0x80) or (data[:8] == b"Rar!\x1a\x07\x01\x00" and b"\x04" in data[8:16]):
                out["encrypted"] = True
                flags.add("encrypted_archive")
            if b"\x00" not in data[8:64] and not names:
                out["encrypted"] = True
        elif fmt in ("7z", "ace", "arj", "cab", "lzh", "lha"):
            flags.add("unsupported_archive_format")
            if fmt == "7z":
                # 7z with encrypted headers: no readable names at all
                names = [m.group(0).decode("latin-1", "replace") for m in _ASCII_EXE_RE.finditer(data[:5_000_000])]
                for n in sorted(set(names))[:50]:
                    add_entry(n.strip(), 0, None, False, False)
                if b"\x06\xf1\x07\x01" in data[:64] or (len(data) > 64 and not names):
                    # 0x06f10701 = kEncodedHeader ... heuristic only
                    out["encryptedHeaders"] = "possible"
        elif fmt in ("iso", "img", "vhd", "vhdx", "udf", "daa", "bin"):
            flags.add("disk_image")
            names = set()
            for m in _UTF16_EXE_RE.finditer(data[:20_000_000]):
                start = max(0, m.start() - 120)
                chunk = data[start:m.end()]
                try:
                    txt = chunk.decode("utf-16-le", "ignore")
                except Exception:  # noqa: BLE001
                    continue
                cand = re.findall(r"[\w\-. ]{1,60}\.(?:exe|lnk|dll|js|vbs|bat|cmd|hta|ps1|scr|msi|wsf|cpl)", txt, re.I)
                if cand:
                    names.add(cand[-1].strip())
            for m in _ASCII_EXE_RE.finditer(data[:20_000_000]):
                names.add(m.group(0).decode("latin-1", "replace").strip())
            for n in sorted(names)[:50]:
                add_entry(n, 0, None, False, False)
            if names:
                flags.add("disk_image_contains_executable")
            if any(n.lower().endswith(".lnk") for n in names):
                flags.add("disk_image_contains_shortcut")
    except zipfile.BadZipFile:
        flags.add("archive_corrupt")
    except Exception as exc:  # noqa: BLE001
        log.debug("archive analysis failed: %s", exc)
        out["error"] = str(exc)[:200]

    out["entries"] = entries[:300]
    if entries:
        flags |= _entry_flags([e["name"] for e in entries if not e["dir"]])
        files = [e for e in entries if not e["dir"]]
        if len(files) == 1 and DANGEROUS_EXT.get(files[0]["ext"]) in EXEC_CATEGORIES:
            flags.add("archive_single_executable")
        if len(files) == 1 and files[0]["ext"] in ("html", "htm", "pdf", "docm", "xlsm", "one", "iso", "img", "lnk"):
            flags.add("archive_single_lure")
    if out["entryCount"] > 500:
        flags.add("archive_many_entries")
    out["flags"] = sorted(flags)
    return out


def _analyze_tar(data: bytes, out: dict[str, Any], flags: set[str],
                 analyze_nested: Callable[[str, bytes, int], dict[str, Any]] | None, depth: int) -> dict[str, Any]:
    out["format"] = "tar"
    entries: list[dict[str, Any]] = []
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
            members = tf.getmembers()
            out["entryCount"] = len(members)
            analyzed = 0
            for m in members[:2000]:
                entries.append({"name": m.name[:300], "size": m.size, "compressedSize": None, "encrypted": False,
                                "dir": m.isdir(), "ext": extension_of(m.name), "category": DANGEROUS_EXT.get(extension_of(m.name))})
                out["uncompressedSize"] += m.size
                if analyze_nested and depth < 2 and m.isfile() and 0 < m.size <= MAX_NESTED_BYTES and analyzed < MAX_ENTRIES_ANALYZED:
                    cat = DANGEROUS_EXT.get(extension_of(m.name))
                    if cat is None:
                        continue
                    f = tf.extractfile(m)
                    if f is None:
                        continue
                    analyzed += 1
                    nested = analyze_nested(m.name, f.read(), depth + 1)
                    out["nested"].append(nested)
                    for fl in nested.get("flags", []):
                        flags.add("nested_" + fl)
    except Exception as exc:  # noqa: BLE001
        out["error"] = str(exc)[:200]
        flags.add("archive_corrupt")
    out["entries"] = entries[:300]
    flags |= _entry_flags([e["name"] for e in entries if not e["dir"]])
    out["flags"] = sorted(flags)
    return out
