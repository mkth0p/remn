"""HTML / SVG / MHT attachment analysis: HTML smuggling, credential-harvesting forms, redirects."""
from __future__ import annotations

import base64
import re
from typing import Any

from services.analysis.urls import extract_urls

_B64_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{1000,}={0,2}")
_SMUGGLE_API = (
    ("atob(", "atob"), ("msSaveOrOpenBlob", "msSaveOrOpenBlob"), ("msSaveBlob", "msSaveBlob"),
    ("createObjectURL", "createObjectURL"), ("new Blob(", "Blob"), ("new File(", "File"),
    ("download=", "download_attr"), (".download", "download_attr"), ("Uint8Array", "Uint8Array"),
    ("charCodeAt", "charCodeAt"), ("fromCharCode", "fromCharCode"), ("unescape(", "unescape"),
    ("decodeURIComponent", "decodeURIComponent"), ("eval(", "eval"), ("document.write", "document_write"),
    ("Function(", "Function"), ("setTimeout(", "setTimeout"), ("XMLHttpRequest", "xhr"), ("fetch(", "fetch"),
    ("navigator.msSaveOrOpenBlob", "msSaveOrOpenBlob"), ("application/octet-stream", "octet_stream"),
    ("application/zip", "zip_mime"), ("application/x-msdownload", "exe_mime"), ("application/pdf", "pdf_mime"),
    (".split('').reverse().join", "reverse_string"), ('.split("").reverse().join', "reverse_string"),
    ("String.fromCharCode", "fromCharCode"), ("window.location", "location_redirect"), ("location.href", "location_redirect"),
    ("location.replace", "location_redirect"), ("btoa(", "btoa"), ("WebAssembly", "wasm"), ("crypto.subtle", "webcrypto"),
    ("CryptoJS", "cryptojs"), ("AES.decrypt", "aes_decrypt"), ("RC4", "rc4"), ("xor", "xor"),
)
_PASSWORD_INPUT = re.compile(r"(?i)<input[^>]*type\s*=\s*[\"']?password")
_EMAIL_INPUT = re.compile(r"(?i)<input[^>]*(?:type\s*=\s*[\"']?email|name\s*=\s*[\"']?(?:email|user(?:name)?|login|login_email|identifier))")
_FORM_ACTION = re.compile(r"(?i)<form[^>]*action\s*=\s*[\"']?([^\"'\s>]+)")
_META_REFRESH = re.compile(r"(?i)<meta[^>]*http-equiv\s*=\s*[\"']?refresh[^>]*content\s*=\s*[\"']?\s*\d+\s*;\s*url\s*=\s*([^\"'>\s]+)")
_SCRIPT_RE = re.compile(r"(?is)<script\b[^>]*>(.*?)</script>")
_SCRIPT_SRC = re.compile(r"(?i)<script[^>]*src\s*=\s*[\"']([^\"']+)")
_ONLOAD = re.compile(r"(?i)\bon(?:load|error|mouseover|focus|click|pageshow|animationstart)\s*=")
_HIDDEN_IFRAME = re.compile(r"(?is)<iframe[^>]*(?:width\s*=\s*[\"']?0|height\s*=\s*[\"']?0|display\s*:\s*none|visibility\s*:\s*hidden)")
_BRAND_TITLE = re.compile(r"(?i)(microsoft|office ?365|outlook|onedrive|sharepoint|adobe|docusign|dropbox|google|gmail|paypal|apple|amazon|webmail|owa|sign ?in|log ?in|connexion|identifiez)")
_LONG_STRING = re.compile(r"[\"'][A-Za-z0-9+/=%\\x]{5000,}[\"']")
_HEX_ESC = re.compile(r"(?:\\x[0-9a-fA-F]{2}){40,}|(?:\\u[0-9a-fA-F]{4}){30,}|(?:%[0-9a-fA-F]{2}){40,}")
_TEL_LURE = re.compile(r"(?i)(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}|\b0[1-9](?:[\s.-]?\d{2}){4}\b")


def smuggling_flags(details: dict[str, Any]) -> set[str]:
    """Classify retained facts too, so existing cases can use the same policy.

    File construction APIs are capabilities, not proof of smuggling. Require a
    suspicious payload/output, or reconstruction plus concealment and delivery.
    """
    apis = set(details.get("apis") or [])
    types = set(details.get("decodedBlobTypes") or [])
    delivery = bool(apis & {"download_attr", "msSaveBlob", "msSaveOrOpenBlob"})
    construction = bool(apis & {"Blob", "File", "createObjectURL", "msSaveBlob", "msSaveOrOpenBlob"})
    reconstruction = bool(apis & {"atob", "fromCharCode", "charCodeAt", "aes_decrypt", "cryptojs", "rc4", "reverse_string"})
    dangerous = bool(types & {"exe", "zip", "archive", "ole", "rtf"}) or bool(details.get("dangerousDownload")) or bool(apis & {"exe_mime", "zip_mime"})
    concealed = bool(details.get("obfuscated")) or bool(apis & {"eval", "unescape", "aes_decrypt", "rc4", "reverse_string"})
    flags: set[str] = set()
    if dangerous and construction and delivery or construction and delivery and reconstruction and concealed:
        flags.add("html_smuggling")
    elif dangerous or construction and delivery and reconstruction:
        flags.add("html_smuggling_possible")
    if types & {"exe", "zip", "archive", "ole", "rtf", "html"}:
        flags.add("html_embedded_payload")
    if types & {"image", "pdf"}:
        flags.add("html_embedded_document")
    if construction and delivery:
        flags.add("html_file_download")
    return flags


def _decode(data: bytes) -> str:
    for enc in ("utf-8", "utf-16", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "replace")


def analyze_html(data: bytes, ext: str) -> dict[str, Any]:
    text = _decode(data[:8_000_000])
    flags: set[str] = set()
    out: dict[str, Any] = {"flags": [], "apis": [], "scripts": 0, "externalScripts": [], "base64Bytes": 0,
                           "base64Blobs": 0, "decodedBlobTypes": [], "forms": [], "redirect": None, "title": None,
                           "urls": [], "passwordInput": False, "size": len(data)}
    m = re.search(r"(?is)<title[^>]*>(.*?)</title>", text)
    if m:
        out["title"] = re.sub(r"\s+", " ", m.group(1)).strip()[:200]
    scripts = _SCRIPT_RE.findall(text)
    out["scripts"] = len(scripts) + len(_SCRIPT_SRC.findall(text))
    out["externalScripts"] = _SCRIPT_SRC.findall(text)[:20]
    if out["scripts"]:
        flags.add("html_script")
    if _ONLOAD.search(text):
        flags.add("html_event_handler")
    joined_js = "\n".join(scripts)
    apis = sorted({tag for needle, tag in _SMUGGLE_API if needle in joined_js or (needle.startswith(".") and needle in text)})
    out["apis"] = apis
    blobs = _B64_RE.findall(text)
    out["base64Blobs"] = len(blobs)
    out["base64Bytes"] = sum(len(b) for b in blobs)
    for b in blobs[:5]:
        try:
            raw = base64.b64decode(b[: 4 * 64] + "=" * (-len(b[: 4 * 64]) % 4), validate=False)
        except Exception:  # noqa: BLE001
            continue
        head = raw[:16]
        if head.startswith(b"PK"):
            out["decodedBlobTypes"].append("zip")
        elif head.startswith(b"MZ"):
            out["decodedBlobTypes"].append("exe")
        elif head.startswith(b"%PDF"):
            out["decodedBlobTypes"].append("pdf")
        elif head.startswith(b"\xd0\xcf\x11\xe0"):
            out["decodedBlobTypes"].append("ole")
        elif head.startswith(b"{\\rtf"):
            out["decodedBlobTypes"].append("rtf")
        elif head.lower().lstrip().startswith((b"<html", b"<!doctype", b"<script", b"<body")):
            out["decodedBlobTypes"].append("html")
        elif head.startswith(b"\x89PNG") or head.startswith(b"\xff\xd8"):
            out["decodedBlobTypes"].append("image")
        elif head.startswith(b"Rar!") or head.startswith(b"7z\xbc\xaf"):
            out["decodedBlobTypes"].append("archive")
        else:
            out["decodedBlobTypes"].append("unknown")
    out["dangerousDownload"] = bool(re.search(r"(?i)(?:\.download\s*=|download\s*=)\s*['\"][^'\"]*\.(?:exe|dll|scr|js|vbs|hta|lnk|iso|img|zip|docm|xlsm)['\"]", text))
    out["obfuscated"] = bool(_LONG_STRING.search(text) or _HEX_ESC.search(text))
    flags.update(smuggling_flags(out))
    if out["obfuscated"]:
        flags.add("html_obfuscated")
    if "eval" in apis or "Function" in apis or "unescape" in apis:
        flags.add("html_dynamic_code")

    # Credential harvesting
    out["passwordInput"] = bool(_PASSWORD_INPUT.search(text))
    actions = _FORM_ACTION.findall(text)
    for a in actions[:10]:
        out["forms"].append(a[:300])
    if out["passwordInput"]:
        flags.add("html_password_form")
        if any(a.lower().startswith(("http://", "https://")) for a in actions) or "xhr" in apis or "fetch" in apis:
            flags.add("html_credential_harvest")
    elif _EMAIL_INPUT.search(text) and actions:
        flags.add("html_email_form")
    if out["title"] and _BRAND_TITLE.search(out["title"]):
        flags.add("html_brand_lure")
    if re.search(r"(?i)(?:autofill|prefill|value\s*=\s*[\"'][^\"'@]+@[^\"']+[\"'])", text) and (out["passwordInput"] or _EMAIL_INPUT.search(text)):
        flags.add("html_prefilled_email")

    # Redirects
    mr = _META_REFRESH.search(text)
    if mr:
        out["redirect"] = mr.group(1)[:400]
        flags.add("html_meta_refresh")
    elif "location_redirect" in apis:
        m2 = re.search(r"(?i)(?:window\.)?location(?:\.href|\.replace\(|\s*=)\s*[\"'(]?\s*[\"']([^\"']{6,400})", joined_js)
        if m2:
            out["redirect"] = m2.group(1)
        flags.add("html_js_redirect")
    if _HIDDEN_IFRAME.search(text):
        flags.add("html_hidden_iframe")
    if ext == "svg" or text.lstrip()[:200].lower().startswith("<svg") or "<svg" in text[:2000].lower():
        if out["scripts"] or _ONLOAD.search(text) or "<foreignObject" in text:
            flags.add("svg_script")
    if len(text) < 800 and out["redirect"]:
        flags.add("html_redirect_only")
    if len(text.strip()) < 200 and out["scripts"]:
        flags.add("html_script_only")
    if _TEL_LURE.search(text) and re.search(r"(?i)(?:call|appelez|contact|support|helpline|hotline|renew|subscription|abonnement|invoice|facture)", text):
        flags.add("html_callback_lure")

    urls, _info = extract_urls(None, text)
    out["urls"] = urls[:100]
    out["flags"] = sorted(flags)
    return out
