"""Rule-format import endpoints: Sigma (event logs) and Sublime MQL (mail)."""
from __future__ import annotations

import io
import json
import zipfile

from django.http import HttpRequest, HttpResponse, JsonResponse
from django.views.decorators.http import require_GET, require_POST

from services.rules import mql, packs, sigma

MAX_RULES = 6000
MAX_ZIP_MEMBER = 512 * 1024


def _texts_from_request(request: HttpRequest) -> list[tuple[str, str]]:
    """Accept JSON {"text": ...} / {"files": [{"name", "text"}]} or a multipart 'file' (.yml, .yaml, .zip)."""
    texts: list[tuple[str, str]] = []
    up = request.FILES.get("file")
    if up is not None:
        data = up.read()
        name = (up.name or "upload").lower()
        if name.endswith(".zip") or data[:2] == b"PK":
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for info in zf.infolist():
                    n = info.filename
                    if info.is_dir() or not n.lower().endswith((".yml", ".yaml")) or info.file_size > MAX_ZIP_MEMBER:
                        continue
                    texts.append((n, zf.read(info).decode("utf-8", "replace")))
                    if len(texts) >= MAX_RULES:
                        break
        else:
            texts.append((up.name or "upload.yml", data.decode("utf-8", "replace")))
        return texts
    try:
        body = json.loads(request.body or b"{}")
    except json.JSONDecodeError:
        return texts
    if isinstance(body.get("text"), str):
        texts.append((str(body.get("name") or "pasted.yml"), body["text"]))
    for f in body.get("files") or []:
        if isinstance(f, dict) and isinstance(f.get("text"), str):
            texts.append((str(f.get("name") or "rule.yml"), f["text"]))
    return texts[:MAX_RULES]


def _convert(request: HttpRequest, converter, what: str):
    texts = _texts_from_request(request)
    if not texts:
        return JsonResponse({"error": f"send {what} as multipart 'file' (.yml/.yaml/.zip) or JSON {{text}}"}, status=400)
    results: list[dict] = []
    for name, text in texts:
        results.extend(converter(text, name))
        if len(results) >= MAX_RULES:
            break
    ok = sum(1 for r in results if r.get("ok"))
    reasons: dict[str, int] = {}
    for r in results:
        if not r.get("ok"):
            key = str(r.get("error") or "?").split(" (")[0][:80]
            reasons[key] = reasons.get(key, 0) + 1
    return JsonResponse({
        "rules": results,
        "summary": {"total": len(results), "converted": ok, "skipped": len(results) - ok,
                    "reasons": sorted(reasons.items(), key=lambda kv: -kv[1])[:20]},
    })


@require_POST
def convert_sigma(request: HttpRequest):
    return _convert(request, sigma.convert_text, "Sigma YAML")


@require_POST
def convert_sublime(request: HttpRequest):
    return _convert(request, mql.convert_text, "Sublime rule YAML")


# ---------------------------------------------------------------------------
# community packs (rules/community/<id>/, written by tools/import_community_rules.py)
# ---------------------------------------------------------------------------
@require_GET
def list_packs(request: HttpRequest):
    return JsonResponse({"packs": packs.list_packs()})


@require_GET
def pack(request: HttpRequest, pack_id: str):
    data = packs.load_pack(pack_id)
    if data is None:
        return JsonResponse({"error": f"unknown rule pack {pack_id!r}"}, status=404)
    return JsonResponse(data)


@require_GET
def pack_license(request: HttpRequest, pack_id: str):
    text = packs.license_text(pack_id)
    if text is None:
        return JsonResponse({"error": f"no licence file for rule pack {pack_id!r}"}, status=404)
    return HttpResponse(text, content_type="text/plain; charset=utf-8")
