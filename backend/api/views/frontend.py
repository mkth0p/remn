"""Serve the Vite build (frontend/dist) from Django on a single port."""

from __future__ import annotations

import mimetypes
from pathlib import Path

from django.conf import settings
from django.http import FileResponse, Http404, HttpResponse


def _safe_join(root: Path, rel: str) -> Path:
    candidate = (root / rel).resolve()
    if root.resolve() not in candidate.parents and candidate != root.resolve():
        raise Http404()
    return candidate


def asset(request, path: str):
    dist = settings.FRONTEND_DIST
    file = _safe_join(dist / "assets", path)
    if not file.is_file():
        raise Http404()
    content_type, _ = mimetypes.guess_type(str(file))
    resp = FileResponse(open(file, "rb"), content_type=content_type or "application/octet-stream")
    resp["Cache-Control"] = "public, max-age=31536000, immutable"
    return resp


def index(request, path: str = ""):
    dist = settings.FRONTEND_DIST
    # Direct file in dist root (favicon, manifest...)
    if path:
        candidate = _safe_join(dist, path)
        if candidate.is_file():
            content_type, _ = mimetypes.guess_type(str(candidate))
            return FileResponse(open(candidate, "rb"), content_type=content_type or "application/octet-stream")
        # a path that names a file (favicon.ico, robots.txt) and does not exist is a 404, not the page:
        # a browser given HTML for an icon shows nothing, and never asks again
        if "." in path.rsplit("/", 1)[-1]:
            raise Http404()
    index_file = dist / "index.html"
    if not index_file.is_file():
        return HttpResponse(
            "<h1>Frontend not built</h1><p>Run <code>npm install &amp;&amp; npm run build</code> in "
            "<code>frontend/</code>, or use the Vite dev server (<code>npm run dev</code>).</p>",
            status=503,
            content_type="text/html",
        )
    resp = FileResponse(open(index_file, "rb"), content_type="text/html")
    resp["Cache-Control"] = "no-store"
    return resp
