"""
Upload handler whose temporary files can be re-opened by path on Windows.

Django's TemporaryUploadedFile relies on NamedTemporaryFile(delete=True), which
Windows opens with O_TEMPORARY: the parsers (pyevtx-rs, libpff) could not open
the same path a second time. We create the file with delete=False and unlink
it ourselves when the request is closed.
"""

from __future__ import annotations

import logging
import os
import tempfile

from django.conf import settings
from django.core.files.uploadedfile import TemporaryUploadedFile, UploadedFile
from django.core.files.uploadhandler import FileUploadHandler, TemporaryFileUploadHandler

log = logging.getLogger(__name__)


class ForensicTemporaryUploadedFile(TemporaryUploadedFile):
    def __init__(self, name, content_type, size, charset, content_type_extra=None):  # noqa: D107
        _, ext = os.path.splitext(name or "")
        file = tempfile.NamedTemporaryFile(suffix=".upload" + ext[:16], dir=settings.FILE_UPLOAD_TEMP_DIR, delete=False)
        UploadedFile.__init__(self, file, name, content_type, size, charset, content_type_extra)

    def close(self):  # noqa: D102
        path = getattr(self.file, "name", None)
        try:
            self.file.close()
        except Exception:  # noqa: BLE001
            pass
        if path:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
            except OSError as exc:
                log.warning("could not remove upload temp file %s: %s", path, exc)


class ForensicTemporaryFileUploadHandler(TemporaryFileUploadHandler):
    def new_file(self, *args, **kwargs):  # noqa: D102
        FileUploadHandler.new_file(self, *args, **kwargs)
        self.file = ForensicTemporaryUploadedFile(self.file_name, self.content_type, 0, self.charset, self.content_type_extra)
