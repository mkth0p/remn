"""What the staging area may hold.

FORENSIC_TMP_DIR holds evidence while it is parsed: chunked uploads, Django's multipart spool and
the members a parse copies out of an archive. One figure bounds all of it, so the upload gate and
the readers that copy members out agree on what fits.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from django.conf import settings

GIB = 1024**3
# The largest archive member copied out for parsing, however much the staging area may hold.
MEMBER_MAX = 4 * GIB
# Without a configured total the staging area may use the free space of its disk, less a reserve
# for the case stores, which grow as staged evidence is ingested, and for the system: a tenth of
# the disk, and never more than 10 GiB of it.
RESERVE_MAX = 10 * GIB


def gib(n: int) -> str:
    return f"{n / GIB:,.1f} GiB"


def root() -> Path:
    return Path(settings.FILE_UPLOAD_TEMP_DIR)


def staged_bytes() -> int:
    """Everything the staging area currently holds, including Django's own multipart spool."""
    total = 0
    for directory in (root() / "uploads", root()):
        try:
            for p in directory.iterdir():
                if p.is_file():
                    total += p.stat().st_size
        except OSError:
            continue
    return total


def reserve(disk_total: int) -> int:
    return min(disk_total // 10, RESERVE_MAX)


def capacity() -> tuple[int, str]:
    """The most the staging area may hold at once, in bytes, and what sets that figure, in words.

    A configured total (FORENSIC_TMP_MAX_GB) is kept to what its disk can actually take, so a
    refusal names the disk rather than a setting that was never the limit. Without one, the figure
    is what the area holds now plus its disk's free space, less the reserve.
    """
    staged = staged_bytes()
    root().mkdir(parents=True, exist_ok=True)
    disk = shutil.disk_usage(root())
    configured = int(settings.FORENSIC_TMP_MAX_GB or 0)
    if configured > 0:
        if configured * GIB <= staged + disk.free:
            return configured * GIB, f"FORENSIC_TMP_MAX_GB is {configured}"
        return staged + disk.free, f"the disk under the staging area has {gib(disk.free)} free"
    kept = reserve(disk.total)
    return max(0, staged + disk.free - kept), (
        f"the disk under the staging area has {gib(disk.free)} free and keeps {gib(kept)} of it for the case stores "
        "and the system; FORENSIC_TMP_MAX_GB sets the total instead"
    )


def member_ceiling() -> int:
    """The largest archive member copied out for parsing: half what the staging area may hold, so
    one member of a small upload cannot fill the area every other upload shares, and never more
    than 4 GiB."""
    return min(MEMBER_MAX, capacity()[0] // 2)
