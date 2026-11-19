"""What the staging area may hold.

FORENSIC_TMP_DIR holds evidence while it is parsed: chunked uploads, Django's multipart spool, the
members a parse copies out of an archive and the directories it expands an archive or stages
event logs into. One figure bounds all of it, so the upload gate and the readers that copy members
out agree on what fits.
"""

from __future__ import annotations

import os
import shutil
import stat
from pathlib import Path

from django.conf import settings

GIB = 1024**3
# The directories a parse creates in the staging area, named by tempfile.mkdtemp with these
# suffixes: a 7z archive expanded to be read, and the event logs staged for one engine run.
DIRECTORY_SUFFIXES = (".7z", ".evtx")
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
    """Everything the staging area currently holds, including Django's own multipart spool and the
    directories a parse writes into. A file linked under two names (an event log staged for the
    engine is a hard link to the member it was copied to) is counted once."""
    seen: set[tuple[int, int]] = set()
    total = 0

    def count(path: str) -> None:
        nonlocal total
        try:
            st = os.lstat(path)
        except OSError:
            return
        if not stat.S_ISREG(st.st_mode) or (st.st_dev, st.st_ino) in seen:
            return
        if st.st_ino:  # some filesystems give no inode number, and then every file is its own
            seen.add((st.st_dev, st.st_ino))
        total += st.st_size

    for directory in (root() / "uploads", root()):
        try:
            entries = list(os.scandir(directory))
        except OSError:
            continue
        for entry in entries:
            if not entry.is_dir(follow_symlinks=False):
                count(entry.path)
            elif directory == root() and entry.name.endswith(DIRECTORY_SUFFIXES):
                for dirpath, _dirs, files in os.walk(entry.path):
                    for name in files:
                        count(os.path.join(dirpath, name))
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
