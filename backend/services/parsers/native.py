"""Native forensic decoders run in a disposable process with bounded resources."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import psutil

MAX_OUTPUT = 64 * 1024**2


def decode(kind: str, path: str, tmp_dir: str) -> str:
    if os.path.getsize(path) > MAX_OUTPUT:
        raise ValueError("native artifact exceeds 64 MiB limit")
    fd, output = tempfile.mkstemp(dir=tmp_dir, suffix=".decoded")
    os.close(fd)
    command = [sys.executable, str(Path(__file__).with_name("native_worker.py")), kind, path, output]
    process = None
    try:
        process = subprocess.Popen(
            command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        )
        monitor = psutil.Process(process.pid)
        started = time.monotonic()
        while process.poll() is None:
            try:
                rss = monitor.memory_info().rss
            except psutil.NoSuchProcess:
                break
            if rss > 512 * 1024**2 or os.path.getsize(output) > MAX_OUTPUT or time.monotonic() - started > 30:
                raise ValueError("native parser exceeded memory, output or 30-second time limit")
            time.sleep(0.05)
        process.wait()
        if os.path.getsize(output) > MAX_OUTPUT:
            raise ValueError("native parser output exceeds 64 MiB")
        if process.returncode:
            with open(output, encoding="utf-8") as fh:
                reason = fh.read(500)
            raise ValueError(reason or "native parser failed")
        return output
    except BaseException:
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.wait()
        os.unlink(output)
        raise


class PartialDecode(Exception):
    """Raised after yielding every record a failed worker managed to decode."""


def records(kind: str, path: str, tmp_dir: str):
    output = decode(kind, path, tmp_dir)
    try:
        with open(output, encoding="utf-8") as fh:
            for line in fh:
                # A worker that failed part-way keeps what it decoded and marks the reason here.
                if line.startswith('{"_partial"'):
                    raise PartialDecode(json.loads(line)["_partial"])
                yield json.loads(line)
    finally:
        os.unlink(output)
