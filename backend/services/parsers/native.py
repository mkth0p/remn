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
# A CAB decodes to an archive, not to records, so it is not bounded by the record-output ceiling.
# A Windows Defender support cab is routinely a couple of hundred megabytes expanded and carries
# the Defender operational event log, which is exactly the evidence an unwanted-software case
# needs. Judging it by the record ceiling rejected the whole thing.
MAX_CAB_OUTPUT = 512 * 1024**2
# Batch limits. Output is held in memory while it is grouped, so it is capped well below the
# single-artifact ceiling; a group that would exceed it is cut short and its remainder decoded
# one artifact at a time.
MAX_BATCH = 64
MAX_BATCH_SECONDS = 60.0
MAX_BATCH_OUTPUT = 16 * 1024**2


def decode(kind: str, path: str, tmp_dir: str) -> str:
    if os.path.getsize(path) > MAX_OUTPUT:
        raise ValueError("native artifact exceeds 64 MiB limit")
    ceiling = MAX_CAB_OUTPUT if kind == "cab" else MAX_OUTPUT
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
            if rss > 512 * 1024**2 or os.path.getsize(output) > ceiling or time.monotonic() - started > 30:
                raise ValueError("native parser exceeded memory, output or 30-second time limit")
            time.sleep(0.05)
        process.wait()
        if os.path.getsize(output) > ceiling:
            raise ValueError(f"native parser output exceeds {ceiling // 1024**2} MiB")
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


def _read_batch(output: str) -> list[tuple[int, list[dict], str | None]]:
    """Group a worker's framed output by artifact, keeping only artifacts that ran to a verdict."""
    decoded: dict[int, list[dict]] = {}
    finished: dict[int, str | None] = {}
    with open(output, encoding="utf-8") as fh:
        for line in fh:
            try:
                entry = json.loads(line)
            except ValueError:
                break  # a truncated final line is what a killed worker leaves
            index = entry.get("_i")
            if not isinstance(index, int):
                continue
            if "r" in entry:
                decoded.setdefault(index, []).append(entry["r"])
            else:
                finished[index] = entry.get("failed")
    # An artifact with no verdict line was never reached, or was cut off part-way. It is left out
    # so the caller can decode it alone rather than reporting a truncated artifact as complete.
    return [(i, decoded.get(i, []), finished[i]) for i in sorted(finished)]


def batch_records(kind: str, paths: list[str], tmp_dir: str) -> list[tuple[int, list[dict], str | None]]:
    """Decode several artifacts in one worker process.

    Returns (index into paths, records, failure reason or None) for every artifact that reached a
    verdict. Artifacts missing from the result were not reached: the caller decodes those
    individually, so a single hostile artifact costs its own decode and not its neighbours'.
    """
    # decode() refuses an oversized artifact before spawning; a group must not be the way in.
    paths = [p for p in paths if os.path.getsize(p) <= MAX_OUTPUT]
    if not paths:
        return []
    fd, manifest = tempfile.mkstemp(dir=tmp_dir, suffix=".manifest")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump([[kind, p] for p in paths], fh)
    fd, output = tempfile.mkstemp(dir=tmp_dir, suffix=".decoded")
    os.close(fd)
    command = [sys.executable, str(Path(__file__).with_name("native_worker.py")), "batch", manifest, output]
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
            # A group that hits a limit is stopped, not failed: the artifacts already flushed are
            # kept and the rest go back to the caller as unreached.
            if rss > 512 * 1024**2 or os.path.getsize(output) > MAX_BATCH_OUTPUT or time.monotonic() - started > MAX_BATCH_SECONDS:
                break
            time.sleep(0.05)
        if process.poll() is None:
            process.kill()
        process.wait()
        return _read_batch(output)
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.wait()
        for path in (manifest, output):
            try:
                os.unlink(path)
            except OSError:
                pass


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
