"""Hayabusa as a detection engine over Windows event logs.

Thousands of curated Sigma rules with tuned levels, run natively, in seconds. REMN's own catalogue
covers what Hayabusa does not: mail, cloud, collected artifacts. The binary is optional. When it is
absent nothing changes; when it is present, every EVTX that is ingested is also handed to it, and
its detections come back as findings tagged with the engine that produced them and linked to the
rows REMN parsed from the same records.

It runs like the native decoders: a separate process, watched for memory, time and output, killed
rather than trusted when it passes a limit, and what it wrote before that is kept.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from collections.abc import Iterator
from datetime import datetime
from typing import Any

import psutil
from django.conf import settings

ENGINE = "hayabusa"
RULE_PREFIX = f"engine:{ENGINE}:"
SEVERITY = {
    "critical": "critical",
    "crit": "critical",
    "high": "high",
    "medium": "medium",
    "med": "medium",
    "low": "low",
    "informational": "info",
    "info": "info",
    "emergency": "critical",
    "emer": "critical",
}
# "2026-08-19 01:34:26.123 +00:00" by default; ISO with a Z or T when asked for UTC
STAMP = re.compile(r"^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s*([+-]\d{2}:?\d{2}|Z)?$")
TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I)

# The bounds. An engine over a few hundred megabytes of logs wants more memory than a decoder
# over one artifact, and the container's memory limit is the ceiling above this one, so the
# operator sizes it (HAYABUSA_MAX_MB) and only HAYABUSA_CONCURRENCY runs share it at once. On a
# public instance that is one: two anonymous uploads must not be able to add up to the container.
MAX_OUTPUT = 256 * 1024**2
_slots: threading.BoundedSemaphore | None = None
_slots_size = 0


def max_rss() -> int:
    return int(getattr(settings, "HAYABUSA_MAX_MB", 1536) or 1536) * 1024**2


def _slot() -> threading.BoundedSemaphore:
    global _slots, _slots_size
    size = max(1, int(getattr(settings, "HAYABUSA_CONCURRENCY", 1) or 1))
    if _slots is None or _slots_size != size:
        _slots, _slots_size = threading.BoundedSemaphore(size), size
    return _slots


def binary() -> str | None:
    configured = str(getattr(settings, "HAYABUSA_PATH", "") or "").strip()
    if configured:
        return configured if os.path.isfile(configured) else None
    return shutil.which("hayabusa")


def rules_dir() -> str | None:
    configured = str(getattr(settings, "HAYABUSA_RULES", "") or "").strip()
    if configured:
        return configured if os.path.isdir(configured) else None
    found = binary()
    if not found:
        return None
    beside = os.path.join(os.path.dirname(os.path.abspath(found)), "rules")
    return beside if os.path.isdir(beside) else None


def available() -> bool:
    return bool(getattr(settings, "HAYABUSA_ENABLED", True)) and binary() is not None and rules_dir() is not None


def engines() -> list[str]:
    """What an ingest stream should announce it will run, so the client can prepare to link."""
    return [ENGINE] if available() else []


def command(target: str, output: str) -> list[str]:
    """The invocation. Kept in one place because it is the part most likely to move between
    Hayabusa releases; HAYABUSA_ARGS replaces the option set wholesale when it does."""
    override = str(getattr(settings, "HAYABUSA_ARGS", "") or "").strip()
    # Hayabusa 4.0 merged csv-timeline and json-timeline into dfir-timeline, with the format chosen
    # by -t. Releases before it want `json-timeline -L` instead: set HAYABUSA_ARGS for those.
    args = [binary() or ENGINE, "dfir-timeline"]
    if override:
        args += override.split()
    else:
        # -t jsonl one object per line, -w no wizard, -q/-Q quiet and no error logs, -C overwrite
        # the output, -b full channel and provider names rather than abbreviations, verbose profile
        # for rule file, tags and the source file, and no colour codes in what we parse.
        args += ["-t", "jsonl", "-w", "-q", "-Q", "-C", "-b", "--no-color", "-p", "verbose", "-m", str(getattr(settings, "HAYABUSA_MIN_LEVEL", "low") or "low")]
        rules = rules_dir()
        if rules:
            args += ["-r", rules]
    args += ["-f" if os.path.isfile(target) else "-d", target, "-o", output]
    return args


def _timestamp(value: Any) -> int | None:
    if not isinstance(value, str):
        return None
    match = STAMP.match(value.strip())
    if not match:
        return None
    day, clock, zone = match.groups()
    zone = "+00:00" if not zone or zone == "Z" else (zone if ":" in zone else f"{zone[:3]}:{zone[3:]}")
    try:
        return int(datetime.fromisoformat(f"{day}T{clock}{zone}").timestamp() * 1000)
    except ValueError:
        return None


def _tags(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if isinstance(value, str) and value.strip():
        return [v.strip() for v in re.split(r"[,¦|]", value) if v.strip()]
    return []


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:120] or "rule"


def to_finding(obj: dict[str, Any]) -> dict[str, Any] | None:
    """One Hayabusa detection as a REMN finding. refKeys name the event rows it belongs to, for
    whichever store holds them to resolve into refs."""
    title = str(obj.get("RuleTitle") or "").strip()
    if not title:
        return None
    level = SEVERITY.get(str(obj.get("Level") or "").strip().lower(), "medium")
    rule_file = str(obj.get("RuleFile") or "").strip()
    identity = os.path.splitext(os.path.basename(rule_file))[0] if rule_file else str(obj.get("RuleID") or title)
    rule_id = RULE_PREFIX + _slug(identity)
    computer, channel, record = obj.get("Computer"), obj.get("Channel"), obj.get("RecordID")
    details = obj.get("Details")
    if isinstance(details, dict):
        description = " | ".join(f"{k}: {v}" for k, v in details.items() if v not in (None, ""))
    else:
        description = str(details or "").strip()
    techniques = sorted({m.group(0).upper() for value in (obj.get("MitreTags"), obj.get("MitreTactics"), obj.get("OtherTags")) for m in TECHNIQUE.finditer(" ".join(_tags(value)))})
    tags = [f"engine:{ENGINE}", f"level:{level}"]
    tags += [f"tactic:{t}" for t in _tags(obj.get("MitreTactics"))][:10]
    tags += [f"tag:{t}" for t in _tags(obj.get("OtherTags")) if not TECHNIQUE.fullmatch(t)][:10]
    entities = {k: str(v) for k, v in (("computer", computer), ("channel", channel), ("eventId", obj.get("EventID")), ("provider", obj.get("Provider"))) if v not in (None, "")}
    ref_key = f"{computer}|{channel}|{record}"
    return {
        "ruleId": rule_id,
        "key": f"{rule_id}|{ref_key}",
        "title": title,
        "description": description[:2000] or None,
        "severity": level,
        "source": "events",
        "ts": _timestamp(obj.get("Timestamp")),
        "entities": entities,
        "count": 1,
        "refs": [],
        "attack": techniques,
        "tags": tags,
        "engine": ENGINE,
        "refKeys": [ref_key],
    }


def parse(lines: Iterator[str]) -> Iterator[dict[str, Any]]:
    for line in lines:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict):
            finding = to_finding(obj)
            if finding is not None:
                yield finding


def run(target: str, tmp_dir: str, *, deadline_s: float | None = None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Run the engine over one .evtx file or one directory of them.

    Returns the findings and a summary the caller can put in front of the analyst: how many, how
    long, and whether the run completed or was stopped at a limit.
    """
    fd, output = tempfile.mkstemp(dir=tmp_dir, suffix=".jsonl")
    os.close(fd)
    max_seconds = float(getattr(settings, "HAYABUSA_MAX_S", 300) or 300)
    limit = min(max_seconds, deadline_s) if deadline_s else max_seconds
    summary: dict[str, Any] = {"engine": ENGINE, "status": "parsed", "findings": 0, "seconds": 0.0}
    process = None
    started = time.monotonic()
    slot = _slot()
    # Waiting holds a worker thread, so the wait is short: an ingest that finds the engine busy
    # says so and carries on without it rather than queueing behind a stranger's upload.
    if not slot.acquire(timeout=float(getattr(settings, "HAYABUSA_WAIT_S", 20) or 20)):
        summary.update(status="unsupported", reason=f"{ENGINE} is busy with another ingest; no detections for this evidence, ingest it again later")
        try:
            os.unlink(output)
        except OSError:
            pass
        return [], summary
    try:
        exe = binary()
        process = subprocess.Popen(
            command(target, output),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            cwd=os.path.dirname(os.path.abspath(exe)) if exe else None,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        monitor = psutil.Process(process.pid)
        stopped = None
        while process.poll() is None:
            try:
                rss = monitor.memory_info().rss
            except psutil.NoSuchProcess:
                break
            if rss > max_rss():
                stopped = f"stopped at the {max_rss() // 1024**2} MiB memory limit"
            elif os.path.getsize(output) > MAX_OUTPUT:
                stopped = f"stopped at the {MAX_OUTPUT // 1024**2} MiB output limit"
            elif time.monotonic() - started > limit:
                stopped = f"stopped at the {limit:g} s time limit"
            if stopped:
                process.kill()
                break
            time.sleep(0.05)
        _out, err = process.communicate(timeout=30)
        if stopped:
            summary.update(status="error", reason=f"{ENGINE} {stopped}; detections written before that are kept")
        elif process.returncode:
            summary.update(status="error", reason=f"{ENGINE} exited {process.returncode}: {(err or b'').decode('utf-8', 'replace').strip()[-300:]}")
        with open(output, encoding="utf-8", errors="replace") as fh:
            findings = list(parse(fh))
        summary["findings"] = len(findings)
        return findings, summary
    except Exception as exc:  # noqa: BLE001
        summary.update(status="error", reason=f"{ENGINE} {type(exc).__name__}: {exc}"[:300])
        return [], summary
    finally:
        slot.release()
        summary["seconds"] = round(time.monotonic() - started, 2)
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        try:
            os.unlink(output)
        except OSError:
            pass


def stage(paths: list[tuple[str, str]], tmp_dir: str) -> str:
    """A directory of .evtx files for a single engine run: hard links where the filesystem allows
    them, copies where it does not. Names carry a position so two members with the same base name
    do not collide."""
    directory = tempfile.mkdtemp(dir=tmp_dir, suffix=".evtx")
    for index, (name, path) in enumerate(paths):
        base = re.sub(r"[^A-Za-z0-9._-]+", "_", os.path.basename(name.replace("\\", "/")))
        if not base.lower().endswith(".evtx"):
            base += ".evtx"
        destination = os.path.join(directory, f"{index:04d}-{base}")
        try:
            os.link(path, destination)
        except OSError:
            shutil.copyfile(path, destination)
    return directory


def resolve_refs(store, evidence_id, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Link findings to the event rows a server store holds for this evidence, by the identity
    both sides carry: computer, channel, record id."""
    cur = store.cursor()
    cur.execute('SELECT id, "computer", "channel", "recordId" FROM events WHERE "evidenceId" = ? AND "recordId" IS NOT NULL', [evidence_id])
    index = {f"{computer}|{channel}|{record}": row_id for row_id, computer, channel, record in cur.fetchall()}
    for finding in findings:
        keys = finding.pop("refKeys", []) or []
        finding["refs"] = [index[k] for k in keys if k in index]
    return findings
