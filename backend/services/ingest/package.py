"""Mixed investigation packages, with a bounded member inventory and explicit coverage."""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import tarfile
import tempfile
import time
import zipfile
from collections.abc import Iterator
from pathlib import PurePosixPath
from typing import Any

from services.analysis import hayabusa
from services.ingest.pipeline import EvtxSource, MailSource, Member, detect_archive, looks_like_mail
from services.ingest.reconcile import reconcile
from services.parsers import collection, m365, native, triage
from services.parsers.mail.common import ParseContext

MAX_FILES = 20_000
# Expectations harvested from collection-summary rows. Capped where they are appended, not only
# where they are read: an uncapped list is both unbounded memory and the driver of the
# reconciliation cost, and a summary CSV naming them is attacker-controlled.
MAX_EXPECTATIONS = 10_000
# Registry hives and prefetch files are decoded by a worker process bounded to 512 MiB, 64 MiB of
# output and 30 seconds. Nothing bounded HOW MANY, so a package of twenty thousand hives was twenty
# thousand subprocesses on one request. What the first version of that cap got wrong was the size
# of a real collection: prefetch files come in the hundreds, one interpreter start each, and a
# genuine 354-file collection spent its whole allowance on process startup and reported two thirds
# of its prefetch as unsupported. Prefetch is now decoded in groups, which costs one startup per
# sixty-four artifacts, so the allowance can be what a large collection actually needs.
MAX_NATIVE_DECODES = 5_000
MAX_NATIVE_SECONDS = 300.0
# Held-back artifacts wait on disk in the staging area, which on a public instance is RAM. This
# is a ceiling on what one REQUEST holds at once, tracked in the shared budget: when it lived on
# the instance, each nesting level got its own allowance and four levels held four times as much
# as the tmpfs was sized for.
MAX_DEFERRED_BYTES = 256 * 1024**2
# A genuine Defender support cab expands about ten to one. Many CFFILE entries can point at the
# same folder data, so the expanded total counts bytes written rather than bytes allocated, and
# without a ratio a few kilobytes of cabinet can manufacture the whole ceiling.
MAX_CAB_RATIO = 200
ENCODING_LABEL = {
    "utf-16": "UTF-16",
    "utf-16-le": "UTF-16LE, which the file does not declare",
    "utf-16-be": "UTF-16BE, which the file does not declare",
    "cp1252": "Windows-1252",
}
BUDGET_SPENT = f"native decoding budget for this package is spent ({MAX_NATIVE_DECODES} artifacts or {MAX_NATIVE_SECONDS:g}s); inventoried and hashed only"
MAX_MEMBER = 4 * 1024**3
MAX_TOTAL = 16 * 1024**3
MAX_STRUCTURED = 64 * 1024**2


def _unlink(path: str | None) -> None:
    if path:
        try:
            os.unlink(path)
        except OSError:
            pass


class PackageSource:
    def __init__(
        self,
        name: str,
        path: str | None,
        data: bytes | None,
        tmp_dir: str,
        ctx: ParseContext,
        include_raw: bool = True,
        package_id: str = "",
        *,
        budget=None,
        depth=0,
        inherited_context=None,
    ) -> None:
        self.name, self.path, self.data = name, path, data
        self.tmp_dir, self.ctx, self.include_raw = tmp_dir, ctx, include_raw
        self.package_id = package_id
        self.format = "investigation-package"
        self.files: list[dict[str, Any]] = []
        self.context: dict[str, Any] = {}
        self.counts = {"events": 0, "mails": 0, "observations": 0}
        self.ranges = {"eventRange": {"firstTs": None, "lastTs": None}, "mailRange": {"firstTs": None, "lastTs": None}}
        self.bytes_read = 0
        self.inventory_complete = True
        self.manifest_count = 0
        self.budget = budget if budget is not None else {"bytes": 0, "files": 0, "decodes": 0, "decodeSeconds": 0.0}
        self.budget.setdefault("decodes", 0)
        self.budget.setdefault("decodeSeconds", 0.0)
        self.depth = depth
        self.inherited_context = inherited_context or {}
        self.expectations = []
        self.nested_reconciliation = []
        # Artifacts decoded as a group later, keyed by staged path so a release is idempotent.
        # A group being decoded stays in here: taking it out is what stranded the files when a
        # client disconnected part-way through one.
        self.deferred: dict[str, tuple[dict[str, Any], str, str, int]] = {}
        self.budget.setdefault("deferredBytes", 0)
        # A collection laid out like a drive (KAPE, Velociraptor, acquire, a copied volume) is read
        # by dissect as one target after the member loop; see _drain_triage.
        self.triage = False
        self.triage_summary: dict[str, Any] = {}
        # a 7z archive (DFIR-ORC) has no streaming member access, so it is extracted once
        self._extracted: str | None = None
        # External detection engines to run over the event logs this package carries. The event
        # log members are held back for that, within the same hold allowance as prefetch, and the
        # findings are collected rather than streamed, so consumers that only want rows are not
        # handed something that is not one.
        self.engines: list[str] = []
        self.evtx_held: dict[str, tuple[dict[str, Any], str]] = {}
        self.findings: list[dict[str, Any]] = []
        self.engine_summaries: list[dict[str, Any]] = []

    def stats(self) -> dict[str, Any]:
        return {
            "count": sum(self.counts.values()),
            **self.counts,
            **self.ranges,
            "files": self.files,
            "errors": sum(f["status"] == "error" for f in self.files),
            "unsupported": sum(f["status"] == "unsupported" for f in self.files),
            "skipped": sum(f["status"] == "skipped" for f in self.files),
            "inventoryComplete": self.inventory_complete,
            "context": self.context,
            "reconciliation": reconcile(self.files, self.expectations) + self.nested_reconciliation,
        }

    def _release(self, tmp_path: str) -> None:
        """Give a held-back artifact its staging bytes back. Safe to call more than once."""
        held = self.deferred.pop(tmp_path, None)
        if held is not None:
            self.budget["deferredBytes"] = max(0, self.budget["deferredBytes"] - int(held[0].get("size") or 0))
        _unlink(tmp_path)

    def _emit(self, entry: dict[str, Any], member_name: str, index: int, rows) -> Iterator[dict[str, Any]]:
        """Stamp provenance onto a member's rows and account for them against the package."""
        for row_index, (kind, row) in enumerate(rows):
            if row.get("artifactType") == "collection-summary" and len(self.expectations) < MAX_EXPECTATIONS:
                self.expectations.append(row["data"])
            row.update(type=kind, packageId=self.package_id, sourceFile=member_name, sourceSha256=entry["sha256"], memberIndex=index)
            row.setdefault("sourceIndex", row_index)
            if str(row.get("parserVersion", "")).startswith("dissect-"):
                row["sourceIndex"] = row_index
            row.setdefault("recordKind", "event")
            row.setdefault("parserVersion", "remn/0.1.1")
            if kind == "event" and not row.get("computer") and self.context.get("host"):
                row["computer"] = self.context["host"]
            entry["count"] += 1
            bucket = "observations" if row["recordKind"] == "observation" else "mails" if kind == "mail" else "events"
            self.counts[bucket] += 1
            ts = row.get("date") if kind == "mail" else row.get("ts")
            if isinstance(ts, int):
                time_range = self.ranges["mailRange" if kind == "mail" else "eventRange"]
                time_range["firstTs"] = ts if time_range["firstTs"] is None else min(ts, time_range["firstTs"])
                time_range["lastTs"] = ts if time_range["lastTs"] is None else max(ts, time_range["lastTs"])
            yield row

    def _decode_one(self, held: tuple[dict[str, Any], str, str, int], raw_records=None, failure: str | None = None) -> Iterator[dict[str, Any]]:
        """Turn one held-back artifact into rows, whether a group decoded it or it decoded alone."""
        entry, tmp_path, member_name, index = held
        rows = None
        try:
            if raw_records is None:
                raw_records = collection.native_records("prefetch", tmp_path, member_name, self.context, self.tmp_dir)
            else:
                raw_records = collection.native_rows("prefetch", raw_records, member_name, self.context)
            rows = (("event", row) for row in raw_records)
            yield from self._emit(entry, member_name, index, rows)
            if failure:
                # Records decoded before the failure are kept, exactly as for a lone artifact.
                raise ValueError(failure)
            entry["status"] = "parsed"
        except Exception as exc:  # noqa: BLE001
            entry.update(status="error", reason=str(exc)[:300])
        finally:
            closer = getattr(rows, "close", None)
            if closer is not None:
                try:
                    closer()
                except Exception:  # noqa: BLE001
                    pass
            self._release(tmp_path)

    def _drain_native(self) -> Iterator[dict[str, Any]]:
        """Decode the prefetch artifacts held back from the member loop, in groups.

        One interpreter start per artifact is fine for a handful of registry hives and ruinous for
        prefetch, which arrives in the hundreds. A real 354-file collection spent its whole
        decoding allowance on process startup and reported two thirds of its prefetch as
        unsupported: artifacts the parser understands perfectly well, described as ones it does not.
        """
        while self.deferred:
            if self.budget["decodes"] >= MAX_NATIVE_DECODES or self.budget["decodeSeconds"] >= MAX_NATIVE_SECONDS:
                for entry, tmp_path, _name, _index in list(self.deferred.values()):
                    entry.update(status="unsupported", reason=BUDGET_SPENT)
                    self._release(tmp_path)
                return
            # Never take more into a group than the allowance still covers, or the allowance would
            # be enforced only between groups and a hostile package could overshoot it by a group.
            size = min(native.MAX_BATCH, MAX_NATIVE_DECODES - self.budget["decodes"])
            group = list(self.deferred.values())[:size]
            started = time.monotonic()
            try:
                results = native.batch_records("prefetch", [held[1] for held in group], self.tmp_dir)
            except Exception:  # noqa: BLE001
                results = []  # every artifact falls back to its own decode below
            finally:
                self.budget["decodeSeconds"] += time.monotonic() - started
            reached = set()
            for position, raw_records, failure in results:
                reached.add(position)
                self.budget["decodes"] += 1
                yield from self._decode_one(group[position], raw_records, failure)
            # An artifact the group never reached is decoded on its own, so one artifact that
            # exhausts a group limit costs its own decode rather than its neighbours.
            for position, held in enumerate(group):
                if position in reached:
                    continue
                if self.budget["decodes"] >= MAX_NATIVE_DECODES or self.budget["decodeSeconds"] >= MAX_NATIVE_SECONDS:
                    held[0].update(status="unsupported", reason=BUDGET_SPENT)
                    self._release(held[1])
                    continue
                self.budget["decodes"] += 1
                started = time.monotonic()
                try:
                    yield from self._decode_one(held)
                finally:
                    self.budget["decodeSeconds"] += time.monotonic() - started

    def _members_7z(self, src) -> Iterator[tuple[Member, str | None]]:
        """DFIR-ORC ships 7z. py7zr offers no streaming member access, so the archive is expanded
        once into the staging area, within the package byte budget, and read from there."""
        try:
            import py7zr
        except ImportError:
            yield Member(self.name, 0, lambda: io.BytesIO(b"")), "7z archives need py7zr (backend/requirements-optional.txt)"
            return
        if self._extracted is None:
            try:
                with py7zr.SevenZipFile(src, mode="r") as archive:
                    # summed from the member list: archiveinfo() insists on a file name, and an
                    # in-memory package has none
                    expanded = sum(int(getattr(member, "uncompressed", 0) or 0) for member in archive.list())
                    if self.budget["bytes"] + expanded > MAX_TOTAL:
                        yield Member(self.name, expanded, lambda: io.BytesIO(b"")), "package exceeds 16 GiB expanded-byte limit"
                        return
                    self._extracted = tempfile.mkdtemp(dir=self.tmp_dir, suffix=".7z")
                    archive.extractall(path=self._extracted)
                    self.budget["bytes"] += expanded
            except Exception as exc:  # noqa: BLE001
                yield Member(self.name, 0, lambda: io.BytesIO(b"")), f"7z: {type(exc).__name__}: {exc}"[:300]
                return
        root = os.path.realpath(self._extracted)
        found = sorted(os.path.join(dirpath, filename) for dirpath, _dirs, files in os.walk(root) for filename in files)
        for i, path in enumerate(found):
            if i >= MAX_FILES:
                self.inventory_complete = False
                break
            real = os.path.realpath(path)
            if not real.startswith(root + os.sep):
                continue  # a member that escaped the extraction directory is not evidence
            name = os.path.relpath(real, root).replace(os.sep, "/")
            yield Member(name, os.path.getsize(real), lambda p=real: open(p, "rb")), None

    def _release_evtx(self) -> None:
        for tmp_path, (entry, _name) in list(self.evtx_held.items()):
            self.budget["deferredBytes"] = max(0, self.budget["deferredBytes"] - int(entry.get("size") or 0))
            _unlink(tmp_path)
        self.evtx_held = {}

    def _drain_engines(self) -> None:
        """Run the external engines over the event logs held back for them, once, together."""
        if not self.engines or not self.evtx_held:
            self._release_evtx()
            return
        remaining = MAX_NATIVE_SECONDS - self.budget["decodeSeconds"]
        if remaining <= 0:
            self.engine_summaries.append({"engine": hayabusa.ENGINE, "status": "unsupported", "findings": 0, "seconds": 0.0, "reason": BUDGET_SPENT})
            self._release_evtx()
            return
        staged = None
        started = time.monotonic()
        try:
            staged = hayabusa.stage([(name, path) for path, (_entry, name) in self.evtx_held.items()], self.tmp_dir)
            findings, summary = hayabusa.run(staged, self.tmp_dir, deadline_s=remaining)
            for finding in findings:
                finding["packageId"] = self.package_id
            self.findings.extend(findings)
            summary["members"] = len(self.evtx_held)
            self.engine_summaries.append(summary)
        finally:
            self.budget["decodeSeconds"] += time.monotonic() - started
            if staged:
                shutil.rmtree(staged, ignore_errors=True)
            self._release_evtx()

    def _drain_triage(self) -> Iterator[dict[str, Any]]:
        """Read the collection as one dissect target and turn its records into rows.

        Every function gets an entry in the coverage table, so the analyst sees which artifacts
        this collection carried, which it did not, and which were cut short.
        """
        if not self.triage:
            return
        remaining = MAX_NATIVE_SECONDS - self.budget["decodeSeconds"]
        if remaining <= 0 or self.budget["decodes"] >= MAX_NATIVE_DECODES:
            self.files.append({"name": "triage!/dissect", "size": 0, "memberIndex": -1, "status": "unsupported", "count": 0, "reason": BUDGET_SPENT})
            return
        staged = None
        target = self.path
        if target is None:
            # dissect picks its loader partly by suffix, so the staged copy keeps the archive's own
            suffix = PurePosixPath(self.name.replace("\\", "/")).suffix.lower() or ".zip"
            with tempfile.NamedTemporaryFile(dir=self.tmp_dir, suffix=suffix, delete=False) as out:
                out.write(self.data or b"")
                staged = target = out.name
        run = triage.TriagePass(target, self.tmp_dir, self.context, deadline_s=remaining)
        entries: dict[str, dict[str, Any]] = {}
        started = time.monotonic()
        try:
            for function, row in run:
                entry = entries.get(function)
                if entry is None:
                    entry = {"name": f"triage!/{function}", "size": 0, "memberIndex": -1, "status": "pending", "count": 0, "format": triage.VERSION, "sha256": self.package_id or None, "artifactType": row.get("artifactType")}
                    entries[function] = entry
                    self.files.append(entry)
                yield from self._emit(entry, entry["name"], -1, [("event", row)])
        finally:
            self.budget["decodeSeconds"] += time.monotonic() - started
            self.budget["decodes"] += 1
            _unlink(staged)
        for function, info in run.summary.items():
            entry = entries.get(function)
            if entry is None:
                entry = {"name": f"triage!/{function}", "size": 0, "memberIndex": -1, "status": "pending", "count": 0, "format": triage.VERSION, "sha256": self.package_id or None}
                self.files.append(entry)
            entry["status"] = info.get("status", "parsed")
            if info.get("reason"):
                entry["reason"] = info["reason"]
            if info.get("note"):
                entry["note"] = info["note"]
        self.triage_summary = {"target": run.target, "functions": run.summary}

    def _members(self) -> Iterator[tuple[Member, str | None]]:
        if self.path:
            with open(self.path, "rb") as fh:
                head = fh.read(512)
        else:
            head = (self.data or b"")[:512]
        fmt = detect_archive(self.name, head)
        src = self.path or io.BytesIO(self.data or b"")
        if fmt == "zip":
            with zipfile.ZipFile(src) as zf:
                for i, info in enumerate(zf.infolist()):
                    if i >= MAX_FILES:
                        self.inventory_complete = False
                        break
                    if info.is_dir():
                        continue
                    reason = "encrypted member" if info.flag_bits & 1 else None
                    if (info.external_attr >> 16) & 0o170000 == 0o120000:
                        reason = "symbolic link"
                    yield Member(info.filename, info.file_size, lambda info=info: zf.open(info)), reason
        elif fmt == "7z":
            yield from self._members_7z(src)
        elif fmt == "tar":
            with tarfile.open(name=self.path, fileobj=None if self.path else src, mode="r:*") as tf:
                for i, info in enumerate(tf):
                    if i >= MAX_FILES:
                        self.inventory_complete = False
                        break
                    if info.isdir():
                        continue
                    reason = None if info.isfile() else "non-regular member"
                    yield Member(info.name, info.size, lambda info=info: tf.extractfile(info)), reason
        else:
            yield (
                Member(
                    self.name,
                    os.path.getsize(self.path) if self.path else len(self.data or b""),
                    lambda: open(self.path, "rb") if self.path else io.BytesIO(self.data or b""),
                ),
                None,
            )

    def __iter__(self) -> Iterator[dict[str, Any]]:
        try:
            yield from self._iterate()
        finally:
            # A cancelled ingest must not leave held-back artifacts in the staging area. They
            # are named like any other staged member, so the periodic sweep would not reclaim
            # them until their retention window expired.
            for held_path in list(self.deferred):
                self._release(held_path)
            self._release_evtx()
            if self._extracted:
                shutil.rmtree(self._extracted, ignore_errors=True)
                self._extracted = None

    def _iterate(self) -> Iterator[dict[str, Any]]:
        # A small explicit manifest supplies collection context regardless of archive order.
        names: list[str] = []
        for member, reason in self._members():
            if len(names) < MAX_FILES:
                names.append(member.name)
            if not reason and member.name == "collection-manifest.json":
                self.manifest_count += 1
                if member.size > 65536:
                    continue
                try:
                    with member.open() as fh:
                        value = json.loads(fh.read(65537))
                    if isinstance(value, dict):
                        self.context = {k: v for k in ("host", "collectedAt", "collector") if isinstance(v := value.get(k), str) and len(v) <= 500}
                        self.expectations = (
                            [v for v in value.get("expectedFiles", []) if isinstance(v, dict)][:10000] if isinstance(value.get("expectedFiles"), list) else []
                        )
                except (ValueError, OSError, RuntimeError):
                    pass  # The inventory pass reports the malformed member.
        if self.manifest_count != 1:
            self.context = {}
            self.expectations = []
        self.context = {**self.inherited_context, **self.context}
        self.triage = triage.is_triage_layout(names)
        for index, (member, reason) in enumerate(self._members()):
            if self.budget["files"] >= MAX_FILES:
                self.inventory_complete = False
                break
            self.budget["files"] += 1
            entry: dict[str, Any] = {"name": member.name, "size": member.size, "memberIndex": index, "status": "pending", "count": 0}
            entry["artifactType"] = collection.category(member.name)
            self.files.append(entry)
            parts = PurePosixPath(member.name.replace("\\", "/")).parts
            if ".." in parts or member.name.startswith(("/", "\\")) or (parts and ":" in parts[0]):
                reason = "unsafe member path"
            if member.size > MAX_MEMBER:
                reason = "member exceeds 4 GiB limit"
            if self.budget["bytes"] + member.size > MAX_TOTAL:
                reason = "package exceeds 16 GiB expanded-byte limit"
            if reason:
                entry.update(status="skipped", reason=reason)
                continue
            tmp_path = None
            rows = source = None
            decode_started = None
            notes: dict[str, Any] = {}
            try:
                digest = hashlib.sha256()
                with tempfile.NamedTemporaryFile(dir=self.tmp_dir, suffix=".member", delete=False) as out:
                    tmp_path = out.name
                    size = 0
                    with member.open() as fh:
                        while chunk := fh.read(1024**2):
                            size += len(chunk)
                            self.bytes_read += len(chunk)
                            self.budget["bytes"] += len(chunk)
                            if size > MAX_MEMBER or self.budget["bytes"] > MAX_TOTAL:
                                raise ValueError("expanded-byte limit reached")
                            digest.update(chunk)
                            out.write(chunk)
                entry["sha256"] = digest.hexdigest()
                if size != member.size:
                    raise ValueError("member size does not match archive metadata")
                with open(tmp_path, "rb") as fh:
                    head = fh.read(4096)
                low = member.name.lower()
                if detect_archive(member.name, head) or head.startswith(b"MSCF"):
                    if self.depth >= 3:
                        raise ValueError("nested archive depth exceeds 3")
                    decoded = None
                    try:
                        if head.startswith(b"MSCF"):
                            # A cabinet is a native decode like any other: it spawns the same
                            # bounded worker and manufactures a whole nested package, so it is
                            # gated and charged against the same allowance instead of being free.
                            if self.budget["decodes"] >= MAX_NATIVE_DECODES or self.budget["decodeSeconds"] >= MAX_NATIVE_SECONDS:
                                raise ValueError(BUDGET_SPENT)
                            self.budget["decodes"] += 1
                            cab_started = time.monotonic()
                            try:
                                decoded = native.decode("cab", tmp_path, self.tmp_dir)
                            finally:
                                self.budget["decodeSeconds"] += time.monotonic() - cab_started
                            # What it expanded to counts against the package, like any other bytes.
                            self.budget["bytes"] += os.path.getsize(decoded)
                            if self.budget["bytes"] > MAX_TOTAL:
                                raise ValueError("package exceeds 16 GiB expanded-byte limit")
                        inherited = {**self.context, "artifactDefault": collection.category(member.name) or self.context.get("artifactDefault")}
                        nested = PackageSource(
                            "nested.zip" if decoded else member.name,
                            decoded or tmp_path,
                            None,
                            self.tmp_dir,
                            self.ctx,
                            self.include_raw,
                            self.package_id,
                            budget=self.budget,
                            depth=self.depth + 1,
                            inherited_context=inherited,
                        )
                        nested.engines = list(self.engines)
                        nested_error = None
                        try:
                            for row in nested:
                                row["sourceFile"] = member.name + "!/" + row["sourceFile"]
                                if row.get("artifactType") == "unknown" and collection.category(member.name) == "defender":
                                    row.update(artifactType="defender", category="collection:defender")
                                yield row
                        except Exception as exc:  # noqa: BLE001
                            nested.inventory_complete = False
                            nested_error = exc
                        for check in nested.stats()["reconciliation"]:
                            self.nested_reconciliation.append({**check, "name": member.name + "!/" + check["name"]})
                        for f in nested.files:
                            f["name"] = member.name + "!/" + f["name"]
                            f.setdefault("containerSha256", entry["sha256"])
                        self.files.extend(nested.files)
                        self.findings.extend(nested.findings)
                        self.engine_summaries.extend(nested.engine_summaries)
                        for k, v in nested.counts.items():
                            self.counts[k] += v
                        for k, v in nested.ranges.items():
                            if v["firstTs"] is not None:
                                self.ranges[k]["firstTs"] = min(x for x in [self.ranges[k]["firstTs"], v["firstTs"]] if x is not None)
                                self.ranges[k]["lastTs"] = max(x for x in [self.ranges[k]["lastTs"], v["lastTs"]] if x is not None)
                        self.inventory_complete &= nested.inventory_complete
                        entry.update(status="parsed", format="cab" if decoded else "archive", count=sum(nested.counts.values()))
                        if nested_error:
                            raise nested_error
                    finally:
                        if decoded:
                            os.unlink(decoded)
                    continue
                if PurePosixPath(low.replace("\\", "/")).name == "collection-manifest.json":
                    if member.name != "collection-manifest.json":
                        raise ValueError("collection-manifest.json must be at the package root")
                    if self.manifest_count != 1:
                        raise ValueError("multiple collection manifests; collection context was not applied")
                    if size > 65536:
                        raise ValueError("manifest exceeds 64 KiB limit")
                    with open(tmp_path, encoding="utf-8-sig") as fh:
                        if not isinstance(json.load(fh), dict):
                            raise ValueError("manifest must be an object")
                    entry.update(status="metadata", format="collection-manifest")
                    continue
                if head.startswith(b"regf") and self.triage:
                    # Walked raw, a hive is a hundred thousand keys of noise. The triage pass reads
                    # the same file for what it means: services, run keys, tasks, exclusions.
                    entry.update(status="metadata", format="regf", reason="registry hive read by the triage pass")
                    continue
                if head.startswith(b"regf") or low.endswith(".pf"):
                    if self.budget["decodes"] >= MAX_NATIVE_DECODES or self.budget["decodeSeconds"] >= MAX_NATIVE_SECONDS:
                        entry.update(status="unsupported", reason=BUDGET_SPENT)
                        continue
                    source = None
                    kind = "registry" if head.startswith(b"regf") else "prefetch"
                    entry["format"] = f"dissect-{kind}/1"
                    if (
                        kind == "prefetch"
                        # decode() refuses an oversized artifact before spawning anything, so an
                        # artifact the lone path would reject must not reach a shared worker.
                        and size <= native.MAX_OUTPUT
                        and self.budget["deferredBytes"] + size <= MAX_DEFERRED_BYTES
                    ):
                        # Held back so a group of these can share one interpreter start. The staged
                        # copy is released by the drain, not by this iteration finally block.
                        self.deferred[tmp_path] = (entry, tmp_path, member.name, index)
                        self.budget["deferredBytes"] += size
                        tmp_path = None
                        continue
                    self.budget["decodes"] += 1
                    decode_started = time.monotonic()
                    rows = (("event", r) for r in collection.native_records(kind, tmp_path, member.name, self.context, self.tmp_dir))
                elif head.startswith(b"ElfFile\x00") or low.endswith(".evtx") or m365.detect_format(member.name, head):
                    source = EvtxSource(member.name, tmp_path, None, self.tmp_dir, self.include_raw)
                    entry["format"] = source.format
                    rows = (("event", r) for r in source)
                elif collection.supported(member.name) or (
                    self.context.get("artifactDefault") == "defender" and low.endswith((".txt", ".log", ".csv", ".json"))
                ):
                    # No size pre-check: collection.records() enforces the parse budget while
                    # reading, so an oversized export yields the records before the ceiling and is
                    # reported as partial rather than contributing nothing but a hash.
                    entry["format"] = collection.VERSION
                    source = None
                    parse_name = member.name if collection.category(member.name) else f"WdSupportLogs/{member.name}"
                    rows = (("event", collection.normalize(r, parse_name, i, self.context)) for i, r in enumerate(collection.records(tmp_path, parse_name, notes)))
                elif low.endswith((".eml", ".msg", ".mbox", ".mbx", ".pst", ".ost")) or looks_like_mail(head):
                    source = MailSource(member.name, tmp_path, None, self.ctx, self.tmp_dir)
                    entry["format"] = source.format
                    rows = (("mail", r) for r in source)
                else:
                    entry.update(status="unsupported", reason="no parser for this member; inventoried and hashed")
                    continue
                yield from self._emit(entry, member.name, index, rows)
                if self.engines and isinstance(source, EvtxSource) and tmp_path and self.budget["deferredBytes"] + size <= MAX_DEFERRED_BYTES:
                    # kept for the engines that run once the loop is done; released by _drain_engines
                    self.evtx_held[tmp_path] = (entry, member.name)
                    self.budget["deferredBytes"] += size
                    tmp_path = None
                if source is not None and source.stats.errors:
                    raise ValueError(f"parser reported {source.stats.errors} error(s); any emitted rows are partial")
                entry["status"] = "parsed"
            except Exception as exc:  # noqa: BLE001
                entry.update(status="error", reason=str(exc)[:300])
            finally:
                # Charged here rather than after the row loop: a decode that raises jumps
                # straight past that point, so a failing decode used to cost the allowance nothing
                # and only the artifact count stopped a package of them.
                if decode_started is not None:
                    self.budget["decodeSeconds"] += time.monotonic() - decode_started
                    decode_started = None
                # Every compromise the parser made to read this member is reported on it, so a
                # table that looks complete cannot quietly be one that was repaired or cut short.
                if notes:
                    encoding = notes.get("encoding")
                    repaired = notes.get("repairedRows", 0)
                    malformed = notes.get("malformedRows", 0)
                    truncated = notes.get("truncatedAtLine", 0)
                    said = []
                    if encoding:
                        said.append(f"decoded as {ENCODING_LABEL.get(encoding, encoding)}")
                    if repaired:
                        said.append(f"{repaired} row(s) had columns merged by the exporter and were split back apart")
                    if malformed:
                        said.append(f"{malformed} row(s) do not match the header and were kept with the mismatch marked")
                    if notes.get("defenderKept") is not None:
                        said.append(
                            f"Defender engine log: {notes.get('defenderScanned', 0):,} lines read, "
                            f"{notes['defenderKept']:,} kept: those naming a detection, threat, quarantine, remediation, "
                            f"exclusion or protection change, with the lines either side that qualify them"
                        )
                    if truncated:
                        said.append(f"kept the first {truncated:,} lines; the file is longer than that")
                    entry["note"] = "; ".join(said)
                # The parsers hold the member file open across their yields, and CPython only
                # clears this frame after the finally block, so the handles are still live here.
                # Windows refuses to unlink an open file, which would both raise out of generator
                # close (masking a cancel) and leak a member of up to 4 GiB.
                for closeable in (rows, source):
                    closer = getattr(closeable, "close", None)
                    if closer is not None:
                        try:
                            closer()
                        except Exception:  # noqa: BLE001
                            pass
                _unlink(tmp_path)

        yield from self._drain_native()
        yield from self._drain_triage()
        self._drain_engines()
