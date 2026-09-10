"""Mixed investigation packages, with a bounded member inventory and explicit coverage."""

from __future__ import annotations

import hashlib
import io
import json
import os
import tarfile
import tempfile
import zipfile
from collections.abc import Iterator
from pathlib import PurePosixPath
from typing import Any

from services.ingest.pipeline import EvtxSource, MailSource, Member, detect_archive, looks_like_mail
from services.ingest.reconcile import reconcile
from services.parsers import collection, m365
from services.parsers.mail.common import ParseContext

MAX_FILES = 20_000
# Expectations harvested from collection-summary rows. Capped where they are appended, not only
# where they are read: an uncapped list is both unbounded memory and the driver of the
# reconciliation cost, and a summary CSV naming them is attacker-controlled.
MAX_EXPECTATIONS = 10_000
MAX_MEMBER = 4 * 1024**3
MAX_TOTAL = 16 * 1024**3
MAX_STRUCTURED = 64 * 1024**2


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
        self.budget = budget if budget is not None else {"bytes": 0, "files": 0}
        self.depth = depth
        self.inherited_context = inherited_context or {}
        self.expectations = []
        self.nested_reconciliation = []

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
        # A small explicit manifest supplies collection context regardless of archive order.
        for member, reason in self._members():
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
                            from services.parsers.native import decode

                            decoded = decode("cab", tmp_path, self.tmp_dir)
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
                if head.startswith(b"regf") or low.endswith(".pf"):
                    source = None
                    kind = "registry" if head.startswith(b"regf") else "prefetch"
                    entry["format"] = f"dissect-{kind}/1"
                    rows = (("event", r) for r in collection.native_records(kind, tmp_path, member.name, self.context, self.tmp_dir))
                elif head.startswith(b"ElfFile\x00") or low.endswith(".evtx") or m365.detect_format(member.name, head):
                    source = EvtxSource(member.name, tmp_path, None, self.tmp_dir, self.include_raw)
                    entry["format"] = source.format
                    rows = (("event", r) for r in source)
                elif collection.supported(member.name) or (
                    self.context.get("artifactDefault") == "defender" and low.endswith((".txt", ".log", ".csv", ".json"))
                ):
                    if size > MAX_STRUCTURED:
                        raise ValueError("structured export exceeds 64 MiB limit; split the export")
                    entry["format"] = collection.VERSION
                    source = None
                    parse_name = member.name if collection.category(member.name) else f"WdSupportLogs/{member.name}"
                    rows = (("event", collection.normalize(r, parse_name, i, self.context)) for i, r in enumerate(collection.records(tmp_path, parse_name)))
                elif low.endswith((".eml", ".msg", ".mbox", ".mbx", ".pst", ".ost")) or looks_like_mail(head):
                    source = MailSource(member.name, tmp_path, None, self.ctx, self.tmp_dir)
                    entry["format"] = source.format
                    rows = (("mail", r) for r in source)
                else:
                    entry.update(status="unsupported", reason="no parser for this member; inventoried and hashed")
                    continue
                for row_index, (kind, row) in enumerate(rows):
                    if row.get("artifactType") == "collection-summary" and len(self.expectations) < MAX_EXPECTATIONS:
                        self.expectations.append(row["data"])
                    row.update(type=kind, packageId=self.package_id, sourceFile=member.name, sourceSha256=entry["sha256"], memberIndex=index)
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
                if source is not None and source.stats.errors:
                    raise ValueError(f"parser reported {source.stats.errors} error(s); any emitted rows are partial")
                entry["status"] = "parsed"
            except Exception as exc:  # noqa: BLE001
                entry.update(status="error", reason=str(exc)[:300])
            finally:
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
                if tmp_path:
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass
