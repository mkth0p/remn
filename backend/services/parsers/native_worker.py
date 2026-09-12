"""Isolated library adapters. No paths supplied by evidence are executed or extracted."""

from __future__ import annotations

import json
import struct
import sys
import zipfile


def prefetch(path):
    from dissect.target.plugins.os.windows.prefetch import Prefetch

    with open(path, "rb") as fh:
        header = fh.read(8)
        if header[:4] == b"MAM\x04" and struct.unpack_from("<I", header, 4)[0] > 64 * 1024**2:
            raise ValueError("prefetch declared expanded size exceeds 64 MiB")
        if header[:4] != b"MAM\x04" and header[4:8] != b"SCCA":
            raise ValueError("invalid Prefetch signature")
        fh.seek(0)
        parsed = Prefetch(fh)
        if parsed.version == 17:
            raise ValueError("Prefetch v17 is not supported by this adapter; export to structured records")
        executable = parsed.header.name.decode("utf-16-le").split("\x00", 1)[0]
        dates = sorted(set(([parsed.latest_timestamp] if parsed.fn.last_run_time else []) + parsed.previous_timestamps))
        if not dates:
            yield {"Name": executable, "RunCount": parsed.fn.run_count, "ReferencedFiles": parsed.metrics, "PrefetchVersion": parsed.version}
        for date in dates:
            yield {
                "Name": executable,
                "LastRunTime": date.isoformat(),
                "RunCount": parsed.fn.run_count,
                "ReferencedFiles": parsed.metrics,
                "PrefetchVersion": parsed.version,
            }


def registry(path):
    from dissect.regf import RegistryHive

    with open(path, "rb") as fh:
        hive = RegistryHive(fh)
        stack = [(hive.root(), "", 0)]
        count = 0
        while stack:
            key, name, depth = stack.pop()
            if depth > 128 or count >= 100000:
                raise ValueError("registry traversal limit reached")
            count += 1
            values = {}
            for value in key.values():
                data = value.value
                values[value.name] = data.hex() if isinstance(data, bytes) else data
            yield {"KeyPath": name or "\\", "LastWriteTime": key.timestamp.isoformat(), "Values": values, "HiveInTransaction": hive.in_transaction}
            for subkey in key.subkeys():
                stack.append((subkey, name + "\\" + subkey.name, depth + 1))


# cabarchive expands every member while it parses the archive, so a ceiling checked afterwards
# never guarded memory: it only threw away work already done. The guard that does hold is the
# parent process watching this one resident size and killing it. This ceiling therefore says what
# is worth keeping, and is sized for a genuine Defender support cab, which runs to a couple of
# hundred megabytes and carries the Defender, system and application event logs.
MAX_CAB_EXPANDED = 256 * 1024**2
MAX_CAB_MEMBERS = 20000
# Several CFFILE entries may point at the same folder data, so the expanded total is bytes written
# rather than bytes allocated, and the ceiling alone puts no limit on the ratio. A real support cab
# runs about ten to one; a cabinet claiming hundreds of times its own size is a bomb, not evidence.
MAX_CAB_RATIO = 200


def cabinet(path, output):
    from cabarchive import CabArchive

    with open(path, "rb") as fh:
        data = fh.read()
        cab = CabArchive(data)
    if len(data) < 30 or len(cab) != struct.unpack_from("<H", data, 28)[0]:
        raise ValueError("CAB member count mismatch (possibly duplicate member names)")
    if len(cab) > MAX_CAB_MEMBERS:
        raise ValueError(f"CAB holds {len(cab)} members, past the {MAX_CAB_MEMBERS} limit")
    expanded = sum(len(f.buf) for f in cab.values())
    if expanded > MAX_CAB_EXPANDED:
        raise ValueError(f"CAB expands to {expanded // 1024**2} MiB, past the {MAX_CAB_EXPANDED // 1024**2} MiB limit")
    if expanded > len(data) * MAX_CAB_RATIO:
        raise ValueError(f"CAB expands {expanded // max(1, len(data))}:1, past the {MAX_CAB_RATIO}:1 limit")
    with zipfile.ZipFile(output, "w", zipfile.ZIP_STORED) as z:
        for name, file in cab.items():
            z.writestr(name, file.buf)


def batch(manifest_path, output):
    """Decode a group of artifacts in one process.

    Starting an interpreter and importing a decoder costs about half a second. That is nothing
    beside a registry hive and everything beside a prefetch file, and a real collection carries
    several hundred prefetch files. Each artifact's records are framed by its position in the
    manifest so they stay separable, a failure is recorded against its own artifact rather than
    ending the group, and the file is flushed after every artifact so a worker that is killed
    still leaves behind everything it finished.
    """
    with open(manifest_path, encoding="utf-8") as fh:
        jobs = json.load(fh)
    with open(output, "w", encoding="utf-8") as out:
        for index, (kind, path) in enumerate(jobs):
            written = 0
            try:
                for record in prefetch(path) if kind == "prefetch" else registry(path):
                    print(json.dumps({"_i": index, "r": record}, ensure_ascii=False), file=out)
                    written += 1
                print(json.dumps({"_i": index, "done": written}), file=out)
            except Exception as exc:  # noqa: BLE001
                reason = f"{kind}: {type(exc).__name__}: {exc}"[:500]
                print(json.dumps({"_i": index, "done": written, "failed": reason}, ensure_ascii=False), file=out)
            out.flush()


if __name__ == "__main__":
    if sys.argv[1] == "batch":
        batch(sys.argv[2], sys.argv[3])
        sys.exit(0)
    kind, path, output = sys.argv[1:]
    written = 0
    try:
        if kind == "cab":
            cabinet(path, output)
        else:
            with open(output, "w", encoding="utf-8") as out:
                for record in prefetch(path) if kind == "prefetch" else registry(path):
                    out.write(json.dumps(record, ensure_ascii=False) + "\n")
                    written += 1
    except Exception as exc:
        reason = f"{kind}: {type(exc).__name__}: {exc}"[:500]
        if written:
            # Damaged artefacts are the normal case in forensics: what was decoded before the
            # failure is evidence and must survive it. Keep the records, append the reason as a
            # trailing marker record, and report success so the reader sees both.
            with open(output, "a", encoding="utf-8") as out:
                out.write(json.dumps({"_partial": reason, "_decoded": written}, ensure_ascii=False) + "\n")
            sys.exit(0)
        with open(output, "w", encoding="utf-8") as out:
            out.write(reason)
        sys.exit(1)
