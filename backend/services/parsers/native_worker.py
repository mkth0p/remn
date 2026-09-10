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


def cabinet(path, output):
    from cabarchive import CabArchive

    with open(path, "rb") as fh:
        data = fh.read()
        cab = CabArchive(data)
    if len(data) < 30 or len(cab) != struct.unpack_from("<H", data, 28)[0]:
        raise ValueError("CAB member count mismatch (possibly duplicate member names)")
    if len(cab) > 20000 or sum(len(f.buf) for f in cab.values()) > 64 * 1024**2:
        raise ValueError("CAB exceeds member or expanded-byte limit")
    with zipfile.ZipFile(output, "w", zipfile.ZIP_STORED) as z:
        for name, file in cab.items():
            z.writestr(name, file.buf)


if __name__ == "__main__":
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
