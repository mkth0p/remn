"""Back up, check and restore the server case stores: one DuckDB file per case under FORENSIC_CASES_DIR.

Usage, from the repository folder (in the container: docker compose exec remn python tools/store_backup.py ...):
  python tools/store_backup.py backup  DEST   [KEY ...]             every case, or the ones named, into the folder DEST
  python tools/store_backup.py verify  SOURCE [KEY ...]             check a backup without restoring it
  python tools/store_backup.py restore SOURCE [KEY ...] [--replace] put cases back from a backup
Every command takes --cases-dir DIR; without it the folder is the server's, read from its settings and .env.

A backup of a case is a folder named by its key, holding the store's files byte for byte and a
manifest.json with each file's size and SHA-256, the store's schema version and the row count of
each table. The tool copies a store while it holds it open read-only, so that nothing can write to it
meanwhile, and checks the copy by opening it before it calls the backup complete. A backup folder is
never written over.

The server holds a store open while it is used, and for FORENSIC_STORE_IDLE_S seconds (600 by
default) after; a backup skips such a store and says so. So while the server runs, every case nobody
is working on is backed up; stop the server first for a backup of every case. While the tool copies a
store, the server answers that case with 503 and asks to try again.

A restore checks the backup's digests and row counts first and changes nothing if they do not match.
It never writes over a case: a case that exists is refused, unless --replace, which moves it aside to
<key>.before-restore-<time> next to the restored one (the server does not list it) and keeps it there.
Restore with the server stopped, or for cases nobody is using.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

import duckdb

from forensic.build import build_id
from services.store.casestore import KEY_RE, SCHEMA_VERSION, held_elsewhere, schema_version

FILES = ("case.duckdb", "case.duckdb.wal")
HELD = (
    "the store is open in a running REMN server. The server closes a store FORENSIC_STORE_IDLE_S seconds (600 by default) after its "
    "last use; run this again then, or stop the server. Nothing was copied or changed."
)


class Refused(Exception):
    """A case the command did not carry out, with the reason; nothing of it was changed."""


def _cases_dir(given: str | None) -> Path:
    if given:
        return Path(given)
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "forensic.settings")
    from django.conf import settings

    return Path(settings.CASES_DIR)


def _open(path: Path) -> duckdb.DuckDBPyConnection:
    """The store read-only. Holding it keeps every writer out, the server included."""
    try:
        return duckdb.connect(str(path), read_only=True)
    except duckdb.Error as exc:
        if held_elsewhere(exc):
            raise Refused(HELD) from exc
        raise Refused(f"the store could not be opened ({type(exc).__name__}: {str(exc).splitlines()[0][:200]}). Nothing was copied.") from exc


def _rows(con: duckdb.DuckDBPyConnection) -> dict[str, int]:
    tables = [r[0] for r in con.execute("SELECT table_name FROM duckdb_tables() WHERE schema_name = 'main' ORDER BY table_name").fetchall()]
    return {t: int(con.execute(f'SELECT count(*) FROM "{t}"').fetchone()[0]) for t in tables}


def _copy(src: Path, dst: Path) -> dict[str, int | str]:
    digest = hashlib.sha256()
    size = 0
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        while block := fin.read(1 << 20):
            digest.update(block)
            fout.write(block)
            size += len(block)
        fout.flush()
        os.fsync(fout.fileno())
    return {"bytes": size, "sha256": digest.hexdigest()}


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while block := fh.read(1 << 20):
            digest.update(block)
    return digest.hexdigest()


def _check(folder: Path, manifest: dict, key: str) -> None:
    """The files of `folder` are those the manifest of case `key` lists, and the store they make holds its rows and version."""
    files = manifest.get("files")
    # only the store's own files, under their own names: a manifest names nothing outside its folder
    if manifest.get("key") != key or not isinstance(files, dict) or "case.duckdb" not in files or not set(files) <= set(FILES):
        raise Refused(f"the manifest in {folder} does not describe a store of this case.")
    for name, want in files.items():
        path = folder / name
        if not isinstance(want, dict) or not path.is_file() or path.stat().st_size != want.get("bytes") or _digest(path) != want.get("sha256"):
            raise Refused(f"{name} in {folder} does not match its manifest: the backup is damaged or incomplete.")
    try:
        con = duckdb.connect(str(folder / "case.duckdb"), read_only=True)
    except duckdb.Error as exc:
        raise Refused(f"the store in {folder} does not open ({type(exc).__name__}).") from exc
    try:
        if _rows(con) != manifest.get("rows") or _version(con) != manifest.get("schemaVersion"):
            raise Refused(f"the store in {folder} does not hold the rows its manifest lists.")
    finally:
        con.close()


def _version(con: duckdb.DuckDBPyConnection) -> int | None:
    try:
        return schema_version(con)
    except RuntimeError:
        return None


def _summary(rows: dict[str, int]) -> str:
    return f"{rows.get('events', 0):,} events, {rows.get('mails', 0):,} mails"


def backup_case(cases: Path, dest: Path, key: str) -> str:
    db = cases / key / "case.duckdb"
    if not db.is_file():
        raise Refused(f"there is no store for this case in {cases}.")
    target = dest / key
    if target.exists():
        raise Refused(f"a backup of this case is already in {dest}; nothing was written over. Back up into a new folder.")
    partial = dest / f".{key}.partial"
    con = _open(db)
    try:
        version = _version(con)
        rows = _rows(con)
        shutil.rmtree(partial, ignore_errors=True)
        partial.mkdir(parents=True)
        files = {name: _copy(cases / key / name, partial / name) for name in FILES if (cases / key / name).is_file()}
    finally:
        con.close()
    manifest = {
        "key": key,
        "createdAt": datetime.now(UTC).isoformat(timespec="seconds"),
        "remn": build_id(),
        "schemaVersion": version,
        "files": files,
        "rows": rows,
    }
    try:
        _check(partial, manifest, key)
    except Refused:
        shutil.rmtree(partial, ignore_errors=True)
        raise
    (partial / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    partial.rename(target)
    size = sum(f["bytes"] for f in files.values())
    return f"backed up {key}: {_summary(rows)}, {size / 2**20:,.1f} MiB, schema {version if version is not None else 'before versions'}"


def _manifest(folder: Path) -> dict:
    try:
        return json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise Refused(f"{folder} has no readable manifest.json: it is not a backup made by this tool.") from exc


def verify_case(source: Path, key: str) -> str:
    manifest = _manifest(source / key)
    _check(source / key, manifest, key)
    return f"backup of {key} is complete: {_summary(manifest['rows'])}, taken {manifest.get('createdAt')}"


def restore_case(source: Path, cases: Path, key: str, replace: bool) -> str:
    folder = source / key
    manifest = _manifest(folder)
    _check(folder, manifest, key)
    version = manifest.get("schemaVersion")
    if version is not None and version > SCHEMA_VERSION:
        raise Refused(
            f"the backup was written by a newer version of REMN (store schema {version}; this version reads up to {SCHEMA_VERSION}). "
            "Restore it with that version. Nothing was changed."
        )
    target = cases / key
    if target.exists() and not replace:
        raise Refused(
            f"a store for this case exists in {cases}; nothing was changed. --replace keeps it as {key}.before-restore-<time> and restores the backup in its place."
        )
    # the copy is made and checked beside the cases before the case itself is touched
    staging = cases / f".{key}.restoring"
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True)
    try:
        for name in manifest["files"]:
            _copy(folder / name, staging / name)
        _check(staging, manifest, key)
        aside = None
        if target.exists():
            if (target / "case.duckdb").is_file():
                _open(target / "case.duckdb").close()
            aside = cases / f"{key}.before-restore-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
            target.rename(aside)
        staging.rename(target)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    kept = f"; the store it replaced is kept as {aside.name}" if aside else ""
    return f"restored {key}: {_summary(manifest['rows'])}, from the backup taken {manifest.get('createdAt')}{kept}"


def _keys(folder: Path, named: list[str], need: str) -> list[str]:
    for key in named:
        if not KEY_RE.match(key):
            raise SystemExit(f"{key!r} is not a case key")
    if named:
        return named
    if not folder.is_dir():
        return []
    return sorted(d.name for d in folder.iterdir() if d.is_dir() and KEY_RE.match(d.name) and (d / need).is_file())


def main(argv: list[str] | None = None) -> int:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--cases-dir", help="the folder of the case stores (default: the server's, FORENSIC_CASES_DIR)")
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    b = commands.add_parser("backup", parents=[common], help="copy case stores into a new backup folder")
    b.add_argument("dest", type=Path)
    b.add_argument("keys", nargs="*")
    v = commands.add_parser("verify", help="check a backup folder against its manifests")
    v.add_argument("source", type=Path)
    v.add_argument("keys", nargs="*")
    r = commands.add_parser("restore", parents=[common], help="put case stores back from a backup folder")
    r.add_argument("source", type=Path)
    r.add_argument("keys", nargs="*")
    r.add_argument("--replace", action="store_true", help="restore over an existing case, keeping it aside as <key>.before-restore-<time>")
    args = parser.parse_args(argv)

    if args.command == "backup":
        cases = _cases_dir(args.cases_dir)
        keys = _keys(cases, args.keys, "case.duckdb")
        args.dest.mkdir(parents=True, exist_ok=True)
        jobs = [(key, lambda key=key: backup_case(cases, args.dest, key)) for key in keys]
        done_word = f"backed up into {args.dest}"
    elif args.command == "verify":
        keys = _keys(args.source, args.keys, "manifest.json")
        jobs = [(key, lambda key=key: verify_case(args.source, key)) for key in keys]
        done_word = "complete"
    else:
        cases = _cases_dir(args.cases_dir)
        cases.mkdir(parents=True, exist_ok=True)
        keys = _keys(args.source, args.keys, "manifest.json")
        jobs = [(key, lambda key=key: restore_case(args.source, cases, key, args.replace)) for key in keys]
        done_word = f"restored into {cases}"

    if not jobs:
        print("no case stores to " + args.command)
        return 0
    done = 0
    for key, job in jobs:
        try:
            print(job(), flush=True)
            done += 1
        except Refused as exc:
            print(f"skipped {key}: {exc}", flush=True)
    print(f"{done} of {len(jobs)} case stores {done_word}" + (f"; {len(jobs) - done} skipped, see above." if done < len(jobs) else "."))
    return 0 if done == len(jobs) else 1


if __name__ == "__main__":
    sys.exit(main())
