"""
Accounts, their tokens and the cases each one may open, for a server shared by a small team.

One JSON file under the data directory (FORENSIC_ACCOUNTS_FILE) holds every account and every case
record. While it does not exist, or holds no account, the server works as it always has: no token,
or the one shared FORENSIC_AUTH_TOKEN. Once it holds an account, every API request carries a
personal token, and what the request may do follows the account's role and the cases it belongs to
(forensic/access.py).

A token is shown once, when it is made, and only a salted SHA-256 digest of it is kept. A token is
32 random bytes, so a slow hash would add nothing against guessing and would cost every request: the
salt only keeps two equal digests from saying that two tokens are equal. The token carries a short
public id, so the server finds the one digest to compare without trying every account.

The file is written whole, to a new file that then replaces it, so a reader never sees half of it,
and readable only by the server's account. Every change is read, made and written under a lock on a
file beside it, because the server (case records) and the management command (accounts) both
change it, from different processes.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import tempfile
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from django.conf import settings

log = logging.getLogger(__name__)

# admin: the accounts and every case. analyst: creates cases, and works on those it owns or is a
# member of. viewer: reads the cases it is a member of and changes nothing.
ROLES = ("admin", "analyst", "viewer")
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
# remn_<id>_<secret>: the id names the token in listings and the audit log, the secret is never kept
TOKEN_RE = re.compile(r"^remn_([0-9a-f]{10})_([A-Za-z0-9_-]{40,64})$")
_ZERO_SALT = bytes(16)


class AccountError(ValueError):
    """A change that cannot be made, in words for the operator or the analyst who asked for it."""


@dataclass(frozen=True)
class Account:
    """The account a request was made with."""

    name: str
    role: str
    token: str


def now() -> str:
    """The time, in UTC to the millisecond, as the files record it."""
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _digest(salt: bytes, secret: str) -> str:
    return hashlib.sha256(salt + secret.encode("ascii")).hexdigest()


@contextlib.contextmanager
def file_lock(path: Path) -> Iterator[None]:
    """Hold an exclusive lock on `path` (created when missing) against other processes and threads."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with _thread_lock(path):
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            if os.name == "nt":
                import msvcrt

                # retried by the system for about ten seconds before it gives up
                msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
                try:
                    yield
                finally:
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_EX)
                yield
        finally:
            os.close(fd)


_thread_locks: dict[str, threading.Lock] = {}
_thread_locks_guard = threading.Lock()


def _thread_lock(path: Path) -> threading.Lock:
    with _thread_locks_guard:
        return _thread_locks.setdefault(str(path), threading.Lock())


def owned_like_folder(path: Path) -> None:
    """Give a file the owner of its folder. The management command run with sudo would otherwise
    leave a file, readable only by its owner, that the server's own account cannot read."""
    if os.name != "posix" or os.geteuid() != 0:
        return
    folder = path.parent.stat()
    if folder.st_uid != 0:
        os.chown(path, folder.st_uid, folder.st_gid)


def write_private(path: Path, text: str) -> None:
    """Replace `path` with `text` in one step, readable and writable by the server's account only."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        owned_like_folder(Path(tmp))
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


class AccountStore:
    """The accounts file: read when it changes on disk, changed only under its lock."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.lock_path = self.path.with_name(self.path.name + ".lock")
        self._lock = threading.Lock()
        self._stamp: tuple[int, int, int] | None = None
        self._data: dict[str, Any] = {}
        self._unreadable = False

    # -- reading ----------------------------------------------------------------------------------
    def _read(self) -> dict[str, Any]:
        """The file's content, read again only when it changed. A file that exists and cannot be
        read keeps accounts on with nobody able to sign in: it never turns the check off."""
        try:
            st = self.path.stat()
        except FileNotFoundError:
            with self._lock:
                self._stamp, self._data, self._unreadable = None, {}, False
            return {}
        stamp = (st.st_mtime_ns, st.st_size, st.st_ino)
        with self._lock:
            if stamp != self._stamp:
                try:
                    data = json.loads(self.path.read_text(encoding="utf-8"))
                    if not isinstance(data, dict) or not isinstance(data.get("accounts", {}), dict) or not isinstance(data.get("cases", {}), dict):
                        raise ValueError("not an accounts file")
                    self._data, self._unreadable = data, False
                except (OSError, ValueError) as exc:
                    log.error("the accounts file %s cannot be read (%s): every request is refused until it is fixed", self.path, type(exc).__name__)
                    self._data, self._unreadable = {}, True
                self._stamp = stamp
            return self._data

    def enabled(self) -> bool:
        """Whether accounts are on: the file holds an account, or exists and cannot be read."""
        data = self._read()
        return self._unreadable or bool(data.get("accounts"))

    def authenticate(self, presented: str) -> tuple[Account | None, str | None]:
        """The account a token belongs to, or None and the name of the account it claims (when it
        names one) for the audit log. A disabled account and a revoked token do not sign in."""
        data = self._read()
        m = TOKEN_RE.match(presented or "")
        token_id, secret = (m.group(1), m.group(2)) if m else ("", "")
        found: tuple[str, dict[str, Any], dict[str, Any]] | None = None
        for name, acc in (data.get("accounts") or {}).items():
            for tok in acc.get("tokens") or []:
                if token_id and tok.get("id") == token_id:
                    found = (name, acc, tok)
        # the digest is computed whether or not the id is known, so the time taken does not say which
        salt = bytes.fromhex(found[2].get("salt", "")) if found else _ZERO_SALT
        right = hmac.compare_digest(_digest(salt, secret or "-"), str(found[2].get("hash", "")) if found else "")
        if not found or not right:
            return None, found[0] if found else None
        name, acc, tok = found
        if acc.get("disabled") or tok.get("revoked") or acc.get("role") not in ROLES:
            return None, name
        return Account(name=name, role=acc["role"], token=token_id), name

    def account(self, name: str) -> dict[str, Any] | None:
        return (self._read().get("accounts") or {}).get(name)

    def accounts(self) -> list[dict[str, Any]]:
        """Every account with its tokens' ids and dates, never their digests."""
        out = []
        for name, acc in sorted((self._read().get("accounts") or {}).items()):
            tokens = [{k: t.get(k) for k in ("id", "created", "revoked")} for t in acc.get("tokens") or []]
            out.append({"name": name, "role": acc.get("role"), "disabled": bool(acc.get("disabled")), "created": acc.get("created"), "tokens": tokens})
        return out

    def case(self, key: str) -> dict[str, Any] | None:
        return (self._read().get("cases") or {}).get(key)

    def cases(self) -> dict[str, dict[str, Any]]:
        return dict(self._read().get("cases") or {})

    # -- changing ---------------------------------------------------------------------------------
    def _change(self, fn: Callable[[dict[str, Any]], Any]) -> Any:
        """Read the file under its lock, let `fn` change the content, write it back whole."""
        with file_lock(self.lock_path):
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
            except FileNotFoundError:
                data = {"version": 1, "accounts": {}, "cases": {}}
            except ValueError:
                raise AccountError(f"{self.path} cannot be read as an accounts file; nothing was changed") from None
            data.setdefault("accounts", {})
            data.setdefault("cases", {})
            result = fn(data)
            write_private(self.path, json.dumps(data, indent=1, sort_keys=True) + "\n")
        self._read()
        return result

    def _named(self, data: dict[str, Any], name: str) -> dict[str, Any]:
        acc = data["accounts"].get(name)
        if acc is None:
            raise AccountError(f"no account named {name!r}")
        return acc

    @staticmethod
    def _new_token(acc: dict[str, Any]) -> str:
        token_id, secret, salt = secrets.token_hex(5), secrets.token_urlsafe(32), secrets.token_bytes(16)
        acc.setdefault("tokens", []).append({"id": token_id, "salt": salt.hex(), "hash": _digest(salt, secret), "created": now(), "revoked": None})
        return f"remn_{token_id}_{secret}"

    def create(self, name: str, role: str) -> str:
        """A new account and its first token, which is returned once and kept nowhere."""
        if not NAME_RE.match(name or ""):
            raise AccountError("an account name is 1 to 64 characters: lower-case letters, digits, '.', '_' and '-', starting with a letter or digit")
        if role not in ROLES:
            raise AccountError(f"the role is one of {', '.join(ROLES)}")

        def add(data: dict[str, Any]) -> str:
            if name in data["accounts"]:
                raise AccountError(f"an account named {name!r} already exists")
            acc = data["accounts"][name] = {"role": role, "disabled": False, "created": now(), "tokens": []}
            return self._new_token(acc)

        return self._change(add)

    def rotate(self, name: str) -> str:
        """Revoke every token the account holds and give it a new one, returned once."""

        def rotate(data: dict[str, Any]) -> str:
            acc = self._named(data, name)
            for tok in acc.get("tokens") or []:
                tok["revoked"] = tok.get("revoked") or now()
            return self._new_token(acc)

        return self._change(rotate)

    def revoke(self, name: str, token_id: str | None = None) -> int:
        """Revoke one token of the account, or all of them; the number revoked."""

        def revoke(data: dict[str, Any]) -> int:
            acc = self._named(data, name)
            hit = [t for t in acc.get("tokens") or [] if not t.get("revoked") and (token_id is None or t.get("id") == token_id)]
            if token_id is not None and not hit and not any(t.get("id") == token_id for t in acc.get("tokens") or []):
                raise AccountError(f"{name!r} has no token {token_id!r}")
            for tok in hit:
                tok["revoked"] = now()
            return len(hit)

        return self._change(revoke)

    def set_disabled(self, name: str, disabled: bool) -> None:
        self._change(lambda data: self._named(data, name).__setitem__("disabled", disabled))

    def set_role(self, name: str, role: str) -> None:
        if role not in ROLES:
            raise AccountError(f"the role is one of {', '.join(ROLES)}")
        self._change(lambda data: self._named(data, name).__setitem__("role", role))

    def register_case(self, key: str, owner: str) -> dict[str, Any]:
        """Record a new case with its owner; a case already recorded is left as it is."""

        def register(data: dict[str, Any]) -> dict[str, Any]:
            return data["cases"].setdefault(key, {"owner": owner, "members": [], "name": "", "created": now()})

        return self._change(register)

    def update_case(self, key: str, *, owner: str | None = None, members: list[str] | None = None, name: str | None = None) -> dict[str, Any]:
        """Change a case's owner, members or name. Every account named must exist."""

        def update(data: dict[str, Any]) -> dict[str, Any]:
            rec = data["cases"].setdefault(key, {"owner": None, "members": [], "name": "", "created": now()})
            if owner is not None:
                self._named(data, owner)
                rec["owner"] = owner
            if members is not None:
                for m in members:
                    self._named(data, m)
                rec["members"] = sorted({m for m in members if m != rec.get("owner")})
            elif owner is not None:
                rec["members"] = [m for m in rec.get("members") or [] if m != owner]
            if name is not None:
                rec["name"] = name.strip()[:200]
            return dict(rec)

        return self._change(update)

    def forget_case(self, key: str) -> bool:
        """Remove a case's record; whether there was one."""
        return bool(self._change(lambda data: data["cases"].pop(key, None)))


_stores: dict[str, AccountStore] = {}
_stores_guard = threading.Lock()


def store() -> AccountStore:
    """The account store of the file the settings name."""
    path = Path(settings.FORENSIC_ACCOUNTS_FILE)
    with _stores_guard:
        return _stores.setdefault(str(path), AccountStore(path))


def accounts_on() -> bool:
    return store().enabled()
