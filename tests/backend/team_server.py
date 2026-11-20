"""A server with accounts for the tests: an accounts file, an audit log and a cases folder of its own,
and four invented accounts, one of each role and a second analyst."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from pathlib import Path

import pytest
from django.test import Client

from forensic.accounts import AccountStore, store
from forensic.middleware import ApiClientHeaderMiddleware
from services.store.casestore import registry

ROLES = {"root": "admin", "ana": "analyst", "ben": "analyst", "vic": "viewer"}


@dataclass
class Team:
    accounts: AccountStore
    tokens: dict[str, str]
    folder: Path

    def headers(self, name: str) -> dict[str, str]:
        return {"HTTP_X_FORENSIC_CLIENT": self.tokens[name]}

    def get(self, name: str, path: str, **extra):
        return Client().get(path, **self.headers(name), **extra)

    def post(self, name: str, path: str, body: object = None, **extra):
        return Client().post(path, data=json.dumps(body if body is not None else {}), content_type="application/json", **self.headers(name), **extra)

    def delete(self, name: str, path: str):
        return Client().delete(path, **self.headers(name))

    def new_case(self, owner: str, members: tuple[str, ...] = ()) -> str:
        """A case `owner` creates by importing one invented event into a new key, with `members` added."""
        key = str(uuid.uuid4())
        line = json.dumps({"type": "event", "eventId": 4624, "ts": 1788300000000, "computer": "WS-INVENTED-01", "channel": "Security"})
        r = Client().post(f"/api/store/{key}/import?evidenceId=1", data=line + "\n", content_type="application/x-ndjson", **self.headers(owner))
        assert r.status_code == 200, r.content
        if members:
            r = self.post(owner, f"/api/store/{key}/access", {"members": list(members)})
            assert r.status_code == 200, r.content
        return key

    def audit(self) -> list[dict]:
        path = self.folder / "audit.log"
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []


@pytest.fixture
def team(tmp_path, settings):
    settings.FORENSIC_ACCOUNTS_FILE = tmp_path / "accounts.json"
    settings.FORENSIC_AUDIT_LOG = tmp_path / "audit.log"
    settings.FORENSIC_AUDIT_KEY = ""
    settings.FORENSIC_AUTH_TOKEN = ""
    old = registry.root
    registry.configure(tmp_path / "cases")
    ApiClientHeaderMiddleware.reset()
    accounts = store()
    tokens = {name: accounts.create(name, role) for name, role in ROLES.items()}
    yield Team(accounts=accounts, tokens=tokens, folder=tmp_path)
    registry.close_all()
    if old:
        registry.configure(old)
    ApiClientHeaderMiddleware.reset()
