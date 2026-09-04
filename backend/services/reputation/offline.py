"""
Offline providers for air-gapped work:

* OfflineLists - block lists dropped in ``backend/data/lists``:
    - ``*.txt``: one indicator per line (``#`` comments). The kind is taken from a
      ``# kind: ip|domain|url|hash`` header line or guessed from the file name
      (ips-*.txt, domains-*.txt, urls-*.txt, hashes-*.txt) or from the value itself.
    - ``urlhaus*.csv`` (official URLhaus CSV export), ``feodo*.csv|txt`` (IP list),
      ``tor*.txt`` (exit nodes), ``openphish*.txt``, ``phishtank*.csv``.
* GeoIP - MaxMind GeoLite2 (City / ASN .mmdb) if ``maxminddb`` is importable and
  the databases are placed in ``backend/data/geoip``.
"""
from __future__ import annotations

import csv
import io
import ipaddress
import logging
import re
import threading
from pathlib import Path
from typing import Any

from services.reputation.base import Provider, Verdict

log = logging.getLogger(__name__)
_HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")


def _guess_kind(value: str) -> str | None:
    v = value.strip().lower()
    if not v:
        return None
    if "://" in v or v.startswith("hxxp"):
        return "url"
    if _HASH_RE.match(v):
        return "hash"
    try:
        ipaddress.ip_network(v, strict=False)
        return "ip"
    except ValueError:
        pass
    if re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", v):
        return "domain"
    return None


class OfflineLists(Provider):
    name = "offline"
    kinds = ("url", "domain", "ip", "hash")
    needs_key = None
    description = "Local block lists (URLhaus CSV, Feodo, Tor exits, OpenPhish, custom txt) - no network"
    homepage = ""

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self.dir = Path(config.get("offline_dir")) if config.get("offline_dir") else None
        self._lock = threading.Lock()
        self._mtime = -1.0
        self._urls: dict[str, str] = {}
        self._domains: dict[str, str] = {}
        self._ips: dict[str, str] = {}
        self._nets: list[tuple[Any, str]] = []
        self._hashes: dict[str, str] = {}
        self._files = 0

    def configured(self) -> bool:
        self._maybe_load()
        return self._files > 0

    def info(self) -> dict[str, Any]:
        d = super().info()
        self._maybe_load()
        d.update({"files": self._files, "urls": len(self._urls), "domains": len(self._domains), "ips": len(self._ips) + len(self._nets), "hashes": len(self._hashes),
                  "directory": str(self.dir) if self.dir else None})
        return d

    def _maybe_load(self) -> None:
        if not self.dir or not self.dir.is_dir():
            return
        files = [p for p in self.dir.iterdir() if p.suffix.lower() in (".txt", ".csv", ".lst") and not p.name.startswith(".")]
        mtime = max((p.stat().st_mtime for p in files), default=0.0)
        with self._lock:
            if mtime == self._mtime and self._files == len(files):
                return
            self._urls, self._domains, self._ips, self._nets, self._hashes = {}, {}, {}, [], {}
            for p in files:
                try:
                    self._load_file(p)
                except Exception as exc:  # noqa: BLE001
                    log.warning("offline list %s failed: %s", p.name, exc)
            self._mtime = mtime
            self._files = len(files)
            log.info("offline lists: %d files, %d urls, %d domains, %d ips, %d hashes", self._files, len(self._urls), len(self._domains), len(self._ips) + len(self._nets), len(self._hashes))

    def _add(self, kind: str | None, value: str, source: str) -> None:
        v = value.strip().strip('"').lower()
        if not v:
            return
        kind = kind or _guess_kind(v)
        if kind == "url":
            self._urls[v.rstrip("/")] = source
            from urllib.parse import urlsplit

            try:
                host = (urlsplit(v if "://" in v else "http://" + v).hostname or "").lower()
                if host:
                    self._domains.setdefault(host, source + " (url host)")
            except ValueError:
                pass
        elif kind == "domain":
            self._domains[v.strip(".")] = source
        elif kind == "ip":
            if "/" in v:
                try:
                    self._nets.append((ipaddress.ip_network(v, strict=False), source))
                except ValueError:
                    pass
            else:
                self._ips[v] = source
        elif kind == "hash":
            self._hashes[v] = source

    def _load_file(self, p: Path) -> None:
        name = p.name.lower()
        source = p.stem
        text = p.read_text(encoding="utf-8", errors="replace")
        if p.suffix.lower() == ".csv":
            if name.startswith("urlhaus"):
                for row in csv.reader(io.StringIO("\n".join(l for l in text.splitlines() if l and not l.startswith("#")))):
                    if len(row) >= 3 and row[2].startswith(("http", "hxxp")):
                        self._add("url", row[2], f"urlhaus:{row[5] if len(row) > 5 else ''}".rstrip(":"))
                return
            if name.startswith("phishtank"):
                for row in csv.DictReader(io.StringIO(text)):
                    if row.get("url"):
                        self._add("url", row["url"], "phishtank")
                return
            for row in csv.reader(io.StringIO("\n".join(l for l in text.splitlines() if l and not l.startswith("#")))):
                for cell in row[:3]:
                    k = _guess_kind(cell)
                    if k:
                        self._add(k, cell, source)
                        break
            return
        kind: str | None = None
        m = re.search(r"(?im)^#\s*kind\s*:\s*(ip|domain|url|hash)", text)
        if m:
            kind = m.group(1).lower()
        elif name.startswith(("ip", "feodo", "tor", "c2", "cc-")):
            kind = "ip"
        elif name.startswith(("domain", "dbl", "dga")):
            kind = "domain"
        elif name.startswith(("url", "openphish", "phish")):
            kind = "url"
        elif name.startswith(("hash", "sha256", "md5", "sha1")):
            kind = "hash"
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", ";", "//")):
                continue
            token = line.split()[0].split(",")[0]
            self._add(kind, token, source)

    def lookup(self, kind: str, value: str) -> Verdict:
        self._maybe_load()
        v = value.strip().lower()
        hit: str | None = None
        if kind == "url":
            hit = self._urls.get(v.rstrip("/"))
            if not hit:
                from urllib.parse import urlsplit

                try:
                    host = (urlsplit(v).hostname or "").lower()
                except ValueError:
                    host = ""
                hit = self._domains.get(host) if host else None
        elif kind == "domain":
            parts = v.strip(".").split(".")
            for i in range(len(parts) - 1):
                cand = ".".join(parts[i:])
                if cand in self._domains:
                    hit = self._domains[cand]
                    break
        elif kind == "ip":
            hit = self._ips.get(v)
            if not hit:
                try:
                    ip = ipaddress.ip_address(v)
                    for net, src in self._nets:
                        if ip in net:
                            hit = src
                            break
                except ValueError:
                    pass
        elif kind == "hash":
            hit = self._hashes.get(v)
        if hit:
            return Verdict(self.name, kind, value, "malicious", 85, tags=[hit.split(":")[0]], details={"list": hit})
        return Verdict(self.name, kind, value, "unknown", details={"lists": self._files})


class GeoIP(Provider):
    name = "geoip"
    kinds = ("ip",)
    needs_key = None
    description = "MaxMind GeoLite2 City/ASN databases (offline) - context only"
    homepage = "https://www.maxmind.com/"

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self.dir = Path(config.get("geoip_dir")) if config.get("geoip_dir") else None
        self._city = self._asn = None
        self._tried = False

    def _open(self) -> None:
        if self._tried:
            return
        self._tried = True
        if not self.dir or not self.dir.is_dir():
            return
        try:
            import maxminddb
        except Exception:  # noqa: BLE001
            return
        for p in self.dir.glob("*.mmdb"):
            try:
                reader = maxminddb.open_database(str(p))
                if "asn" in p.name.lower():
                    self._asn = reader
                else:
                    self._city = reader
            except Exception as exc:  # noqa: BLE001
                log.warning("geoip db %s failed: %s", p.name, exc)

    def configured(self) -> bool:
        self._open()
        return bool(self._city or self._asn)

    def lookup(self, kind: str, value: str) -> Verdict:
        self._open()
        details: dict[str, Any] = {}
        if self._city:
            r = self._city.get(value) or {}
            details["country"] = ((r.get("country") or {}).get("iso_code"))
            details["city"] = (((r.get("city") or {}).get("names") or {}).get("en"))
            loc = r.get("location") or {}
            details["lat"], details["lon"] = loc.get("latitude"), loc.get("longitude")
        if self._asn:
            r = self._asn.get(value) or {}
            if r.get("autonomous_system_number"):
                details["asn"] = f"AS{r['autonomous_system_number']}"
                details["org"] = r.get("autonomous_system_organization")
        return Verdict(self.name, kind, value, "unknown", None, details=details)
