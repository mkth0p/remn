"""
Reputation providers: common model, in-memory TTL cache, per-provider rate
limiting and a registry that fans a batch of IOCs out to every configured
provider. Nothing here is Django-specific; ``configure()`` receives the keys.
"""
from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Iterable

log = logging.getLogger(__name__)

KINDS = ("url", "domain", "ip", "hash")
VERDICTS = ("malicious", "suspicious", "clean", "unknown", "error", "not_configured")


@dataclass
class Verdict:
    provider: str
    kind: str
    value: str
    verdict: str = "unknown"
    score: int | None = None  # 0-100 badness when the provider gives one
    tags: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    link: str | None = None
    cached: bool = False
    fetched_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider, "kind": self.kind, "value": self.value, "verdict": self.verdict,
            "score": self.score, "tags": self.tags[:20], "details": self.details, "link": self.link,
            "cached": self.cached, "fetchedAt": int(self.fetched_at * 1000) if self.fetched_at else None,
        }


class Provider:
    name = "base"
    kinds: tuple[str, ...] = ()
    needs_key: str | None = None  # key name in the config dict
    min_interval: float = 0.0  # seconds between two calls (rate limit)
    description = ""
    homepage = ""

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self.timeout = float(config.get("timeout", 15))
        self._last_call = 0.0
        self._lock = threading.Lock()

    @property
    def key(self) -> str:
        return (self.config.get("keys", {}) or {}).get(self.needs_key or "", "") or ""

    def configured(self) -> bool:
        return not self.needs_key or bool(self.key)

    def throttle(self) -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            wait = self._last_call + self.min_interval - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            self._last_call = time.monotonic()

    def lookup(self, kind: str, value: str) -> Verdict:  # pragma: no cover - abstract
        raise NotImplementedError

    def info(self) -> dict[str, Any]:
        return {"name": self.name, "kinds": list(self.kinds), "configured": self.configured(),
                "needsKey": self.needs_key, "description": self.description, "homepage": self.homepage}


class TTLCache:
    def __init__(self, ttl: float) -> None:
        self.ttl = ttl
        self._data: dict[tuple[str, str, str], tuple[float, Verdict]] = {}
        self._lock = threading.Lock()

    def get(self, provider: str, kind: str, value: str) -> Verdict | None:
        with self._lock:
            item = self._data.get((provider, kind, value))
            if not item:
                return None
            exp, verdict = item
            if exp < time.time():
                del self._data[(provider, kind, value)]
                return None
            v = Verdict(**{**verdict.__dict__})
            v.cached = True
            return v

    def put(self, verdict: Verdict) -> None:
        if verdict.verdict in ("error", "not_configured"):
            return
        with self._lock:
            if len(self._data) > 20000:
                # drop the oldest half
                for k in sorted(self._data, key=lambda k: self._data[k][0])[:10000]:
                    del self._data[k]
            self._data[(verdict.provider, verdict.kind, verdict.value)] = (time.time() + self.ttl, verdict)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()

    def __len__(self) -> int:
        return len(self._data)


class Registry:
    def __init__(self) -> None:
        self.providers: dict[str, Provider] = {}
        self.cache = TTLCache(6 * 3600)
        self.config: dict[str, Any] = {}

    def configure(self, keys: dict[str, str], timeout: float = 15, cache_ttl: float = 6 * 3600,
                  offline_dir: str | None = None, geoip_dir: str | None = None, spamhaus_dqs: str | None = None) -> None:
        from services.reputation import offline, providers, spamhaus

        self.config = {"keys": dict(keys or {}), "timeout": timeout, "offline_dir": offline_dir, "geoip_dir": geoip_dir}
        if spamhaus_dqs:
            self.config["keys"]["spamhaus_dqs"] = spamhaus_dqs
        self.cache = TTLCache(cache_ttl)
        self.providers = {}
        for cls in (*providers.ALL, spamhaus.Spamhaus, offline.OfflineLists, offline.GeoIP):
            try:
                p = cls(self.config)
                self.providers[p.name] = p
            except Exception as exc:  # noqa: BLE001
                log.warning("provider %s failed to initialise: %s", cls.__name__, exc)

    def list(self) -> list[dict[str, Any]]:
        return [p.info() for p in self.providers.values()]

    def lookup_one(self, provider: Provider, kind: str, value: str) -> Verdict:
        cached = self.cache.get(provider.name, kind, value)
        if cached is not None:
            return cached
        if not provider.configured():
            return Verdict(provider.name, kind, value, "not_configured")
        try:
            provider.throttle()
            v = provider.lookup(kind, value)
            v.fetched_at = time.time()
        except Exception as exc:  # noqa: BLE001
            log.info("%s lookup failed for %s %s: %s", provider.name, kind, value[:80], exc)
            v = Verdict(provider.name, kind, value, "error", details={"error": str(exc)[:200]})
        self.cache.put(v)
        return v

    def lookup(self, items: Iterable[tuple[str, str]], providers: Iterable[str] | None = None,
               max_workers: int = 8, deadline: float = 60.0) -> list[dict[str, Any]]:
        """items: iterable of (kind, value). Returns one dict per (item, provider)."""
        wanted = [p for p in self.providers.values() if (providers is None or p.name in providers)]
        jobs: list[tuple[Provider, str, str]] = []
        seen: set[tuple[str, str, str]] = set()
        for kind, value in items:
            if kind not in KINDS or not value:
                continue
            value = value.strip()
            for p in wanted:
                if kind in p.kinds and (p.name, kind, value) not in seen:
                    seen.add((p.name, kind, value))
                    jobs.append((p, kind, value))
        results: list[dict[str, Any]] = []
        if not jobs:
            return results
        start = time.monotonic()
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(self.lookup_one, p, k, v): (p, k, v) for p, k, v in jobs}
            for fut in as_completed(futures, timeout=deadline + 5):
                p, k, v = futures[fut]
                try:
                    results.append(fut.result().to_dict())
                except Exception as exc:  # noqa: BLE001
                    results.append(Verdict(p.name, k, v, "error", details={"error": str(exc)[:200]}).to_dict())
                if time.monotonic() - start > deadline:
                    break
        return results


registry = Registry()


def summarize(verdicts: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Fold per-provider verdicts into one overall verdict per (kind, value)."""
    rank = {"malicious": 4, "suspicious": 3, "clean": 1, "unknown": 0, "error": 0, "not_configured": 0}
    out: dict[str, dict[str, Any]] = {}
    for v in verdicts:
        key = f"{v['kind']}:{v['value']}"
        agg = out.setdefault(key, {"kind": v["kind"], "value": v["value"], "verdict": "unknown", "providers": [],
                                   "malicious": 0, "suspicious": 0, "clean": 0, "tags": set(), "geo": None, "asn": None})
        agg["providers"].append(v["provider"])
        if v["verdict"] in ("malicious", "suspicious", "clean"):
            agg[v["verdict"]] += 1
        if rank.get(v["verdict"], 0) > rank.get(agg["verdict"], 0):
            agg["verdict"] = v["verdict"]
        for t in v.get("tags", []):
            agg["tags"].add(t)
        d = v.get("details") or {}
        if d.get("country") and not agg["geo"]:
            agg["geo"] = {"country": d.get("country"), "city": d.get("city"), "org": d.get("org")}
        if d.get("asn") and not agg["asn"]:
            agg["asn"] = d.get("asn")
    for agg in out.values():
        agg["tags"] = sorted(agg["tags"])[:30]
    return out
