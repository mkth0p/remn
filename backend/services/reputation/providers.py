"""HTTP reputation providers (all opt-in; keys come from .env)."""

from __future__ import annotations

import base64
import hashlib
from datetime import UTC
from typing import Any

import httpx

from services.reputation.base import Provider, Verdict

UA = "remn-forensic-analyzer/0.1 (+local)"


def _client(timeout: float) -> httpx.Client:
    return httpx.Client(timeout=timeout, headers={"User-Agent": UA}, follow_redirects=True)


class URLhaus(Provider):
    name = "urlhaus"
    kinds = ("url", "domain", "ip")
    needs_key = "abusech"
    min_interval = 0.2
    description = "abuse.ch URLhaus: malware distribution URLs and hosts"
    homepage = "https://urlhaus.abuse.ch/"

    def lookup(self, kind: str, value: str) -> Verdict:
        with _client(self.timeout) as c:
            headers = {"Auth-Key": self.key}
            if kind == "url":
                r = c.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": value}, headers=headers)
            else:
                r = c.post("https://urlhaus-api.abuse.ch/v1/host/", data={"host": value}, headers=headers)
            r.raise_for_status()
            d = r.json()
        status = d.get("query_status")
        if status == "no_results":
            return Verdict(self.name, kind, value, "clean" if kind == "url" else "unknown", details={"status": status})
        if status != "ok":
            return Verdict(self.name, kind, value, "error", details={"status": status})
        if kind == "url":
            tags = d.get("tags") or []
            return Verdict(
                self.name,
                kind,
                value,
                "malicious",
                95,
                tags=[str(t) for t in tags],
                details={"threat": d.get("threat"), "urlStatus": d.get("url_status"), "dateAdded": d.get("date_added"), "blacklists": d.get("blacklists")},
                link=d.get("urlhaus_reference"),
            )
        urls = d.get("urls") or []
        online = sum(1 for u in urls if u.get("url_status") == "online")
        tags = sorted({t for u in urls for t in (u.get("tags") or [])})[:20]
        verdict = "malicious" if online else ("suspicious" if urls else "unknown")
        return Verdict(
            self.name,
            kind,
            value,
            verdict,
            90 if online else 60,
            tags=tags,
            details={
                "urlCount": d.get("url_count") or len(urls),
                "online": online,
                "firstSeen": d.get("firstseen"),
                "blacklists": d.get("blacklists"),
                "sample": [u.get("url") for u in urls[:5]],
            },
            link=d.get("urlhaus_reference"),
        )


class MalwareBazaar(Provider):
    name = "malwarebazaar"
    kinds = ("hash",)
    needs_key = "abusech"
    min_interval = 0.2
    description = "abuse.ch MalwareBazaar: known malware samples by hash"
    homepage = "https://bazaar.abuse.ch/"

    def lookup(self, kind: str, value: str) -> Verdict:
        with _client(self.timeout) as c:
            r = c.post("https://mb-api.abuse.ch/api/v1/", data={"query": "get_info", "hash": value}, headers={"Auth-Key": self.key})
            r.raise_for_status()
            d = r.json()
        status = d.get("query_status")
        if status == "hash_not_found":
            return Verdict(self.name, kind, value, "unknown", details={"status": status})
        if status != "ok":
            return Verdict(self.name, kind, value, "error", details={"status": status})
        data = (d.get("data") or [{}])[0]
        return Verdict(
            self.name,
            kind,
            value,
            "malicious",
            98,
            tags=[str(t) for t in (data.get("tags") or [])],
            details={
                "fileName": data.get("file_name"),
                "fileType": data.get("file_type"),
                "signature": data.get("signature"),
                "firstSeen": data.get("first_seen"),
                "sha256": data.get("sha256_hash"),
                "deliveryMethod": data.get("delivery_method"),
            },
            link=f"https://bazaar.abuse.ch/sample/{data.get('sha256_hash') or value}/",
        )


class ThreatFox(Provider):
    name = "threatfox"
    kinds = ("url", "domain", "ip", "hash")
    needs_key = "abusech"
    min_interval = 0.2
    description = "abuse.ch ThreatFox: IOCs shared by the community (C2, payload URLs)"
    homepage = "https://threatfox.abuse.ch/"

    def lookup(self, kind: str, value: str) -> Verdict:
        with _client(self.timeout) as c:
            r = c.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "search_ioc", "search_term": value, "exact_match": True},
                headers={"Auth-Key": self.key},
            )
            r.raise_for_status()
            d = r.json()
        status = d.get("query_status")
        if status in ("no_result", "no_results"):
            return Verdict(self.name, kind, value, "unknown", details={"status": status})
        if status != "ok":
            return Verdict(self.name, kind, value, "error", details={"status": status})
        items = d.get("data") or []
        best = items[0] if items else {}
        return Verdict(
            self.name,
            kind,
            value,
            "malicious",
            int(best.get("confidence_level") or 80),
            tags=[str(t) for t in (best.get("tags") or [])] + [best.get("malware_printable") or ""],
            details={
                "threatType": best.get("threat_type"),
                "malware": best.get("malware_printable"),
                "firstSeen": best.get("first_seen"),
                "reporter": best.get("reporter"),
                "count": len(items),
            },
            link=f"https://threatfox.abuse.ch/ioc/{best.get('id')}/" if best.get("id") else None,
        )


class VirusTotal(Provider):
    name = "virustotal"
    kinds = ("url", "domain", "ip", "hash")
    needs_key = "virustotal"
    min_interval = 15.5  # free tier: 4 requests / minute
    description = "VirusTotal v3 (free tier: 4 lookups/min, 500/day)"
    homepage = "https://www.virustotal.com/"

    def lookup(self, kind: str, value: str) -> Verdict:
        if kind == "url":
            ident = base64.urlsafe_b64encode(value.encode()).decode().strip("=")
            path = f"urls/{ident}"
            link = f"https://www.virustotal.com/gui/url/{hashlib.sha256(value.encode()).hexdigest()}"
        elif kind == "domain":
            path = f"domains/{value}"
            link = f"https://www.virustotal.com/gui/domain/{value}"
        elif kind == "ip":
            path = f"ip_addresses/{value}"
            link = f"https://www.virustotal.com/gui/ip-address/{value}"
        else:
            path = f"files/{value}"
            link = f"https://www.virustotal.com/gui/file/{value}"
        with _client(self.timeout) as c:
            r = c.get(f"https://www.virustotal.com/api/v3/{path}", headers={"x-apikey": self.key})
            if r.status_code == 404:
                return Verdict(self.name, kind, value, "unknown", details={"status": "not found"}, link=link)
            if r.status_code == 429:
                return Verdict(self.name, kind, value, "error", details={"error": "rate limited"}, link=link)
            r.raise_for_status()
            d = r.json()
        attrs = (d.get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        mal = int(stats.get("malicious", 0))
        sus = int(stats.get("suspicious", 0))
        total = sum(int(v) for v in stats.values()) or 1
        verdict = "malicious" if mal >= 3 else ("suspicious" if mal + sus >= 1 else ("clean" if stats else "unknown"))
        score = min(100, int(100 * (mal + 0.5 * sus) / total * 3)) if stats else None
        details: dict[str, Any] = {
            "malicious": mal,
            "suspicious": sus,
            "harmless": stats.get("harmless"),
            "undetected": stats.get("undetected"),
            "reputation": attrs.get("reputation"),
            "categories": attrs.get("categories"),
        }
        if kind == "ip":
            details.update({"asn": attrs.get("asn"), "org": attrs.get("as_owner"), "country": attrs.get("country"), "network": attrs.get("network")})
        if kind == "domain":
            details.update({"registrar": attrs.get("registrar"), "creationDate": attrs.get("creation_date"), "whoisDate": attrs.get("whois_date")})
        if kind == "hash":
            details.update(
                {
                    "names": (attrs.get("names") or [])[:5],
                    "typeDescription": attrs.get("type_description"),
                    "popularThreat": ((attrs.get("popular_threat_classification") or {}).get("suggested_threat_label")),
                    "firstSubmission": attrs.get("first_submission_date"),
                }
            )
        tags = [str(t) for t in (attrs.get("tags") or [])][:15]
        return Verdict(self.name, kind, value, verdict, score, tags=tags, details=details, link=link)


class AbuseIPDB(Provider):
    name = "abuseipdb"
    kinds = ("ip",)
    needs_key = "abuseipdb"
    min_interval = 0.5
    description = "AbuseIPDB: community abuse reports per IP (1000/day free)"
    homepage = "https://www.abuseipdb.com/"

    def lookup(self, kind: str, value: str) -> Verdict:
        with _client(self.timeout) as c:
            r = c.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": value, "maxAgeInDays": 90, "verbose": ""},
                headers={"Key": self.key, "Accept": "application/json"},
            )
            r.raise_for_status()
            d = (r.json() or {}).get("data") or {}
        conf = int(d.get("abuseConfidenceScore") or 0)
        verdict = "malicious" if conf >= 75 else ("suspicious" if conf >= 25 else ("clean" if d else "unknown"))
        tags = []
        if d.get("isTor"):
            tags.append("tor")
        if d.get("isWhitelisted"):
            tags.append("whitelisted")
        if d.get("usageType"):
            tags.append(str(d["usageType"]).lower())
        return Verdict(
            self.name,
            kind,
            value,
            verdict,
            conf,
            tags=tags,
            details={
                "totalReports": d.get("totalReports"),
                "distinctUsers": d.get("numDistinctUsers"),
                "lastReported": d.get("lastReportedAt"),
                "isp": d.get("isp"),
                "org": d.get("isp"),
                "country": d.get("countryCode"),
                "domain": d.get("domain"),
                "usageType": d.get("usageType"),
                "isTor": d.get("isTor"),
            },
            link=f"https://www.abuseipdb.com/check/{value}",
        )


class GreyNoise(Provider):
    name = "greynoise"
    kinds = ("ip",)
    needs_key = "greynoise"
    min_interval = 0.5
    description = "GreyNoise community: internet-wide scanners vs. benign services"
    homepage = "https://viz.greynoise.io/"

    def lookup(self, kind: str, value: str) -> Verdict:
        with _client(self.timeout) as c:
            r = c.get(f"https://api.greynoise.io/v3/community/{value}", headers={"key": self.key, "Accept": "application/json"})
            if r.status_code == 404:
                return Verdict(self.name, kind, value, "unknown", details={"status": "not observed"}, link=f"https://viz.greynoise.io/ip/{value}")
            r.raise_for_status()
            d = r.json()
        cls = (d.get("classification") or "").lower()
        verdict = {"malicious": "malicious", "benign": "clean"}.get(cls, "suspicious" if d.get("noise") else "unknown")
        tags = []
        if d.get("noise"):
            tags.append("scanner")
        if d.get("riot"):
            tags.append("riot-common-service")
        return Verdict(
            self.name,
            kind,
            value,
            verdict,
            {"malicious": 85, "benign": 5}.get(cls),
            tags=tags,
            details={"name": d.get("name"), "classification": cls, "lastSeen": d.get("last_seen"), "noise": d.get("noise"), "riot": d.get("riot")},
            link=d.get("link") or f"https://viz.greynoise.io/ip/{value}",
        )


class IPInfo(Provider):
    name = "ipinfo"
    kinds = ("ip",)
    needs_key = None  # works without a token at a low rate; token raises the quota
    min_interval = 0.3
    description = "ipinfo.io: geolocation / ASN / hosting for an IP (context, not a verdict)"
    homepage = "https://ipinfo.io/"

    def lookup(self, kind: str, value: str) -> Verdict:
        token = (self.config.get("keys") or {}).get("ipinfo", "")
        with _client(self.timeout) as c:
            r = c.get(f"https://ipinfo.io/{value}/json", params={"token": token} if token else None, headers={"Accept": "application/json"})
            r.raise_for_status()
            d = r.json()
        if d.get("bogon"):
            return Verdict(self.name, kind, value, "unknown", tags=["bogon"], details={"bogon": True})
        org = d.get("org") or ""
        asn = org.split(" ")[0] if org.startswith("AS") else None
        tags = []
        privacy = d.get("privacy") or {}
        for k in ("vpn", "proxy", "tor", "hosting", "relay"):
            if privacy.get(k):
                tags.append(k)
        return Verdict(
            self.name,
            kind,
            value,
            "unknown",
            None,
            tags=tags,
            details={
                "country": d.get("country"),
                "region": d.get("region"),
                "city": d.get("city"),
                "org": org,
                "asn": asn,
                "hostname": d.get("hostname"),
                "timezone": d.get("timezone"),
                "anycast": d.get("anycast"),
            },
            link=f"https://ipinfo.io/{value}",
        )


class RDAP(Provider):
    name = "rdap"
    kinds = ("domain",)
    needs_key = None
    min_interval = 0.5
    description = "RDAP (registry data): domain registration date, registrar, status - flags very young domains"
    homepage = "https://rdap.org/"

    def lookup(self, kind: str, value: str) -> Verdict:
        from services.analysis.lookalike import registrable

        dom = registrable(value) or value
        with _client(self.timeout) as c:
            r = c.get(f"https://rdap.org/domain/{dom}", headers={"Accept": "application/rdap+json, application/json"})
            if r.status_code == 404:
                return Verdict(self.name, kind, value, "suspicious", 40, tags=["unregistered_or_unknown"], details={"domain": dom, "status": "not found"})
            r.raise_for_status()
            d = r.json()
        events = {e.get("eventAction"): e.get("eventDate") for e in (d.get("events") or []) if isinstance(e, dict)}
        reg = events.get("registration")
        age_days = None
        if reg:
            from datetime import datetime

            try:
                dt = datetime.fromisoformat(reg.replace("Z", "+00:00"))
                age_days = (datetime.now(UTC) - dt).days
            except ValueError:
                pass
        registrar = None
        for ent in d.get("entities") or []:
            if "registrar" in (ent.get("roles") or []):
                vcard = ent.get("vcardArray") or []
                try:
                    for item in vcard[1]:
                        if item[0] == "fn":
                            registrar = item[3]
                except Exception:  # noqa: BLE001
                    pass
                if not registrar:
                    registrar = ent.get("handle")
        tags = []
        verdict = "unknown"
        score = None
        if age_days is not None:
            if age_days < 30:
                tags.append("domain_age_lt_30d")
                verdict, score = "suspicious", 60
            elif age_days < 180:
                tags.append("domain_age_lt_6m")
                verdict, score = "suspicious", 30
            else:
                tags.append("established_domain")
        return Verdict(
            self.name,
            kind,
            value,
            verdict,
            score,
            tags=tags,
            details={
                "domain": dom,
                "registered": reg,
                "ageDays": age_days,
                "expires": events.get("expiration"),
                "lastChanged": events.get("last changed"),
                "registrar": registrar,
                "status": (d.get("status") or [])[:8],
                "nameservers": [n.get("ldhName") for n in (d.get("nameservers") or [])[:6] if isinstance(n, dict)],
            },
            link=f"https://rdap.org/domain/{dom}",
        )


class SafeBrowsing(Provider):
    name = "safebrowsing"
    kinds = ("url",)
    needs_key = "safebrowsing"
    min_interval = 0.1
    description = "Google Safe Browsing v4 lookup API"
    homepage = "https://developers.google.com/safe-browsing"

    def lookup(self, kind: str, value: str) -> Verdict:
        body = {
            "client": {"clientId": "remn-forensic", "clientVersion": "0.1"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": value}],
            },
        }
        with _client(self.timeout) as c:
            r = c.post("https://safebrowsing.googleapis.com/v4/threatMatches:find", params={"key": self.key}, json=body)
            r.raise_for_status()
            d = r.json() or {}
        matches = d.get("matches") or []
        if not matches:
            return Verdict(self.name, kind, value, "clean", 0)
        types = sorted({m.get("threatType", "") for m in matches})
        return Verdict(self.name, kind, value, "malicious", 95, tags=[t.lower() for t in types], details={"matches": len(matches)})


ALL = (URLhaus, MalwareBazaar, ThreatFox, VirusTotal, AbuseIPDB, GreyNoise, IPInfo, RDAP, SafeBrowsing)
