"""Spamhaus ZEN (IP) and DBL (domain) lookups over DNS, with optional DQS key."""
from __future__ import annotations

import ipaddress

from services.reputation.base import Provider, Verdict

ZEN_CODES = {
    "127.0.0.2": ("SBL", "spam source"), "127.0.0.3": ("CSS", "snowshoe / compromised host"),
    "127.0.0.4": ("XBL", "exploited host (bot, proxy)"), "127.0.0.5": ("XBL", "exploited host"),
    "127.0.0.6": ("XBL", "exploited host"), "127.0.0.7": ("XBL", "exploited host"),
    "127.0.0.9": ("SBL", "DROP listed (hijacked netblock)"), "127.0.0.10": ("PBL", "end-user / dynamic IP policy block"),
    "127.0.0.11": ("PBL", "end-user / dynamic IP policy block"),
}
DBL_CODES = {
    "127.0.1.2": "spam domain", "127.0.1.4": "phishing domain", "127.0.1.5": "malware domain", "127.0.1.6": "botnet C&C domain",
    "127.0.1.102": "abused legit spam", "127.0.1.103": "abused spammed redirector", "127.0.1.104": "abused legit phish",
    "127.0.1.105": "abused legit malware", "127.0.1.106": "abused legit botnet C&C", "127.0.1.255": "IP queries not allowed on DBL",
}
ERROR_CODES = {
    "127.255.255.252": "typing error in DNSBL name", "127.255.255.254": "query via public/open resolver is blocked - use a DQS key",
    "127.255.255.255": "excessive query volume",
}


class Spamhaus(Provider):
    name = "spamhaus"
    kinds = ("ip", "domain")
    needs_key = None
    min_interval = 0.05
    description = "Spamhaus ZEN/DBL over DNS (public mirror is blocked from open resolvers such as 8.8.8.8; a free DQS key fixes that)"
    homepage = "https://www.spamhaus.org/"

    def _zone(self, base: str) -> str:
        key = (self.config.get("keys") or {}).get("spamhaus_dqs", "")
        return f"{key}.{base}.dq.spamhaus.net" if key else f"{base}.spamhaus.org"

    def lookup(self, kind: str, value: str) -> Verdict:
        import dns.exception
        import dns.resolver

        resolver = dns.resolver.Resolver()
        resolver.lifetime = self.timeout
        if kind == "ip":
            ip = ipaddress.ip_address(value)
            if not ip.is_global:
                return Verdict(self.name, kind, value, "unknown", tags=["private_ip"])
            if ip.version == 4:
                rev = ".".join(reversed(value.split(".")))
            else:
                rev = ".".join(reversed(ip.exploded.replace(":", "")))
            qname = f"{rev}.{self._zone('zen')}"
            codes = ZEN_CODES
        else:
            from services.analysis.lookalike import registrable

            dom = registrable(value) or value
            qname = f"{dom}.{self._zone('dbl')}"
            codes = {k: ("DBL", v) for k, v in DBL_CODES.items()}
        try:
            answers = resolver.resolve(qname, "A")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return Verdict(self.name, kind, value, "clean", 0, details={"query": qname})
        except dns.exception.DNSException as exc:
            return Verdict(self.name, kind, value, "error", details={"error": str(exc)[:120], "query": qname})
        results = [r.to_text() for r in answers]
        errs = [ERROR_CODES[r] for r in results if r in ERROR_CODES]
        if errs:
            return Verdict(self.name, kind, value, "error", details={"error": errs[0], "codes": results, "query": qname})
        listed = [(r, codes.get(r)) for r in results if r in codes]
        if not listed:
            return Verdict(self.name, kind, value, "unknown", details={"codes": results, "query": qname})
        tags = sorted({c[0] for _, c in listed if c})
        desc = "; ".join(c[1] for _, c in listed if c)
        only_pbl = all(c and c[0] == "PBL" for _, c in listed)
        verdict = "suspicious" if only_pbl else "malicious"
        return Verdict(self.name, kind, value, verdict, 40 if only_pbl else 90, tags=tags,
                       details={"listed": desc, "codes": results, "query": qname},
                       link=f"https://check.spamhaus.org/results/?query={value}")
