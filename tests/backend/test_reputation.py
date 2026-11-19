from __future__ import annotations

import threading
import time

from services.reputation.base import Provider, Registry, Verdict


class _Slow(Provider):
    name = "slow"
    kinds = ("ip",)

    def __init__(self) -> None:
        super().__init__({})
        self.calls = 0
        self._count = threading.Lock()

    def lookup(self, kind: str, value: str) -> Verdict:
        with self._count:
            self.calls += 1
        time.sleep(0.5)
        return Verdict(self.name, kind, value, "clean")


def test_deadline_cancels_queued_lookups_and_reports_them():
    # Leaving the executor's `with` block waited for every queued call, so the deadline only
    # stopped the collection of results while the calls went on. Queued calls are now
    # cancelled and every lookup without an answer is reported as "timeout".
    reg = Registry()
    slow = _Slow()
    reg.providers = {"slow": slow}
    t0 = time.monotonic()
    out = reg.lookup([("ip", f"192.0.2.{i}") for i in range(8)], max_workers=1, deadline=0.05)
    assert time.monotonic() - t0 < 0.4
    assert len(out) == 8 and {o["verdict"] for o in out} == {"timeout"}
    time.sleep(0.7)
    assert slow.calls == 1  # the call in flight at the deadline; the seven queued ones never ran


def test_a_spamhaus_answer_never_carries_the_query_key(monkeypatch):
    # with a DQS key the DNS name queried contains the key; the answer goes to any client that
    # asks for a lookup, so it shows the name with the key replaced
    import ipaddress

    import dns.exception
    import dns.resolver

    from services.reputation.spamhaus import Spamhaus

    key = "invented0dqs0key0for0this0test"
    answers: dict[str, object] = {}

    class _Answer:
        def __init__(self, text: str) -> None:
            self.text = text

        def to_text(self) -> str:
            return self.text

    def resolve(self, qname, rdtype):
        assert key in qname  # the query itself still carries the key
        outcome = answers["next"]
        if callable(outcome):
            outcome = outcome(qname)
        if isinstance(outcome, Exception):
            raise outcome
        return [_Answer(t) for t in outcome]

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", resolve)
    # the invented address is from a documentation range, which Spamhaus is never asked about
    monkeypatch.setattr(ipaddress.IPv4Address, "is_global", property(lambda self: True))
    provider = Spamhaus({"keys": {"spamhaus_dqs": key}, "timeout": 1})
    outcomes = [
        ["127.0.0.2"],
        ["127.255.255.254"],
        ["127.0.0.200"],
        dns.resolver.NXDOMAIN(),
        # the resolver names the query in the text of some of its errors
        lambda qname: dns.exception.DNSException(f"All nameservers failed to answer the query {qname} IN A"),
        dns.exception.Timeout(),
    ]
    for outcome in outcomes:
        answers["next"] = outcome
        for kind, value in (("ip", "198.51.100.7"), ("domain", "invented-example.test")):
            verdict = provider.lookup(kind, value).to_dict()
            text = str(verdict)
            assert key not in text, (outcome, text)
            assert verdict["details"]["query"].endswith("<key>.zen.dq.spamhaus.net" if kind == "ip" else "<key>.dbl.dq.spamhaus.net")
