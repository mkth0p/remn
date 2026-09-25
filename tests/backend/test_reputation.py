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
