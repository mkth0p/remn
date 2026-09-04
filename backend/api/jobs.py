"""Tiny in-process job manager (threads) for long ingestion / rule runs. Jobs are per-process and not persisted."""
from __future__ import annotations

import logging
import threading
import time
import traceback
import uuid
from typing import Any, Callable

log = logging.getLogger(__name__)


class JobCancelled(Exception):
    pass


class Job:
    def __init__(self, kind: str, case_key: str | None, label: str = "") -> None:
        self.id = uuid.uuid4().hex
        self.kind = kind
        self.case_key = case_key
        self.label = label
        self.status = "queued"
        self.progress: dict[str, Any] = {}
        self.result: Any = None
        self.error: str | None = None
        self.created = time.time()
        self.started: float | None = None
        self.finished: float | None = None
        self._cancel = threading.Event()
        self._lock = threading.Lock()
        self.log: list[str] = []

    def update(self, **fields: Any) -> None:
        with self._lock:
            self.progress.update(fields)

    def note(self, text: str) -> None:
        with self._lock:
            self.log.append(f"{time.strftime('%H:%M:%S')} {text}")
            if len(self.log) > 200:
                self.log = self.log[-200:]

    def cancel(self) -> None:
        self._cancel.set()

    @property
    def cancelled(self) -> bool:
        return self._cancel.is_set()

    def check(self) -> None:
        if self._cancel.is_set():
            raise JobCancelled()

    def to_dict(self, with_result: bool = False) -> dict[str, Any]:
        with self._lock:
            d = {"id": self.id, "kind": self.kind, "caseKey": self.case_key, "label": self.label, "status": self.status, "progress": dict(self.progress),
                 "error": self.error, "created": int(self.created * 1000), "started": int(self.started * 1000) if self.started else None,
                 "finished": int(self.finished * 1000) if self.finished else None, "log": list(self.log[-30:])}
            if with_result:
                d["result"] = self.result
            return d


class JobManager:
    def __init__(self, max_workers: int = 2) -> None:
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._sem = threading.Semaphore(max_workers)

    def submit(self, kind: str, case_key: str | None, fn: Callable[[Job], Any], label: str = "") -> Job:
        job = Job(kind, case_key, label)
        with self._lock:
            self._jobs[job.id] = job
            self._gc()

        def runner() -> None:
            with self._sem:
                job.started = time.time()
                job.status = "running"
                try:
                    job.result = fn(job)
                    job.status = "cancelled" if job.cancelled else "done"
                except JobCancelled:
                    job.status = "cancelled"
                except Exception as exc:  # noqa: BLE001
                    job.status = "error"
                    job.error = str(exc)[:500]
                    log.error("job %s failed: %s\n%s", job.id, exc, traceback.format_exc())
                finally:
                    job.finished = time.time()

        t = threading.Thread(target=runner, name=f"job-{kind}-{job.id[:8]}", daemon=True)
        t.start()
        return job

    def get(self, job_id: str) -> Job | None:
        return self._jobs.get(job_id)

    def list(self, case_key: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            jobs = [j for j in self._jobs.values() if case_key is None or j.case_key == case_key]
        return [j.to_dict() for j in sorted(jobs, key=lambda j: -j.created)]

    def cancel(self, job_id: str) -> bool:
        j = self._jobs.get(job_id)
        if not j:
            return False
        j.cancel()
        return True

    def _gc(self) -> None:
        # keep the last 200 finished jobs
        finished = [j for j in self._jobs.values() if j.finished]
        if len(finished) > 200:
            for j in sorted(finished, key=lambda j: j.finished or 0)[: len(finished) - 200]:
                self._jobs.pop(j.id, None)


manager = JobManager()
