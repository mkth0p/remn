"""Bounded, synthetic archive. Standard library only; production transport is AF_UNIX."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import http.client
import json
import os
import re
import secrets
import socket
import socketserver
import threading
import time
from collections import OrderedDict
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from honeypot import narrative

VERSION = "ghost-archive/1"
TTL = 86400
MAX_DEPTH = 8
MAX_BODY = 8192
MAX_RESPONSE = 32768
ID = re.compile(r"[a-f0-9]{32}\Z")
PATHS = {
    "release": "/compat/release.json",
    "index": "/registry/current.json",
    "schema": "/compat/fields",
    "copy": "/reference/RC-0041",
    "schedule": "/records/TS-17",
    "closure": "/records/FC-12",
    "delegation": "/records/D-6",
    "instruction": "/records/RI-4",
    "amendment": "/records/SA-2",
    "receipt": "/reference/receipt",
    "resolve": "/exercise/reconcile",
    "disposition": "/exercise/disposition.zip",
}
TARGETS = {path: name for name, path in PATHS.items()}


def encoded(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()


def utc(now=None):
    return datetime.fromtimestamp(time.time() if now is None else now, UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


class Markers:
    def __init__(self, key, clock=time.time):
        if len(key) < 32:
            raise ValueError("archive key must contain at least 32 random bytes")
        self.key, self.clock = key, clock

    def sign(self, claims):
        body = b64(encoded(claims))
        return body + "." + b64(hmac.digest(self.key, body.encode(), "sha256"))

    def read(self, token, target):
        try:
            if len(token) > 1400 or not re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}", token):
                raise ValueError
            body, sig = token.split(".")
            if not hmac.compare_digest(sig, b64(hmac.digest(self.key, body.encode(), "sha256"))):
                raise ValueError
            c = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
            now = self.clock()
            if not isinstance(c, dict) or c.get("t") != target or c.get("s") not in ("archive", "challenge"):
                raise ValueError
            if not all(isinstance(c.get(k), str) and ID.fullmatch(c[k]) for k in ("e", "p")):
                raise ValueError
            if type(c.get("d")) is not int or not 1 <= c["d"] <= MAX_DEPTH:
                raise ValueError
            if type(c.get("x")) is not int or not now < c["x"] <= now + TTL + 5:
                raise ValueError
            if "receiptAt" in c:
                if type(c["receiptAt"]) is not int or not now - TTL <= c["receiptAt"] / 1000 <= now + 5:
                    raise ValueError
                if not isinstance(c.get("receiptId"), str) or not ID.fullmatch(c["receiptId"]):
                    raise ValueError
                if not isinstance(c.get("receiptParent"), str) or not ID.fullmatch(c["receiptParent"]):
                    raise ValueError
                if type(c.get("receiptStage")) is not int or not 1 <= c["receiptStage"] <= MAX_DEPTH:
                    raise ValueError
            if "dispositionAt" in c:
                if type(c["dispositionAt"]) is not int or not now - TTL <= c["dispositionAt"] / 1000 <= now + 5:
                    raise ValueError
                if not all(isinstance(c.get(k), str) and ID.fullmatch(c[k]) for k in ("dispositionId", "dispositionParent")):
                    raise ValueError
            return c
        except (ValueError, TypeError, KeyError):
            return None


class Bucket:
    def __init__(self, rate, burst, clock=time.monotonic):
        self.rate, self.burst, self.clock = rate, burst, clock
        self.credit, self.at = float(burst), clock()

    def take(self):
        now = self.clock()
        self.credit = min(self.burst, self.credit + (now - self.at) * self.rate)
        self.at = now
        if self.credit < 1:
            return False
        self.credit -= 1
        return True


class Journal:
    """48 MiB for signed transitions, 16 MiB for discovery/noise; no raw requests."""

    def __init__(self, directory, segment_bytes=8 * 1024**2, clock=time.time):
        self.directory, self.segment_bytes, self.clock = Path(directory), segment_bytes, clock
        self.directory.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.seen = OrderedDict()
        self.noise = Bucket(1, 8)
        self.dropped = 0
        self.errors = 0
        self.last_prune = 0
        self.prune()

    def prune(self):
        with self.lock:
            now = self.clock()
            if now - self.last_prune < 30:
                return
            self.last_prune = now
            try:
                for path in self.directory.glob("*.ndjson"):
                    if re.fullmatch(r"(?:trail|noise)-[0-9]{13}-[a-f0-9]{6}\.ndjson", path.name) and int(path.stem.split("-")[1]) <= (now - 7 * TTL) * 1000:
                        path.unlink()
            except OSError:
                self.errors += 1

    def append(self, row):
        with self.lock:
            key = (row.get("episodeId"), row.get("parentExhibitId"), row["action"])
            novel = bool(row.get("parentExhibitId")) and key not in self.seen
            row = {**row, "novelTransition": novel, "suppressedEvents": self.dropped, "journalErrors": self.errors}
            if not novel and not self.noise.take():
                self.dropped += 1
                return
            lane, count = ("trail", 6) if novel else ("noise", 2)
            try:
                now = self.clock()
                files = sorted(self.directory.glob(f"{lane}-*.ndjson"), key=lambda p: p.name)
                for path in list(files):
                    # Creation timestamp in the controlled filename gives a strict age bound.
                    if int(path.stem.split("-")[1]) < (now - 7 * TTL) * 1000:
                        path.unlink()
                        files.remove(path)
                data = encoded(row) + b"\n"
                path = files[-1] if files else None
                if path is None or path.stat().st_size + len(data) > self.segment_bytes or int(path.stem.split("-")[1]) < (now - TTL) * 1000:
                    while len(files) >= count:
                        files.pop(0).unlink()
                    path = self.directory / f"{lane}-{int(now * 1000):013d}-{secrets.token_hex(3)}.ndjson"
                with path.open("ab") as stream:
                    stream.write(data)
                if novel:
                    self.seen[key] = True
                    while len(self.seen) > 4096:
                        self.seen.popitem(last=False)
            except OSError:
                self.errors += 1
                self.dropped += 1


class Archive:
    def __init__(self, origin, key, journal, clock=time.time, allow_loopback=False):
        parsed = urlsplit(origin)
        local = allow_loopback and parsed.scheme == "http" and parsed.hostname == "127.0.0.1" and parsed.port and not parsed.username
        if not local and (parsed.scheme != "https" or not parsed.hostname or parsed.netloc != parsed.hostname):
            raise ValueError("ARCHIVE_ORIGIN must be an HTTPS origin without a path or port")
        if parsed.path or parsed.query or parsed.fragment or not re.fullmatch(r"[a-z0-9.-]+", parsed.hostname):
            raise ValueError("invalid archive hostname")
        self.origin, self.journal, self.clock = origin, journal, clock
        self.markers = Markers(key, clock)
        self.lock = threading.Lock()
        self.seed_budget, self.read_budget = Bucket(2, 8), Bucket(12, 32)

    def handle(self, method, url, body=b"", origin=""):
        started = time.monotonic()
        exhibit = secrets.token_hex(16)
        claims = None
        action = "unmapped"

        def finish(status, mime, payload, result="served"):
            data = payload if isinstance(payload, bytes) else payload.encode()
            if len(data) > MAX_RESPONSE:
                status, mime, data, result = 503, "text/plain", b"Reference unavailable.\n", "response-limit"
            if action != "health":
                self.journal.append(
                    {
                        "schema": VERSION,
                        "timestamp": utc(self.clock()),
                        "exhibitId": exhibit,
                        "episodeId": claims["e"] if claims else None,
                        "parentExhibitId": claims.get("p") if claims else None,
                        "scope": claims["s"] if claims else "unassigned",
                        "stage": claims["d"] if claims else 0,
                        "action": action,
                        "result": result,
                        "status": status,
                        "bytes": len(data),
                        "responseSha256": hashlib.sha256(data).hexdigest(),
                        "durationMs": round((time.monotonic() - started) * 1000),
                        "syntheticService": True,
                    }
                )
            return status, mime, data

        if len(url) > 2048 or len(body) > MAX_BODY:
            return finish(413, "text/plain", "Request exceeds reference limits.\n", "size-limit")
        try:
            parsed = urlsplit(url)
            params = parse_qs(parsed.query, strict_parsing=True, max_num_fields=2) if parsed.query else {}
            if parsed.scheme or parsed.netloc or parsed.fragment or set(params) - {"r"} or len(params.get("r", [])) > 1:
                raise ValueError
        except ValueError:
            return finish(400, "text/plain", "Invalid reference.\n", "invalid-request")
        path = parsed.path
        if path == "/healthz" and method == "GET" and not params:
            action = "health"
            return finish(200 if not self.journal.errors else 503, "text/plain", "ready\n" if not self.journal.errors else "journal unavailable\n")
        if method not in ("GET", "POST", "HEAD"):
            return finish(405, "text/plain", "Method unavailable.\n", "method-denied")
        if method == "HEAD":
            # HEAD probes never mint a reference or simulate a retrieval.
            return finish(200 if path in TARGETS or path in ("/discovery/env", "/discovery/build", "/exercise") else 404, "text/plain", b"", "head-only")
        if path == "/exercise" and method == "GET" and not params:
            action = "exercise-notice"
            return finish(200, "text/html", narrative.consent())

        is_seed = path in ("/discovery/env", "/discovery/build", "/exercise/start")
        action = {"/discovery/env": "config-discovery", "/discovery/build": "build-discovery", "/exercise/start": "challenge-start"}.get(
            path, TARGETS.get(path, "unmapped")
        )
        if is_seed:
            if (
                params
                or (path == "/exercise/start" and (method != "POST" or origin != self.origin or body != b"consent=yes"))
                or (path != "/exercise/start" and method != "GET")
            ):
                return finish(403, "text/plain", "Request unavailable.\n", "scope-denied")
            claims = {"e": secrets.token_hex(16), "s": "challenge" if path == "/exercise/start" else "archive", "d": 0, "x": int(self.clock()) + TTL}
        elif path in TARGETS:
            claims = self.markers.read(params.get("r", [""])[0], action)
            if not claims:
                return finish(404, "text/plain", "Reference unavailable.\n", "invalid-reference")
            if method != ("POST" if action == "resolve" else "GET"):
                return finish(405, "text/plain", "Method unavailable.\n", "method-denied")
            if action in ("resolve", "disposition") and claims["s"] != "challenge":
                return finish(404, "text/plain", "Reference unavailable.\n", "scope-denied")
            if action == "resolve" and origin != self.origin:
                return finish(403, "text/plain", "Request unavailable.\n", "origin-denied")
        else:
            return finish(404, "text/plain", "Not found.\n", "not-found")
        with self.lock:
            allowed = (self.seed_budget if is_seed else self.read_budget).take()
        if not allowed:
            return finish(429, "text/plain", "Reference service busy. Retry later.\n", "rate-limited")
        if action == "copy":
            # Issued only when this copy is actually requested; never a fictional historical event.
            claims = {**claims, "receiptAt": int(self.clock() * 1000), "receiptId": exhibit, "receiptParent": claims["p"], "receiptStage": claims["d"]}

        def reference(target):
            if claims["d"] >= MAX_DEPTH or (target in ("receipt", "resolve") and "receiptAt" not in claims):
                return None
            if target in ("resolve", "disposition") and claims["s"] != "challenge":
                return None
            child = {**claims, "t": target, "d": claims["d"] + 1, "p": exhibit}
            return self.origin + PATHS[target] + "?r=" + self.markers.sign(child)

        if path == "/discovery/env":
            return finish(200, "text/plain", "APP_MODE=browser\nCASE_STORE=disabled\nRETENTION_COMPAT_MANIFEST=" + reference("release") + "\n")
        if path == "/discovery/build":
            return finish(
                200, "application/json", encoded({"release": "web-2021.11-r3", "retained": {"compatibility": reference("release")}, "sourceMaps": False})
            )
        if path == "/exercise/start":
            return finish(
                200,
                "text/html",
                narrative.page(
                    "Reference exercise",
                    "Training copy",
                    "<p>The records below are fictional. Only your requests to this simulator are measured.</p>"
                    + narrative.links(reference, [("release", "Compatibility manifest")]),
                ),
            )
        if action == "resolve":
            # A deduction about document scope, not a password or a request to a real system.
            if body != b"scope=temporary-reference&authority=SA-2":
                return finish(
                    422,
                    "text/html",
                    narrative.page(
                        "Scope review",
                        "Unresolved",
                        "<p>The submitted scope does not distinguish a transfer obligation from a temporary reference receipt.</p>",
                    ),
                    "scope-unresolved",
                )
            claims = {**claims, "dispositionAt": int(self.clock() * 1000), "dispositionId": exhibit, "dispositionParent": claims["p"]}
            return finish(
                200,
                "text/html",
                narrative.page(
                    "Disposition recorded",
                    "Temporary reference / closed",
                    "<p>The reference receipt is excluded from the transfer closure dependency under SA-2. The historical transfer remains outstanding.</p><p>No further action is required from this location.</p>"
                    + narrative.links(reference, [("disposition", "Download disposition record")]),
                ),
                "scope-reconciled",
            )
        return finish(*narrative.render(action, claims, reference))


HEADERS = {
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
    "X-Robots-Tag": "noindex, nofollow, noarchive",
    "Connection": "close",
}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def parse_request(self):
        original = self.rfile

        class HeaderReader:
            remaining = 8192

            def readline(self, size=-1):
                data = original.readline(min(size if size > 0 else 8193, self.remaining + 1))
                self.remaining -= len(data)
                if self.remaining < 0:
                    raise http.client.LineTooLong("headers")
                return data

        self.rfile = HeaderReader()
        try:
            return super().parse_request()
        finally:
            self.rfile = original

    def log_message(self, *_args):
        pass  # Never emit raw request lines, headers, tokens or bodies to container logs.

    def respond(self, status, mime, body):
        self.send_response_only(status)
        self.send_header("Content-Type", mime if mime == "application/zip" else mime + "; charset=utf-8")
        if mime == "application/zip":
            self.send_header("Content-Disposition", 'attachment; filename="reference-disposition.zip"')
        self.send_header("Content-Length", str(len(body)))
        for key, value in HEADERS.items():
            # Chromium can send Origin: null on form POSTs under no-referrer.
            # Keep same-origin form validation while never sending referrers off-origin.
            if key == "Referrer-Policy" and mime == "text/html":
                value = "same-origin"
            self.send_header(key, value)
        if status == 429:
            self.send_header("Retry-After", "2")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        self.close_connection = True

    def send_error(self, code, message=None, explain=None):
        self.respond(code, "text/plain", b"Request unavailable.\n")

    def run_request(self):
        if len(self.path) > 2048 or sum(len(k) + len(v) for k, v in self.headers.items()) > 8192:
            return self.respond(431, "text/plain", b"Request too large.\n")
        lengths = self.headers.get_all("Content-Length", [])
        if self.headers.get("Transfer-Encoding") or len(lengths) > 1 or (lengths and not re.fullmatch(r"[0-9]{1,6}", lengths[0])):
            return self.respond(400, "text/plain", b"Invalid framing.\n")
        size = int(lengths[0]) if lengths else 0
        if size > MAX_BODY or (self.command != "POST" and size):
            return self.respond(413, "text/plain", b"Body unavailable.\n")
        body = self.rfile.read(size)
        if len(body) != size:
            return self.respond(400, "text/plain", b"Incomplete body.\n")
        self.respond(*self.server.archive.handle(self.command, self.path, body, self.headers.get("Origin", "")))

    do_GET = do_HEAD = do_POST = do_OPTIONS = do_PUT = do_DELETE = run_request


class BoundedServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    request_queue_size = 8
    allow_reuse_address = True

    def __init__(self, address, archive, unix=True):
        self.address_family = socket.AF_UNIX if unix else socket.AF_INET
        self.archive = archive
        self.slots = threading.BoundedSemaphore(16)
        self.connections = {}
        self.conn_lock = threading.Lock()
        self.stop_monitor = threading.Event()
        super().__init__(address, Handler)
        threading.Thread(target=self.monitor, daemon=True).start()

    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = "records-continuity", 0

    def process_request(self, request, client_address):
        request.settimeout(2)
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        with self.conn_lock:
            self.connections[request] = time.monotonic() + 5
        try:
            super().process_request(request, client_address)
        except Exception:
            with self.conn_lock:
                self.connections.pop(request, None)
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self.conn_lock:
                self.connections.pop(request, None)
            self.slots.release()

    def monitor(self):
        while not self.stop_monitor.wait(0.25):
            if isinstance(self.archive.journal, Journal):
                self.archive.journal.prune()
            with self.conn_lock:
                for conn, deadline in list(self.connections.items()):
                    if deadline < time.monotonic():
                        try:
                            conn.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass

    def handle_error(self, request, client_address):
        pass  # Disconnects and malformed requests must not become unbounded stderr logs.

    def server_close(self):
        self.stop_monitor.set()
        super().server_close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", default="/run/archive/http.sock")
    parser.add_argument("--state", default="/var/lib/archive")
    parser.add_argument("--dev-port", type=int, help="loopback-only local preview; never used in deployment")
    args = parser.parse_args()
    state = Path(args.state)
    state.mkdir(parents=True, exist_ok=True)
    os.umask(0o077)
    keyfile = state / "marker.key"
    if not keyfile.exists():
        with keyfile.open("xb") as stream:
            stream.write(secrets.token_bytes(32))
    key = keyfile.read_bytes()
    if len(key) != 32:
        raise ValueError("invalid marker.key; expected exactly 32 bytes")
    origin = f"http://127.0.0.1:{args.dev_port}" if args.dev_port else os.environ.get("ARCHIVE_ORIGIN", "https://vault.remn.tech")
    app = Archive(origin, key, Journal(state / "journal"), allow_loopback=args.dev_port is not None)
    address = ("127.0.0.1", args.dev_port) if args.dev_port is not None else args.socket
    if args.dev_port is None:
        path = Path(args.socket)
        if path.exists():
            if not path.is_socket():
                raise ValueError("refusing to replace a non-socket")
            path.unlink()
    with BoundedServer(address, app, unix=args.dev_port is None) as server:
        if args.dev_port is None:
            os.chmod(args.socket, 0o660)
        server.serve_forever(poll_interval=0.25)


if __name__ == "__main__":
    main()
