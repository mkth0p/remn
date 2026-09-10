"""Standard-library regression suite; also runnable inside the isolated image."""

import hashlib
import http.client
import io
import json
import re
import socket
import tempfile
import threading
import time
import unittest
import zipfile
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from honeypot.archive import MAX_DEPTH, PATHS, Archive, BoundedServer, Bucket, Journal
from honeypot.narrative import COPY, SHA
from honeypot.operator import export_package, read_rows, replay


class MemoryJournal:
    def __init__(self):
        self.rows = []
        self.errors = 0

    def append(self, row):
        self.rows.append(row)


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.now = time.time()
        self.journal = MemoryJournal()
        self.app = Archive("https://vault.example.test", b"k" * 32, self.journal, lambda: self.now)

    def request(self, url, method="GET", body=b"", origin=""):
        parsed = urlsplit(url)
        return self.app.handle(method, parsed.path + ("?" + parsed.query if parsed.query else ""), body, origin)

    def seed(self):
        status, _, body = self.request("/discovery/env")
        self.assertEqual(status, 200)
        return body.decode().split("RETENTION_COMPAT_MANIFEST=")[1].strip()

    def obj(self, url):
        status, mime, body = self.request(url)
        self.assertEqual((status, mime), (200, "application/json"))
        return json.loads(body)

    def test_braided_story_and_accurate_receipt(self):
        release = self.obj(self.seed())
        current = self.obj(release["replacementIndex"])
        withdrawn = current["records"][1]
        copy = self.obj(withdrawn["compatibilityReference"])
        self.assertEqual(hashlib.sha256(COPY).hexdigest(), SHA)
        self.assertEqual(copy["contentSha256"], withdrawn["contentSha256"])
        self.assertEqual(copy["custody"]["receivingOffice"], "C/17")
        self.assertIsNone(withdrawn["receiver"])
        self.assertEqual(copy["content"].encode(), COPY)
        copy_row = self.journal.rows[-1]
        self.now += 30
        receipt = self.request(copy["references"]["currentReceipt"])[2].decode()
        self.assertIn(copy_row["exhibitId"][:12].upper(), receipt)
        self.assertIn(copy_row["timestamp"], receipt)
        self.assertIn("External reference request", receipt)
        for i, row in enumerate(self.journal.rows[1:], 1):
            self.assertEqual(row["parentExhibitId"], self.journal.rows[i - 1]["exhibitId"])
        self.assertEqual(len({r["episodeId"] for r in self.journal.rows}), 1)
        self.assertNotIn("Cookie", json.dumps(self.journal.rows))

    def test_marker_tamper_expiry_purpose_depth_and_scope(self):
        url = self.seed()
        token = parse_qs(urlsplit(url).query)["r"][0]
        claims = self.app.markers.read(token, "release")
        self.assertIsNotNone(claims)
        self.assertIsNone(self.app.markers.read(token, "copy"))
        self.assertIsNone(self.app.markers.read("x" + token[1:], "release"))
        for changed in ({"d": 9}, {"d": True}, {"s": "operator"}, {"x": int(self.now)}, {"p": "../../file"}):
            self.assertIsNone(self.app.markers.read(self.app.markers.sign({**claims, **changed}), "release"))
        self.now += 86401
        self.assertEqual(self.request(url)[0], 404)

    def test_no_reflection_or_arbitrary_routes(self):
        for url in (
            "/api/store",
            "/.env",
            "/records/../../../etc/passwd",
            "/operator",
            "/reference/RC-0041?r=bad",
            "/compat/release.json?r=bad&r=two",
            "/compat/release.json?url=http://169.254.169.254/",
        ):
            status, _, body = self.request(url)
            self.assertIn(status, (400, 404))
            self.assertNotIn(b"169.254", body)
        self.assertNotIn("169.254", json.dumps(self.journal.rows))
        self.assertEqual(self.request("/discovery/env", body=b"a" * 8193)[0], 413)
        self.assertEqual(self.request("/discovery/env", method="DELETE")[0], 405)

    def test_head_never_creates_episode(self):
        self.assertEqual(self.request("/discovery/env", method="HEAD")[0], 200)
        self.assertIsNone(self.journal.rows[-1]["episodeId"])

    def test_seed_budget_and_signed_budget_are_separate(self):
        url = self.seed()
        statuses = [self.request("/discovery/env")[0] for _ in range(20)]
        self.assertIn(429, statuses)
        self.assertEqual(self.request(url)[0], 200)

    def test_depth_terminates_without_new_links(self):
        url = self.seed()
        claims = self.app.markers.read(parse_qs(urlsplit(url).query)["r"][0], "release")
        claims.update(d=MAX_DEPTH)
        release = self.obj(PATHS["release"] + "?r=" + self.app.markers.sign(claims))
        self.assertIsNone(release["replacementIndex"])
        self.assertIsNone(release["fieldDictionary"])

    def test_consent_is_separate_and_resolution_is_specific(self):
        original = self.obj(self.seed())
        archive_episode = self.journal.rows[-1]["episodeId"]
        self.assertEqual(self.request("/exercise/start", "POST", b"consent=yes")[0], 403)
        status, _, body = self.request("/exercise/start", "POST", b"consent=yes", self.app.origin)
        self.assertEqual(status, 200)
        url = re.search(r'href="([^"]+)"', body.decode()).group(1)
        release = self.obj(url)
        index = self.obj(release["replacementIndex"])
        copy = self.obj(index["records"][1]["compatibilityReference"])
        status, _, receipt = self.request(copy["references"]["currentReceipt"])
        amendment = re.search(r'href="([^"]+/records/SA-2[^\"]+)"', receipt.decode()).group(1)
        page = self.request(amendment)[2].decode()
        resolve = re.search(r'action="([^"]+)"', page).group(1)
        self.assertEqual(self.request(resolve, "POST", b"scope=transfer&authority=SA-2", self.app.origin)[0], 422)
        self.assertEqual(self.request(resolve, "POST", b"scope=temporary-reference&authority=SA-2", "https://evil.test")[0], 403)
        result = self.request(resolve, "POST", b"scope=temporary-reference&authority=SA-2", self.app.origin)
        self.assertEqual(result[0], 200)
        disposition = re.search(r'href="([^"]+)"', result[2].decode()).group(1)
        status, mime, blob = self.request(disposition)
        self.assertEqual((status, mime), (200, "application/zip"))
        with zipfile.ZipFile(io.BytesIO(blob)) as archive:
            self.assertEqual(json.loads(archive.read("disposition.json"))["historicalTransfer"], "outstanding")
            self.assertEqual(len(archive.read("Deception/observations.ndjson").splitlines()), 2)
        self.assertNotEqual(self.journal.rows[-1]["episodeId"], archive_episode)
        self.assertEqual(self.journal.rows[-1]["scope"], "challenge")
        self.obj(original["replacementIndex"])
        self.assertEqual(self.journal.rows[-1]["scope"], "archive")

    def test_archive_scope_cannot_resolve(self):
        url = self.seed()
        c = self.app.markers.read(parse_qs(urlsplit(url).query)["r"][0], "release")
        c["t"] = "resolve"
        url = PATHS["resolve"] + "?r=" + self.app.markers.sign(c)
        self.assertEqual(self.request(url, "POST", b"scope=temporary-reference&authority=SA-2", self.app.origin)[0], 404)

    def test_journal_rotation_retention_and_export(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = Journal(directory, segment_bytes=1400, clock=lambda: self.now)
            self.app.journal = journal
            release = self.obj(self.seed())
            index = self.obj(release["replacementIndex"])
            self.obj(index["records"][1]["compatibilityReference"])
            rows = list(read_rows(directory))
            episode = rows[0]["episodeId"]
            blob = export_package(directory, episode)
            self.assertLess(len(blob), 128 * 1024)
            with zipfile.ZipFile(io.BytesIO(blob)) as z:
                manifest = json.loads(z.read("collection-manifest.json"))
                data = z.read("Deception/observations.ndjson")
                self.assertEqual(hashlib.sha256(data).hexdigest(), manifest["expectedFiles"][0]["sha256"])
                self.assertIn(b"information lineage", z.read("operator-replay.html"))
                self.assertNotIn(b"?r=", data)
            for i in range(30):
                self.now += 1
                journal.append({**rows[-1], "action": "copy", "parentExhibitId": f"{i:032x}"})
            self.assertLessEqual(len(list(Path(directory).glob("trail-*.ndjson"))), 6)
            self.assertLessEqual(sum(p.stat().st_size for p in Path(directory).glob("*.ndjson")), 8 * 1400)
            self.now += 8 * 86400
            journal.append({**rows[-1], "parentExhibitId": "f" * 32})
            self.assertEqual(len(list(Path(directory).glob("trail-*.ndjson"))), 1)

    def test_replay_escapes_script_terminator(self):
        html = replay([{"action": "</script><img src=x onerror=alert(1)>"}])
        self.assertNotIn(b"</script><img", html)
        self.assertIn(b"\\u003c/script", html)

    def test_bucket_has_no_unbounded_client_map(self):
        now = [0]
        bucket = Bucket(2, 2, lambda: now[0])
        self.assertTrue(bucket.take())
        self.assertTrue(bucket.take())
        self.assertFalse(bucket.take())
        now[0] = 0.5
        self.assertTrue(bucket.take())


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.app = Archive("https://vault.example.test", b"x" * 32, MemoryJournal())
        self.server = BoundedServer(("127.0.0.1", 0), self.app, unix=False)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)

    def raw(self, data):
        with socket.create_connection(self.server.server_address, timeout=3) as conn:
            conn.sendall(data)
            out = bytearray()
            while chunk := conn.recv(65536):
                out.extend(chunk)
            return bytes(out)

    def test_http_headers_and_framing(self):
        response = self.raw(b"GET /discovery/env HTTP/1.1\r\nHost: vault.example.test\r\nCookie: private=SECRET\r\nAuthorization: SECRET\r\n\r\n")
        self.assertIn(b"200 OK", response)
        self.assertIn(b"Content-Security-Policy: default-src 'none'", response)
        self.assertIn(b"Cache-Control: no-store", response)
        self.assertNotIn(b"Set-Cookie", response)
        self.assertNotIn(b"Server:", response)
        self.assertNotIn("SECRET", json.dumps(self.app.journal.rows))
        for framing in (b"Content-Length: 1\r\nContent-Length: 2", b"Transfer-Encoding: chunked", b"Content-Length: -1"):
            response = self.raw(b"POST /exercise/start HTTP/1.1\r\nHost: archive\r\n" + framing + b"\r\n\r\n")
            self.assertIn(b"400 Bad Request", response)
        response = self.raw(b"GET / HTTP/1.1\r\nHost: archive\r\nX-Large: " + b"x" * 9000 + b"\r\n\r\n")
        self.assertIn(b"431", response)

    def test_health_and_operator_unavailable(self):
        conn = http.client.HTTPConnection(*self.server.server_address, timeout=2)
        conn.request("GET", "/operator")
        self.assertEqual(conn.getresponse().status, 404)
        conn.close()
        self.assertIn(b"200 OK", self.raw(b"GET /healthz HTTP/1.1\r\nHost: archive\r\n\r\n"))
        response = self.raw(b"GET /exercise HTTP/1.1\r\nHost: archive\r\n\r\n")
        self.assertIn(b"Referrer-Policy: same-origin", response)
        self.assertNotIn(b"Referrer-Policy: no-referrer", response)

    def test_slow_request_has_absolute_deadline(self):
        with socket.create_connection(self.server.server_address, timeout=2) as conn:
            conn.sendall(b"GET / HTTP/1.1\r\nX-Slow: ")
            start = time.monotonic()
            for _ in range(7):
                time.sleep(0.9)
                try:
                    conn.sendall(b"x")
                except OSError:
                    break
            self.assertLess(time.monotonic() - start, 7)
            with self.server.conn_lock:
                self.assertEqual(len(self.server.connections), 0)


if __name__ == "__main__":
    unittest.main()
