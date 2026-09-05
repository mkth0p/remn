"""Small offline EVTX writer for synthetic test evidence, not OS log modification.

Uses literal BinXML elements (no templates), chunk-relative names, and CRC32.
Format references:
https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even6/c73573ae-1c90-43a2-a65f-ad7501155956
"""
from __future__ import annotations

import struct
import zlib
from pathlib import Path

CHUNK = 65536


def element(name, value=None, attrs=None, children=None):
    return (name, value, attrs or {}, children or [])


class BinXml:
    def __init__(self, offset):
        self.offset = offset
        self.buf = bytearray(b"\x0f\x01\x01\x00")
        self.names = []

    def name(self, value):
        self.buf.extend(struct.pack("<I", self.offset + len(self.buf) + 4))
        encoded = value.encode("utf-16le")
        hash_value = 0
        for char in value:
            hash_value = (hash_value * 65599 + ord(char)) & 0xffff
        self.names.append((self.offset + len(self.buf), hash_value))
        self.buf.extend(struct.pack("<IHH", 0, hash_value, len(encoded) // 2) + encoded + b"\0\0")

    def text(self, value):
        encoded = str(value).encode("utf-16le")
        if len(encoded) // 2 > 65535:
            raise ValueError("synthetic value exceeds BinXML string limit")
        self.buf.extend(b"\x05\x01" + struct.pack("<H", len(encoded) // 2) + encoded)

    def node(self, node):
        name, value, attrs, children = node
        start = len(self.buf)
        # Dependency IDs belong to template definitions, not literal fragments.
        self.buf.extend(struct.pack("<BI", 0x41 if attrs else 1, 0))
        self.name(name)
        if attrs:
            astart = len(self.buf)
            self.buf.extend(b"\0" * 4)
            for i, (key, val) in enumerate(attrs.items()):
                self.buf.append(0x46 if i < len(attrs) - 1 else 6)
                self.name(key)
                self.text(val)
            struct.pack_into("<I", self.buf, astart, len(self.buf) - astart - 4)
        if value is None and not children:
            self.buf.append(3)
        else:
            self.buf.append(2)
            if value is not None:
                self.text(value)
            for child in children:
                self.node(child)
            self.buf.append(4)
        struct.pack_into("<I", self.buf, start + 1, len(self.buf) - start - 5)


class EvtxWriter:
    def __init__(self, path: Path):
        self.path = path
        self.fh = path.open("xb")
        self.fh.write(b"\0" * 4096)
        self.chunks = 0
        self.count = 0
        self._new_chunk()

    def _new_chunk(self):
        self.buf = bytearray(CHUNK)
        self.pos = 512
        self.first = self.count + 1
        self.last_offset = 512
        self.buckets = [0] * 64

    def _flush(self):
        if self.pos == 512:
            return
        struct.pack_into("<8sQQQQIIII", self.buf, 0, b"ElfChnk\0", self.first, self.count, self.first, self.count,
                         128, self.last_offset, self.pos, zlib.crc32(self.buf[512:self.pos]))
        struct.pack_into("<64I", self.buf, 128, *self.buckets)
        struct.pack_into("<I", self.buf, 124, zlib.crc32(self.buf[:120] + self.buf[128:512]))
        self.fh.write(self.buf)
        self.chunks += 1
        self._new_chunk()

    def add(self, node, ts_ms):
        xml = BinXml(self.pos + 24)
        xml.node(node)
        xml.buf.append(0)
        size = (24 + len(xml.buf) + 4 + 7) // 8 * 8
        if size > CHUNK - 512:
            raise ValueError("synthetic event exceeds chunk capacity")
        if self.pos + size > CHUNK:
            self._flush()
            xml = BinXml(self.pos + 24)
            xml.node(node)
            xml.buf.append(0)
        self.count += 1
        self.last_offset = self.pos
        struct.pack_into("<IIQQ", self.buf, self.pos, 0x2a2a, size, self.count, int(ts_ms) * 10000 + 116444736000000000)
        self.buf[self.pos + 24:self.pos + 24 + len(xml.buf)] = xml.buf
        for offset, hash_value in xml.names:
            bucket = hash_value % 64
            struct.pack_into("<I", self.buf, offset, self.buckets[bucket])
            self.buckets[bucket] = offset
        struct.pack_into("<I", self.buf, self.pos + size - 4, size)
        self.pos += size

    def close(self):
        if self.fh.closed:
            return
        self._flush()
        header = bytearray(4096)
        struct.pack_into("<8sQQQIHHHI", header, 0, b"ElfFile\0", 0, max(0, self.chunks - 1), self.count + 1, 128, 1, 3, 4096, self.chunks)
        struct.pack_into("<I", header, 124, zlib.crc32(header[:120]))
        self.fh.seek(0)
        self.fh.write(header)
        self.fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


def event_node(record_id, date, provider, channel, host, event_id, data, level=4):
    system = element("System", children=[
        element("Provider", attrs={"Name": provider}), element("EventID", event_id), element("Version", 0),
        element("Level", level), element("Task", 0), element("Opcode", 0), element("Keywords", "0x8000000000000000"),
        element("TimeCreated", attrs={"SystemTime": date}), element("EventRecordID", record_id),
        element("Execution", attrs={"ProcessID": 1000, "ThreadID": 1001}), element("Channel", channel),
        element("Computer", host), element("Security", attrs={"UserID": "S-1-5-18"}),
    ])
    return element("Event", attrs={"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}, children=[
        system, element("EventData", children=[element("Data", value, {"Name": key}) for key, value in data.items()]),
    ])
