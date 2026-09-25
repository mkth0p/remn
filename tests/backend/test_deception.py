import hashlib
import io
import json
import zipfile

import pytest

from services.analysis.relationships import build
from services.ingest.package import PackageSource
from services.parsers.deception import normalize
from services.parsers.mail.common import ParseContext
from services.store.casestore import StoreRegistry
from services.store.writers import EventWriter


def observation(exhibit="b" * 32, parent=None, scope="archive"):
    return {
        "schema": "ghost-archive/1",
        "timestamp": "2026-09-10T12:00:00Z",
        "syntheticService": True,
        "episodeId": "a" * 32,
        "exhibitId": exhibit,
        "parentExhibitId": parent,
        "scope": scope,
        "action": "copy",
        "result": "served",
        "stage": 3,
        "status": 200,
    }


def test_deception_package_parser_and_graph(tmp_path):
    data = b"\n".join(json.dumps(row).encode() for row in (observation(), observation("c" * 32, "b" * 32)))
    blob = io.BytesIO()
    with zipfile.ZipFile(blob, "w") as z:
        z.writestr("Deception/observations.ndjson", data)
        z.writestr("collection-manifest.json", json.dumps({"collector": "ghost-archive/1", "collectedAt": "2026-09-10T13:00:00Z"}))
    source = PackageSource("archive.zip", None, blob.getvalue(), str(tmp_path), ParseContext(analyze_attachments=False))
    rows = list(source)
    assert len(rows) == 2
    assert source.stats()["errors"] == 0
    for index, row in enumerate(rows):
        row.update(id=index + 1, evidenceId=1)
        assert row["ts"] == 1789041600000
        assert row["eventId"] is None and row["recordKind"] == "event"
        assert row["sourceSha256"] == hashlib.sha256(data).hexdigest()
    graph = build(rows, [])
    lineage = [edge for edge in graph["edges"] if edge["relation"] == "supplied reference"]
    assert len(lineage) == 1 and lineage[0]["refs"][0]["id"] == 2
    assert not {"host", "ip", "account"} & {node["kind"] for node in graph["nodes"]}


def test_deception_columns_roundtrip(tmp_path):
    registry = StoreRegistry()
    registry.configure(tmp_path / "stores")
    store = registry.get("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
    row = normalize(observation("c" * 32, "b" * 32, "challenge"), 0, {})
    writer = EventWriter(store, 1)
    writer.add(row)
    writer.flush()
    cur = store.cursor()
    try:
        saved = cur.execute(
            'SELECT "deceptionScope", "deceptionEpisodeId", "deceptionExhibitId", "deceptionParentExhibitId", "deceptionStage" FROM events'
        ).fetchone()
        assert saved == ("challenge", "a" * 32, "c" * 32, "b" * 32, 3)
    finally:
        cur.close()
        store.close()


@pytest.mark.parametrize("change", [{"timestamp": "2020-01-01"}, {"syntheticService": False}, {"exhibitId": "../../"}, {"scope": "operator"}, {"stage": True}])
def test_deception_rejects_untyped_rows(change):
    with pytest.raises(ValueError):
        normalize({**observation(), **change}, 0, {})
