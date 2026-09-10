"""Private CLI: list episodes or write a sanitized ZIP to stdout. No operator HTTP route."""

import argparse
import hashlib
import heapq
import io
import json
import re
import sys
import time
import zipfile
from collections import Counter
from pathlib import Path

from honeypot.archive import TTL, VERSION, encoded, utc

EXPORT_LIMIT = 128 * 1024
ROW_LIMIT = 96
FIELDS = {
    "schema",
    "timestamp",
    "exhibitId",
    "episodeId",
    "parentExhibitId",
    "scope",
    "stage",
    "action",
    "result",
    "status",
    "bytes",
    "responseSha256",
    "durationMs",
    "syntheticService",
    "novelTransition",
    "suppressedEvents",
    "journalErrors",
}


def read_rows(directory, now=None):
    now = time.time() if now is None else now
    files = sorted(Path(directory).glob("*.ndjson"))
    for path in files[:8]:
        if not re.fullmatch(r"(?:trail|noise)-[0-9]{13}-[a-f0-9]{6}\.ndjson", path.name):
            continue
        if int(path.stem.split("-")[1]) < (now - 7 * TTL) * 1000:
            continue
        try:
            # One bounded snapshot per file, even while the service is appending/rotating.
            with path.open("rb") as stream:
                remaining = min(path.stat().st_size, 8 * 1024**2)
                while remaining > 0:
                    line = stream.readline(min(4097, remaining))
                    remaining -= len(line)
                    if not line or len(line) > 4096 or not line.endswith(b"\n"):
                        break
                    try:
                        row = json.loads(line)
                        if row.get("schema") == VERSION and row.get("syntheticService") is True:
                            yield {k: v for k, v in row.items() if k in FIELDS}
                    except (ValueError, AttributeError):
                        continue
        except FileNotFoundError:
            continue  # Concurrent rotation; exports explicitly describe coverage limits.


def replay(rows):
    data = json.dumps(rows, ensure_ascii=True).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    return (
        """<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-private-replay'; base-uri 'none'; form-action 'none'">
<title>Archive / observed reference trail</title><style>
body{margin:0;background:#111a19;color:#d5dfd9;font:14px/1.6 system-ui}main{max-width:1140px;margin:40px auto;padding:20px}h1{font-weight:450;font-size:28px}.quiet{color:#a4b6ac}.bar{display:flex;gap:20px;align-items:center;margin:28px 0}input{flex:1}button{background:#273e35;color:#e3ede6;border:1px solid #61786a;padding:8px 18px}section{display:grid;grid-template-columns:1fr 1fr;gap:24px}ol{padding-left:24px}li{padding:8px;opacity:.32}li.active{opacity:1}li.current{background:#20392e}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#182722;padding:24px;border:1px solid #42584c}code{font-size:12px}a{color:inherit}@media(max-width:700px){section{display:block}}
</style><main><div class="quiet">REMN / private operator export</div><h1>Observed reference trail</h1>
<p class="quiet">Measured requests to a synthetic service. Shared references establish information lineage, not identity or malicious intent. This is a bounded export; parents may be outside its coverage.</p>
<div class="bar"><button id="play">Play</button><label for="position">Observation</label><input id="position" type="range" min="0" step="1"><output id="counter"></output></div>
<section><ol id="trail"></ol><div><h2 id="title"></h2><p id="lineage"></p><pre id="detail"></pre></div></section>
<p class="quiet">The response digest identifies the served bytes. Reference tokens and response bodies are deliberately absent; this replay does not reconstruct an exact response.</p></main>
<script nonce="private-replay">const rows="""
        + data
        + """;
const slider=document.getElementById('position'), trail=document.getElementById('trail');let timer=null;
slider.max=Math.max(0,rows.length-1);slider.value=0;
for(const row of rows){const li=document.createElement('li');li.textContent=row.timestamp+' · '+row.action+' / '+row.result;trail.append(li);}
function show(){const n=Number(slider.value),r=rows[n];document.getElementById('counter').textContent=(rows.length?n+1:0)+' / '+rows.length;
Array.from(trail.children).forEach((li,i)=>{li.className=(i<=n?'active':'')+(i===n?' current':'');});if(!r)return;
document.getElementById('title').textContent=r.action;
const p=rows.findIndex(v=>v.exhibitId===r.parentExhibitId);
document.getElementById('lineage').textContent=r.parentExhibitId?(p<0?'Parent exhibit outside export: ':'Reference supplied by observation '+(p+1)+': ')+r.parentExhibitId:'New discovery; no incoming signed reference.';
document.getElementById('detail').textContent=JSON.stringify(r,null,2);}
slider.addEventListener('input',show);document.getElementById('play').addEventListener('click',()=>{if(timer){clearInterval(timer);timer=null;document.getElementById('play').textContent='Play';return;}if(Number(slider.value)>=rows.length-1)slider.value=0;document.getElementById('play').textContent='Pause';timer=setInterval(()=>{show();if(Number(slider.value)>=rows.length-1){clearInterval(timer);timer=null;document.getElementById('play').textContent='Play';}else slider.value=Number(slider.value)+1;},900);});show();</script></html>"""
    ).encode()


def export_package(directory, episode):
    if not re.fullmatch(r"[a-f0-9]{32}", episode):
        raise ValueError("episode must be a 32-character hex ID")
    recent, matched = [], 0
    # Journal segments are lane-ordered, so explicitly retain the latest timestamps.
    for row in read_rows(directory):
        if row.get("episodeId") == episode:
            matched += 1
            item = (row["timestamp"], row["exhibitId"], matched, row)
            if len(recent) < ROW_LIMIT:
                heapq.heappush(recent, item)
            else:
                heapq.heappushpop(recent, item)
    rows = [item[-1] for item in sorted(recent)]
    if not rows:
        raise ValueError("no retained observations for this episode")
    trail = b"".join(encoded(row) + b"\n" for row in rows)
    manifest = {
        "collector": VERSION,
        "collectedAt": utc(),
        "syntheticService": True,
        "episodeId": episode,
        "exportedRows": len(rows),
        "matchedRetainedRows": matched,
        "truncated": matched > len(rows),
        "coverage": "Bounded rotating telemetry; sampling, rotation, expiry, restarts and concurrent writes may omit observations. No identity inference.",
        "expectedFiles": [{"path": "Deception/observations.ndjson", "sha256": hashlib.sha256(trail).hexdigest(), "count": len(rows)}],
    }
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("collection-manifest.json", encoded(manifest))
        archive.writestr("Deception/observations.ndjson", trail)
        archive.writestr("operator-replay.html", replay(rows))
    if len(out.getvalue()) > EXPORT_LIMIT:
        raise ValueError("export exceeds 128 KiB")
    return out.getvalue()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("list", "export"))
    parser.add_argument("--journal", default="/var/lib/archive/journal")
    parser.add_argument("--episode")
    args = parser.parse_args()
    if args.command == "export":
        if not args.episode:
            parser.error("export requires --episode")
        sys.stdout.buffer.write(export_package(args.journal, args.episode))
        return
    episodes = {}
    scopes = Counter()
    for row in read_rows(args.journal):
        episode = row.get("episodeId")
        if not episode:
            continue
        if episode not in episodes:
            if len(episodes) >= 4096:
                continue
            episodes[episode] = {"episodeId": episode, "scope": row["scope"], "maxStage": 0, "observations": 0, "last": row["timestamp"]}
        entry = episodes[episode]
        entry["observations"] += 1
        entry["maxStage"] = max(entry["maxStage"], row["stage"])
        entry["last"] = max(entry["last"], row["timestamp"])
        scopes[row["scope"]] += 1
    print(
        json.dumps(
            {
                "episodes": sorted(episodes.values(), key=lambda e: (e["maxStage"], e["last"]), reverse=True),
                "observationsByScope": scopes,
                "episodeLimit": 4096,
                "coverage": "retained sampled observations only; challenge activity is separate",
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
