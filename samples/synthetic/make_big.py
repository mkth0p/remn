"""
Heavy-file generators for validating REMN against multi-GB evidence before
real case exports arrive. Everything streams: memory stays flat whatever the
target size.

    .venv\\Scripts\\python.exe samples\\synthetic\\make_big.py mbox --messages 300000 --attach-ratio 0.03 --out big.mbox
    .venv\\Scripts\\python.exe samples\\synthetic\\make_big.py evtx-zip --copies 40 --out big-evtx.zip
    .venv\\Scripts\\python.exe samples\\synthetic\\make_big.py blob --gb 1 --out big.blob

`mbox` writes ~3-5 KB per message (~1.2-1.6 GB at 350k messages); the mix is
mostly legitimate corporate traffic (newsletters, notifications, internal
threads) with ~0.5% planted phishing so rules still find something.
`evtx-zip` bundles the real .evtx exports from samples/ N times under distinct
names. `blob` is upload-path-only random data.
"""
from __future__ import annotations

import argparse
import base64
import os
import random
import sys
import time
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent

FIRST = ["jean", "marie", "paul", "claire", "luc", "sophie", "hugo", "emma", "louis", "lea", "nadia", "karim", "ines", "thomas", "julie"]
LAST = ["dupont", "lefevre", "martin", "bernard", "petit", "durand", "moreau", "laurent", "garcia", "roux", "fontaine", "chevalier"]
SAAS = [("notifications@github.com", "github.com", "[repo] Pull request #%d review requested"),
        ("noreply@email.teams.microsoft.com", "microsoft.com", "%s mentioned you in a conversation"),
        ("jira@acme-corp.atlassian.net", "atlassian.net", "[JIRA] (PROJ-%d) status changed"),
        ("no-reply@slack.com", "slack.com", "New message in #incident-%d"),
        ("notification@service-now.example-itsm.com", "example-itsm.com", "Ticket INC00%d updated")]
NEWSLETTERS = [("news@newsletter.acme-corp.com", "Weekly digest #%d"), ("info@techweekly-mail.com", "Tech weekly: issue %d"),
               ("updates@vendor-portal.io", "Product update %d")]


def _rand_person(rng: random.Random) -> tuple[str, str]:
    f, l = rng.choice(FIRST), rng.choice(LAST)
    return f"{f.capitalize()} {l.capitalize()}", f"{f}.{l}@interne.fr"


def _attachment_mime(rng: random.Random) -> tuple[str, str, bytes]:
    kind = rng.random()
    if kind < 0.6:
        return "rapport.pdf", "application/pdf", b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< >>\n%%EOF\n" + os.urandom(rng.randint(500, 4000))
    if kind < 0.9:
        return "donnees.csv", "text/csv", ("col1;col2;col3\n" + "\n".join(f"{i};{i * 2};x" for i in range(rng.randint(20, 200)))).encode()
    return "presentation.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", b"PK\x03\x04" + os.urandom(rng.randint(800, 3000))


def gen_message(i: int, rng: random.Random, attach_ratio: float = 0.0) -> bytes:
    """One RFC-822 message as bytes (no mbox From-line). Fast manual assembly."""
    ts = 1786000000 + i * 7 + rng.randint(0, 600)
    date = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime(ts))
    to_name, to_addr = _rand_person(rng)
    r = rng.random()
    planted = rng.random() < 0.005
    if planted:
        frm = '"Marie Lefevre" <marie.lefevre@interne-fr.co>'
        subject = f"URGENT: virement fournisseur ref {i}"
        body = "Je suis en reunion, merci de traiter le virement en urgence. C'est confidentiel.\nMarie"
        auth = "mx.interne.fr; spf=fail smtp.mailfrom=interne-fr.co; dkim=none; dmarc=fail header.from=interne-fr.co"
    elif r < 0.35:
        addr, dom, subj = rng.choice(SAAS)
        name, _ = _rand_person(rng)
        frm = f'"{name} (via notifications)" <{addr}>'
        subject = subj % (name if "%s" in subj else rng.randint(100, 9999),) if "%s" in subj else subj % rng.randint(100, 9999)
        body = f"{name} did something in the tool.\nOpen the app to see details.\nYou receive this because you are watching the project."
        auth = f"mx.interne.fr; spf=pass smtp.mailfrom={dom}; dkim=pass header.d={dom}; dmarc=pass header.from={dom}"
    elif r < 0.55:
        addr, subj = rng.choice(NEWSLETTERS)
        frm = f'"Newsletter" <{addr}>'
        subject = subj % i
        body = ("This week in the company: lots of news.\n" * rng.randint(3, 30)) + "\nUnsubscribe: https://newsletter.acme-corp.com/unsub?u=%d" % i
        auth = "mx.interne.fr; spf=pass smtp.mailfrom=acme-corp.com; dkim=pass header.d=acme-corp.com; dmarc=pass"
    else:
        name, addr = _rand_person(rng)
        frm = f'"{name}" <{addr}>'
        subject = rng.choice(["RE: point projet", "compte rendu reunion", "planning semaine", "RE: budget 2026", "notes atelier"]) + f" ({i})"
        body = ("Bonjour,\n\n" + "Voici les elements demandes. " * rng.randint(2, 40) + "\n\nCordialement,\n" + name)
        auth = "mx.interne.fr; spf=pass smtp.mailfrom=interne.fr; dkim=pass header.d=interne.fr; dmarc=pass header.from=interne.fr"

    lines = [
        f"From: {frm}",
        f'To: "{to_name}" <{to_addr}>',
        f"Subject: {subject}",
        f"Date: {date}",
        f"Message-ID: <big-{i}-{rng.randint(1000, 9999)}@mail.interne.fr>",
        "Received: from mx-out.example.net (mx-out.example.net [198.51.100.10]) by mx.interne.fr with ESMTPS id X%d; %s" % (i, date),
        f"Authentication-Results: {auth}",
        "MIME-Version: 1.0",
    ]
    if attach_ratio and rng.random() < attach_ratio:
        name_, mime, data = _attachment_mime(rng)
        b64 = base64.b64encode(data).decode()
        wrapped = "\n".join(b64[j:j + 76] for j in range(0, len(b64), 76))
        boundary = f"----=_big_{i}"
        lines += [
            f'Content-Type: multipart/mixed; boundary="{boundary}"', "",
            f"--{boundary}", "Content-Type: text/plain; charset=utf-8", "", body, "",
            f"--{boundary}", f'Content-Type: {mime}; name="{name_}"', "Content-Transfer-Encoding: base64",
            f'Content-Disposition: attachment; filename="{name_}"', "", wrapped,
            f"--{boundary}--", "",
        ]
    else:
        lines += ["Content-Type: text/plain; charset=utf-8", "", body, ""]
    return "\n".join(lines).encode("utf-8", errors="replace")


def write_mbox(out: Path, messages: int, attach_ratio: float, seed: int = 42, progress: bool = True) -> int:
    rng = random.Random(seed)
    t0 = time.time()
    written = 0
    with open(out, "wb") as fh:
        for i in range(messages):
            raw = gen_message(i, rng, attach_ratio)
            fh.write(b"From MAILER-DAEMON Thu Aug 27 09:00:00 2026\n")
            fh.write(raw.replace(b"\nFrom ", b"\n>From "))
            fh.write(b"\n\n")
            written += 1
            if progress and i and i % 50_000 == 0:
                print(f"  {i:,} messages, {out.stat().st_size / 1e6:.0f} MB, {i / (time.time() - t0):,.0f} msg/s", flush=True)
    if progress:
        print(f"wrote {written:,} messages, {out.stat().st_size / 1e6:.0f} MB in {time.time() - t0:.0f}s -> {out}")
    return written


def write_evtx_zip(out: Path, copies: int, progress: bool = True) -> int:
    sources = sorted((HERE.parent).glob("*.evtx"))
    if not sources:
        print("no .evtx files in samples/ - drop some exports there first", file=sys.stderr)
        return 0
    n = 0
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for c in range(copies):
            for src in sources:
                z.write(src, f"batch{c:03d}/{src.stem}-{c:03d}.evtx")
                n += 1
        if progress and n:
            print(f"zipped {n} evtx files ({len(sources)} sources x {copies} copies), {out.stat().st_size / 1e6:.0f} MB -> {out}")
    return n


def write_blob(out: Path, gb: float, seed: int = 42, progress: bool = True) -> int:
    rng = random.Random(seed)
    chunk = bytes(rng.getrandbits(8) for _ in range(1024)) * 1024  # 1 MB, deterministic
    total = int(gb * 1024)
    with open(out, "wb") as fh:
        for i in range(total):
            fh.write(chunk)
    if progress:
        print(f"wrote {total} MB blob -> {out}")
    return total * 1024 * 1024


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("mbox")
    m.add_argument("--messages", type=int, default=350_000)
    m.add_argument("--attach-ratio", type=float, default=0.03)
    m.add_argument("--out", default=str(HERE / "big.mbox"))
    e = sub.add_parser("evtx-zip")
    e.add_argument("--copies", type=int, default=40)
    e.add_argument("--out", default=str(HERE / "big-evtx.zip"))
    b = sub.add_parser("blob")
    b.add_argument("--gb", type=float, default=1.0)
    b.add_argument("--out", default=str(HERE / "big.blob"))
    a = ap.parse_args()
    if a.cmd == "mbox":
        write_mbox(Path(a.out), a.messages, a.attach_ratio)
    elif a.cmd == "evtx-zip":
        write_evtx_zip(Path(a.out), a.copies)
    else:
        write_blob(Path(a.out), a.gb)


if __name__ == "__main__":
    main()
