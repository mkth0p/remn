"""
Scale test for the server case store: generates synthetic Windows events (and,
with --mail, synthetic mailboxes) with realistic distributions, writes them to
a temporary DuckDB case store and times the query layer and the rule engine.

    .venv\\Scripts\\python.exe samples\\synthetic\\scale_test.py 1000000
    .venv\\Scripts\\python.exe samples\\synthetic\\scale_test.py --mail 20000
"""

from __future__ import annotations

import json
import random
import shutil
import sys
import tempfile
import time
import uuid
from pathlib import Path

sys.path.insert(0, "backend")
from services.store import queries as Q  # noqa: E402
from services.store import rules as R  # noqa: E402
from services.store.casestore import StoreRegistry  # noqa: E402
from services.store.writers import EventWriter  # noqa: E402

random.seed(42)
T0 = 1785000000000  # ~2026-07-25
SPAN = 30 * 86400 * 1000
HOSTS = [f"WS{i:03d}" for i in range(1, 60)] + ["DC01", "DC02", "FS01", "EXCH01"]
USERS = [f"user{i:03d}" for i in range(1, 400)] + ["administrator", "svc_backup", "svc_sql", "j.dupont", "m.lefevre"]
IPS = [f"10.{random.randint(0, 20)}.{random.randint(0, 255)}.{random.randint(1, 254)}" for _ in range(600)] + ["185.220.101.4", "45.155.205.33", "203.0.113.5"]
PROC = [
    "C:\\Windows\\System32\\svchost.exe",
    "C:\\Windows\\explorer.exe",
    "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "C:\\Windows\\System32\\cmd.exe",
    "C:\\Users\\Public\\update.exe",
]


def gen(i: int) -> dict:
    r = random.random()
    ts = T0 + int(random.random() ** 1.3 * SPAN)
    host = random.choice(HOSTS)
    if r < 0.55:
        eid, cat = 4624, "logon"
        lt = random.choice([2, 3, 3, 3, 5, 7, 10, 11])
        u, ip = random.choice(USERS), random.choice(IPS)
        data = {"TargetUserName": u, "LogonType": lt, "IpAddress": ip, "AuthenticationPackageName": random.choice(["Kerberos", "NTLM"])}
        return {
            "recordId": i,
            "ts": ts,
            "eventId": eid,
            "provider": "Microsoft-Windows-Security-Auditing",
            "channel": "Security",
            "computer": host,
            "level": 0,
            "levelName": "LogAlways",
            "category": cat,
            "targetUser": u,
            "targetDomain": "CORP",
            "logonType": lt,
            "logonTypeName": "Network",
            "ipAddress": ip,
            "authPackage": data["AuthenticationPackageName"],
            "summary": f"Logon type {lt} as CORP\\{u} from {ip}",
            "data": data,
            "raw": json.dumps({"EventID": eid, "EventData": data}),
        }
    if r < 0.80:
        eid = 4625
        # bursts: 2% of failures come from an attacker IP against admin within a short window
        if random.random() < 0.02:
            ip, u, ts = "185.220.101.4", "administrator", T0 + 12 * 86400 * 1000 + random.randint(0, 600) * 1000
        else:
            ip, u = random.choice(IPS), random.choice(USERS)
        data = {"TargetUserName": u, "IpAddress": ip, "Status": "0xc000006d", "SubStatus": "0xc000006a", "LogonType": 3}
        return {
            "recordId": i,
            "ts": ts,
            "eventId": eid,
            "provider": "Microsoft-Windows-Security-Auditing",
            "channel": "Security",
            "computer": host,
            "level": 0,
            "levelName": "LogAlways",
            "category": "logon",
            "targetUser": u,
            "targetDomain": "CORP",
            "logonType": 3,
            "ipAddress": ip,
            "status": "0xc000006d",
            "subStatus": "0xc000006a",
            "statusText": "Wrong password",
            "summary": f"Failed logon Network as CORP\\{u} from {ip} - Wrong password",
            "data": data,
            "raw": json.dumps({"EventID": eid, "EventData": data}),
        }
    if r < 0.97:
        eid = 4688
        p = random.choice(PROC)
        cmd = p + (" -enc SQBFAFgA" if "powershell" in p and random.random() < 0.01 else "")
        u = random.choice(USERS)
        data = {"NewProcessName": p, "CommandLine": cmd, "SubjectUserName": u, "ParentProcessName": random.choice(PROC)}
        return {
            "recordId": i,
            "ts": ts,
            "eventId": eid,
            "provider": "Microsoft-Windows-Security-Auditing",
            "channel": "Security",
            "computer": host,
            "level": 0,
            "levelName": "LogAlways",
            "category": "process",
            "subjectUser": u,
            "processName": p,
            "commandLine": cmd,
            "parentProcessName": data["ParentProcessName"],
            "summary": f"Process {p} by CORP\\{u}",
            "data": data,
            "raw": json.dumps({"EventID": eid, "EventData": data}),
        }
    eid = random.choice([7045, 4720, 1102, 4698, 4672, 4104])
    data = {
        "ServiceName": "PSEXESVC" if eid == 7045 and random.random() < 0.3 else "UpdateSvc",
        "ImagePath": random.choice(PROC),
        "SubjectUserName": random.choice(USERS),
    }
    return {
        "recordId": i,
        "ts": ts,
        "eventId": eid,
        "provider": "Service Control Manager" if eid == 7045 else "Microsoft-Windows-Security-Auditing",
        "channel": "System" if eid == 7045 else "Security",
        "computer": host,
        "level": 4,
        "levelName": "Information",
        "category": "persistence",
        "subjectUser": data["SubjectUserName"],
        "serviceName": data["ServiceName"],
        "serviceFile": data["ImagePath"],
        "summary": f"Service installed {data['ServiceName']} -> {data['ImagePath']}",
        "data": data,
        "raw": json.dumps({"EventID": eid, "EventData": data}),
    }


def main(N: int = 200_000) -> None:
    root = Path(tempfile.mkdtemp(prefix="remn-scale-"))
    reg = StoreRegistry()
    reg.configure(root)
    st = reg.get(str(uuid.uuid4()))
    print(f"store at {st.path}")
    t0 = time.time()
    w = EventWriter(st, 1, include_raw=True)
    for i in range(N):
        w.add(gen(i))
        if i and i % 200_000 == 0:
            print(f"  {i:,} rows, {i / (time.time() - t0):,.0f} rows/s", flush=True)
    w.flush()
    dt = time.time() - t0
    print(f"wrote {N:,} events in {dt:.1f}s ({N / dt:,.0f} rows/s), file {st.size_bytes() / 1e6:.1f} MB")
    s = {
        "internal_ips": ["10.0.0.0/8"],
        "businessHours": {"start": 8, "end": 19, "tz": "Europe/Paris"},
        "weekendDays": [0, 6],
        "service_accounts": ["svc_backup", "svc_sql"],
        "admin_accounts": ["administrator"],
    }

    def timed(label, fn):
        t = time.time()
        r = fn()
        print(f"  {label:<58s} {1000 * (time.time() - t):7.0f} ms", flush=True)
        return r

    print("queries:")
    timed("count all", lambda: Q.count(st, "events", {}))
    timed("count eventId=4625", lambda: Q.count(st, "events", {"conditions": [{"field": "eventId", "op": "eq", "value": 4625}]}))
    timed(
        "search 4625 from external ip (nin_setting), 3000 rows",
        lambda: Q.search(
            st,
            "events",
            {"conditions": [{"field": "eventId", "op": "eq", "value": 4625}, {"field": "ipAddress", "op": "nin_setting", "value": "internal_ips"}]},
            3000,
            settings=s,
        ),
    )
    timed("text search 'psexesvc'", lambda: Q.count(st, "events", {"text": "psexesvc"}))
    timed("regex on raw '-enc'", lambda: Q.count(st, "events", {"regex": {"field": "*", "pattern": "-enc\\s+[A-Za-z0-9+/=]{6,}"}}))
    timed("outside business hours count", lambda: Q.count(st, "events", {"hourRange": {"from": 8, "to": 19, "outside": True, "tz": "Europe/Paris"}}, s))
    timed(
        "aggregate ipAddress top 25 (4625)",
        lambda: Q.aggregate(st, "events", {"conditions": [{"field": "eventId", "op": "eq", "value": 4625}]}, "ipAddress", 25, s),
    )
    timed("timeline per hour", lambda: Q.timeline(st, "events", {}, "hour"))
    timed("facets targetUser", lambda: Q.facets(st, "events", "targetUser", 50))
    timed("pivot 185.220.101.4", lambda: Q.pivot(st, "185.220.101.4"))
    timed("sql group by computer", lambda: Q.run_sql(st, "SELECT computer, count(*) c FROM events GROUP BY 1 ORDER BY c DESC", 10))

    import yaml

    rules = []
    for p in sorted(Path("rules/windows").glob("*.yaml")):
        rules += [d for d in yaml.safe_load_all(p.read_text(encoding="utf-8")) if isinstance(d, dict)]
    print(f"rules: {len(rules)} windows rules")
    t = time.time()
    res = R.run_rules(
        st,
        rules,
        s,
        progress=lambda p: print(f"  {p['ruleId']:<45s} {p['findings']:5d} findings {p['ms']:6d} ms", flush=True) if p["findings"] or p["ms"] > 500 else None,
    )
    print(f"rules total: {res['total']} findings in {time.time() - t:.1f}s, errors: {res['errors']}")
    bf = [f for f in res["findings"] if f["ruleId"] == "win-bruteforce-4625-by-ip"]
    print("brute-force findings:", [(f["entities"].get("ipAddress"), f["count"], f["severity"]) for f in bf[:5]])
    reg.close_all()
    shutil.rmtree(root, ignore_errors=True)


def run_mail(n: int) -> None:
    """Mail-side timing: generate with make_big, parse through the real
    pipeline, then time the mail queries and the mail rule catalogue."""
    import make_big

    from services.parsers.mail.common import ParseContext, parse_message_bytes
    from services.store.writers import MailWriter

    root = Path(tempfile.mkdtemp(prefix="remn-scale-mail-"))
    reg = StoreRegistry()
    reg.configure(root)
    st = reg.get(str(uuid.uuid4()))
    ctx = ParseContext(internal_domains=["interne.fr"], vip_names=["Marie Lefevre"], analyze_attachments=False)
    rng = random.Random(42)
    t0 = time.time()
    w = MailWriter(st, 1)
    for i in range(n):
        w.add(parse_message_bytes(make_big.gen_message(i, rng, 0.01), ctx))
        if i and i % 10_000 == 0:
            print(f"  {i:,} mails, {i / (time.time() - t0):,.0f} mails/s", flush=True)
    w.flush()
    dt = time.time() - t0
    print(f"parsed+wrote {n:,} mails in {dt:.1f}s ({n / dt:,.0f} mails/s), file {st.size_bytes() / 1e6:.1f} MB")
    s = {
        "internal_domains": ["interne.fr"],
        "vip_names": ["Marie Lefevre"],
        "trusted_senders": [],
        "businessHours": {"start": 8, "end": 19, "tz": "Europe/Paris"},
        "weekendDays": [0, 6],
    }

    def timed(label, fn):
        t = time.time()
        r = fn()
        print(f"  {label:<58s} {1000 * (time.time() - t):7.0f} ms", flush=True)
        return r

    print("queries:")
    timed("count all", lambda: Q.count(st, "mails", {}))
    timed("count risk >= 80", lambda: Q.count(st, "mails", {"conditions": [{"field": "risk", "op": "gte", "value": 80}]}))
    timed("text search 'virement'", lambda: Q.count(st, "mails", {"text": "virement"}))
    timed("aggregate fromRegistrable top 25", lambda: Q.aggregate(st, "mails", {}, "fromRegistrable", 25))
    timed("flags contains trusted_sender", lambda: Q.count(st, "mails", {"conditions": [{"field": "flags", "op": "contains", "value": "trusted_sender"}]}))
    timed("timeline per day", lambda: Q.timeline(st, "mails", {}, "day"))
    timed("facets fromDomain", lambda: Q.facets(st, "mails", "fromDomain", 50))
    timed("body regex 'gift ?cards?'", lambda: Q.count(st, "mails", {"regex": {"field": "bodyText", "pattern": "gift ?cards?"}}))

    import yaml

    rules = []
    for pth in sorted(Path("rules/mail").glob("*.yaml")):
        rules += [d for d in yaml.safe_load_all(pth.read_text(encoding="utf-8")) if isinstance(d, dict)]
    print(f"rules: {len(rules)} mail rules")
    t = time.time()
    res = R.run_rules(
        st,
        rules,
        s,
        progress=lambda p: print(f"  {p['ruleId']:<45s} {p['findings']:5d} findings {p['ms']:6d} ms", flush=True) if p["findings"] or p["ms"] > 500 else None,
    )
    print(f"rules total: {res['total']} findings in {time.time() - t:.1f}s, errors: {res['errors']}")
    reg.close_all()
    shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="REMN store scale test")
    ap.add_argument("n", nargs="?", type=int, default=200_000, help="number of synthetic events")
    ap.add_argument("--mail", type=int, metavar="M", help="run the MAIL scale test with M messages instead")
    args = ap.parse_args()
    if args.mail:
        run_mail(args.mail)
    else:
        main(args.n)
