"""Create a small, fully synthetic mixed investigation package for import and UI checks."""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
import zipfile
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path

from evtx_writer import EvtxWriter, event_node


def generate(target: Path) -> None:
    stamp = "2026-09-09T10:00:00Z"
    payload = b"REMN synthetic attachment, not executable."
    digest = hashlib.sha256(payload).hexdigest()
    mail = EmailMessage()
    mail["From"], mail["To"] = "sender@vendor.example", "alice@northstar.example"
    mail["Date"], mail["Subject"] = "Wed, 09 Sep 2026 09:00:00 +0000", "Synthetic package attachment"
    mail.set_content("Synthetic investigation sample. Visit https://collector.example/download")
    mail.add_attachment(payload, maintype="application", subtype="octet-stream", filename="agent.exe")
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        evtx = Path(tmp) / "Security.evtx"
        with EvtxWriter(evtx) as writer:
            writer.add(
                event_node(
                    1,
                    stamp,
                    "Microsoft-Windows-Security-Auditing",
                    "Security",
                    "WS01",
                    4688,
                    {"NewProcessName": r"C:\Tools\agent.exe", "NewProcessId": "0x7b", "SubjectUserName": "alice", "SubjectDomainName": "NORTHSTAR"},
                ),
                int(datetime.fromisoformat(stamp).timestamp() * 1000),
            )
        with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("collection-manifest.json", json.dumps({"host": "WS01", "collectedAt": stamp, "collector": "REMN synthetic sample"}))
            z.writestr(
                "Processes/processes.csv",
                f"Name,ExecutablePath,PID,CreationDate,SHA256,UserName\nagent.exe,C:\\Tools\\agent.exe,123,{stamp},{digest},alice@northstar.example\n",
            )
            z.writestr("Services/services.json", json.dumps([{"Name": "SyntheticAgent", "PathName": r"C:\Tools\agent.exe", "StartName": "NORTHSTAR\\alice"}]))
            z.writestr(
                "Network Connections/connections.csv",
                f"ExecutablePath,OwningProcess,CreationDate,RemoteAddress,RemotePort\nC:\\Tools\\agent.exe,123,{stamp},203.0.113.10,443\n",
            )
            z.writestr("Scheduled Tasks/tasks.json", json.dumps([{"TaskName": "SyntheticTask", "Execute": r"C:\Tools\agent.exe"}]))
            z.writestr("Autoruns/autoruns.csv", "Entry,ImagePath\nSyntheticRun,C:\\Tools\\agent.exe\n")
            z.writestr("Installed Programs/programs.csv", "Name,Publisher\nSynthetic Agent,Example Publisher\n")
            z.writestr("Users and Groups/users.csv", "UserName,GroupName,SID\nalice,Analysts,S-1-5-21-100-200-300-1001\n")
            z.writestr("Mail/sample.eml", mail.as_bytes())
            z.write(evtx, "Security Event Log/Security.evtx")
            from cabarchive import CabArchive, CabFile
            from native_artifacts import prefetch_bytes, registry_bytes

            z.writestr("Prefetch Files/POWERSHELL.pf", prefetch_bytes())
            z.writestr("Registry/synthetic.hiv", registry_bytes())
            cab = CabArchive()
            cab["MPLog.txt"] = CabFile(b"Synthetic diagnostic line: threat detected\n")
            z.writestr("WdSupportLogs/diagnostics.cab", cab.save())
            z.writestr("Prefetch Files/unknown.bin", b"unsupported synthetic binary placeholder")
            z.writestr("WdSupportLogs/support.cab", b"unsupported synthetic support placeholder")
            z.writestr("Forensics Collection Summary.csv", "Artifact,Count\nProcesses,1\nServices,1\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("samples/generated/investigation-package.zip"))
    args = parser.parse_args()
    generate(args.out)
    print(args.out)
