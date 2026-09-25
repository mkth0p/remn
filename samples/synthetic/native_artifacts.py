"""Small, invented binary fixtures. Contains no collected evidence."""

import struct

STAMP = 1788948000000


def prefetch_bytes():
    name = "POWERSHELL.EXE".encode("utf-16-le")
    referenced = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".encode("utf-16-le")
    header = struct.pack("<I4sII60sII", 30, b"SCCA", 0, 340 + len(referenced), name, 0, 0)
    info = bytearray(224)
    struct.pack_into("<II", info, 0, 308, 1)
    struct.pack_into("<II", info, 16, 340, len(referenced))
    struct.pack_into("<QQ", info, 44, (STAMP + 11644473600000) * 10000, (STAMP - 60000 + 11644473600000) * 10000)
    struct.pack_into("<I", info, 124, 3)
    metric = struct.pack("<IIIIIIQ", 0, 0, 0, 0, len(referenced) // 2, 0, 0)
    return header + info + metric + referenced


def registry_bytes():
    from dissect.regf.c_regf import KEY, c_regf
    from dissect.regf.regf import xor32_crc

    key = (
        c_regf._CM_KEY_NODE(
            Signature=b"nk",
            Flags=KEY.HIVE_ENTRY | KEY.COMP_NAME,
            LastWriteTime=(STAMP + 11644473600000) * 10000,
            Parent=0xFFFFFFFF,
            Class=0xFFFFFFFF,
            NameLength=4,
        ).dumps()
        + b"ROOT"
    )
    header = c_regf._HBASE_BLOCK(Signature=0x66676572, Sequence1=1, Sequence2=1, Major=1, Minor=5, RootCell=32, Length=4096, Cluster=1)
    header.CheckSum = xor32_crc(header.dumps()[:508])
    hbin = struct.pack("<IIIIQII", 0x6E696268, 0, 4096, 0, 0, 0, 0)
    return header.dumps() + (hbin + struct.pack("<i", -(len(key) + 4)) + key).ljust(4096, b"\0")
