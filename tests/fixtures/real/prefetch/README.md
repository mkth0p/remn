# Prefetch files written by Windows

These files were written by Windows itself, not made for REMN. They are the test data of the
plaso project, taken unchanged from
https://github.com/log2timeline/plaso/tree/6340a71a536d9df5724ca70b75e259cb439798b3/test_data/winprefetch
and distributed under plaso's licence, the Apache License 2.0
(https://github.com/log2timeline/plaso/blob/6340a71a536d9df5724ca70b75e259cb439798b3/LICENSE).
Nothing was trimmed. They hold no personal data: the paths they reference name system
directories, and one user directory, `\USERS\TEST\`. Plaso's `WUAUCLT.EXE-830BCC14.pf` is left
out, because it repeats the version 23 case and its paths name a user directory.

The expected values in `tests/backend/test_real_prefetch.py` come from plaso's own test of the
same files (`tests/parsers/winprefetch.py` at the same commit), and where that test does not give
a value, from the bytes read by hand at the offsets the libscca format description documents
(https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20(PF)%20format.asciidoc).

| File | Format version | Windows | SHA-256 |
| --- | --- | --- | --- |
| `CMD.EXE-087B4001.pf` | 17 | XP | `93ec53e941b285d1d2a11e1224ab2d5c7a1b8ac493ab8dec407f518c5655ae75` |
| `PING.EXE-B29F6629.pf` | 23 | 7 | `cdb6e2de2b02808755aa2591708ebe155ee3483947e230f5fdd6870390fafd26` |
| `TASKHOST.EXE-3AE259FC.pf` | 26 | 8.1 | `00178686d5e755e596ee164e78473eab3aba382541d0f67f93654ef84d4ed36b` |
| `BYTECODEGENERATOR.EXE-C1E9BCE6.pf` | 30, compressed | 10 | `7b5855fbb17fabfeba6b3b5d90c8ef23b548106edf7e24b3d67fd826a1d6d537` |
| `ONEDRIVE.EXE-7E152375.pf` | 30 variant 1, compressed | 10 | `e9a5db11b673ba592a794a2bfeaa2aba95814d3004c32a76e4dc668789fa2424` |
| `NOTEPAD.EXE-D8414F97.pf` | 30 variant 2, compressed | 10, 1903 or later | `2eb257a375eda819c65e6b4e60dfb7b9c6691280e8cb40cec30d3e46ac96a50f` |
| `AM_DELTA_PATCH_1.443.990.0.EX-7037CF86.pf` | 31, compressed, executable name cut to 29 characters | 11 | `9a5ad5a3c56ec67fb2f785e1f75366a642a2ea552694f5016cc8191cf3f49861` |
