# Mail written by real mail clients

These files were written by the mail clients they name, not made for REMN. They are the test
data of Apache Tika, taken unchanged from
https://github.com/apache/tika/tree/8cbd68506d8827e9fd5ae958f4608f81dcc10c75/tika-parsers/tika-parsers-standard
and distributed under Tika's licence, the Apache License 2.0
(https://github.com/apache/tika/blob/8cbd68506d8827e9fd5ae958f4608f81dcc10c75/LICENSE.txt).
Nothing was trimmed. They name no person: the Outlook message is Microsoft's own welcome
message, and in the others the senders and recipients were masked by Tika's contributors
(`XXX.XXX@XXXX.de`, `$$$.$$$.$$$`, `hey@example.com`).

Tika's other mail samples, which name real people, are not committed. The tests marked heavy
download them by URL and SHA-256 (`tests/backend/real_samples.py`): `testMSG.msg`,
`testMSG_chinese.msg`, `testThunderbirdEml.eml`, `complex.mbox` and `testPST.pst`.

The expected values in `tests/backend/test_real_mail.py` come from Tika's own tests of the same
files (`OutlookParserTest.java`, `RFC822ParserTest.java` and `MboxParserTest.java` at the same
commit), and where those do not give a value, from the file's own headers.

| File | Written by | Path under the folder above | SHA-256 |
| --- | --- | --- | --- |
| `test-outlook.msg` | Outlook, a message in 8-bit strings with no message code page | `tika-parsers-standard-modules/tika-parser-microsoft-module/src/test/resources/test-documents/` | `ba546a434638c46fc6f1edd802c9084b95752afef2fa0aee8301388ab1f8131e` |
| `testLotusEml.eml` | Lotus Notes 8.5.3 | `tika-parsers-standard-integration-tests/src/test/resources/test-documents/` | `5190e77d06567279dc2427c001974ae642e12be700b30961f2da330cbbef0884` |
| `testGroupWiseEml.eml` | GroupWise 2012, with an attached message encoded in base64 | `tika-parsers-standard-modules/tika-parser-mail-module/src/test/resources/test-documents/` | `9e313395e35efe1e0d0eab9410b2820bbc354965144d017c42e91740815f2233` |
| `testMBOX_complex.mbox` | an mbox of one message written by Outlook 14 | `tika-parsers-standard-modules/tika-parser-mail-module/src/test/resources/test-documents/` | `e5e46325c81c074b70338f217e8ce4e8ecb20c5a75a26d0069374b211ec85b7e` |
| `simple.mbox` | an mbox of two messages with no headers but the separator line | `tika-parsers-standard-modules/tika-parser-mail-module/src/test/resources/test-documents/` | `0519c18318bab368368d09c433052efea476af9bf2f704ba199843a68220aa56` |
