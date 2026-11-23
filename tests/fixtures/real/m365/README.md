# Microsoft 365 records written by the service

`microsoft_audit_log.jsonl` holds three Unified Audit Log records as Microsoft 365 wrote them for
a test tenant (`sst5f.onmicrosoft.com`), one JSON object a line. They are taken from the plaso
project's test data,
https://github.com/log2timeline/plaso/blob/6340a71a536d9df5724ca70b75e259cb439798b3/test_data/jsonl/microsoft_audit_log.jsonl
(SHA-256 `d9b3f230989b63055441e46b48d8aedbae377305448a8d4189e83eb84b1bd890`), distributed under
plaso's licence, the Apache License 2.0.

Trimmed: the source's fourth and last record, a sign-in by a named account of the tenant, is
left out, so this file is its first three lines unchanged, each ending in a line feed. The three
are operations the service ran itself (`NT AUTHORITY\SYSTEM (Microsoft.Exchange.Servicehost)`)
and name no person. SHA-256 of the file as committed:
`9f50e47341af6d486ce61cc77342b3632a203e1c1819ef5cd76f55382211b406`.

The expected values in `tests/backend/test_real_m365.py` come from plaso's own test of the file
(`tests/parsers/jsonl_plugins/microsoft365_audit_log.py` at the same commit), which reads
`CreationTime` as UTC, and from the records themselves.

The larger public samples, Splunk's attack_data recordings of Microsoft 365 and Entra ID, name
accounts of their research tenants, so they are not committed: the tests marked heavy download
them by URL and SHA-256 (`tests/backend/real_samples.py`). No public sample made by the service
was found for the Graph directory audits, risk detections and risky users exports, the Entra
portal downloads, or the message trace exports; those are covered by the invented files in
`tests/fixtures/m365/`.
