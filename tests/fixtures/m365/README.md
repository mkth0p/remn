# Microsoft 365 and Entra export fixtures

Every record in these files is invented for the tests: the tenant (contoso.com), the people,
the applications, the devices and the addresses (documentation ranges 192.0.2.0/24,
198.51.100.0/24 and 203.0.113.0/24, and attacker.example) are not real. The field and column
names follow the Microsoft documentation named for each file, exactly; where a value's form is
not documented, it is invented and said so below.

| File | Follows |
| --- | --- |
| `entra-directory-audits.graph.json` | A page of `GET /auditLogs/directoryAudits`, as the example response of [List directoryAudits](https://learn.microsoft.com/graph/api/directoryaudit-list) shows it, with the properties of [directoryAudit](https://learn.microsoft.com/graph/api/resources/directoryaudit), [targetResource](https://learn.microsoft.com/graph/api/resources/targetresource) and modifiedProperty. The activity names are those of [Microsoft Entra audit log activities](https://learn.microsoft.com/entra/identity/monitoring-health/reference-audit-activities); the modified property names (`ConsentAction.Permissions`, `Role.DisplayName`) are those the Unified Audit Log gives the same activities. |
| `entra-directory-audits.portal.json` | The Entra admin centre's audit log download as JSON ([How to download logs](https://learn.microsoft.com/entra/identity/monitoring-health/howto-download-logs)): an array of the same directoryAudit objects. |
| `entra-directory-audits.portal.csv` | The Entra admin centre's audit log download as CSV. Microsoft does not document its columns; the 83 column names are those of a download from a portal shown in Japanese, as a public write-up reproduces the header (tech-lab.sios.jp, "Azure ADの監査ログを取得 ～ポータルダウンロード編～"). The first and the third to sixth columns are translated into the language of the portal; the others are written in English whatever the language. The values of `ActorType` are invented. |
| `entra-risk-detections.graph.json` | A page of `GET /identityProtection/riskDetections`, with the properties of [riskDetection](https://learn.microsoft.com/graph/api/resources/riskdetection) and the `additionalInfo` keys that page lists. |
| `entra-risk-detections.extractor.csv` | Microsoft-Extractor-Suite's `Get-RiskyDetections` (Scripts/Get-RiskyEvents.ps1): the columns of the object it builds from each riskDetection, in its order, written by `Export-Csv -NoTypeInformation -Encoding UTF8` in Windows PowerShell (UTF-8 with a byte order mark). The times are as a session in a day-first culture (en-GB) writes a DateTime. |
| `entra-risky-users.graph.json` | A page of `GET /identityProtection/riskyUsers`, with the properties of [riskyUser](https://learn.microsoft.com/graph/api/resources/riskyuser). |
| `entra-risky-users.extractor.csv` | Microsoft-Extractor-Suite's `Get-RiskyUsers` (Scripts/Get-RiskyEvents.ps1): its columns, in its order, written with `-Encoding Unicode` (UTF-16, little-endian, with a byte order mark). The times are as an en-US session writes a DateTime. |
