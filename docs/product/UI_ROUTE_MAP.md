# UI Route Map — MVP

```text
/                 Home
/scan/new         New Scan
/scan/:id         Scan Progress or Results
/history          Local History
/settings         Settings / About / Diagnostics
```

## Route obligations

- Home shows scanner/core/rule-pack status and the last summary.
- New Scan accepts file/folder picker output only; it discloses read-only behavior.
- Progress renders bounded updates and exposes cancellation.
- Results renders normalized findings, evidence, errors, and receipt export.
- History reopens local receipts and requires confirmation before deleting history metadata.
- Settings exposes versions, data location, privacy statement, and diagnostics export.

No route implies protection, remediation, quarantine, cloud sync, telemetry, or antivirus status.
