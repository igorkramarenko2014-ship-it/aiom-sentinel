# Product DTO Contract v1

The UI communicates with the Rust application service only through these versioned DTOs. Internal crate structs are not UI API.

```text
ScanRequestV1 {
  request_id: string,
  targets: [TargetV1],
  recursive: boolean,
  skip_symlinks: boolean,
  rules: RuleSelectionV1
}

ScanProgressV1 {
  request_id: string,
  current_path: string|null,
  processed_count: integer,
  finding_count: integer,
  elapsed_ms: integer,
  state: "queued"|"running"|"cancelling"|"completed"|"cancelled"|"failed"
}

ScanFindingV1 {
  path: string,
  identity: object,
  rule_id: string|null,
  matched_evidence: object|null,
  confidence: string|null,
  severity: string|null
}

ScanSummaryV1 {
  request_id: string,
  state: string,
  processed_count: integer,
  finding_count: integer,
  errors: [ApplicationErrorV1]
}

RulePackStatusV1 { identity: string, verification_state: string, schema_version: string }
ExportReceiptV1 { receipt_id: string, schema_version: string, bytes: string, destination: string }
ApplicationErrorV1 { code: string, message: string, path: string|null, retryable: boolean }
```

The first implementation must preserve nullable fields where the current core does not supply severity or confidence. The UI must not invent values.
