# Source Corpus Publication Decision

publication_status: LOCAL_RESTRICTED_NOT_FOR_PUBLIC_RELEASE
implementation_authority: NONE

## Decision

The verbatim research corpus is retained locally, identified by the SHA-256 in
`architecture-input/SOURCE_CORPUS_RECEIPT.json`, and excluded from the public release candidate.
It contains offensive-detail phrasing that is unnecessary for users or reviewers to validate the
implemented Phase 1 scanner.

## Public review material

The public candidate includes the receipt, the defensive `docs/research/KIMI_CLAIM_LEDGER.md`,
architecture contracts, and the verifier. When the raw corpus is absent, the verifier enters
`receipt-only` mode and requires the explicit publication decision in the receipt.

## Consequence

Receipt-only verification proves contract integrity and publication policy, not the contents of the
restricted corpus. A reviewer who needs verbatim-source validation requires authorized local access.
