# Rule Compiler Autoloader Boundary
implementation_authority: PASS_F_FOUNDATION_ONLY
current_runtime_status: FOUNDATION_IMPLEMENTED_TESTED_LOCAL

Future pipeline: discovery → verification → durable LKG selection → advisory
evidence.

Pass F implements only two real foundations:

- strict Ed25519 verification against a repository-pinned public-key registry;
- a scanner-owned `ActiveRuleSet` using `ArcSwap<RuleSetSnapshot>`, serialized
  writers, immutable reader snapshots, idempotent content identity, and a
  test-only failure injection boundary.

The original `scan(request, rules)` API remains available. The additional
`scan_with_active` path captures one immutable snapshot per scan. There is no
global mutable singleton and no parallel test scanner.

The compiler, bundle discovery, approval gate, durable LKG, rollback/recovery,
receipt persistence, and complete Autoloader state machine remain
`NOT_IMPLEMENTED` until Pass A.
