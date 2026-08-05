# P0 Mutation Plan

Branch: `feat/sentinel-desktop-product`
Base HEAD: `58a978bde0fb24c9879fbd92bf04b7d9d569af73`
Base tree: `75bb14f396e316ce4ca047a5a9d5595f1c8df7f2`

## P0 create surface

- `docs/product/ADR-001-DESKTOP-SHELL.md`
- `docs/product/ADR-002-LOCAL-PERSISTENCE.md`
- `docs/product/DTO_CONTRACT_V1.md`
- `docs/product/UI_ROUTE_MAP.md`
- `docs/product/PRODUCT_RISK_REGISTER.md`
- `docs/product/P0_MUTATION_PLAN.md`

## Frozen surfaces

The legacy workspace, existing evidence schemas, existing verifiers, and current Rust scanner behavior are frozen. No file under the legacy root is in scope.

## P1 boundary

P1 may add a Rust application-service crate/module, DTO serialization tests, and the smallest Tauri project after toolchain availability is measured. It must prove one harmless-file scan and deterministic receipt export before broader UI scope.

## Rollback

Revert this branch's P0 commit or delete only the new productization files on this branch. The base branch and legacy workspace remain untouched.
