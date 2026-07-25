# Dependency Review

review_scope: direct workspace dependencies resolved from Cargo.lock
review_state: LOCAL_STATIC_REVIEW

## Direct dependencies

| Crate | Resolved version | License |
| --- | --- | --- |
| base64 | 0.22.1 | MIT OR Apache-2.0 |
| clap | 4.6.3 | MIT OR Apache-2.0 |
| criterion | 0.5.1 | Apache-2.0 OR MIT |
| digest | 0.10.7 | MIT OR Apache-2.0 |
| hex | 0.4.3 | MIT OR Apache-2.0 |
| md-5 | 0.10.6 | MIT OR Apache-2.0 |
| serde | 1.0.229 | MIT OR Apache-2.0 |
| serde_json | 1.0.151 | MIT OR Apache-2.0 |
| sha1 | 0.10.7 | MIT OR Apache-2.0 |
| sha2 | 0.10.9 | MIT OR Apache-2.0 |
| tempfile | 3.27.0 | MIT OR Apache-2.0 |
| thiserror | 2.0.19 | MIT OR Apache-2.0 |
| time | 0.3.54 | MIT OR Apache-2.0 |
| tokio | 1.53.1 | MIT |
| uuid | 1.24.0 | Apache-2.0 OR MIT |

`criterion` and `tempfile` are development-only. The remaining direct dependencies support CLI
parsing, hashing, serialization, errors, timestamps, asynchronous file I/O, and identifiers. This
review found no unnecessary direct dependency.

## Source and safety review

- `Cargo.lock` is present. It must be included in the first authorized commit.
- No Git dependency was declared. `path` dependencies are internal workspace crates only.
- No external path dependency was declared.
- No owned `unsafe {` block was found in `crates/` or `tests/`; workspace lints forbid unsafe code.
- Direct dependency source trees do contain `unsafe` tokens, notably `tokio`, `time`, `sha2`,
  `criterion`, `base64`, and other low-level or portability implementations. This is an observed
  dependency fact, not an approval of their internals.

## Unverified items

No vulnerability database or license-policy tool ran because `cargo-audit` and `cargo-deny` were
unavailable. Before public publication, run them against the locked dependency graph and resolve
any findings under the project security policy.
