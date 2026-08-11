# Security policy

AIOM Sentinel is a defensive prototype. Security reports should be submitted through GitHub Private
Vulnerability Reporting for this repository. Do not open a public issue for a suspected
vulnerability or attach live malware or unrelated user data. Use harmless reproduction material
when possible. Include the affected commit, expected impact, and whether the report contains
sensitive data.

Security fixes must preserve bounded resource use, explicit failure reporting, identity
revalidation, and the documented production-response boundary. The scanner performs defensive,
read-only analysis. The service-level portfolio pipeline can exercise transactional quarantine with
harmless fixtures and test-only key authority; production automatic remediation is disabled,
production key authority is not implemented, and Tauri is not wired to the transactional V2 response
path. Every Sentinel workspace crate forbids unsafe Rust, although dependencies may contain
internally reviewed `unsafe` code.
