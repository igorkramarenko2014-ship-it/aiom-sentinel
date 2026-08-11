# Security policy

AIOM Sentinel is a defensive prototype. Please report vulnerabilities privately through the
repository host's private reporting mechanism or the maintainers' private channel; do not open a
public issue for a suspected vulnerability or attach malware samples. Include the affected commit,
a harmless reproduction, expected impact, and whether the report contains sensitive data.

Security fixes must preserve bounded resource use, explicit failure reporting, identity
revalidation, and the documented production-response boundary. The local transactional demo uses a
test-only key and is not production remediation authority. Every Sentinel workspace crate forbids
unsafe Rust, although dependencies may contain internally reviewed `unsafe` code.
