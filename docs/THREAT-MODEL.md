# Threat model

Untrusted inputs include filesystem metadata, file bytes, malformed PE structures, local rule files,
non-UTF-8 paths, sparse files, and inaccessible directories. Controls include bounded depth/count/
size, no symlink following, streaming hashes, parser bounds, explicit partial errors, and no target
mutation.

Availability remains operator-controlled: scan errors generate evidence and exit code `2`; Sentinel
does not block file access or execution. There is no network path. Rule files are local configuration,
not a trust feed. The scanner is not a malware sandbox and does not execute or unpack content.

Dependency code may use unsafe internally; the workspace's `forbid(unsafe_code)` guarantee applies
to Sentinel-owned crates, not transitive dependencies.
