# PE Parser Contract

implementation_authority: NONE for expansion
current_runtime_status: Phase 1 bounded metadata subset IMPLEMENTED

Phase 1 validates DOS/PE signatures, bounded COFF/optional headers, at most 96 section headers,
section offsets/sizes, section entropy, and certificate-table presence. Every offset and length is
checked with overflow-safe arithmetic; malformed data returns controlled errors and never executes,
maps, emulates, unpacks, or repairs a binary.

Future import/export/resource/TLS/load-config parsing is design-only and requires explicit count,
recursion, allocation, string, and total-work limits. Signature presence is not trust. Entropy is one
feature only and never a malware verdict. Fuzz targets use malformed/synthetic corpora without malware.
