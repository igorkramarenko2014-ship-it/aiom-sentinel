# Mach-O Parser Contract

implementation_authority: NONE
current_runtime_status: DESIGN_ONLY

The future parser may expose thin/fat magic, CPU/file type, bounded load commands, segments/sections,
dylib references, symbol metadata, entry command, and code-signature blob location. Every universal
slice, command count/size, file range, string, symbol count, and nested offset is bounded and validated.

Malformed input produces controlled errors; overlapping or inconsistent ranges produce warnings and
no unchecked reads. Code-signature presence is not a benign verdict. Dyld-cache/runtime-hook claims are
outside static parsing. No mapping, loading, execution, emulation, injection guidance, or signature
bypass behavior is implemented. Fuzzing uses synthetic multi-slice and malformed corpora.
