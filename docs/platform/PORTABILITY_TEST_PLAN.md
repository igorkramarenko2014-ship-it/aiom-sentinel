# Portability Test Plan

implementation_authority: NONE
current_runtime_status: DESIGN_ONLY

Run format, clippy, test, build, evidence verifier, architecture verifier, and portability verifier on
Windows, Linux, and macOS. Record build, test, and runtime evidence separately. Exercise native path
encoding, partial identity, symlink handling, bounded malformed PE input, ELF and Mach-O probes, and
controlled unsupported results. CI configuration is not execution evidence.
