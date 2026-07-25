# Rule Bundle Portable Path Contract
implementation_authority: NONE
current_runtime_status: DESIGN_ONLY
Relative UTF-8 NFC `/` paths only. Reject traversal, absolute, drive, UNC, NUL, reserved names, trailing dots/spaces, symlinks, and NFC-plus-casefold collisions.
