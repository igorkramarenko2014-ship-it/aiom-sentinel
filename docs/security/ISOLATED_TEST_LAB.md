# Isolated Test Lab
implementation_authority: NONE
current_runtime_status: DESIGN_ONLY
HOST_DEVELOPMENT and EPHEMERAL_CI use harmless fixtures. Untrusted samples require disposable isolated VMs; privileged work requires disposable privileged labs. No credentials, mounts, clipboard, drag-and-drop, shared folders, or default network; revert after sessions. VM isolation is not absolute.
