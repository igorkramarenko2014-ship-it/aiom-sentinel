# Linux Collector Contract

implementation_authority: NONE
current_runtime_status: DESIGN_ONLY

Supported distributions, kernels, and container runtimes are unresolved pending an explicit matrix.
Audit, fanotify/inotify, tracepoints, eBPF, LSM, namespaces, cgroups, and container metadata are
separate candidate sources with different privilege, loss, and stability contracts. No source is
assumed universally available or zero-overhead.

Collectors require explicit capabilities, verifier/attach validation where relevant, bounded maps and
queues, event-loss counters, backpressure, namespace-aware process identity, container/host scope,
privacy classification, and health evidence. Kernel structures, raw filesystem parsing, kprobes, and
unstable symbols require primary-source and version-specific review before implementation.

Validation covers supported kernels, privilege minimization, container namespace identity, event loss,
resource limits, collector unload/recovery, malformed events, and degraded telemetry. Configuration
monitoring maps native files/systemd/D-Bus/XDG surfaces; it is not called registry monitoring.
