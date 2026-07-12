# Architecture and Dependency Rules

The workspace encodes Linux-visible policy over explicit lower-layer
mechanisms. Dependency arrows must point from policy consumers toward small,
stable leaves; cyclic subsystem dependencies are rejected.

The initial graph is:

```text
thekernel-linux-signal -> thekernel-linux-usercopy
thekernel-linux-process   (independent)
thekernel-linux-usercopy  (independent)
```

Future credentials remain independent. VFS may depend on credentials and a
generic VFS contract; FD may depend on credentials, signals, and generic
readiness; MM may depend on credentials, usercopy, and generic mapping
mechanisms. VFS objects and file-backed MM are connected through explicit
adapter traits rather than dependency cycles.

No crate obtains the current task, address space, filesystem context, or FD
table implicitly. Operation context and immutable snapshots are passed by the
caller.
