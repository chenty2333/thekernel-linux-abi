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

Signal frame and action access therefore crosses into userspace only through a
caller-provided `UserMemoryContext`. The signal crate does not recover an
address space from a current-task singleton, and it does not depend on the
process crate; the embedding kernel supplies those integration decisions.

Pending-signal capacity and shared-account refunds are Linux-visible resource
policy, so they live in the signal ABI crate. Scheduler wake mechanics remain
below this workspace. Standard-signal slots and intrusive real-time queues are
bounded, including under concurrent enqueue, disposition changes, endpoint
registration, and teardown. Endpoint cancellation quiesces a complete delivery
before returning; no usercopy or handler-state publication may outlive the
thread endpoint.

One-shot dispositions and signal return are transactions rather than syscall
side effects. `SA_RESETHAND` claims are generation checked, and `uc_stack`
restore separates crate-owned structural validation from caller-owned address,
minimum-size, and active-stack policy. The syscall adapter may select policy,
but it must not reconstruct frame, reset, or rollback semantics.
