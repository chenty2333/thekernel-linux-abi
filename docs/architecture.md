# Architecture and Dependency Rules

The workspace encodes Linux-visible policy over explicit lower-layer
mechanisms. Dependency arrows must point from policy consumers toward small,
stable leaves; cyclic subsystem dependencies are rejected.

The initial graph is:

```text
thekernel-linux-signal -> thekernel-linux-usercopy
thekernel-linux-vfs       (independent policy core)
thekernel-linux-fd        (independent policy core)
thekernel-linux-process   (independent)
thekernel-linux-usercopy  (independent)
```

Future credentials remain independent. VFS and FD currently accept typed
caller snapshots rather than depending on a credential, signal, or generic
mechanism package. MM may depend on credentials, usercopy, and generic mapping
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

The VFS crate owns Linux path scope, traversal budgets, DAC/create decisions,
and mutation rollback over a generic walker supplied by the consumer. The FD
crate owns descriptor/OFD identity and Linux readiness/epoll state over
retained generic source registrations. Neither crate fixes a concrete lock,
map, RCU scheme, filesystem object, waker, task, errno, or syscall record.

The FD adapter must publish `EpollGraph` and `EpollCore` changes as one
transaction, retain every source token until cancellation, and run
check-arm-check around source installation. Timeout, signal interruption,
close, `DEL`, `MOD`, copyout failure, and partial arm failure all terminate in
an explicit cancel, replay, or rollback path; no periodic scan or hidden
busy-poll fallback is part of the contract.
