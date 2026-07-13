# Architecture and Dependency Rules

The workspace encodes Linux-visible policy over explicit lower-layer
mechanisms. Dependency arrows must point from policy consumers toward small,
stable leaves; cyclic subsystem dependencies are rejected.

The initial graph is:

```text
thekernel-linux-signal -> thekernel-linux-usercopy
thekernel-linux-cred      (independent credential policy leaf)
thekernel-linux-vfs       (independent policy core)
thekernel-linux-fd        (independent policy core)
thekernel-linux-process   (independent)
thekernel-linux-usercopy  (independent)
```

Credentials are an independent leaf. The extraction owns typed kernel/user
IDs, immutable bidirectional ID maps, immutable credential values,
capability-set invariants, namespace-capability topology policy, and a
lock-neutral namespace core for hierarchy, owner, map, and setgroups state. It
does not own the embedding namespace allocation/lock/lifetime extension,
credential publication slot, process, VFS, signal, MM, security-hook registry,
exec transaction, syscall, or errno type. Its nightly `allocator_api`
requirement is a fallible-allocation toolchain constraint, not a dependency on
`kspin` or any kernel synchronization crate.

VFS and FD accept typed caller snapshots rather than depending on a
credential, signal, or generic mechanism package. MM may depend on credentials,
usercopy, and generic mapping mechanisms. VFS objects and file-backed MM are
connected through explicit adapter traits rather than dependency cycles.

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

Queue accounts and each process-local endpoint registry have immutable finite
limits; `usize::MAX` is never a policy value. Bare-metal signal consumers use a
sleepable lifecycle mutex, and unsupported no-`multitask` builds fail at
compile time rather than taking an IRQ-off lock across usercopy or allocation.
The immutable registry owner is acquired under that sleepable mutex as well;
registration rollback moves strong ownership out of IRQ-safe slots before
destruction. Process registry charges use checked admission and non-wrapping
release, so duplicate cleanup cannot manufacture effective infinity.

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

Epoll delivery selects a generation-tagged candidate while the core lock is
held, prepares owned or fallible output after releasing that lock, and commits
only after revalidation. The core does not call arbitrary `Clone`, allocation,
callback, or destruction code. Defensive ready recovery is likewise explicit:
generation-tagged rescan tokens carry persistent bounded progress, a full
queue leaves the current slot retryable, and a newer overflow invalidates an
older recovery worker.

The release boundary is the Cargo-normalized archive, not the workspace source
tree. CI rejects dependency path/git/workspace leakage while allowing Cargo's
package-local lib/test target paths, tests every unpacked archive, and runs
registry-only publication dry-runs. Signal's first release remains a deliberate
two-step gate: package-workspace testing against the packaged usercopy source,
then a true registry-only dry-run after usercopy is visible.
