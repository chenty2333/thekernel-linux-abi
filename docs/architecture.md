# Architecture and Dependency Rules

The workspace encodes Linux-visible policy over explicit lower-layer
mechanisms. Dependency arrows must point from policy consumers toward small,
stable leaves; cyclic subsystem dependencies are rejected.

The initial graph is:

```text
thekernel-linux-signal -> thekernel-linux-usercopy
thekernel-linux-cred      (independent credential policy leaf)
thekernel-linux-mm        (independent MM policy/lifecycle core)
thekernel-linux-vfs       (independent policy core)
thekernel-linux-fd        (independent policy core)
thekernel-linux-process   (independent)
thekernel-linux-usercopy  (independent)
```

Credentials are an independent leaf. The extraction owns typed kernel/user
IDs, immutable bidirectional ID maps, immutable credential values,
capability-set invariants, namespace-capability topology policy, and a
lock-neutral namespace core for hierarchy, owner, map, and setgroups state. It
also owns normalized parsing of Linux executable file-capability records, but
not xattr storage or executable lookup. Ordinary transitions and pure exec
policy produce exact-old-bound immutable credential proposals plus typed
effects. Proposal accessors borrow old/proposed values, and only an exact old
Linux credential `Arc` releases the proposed owner. A consumer wrapping the
same core in distinct composite credentials additionally binds its exact outer
identity locally. The crate does not own the embedding namespace
allocation/lock/lifetime extension, credential publication slot, process, VFS,
signal, MM, security-hook registry/dispatch, executable lease, exec publication
transaction, syscall, or errno type. Ptrace, traceme, and scheduler commoncap
policy consumes typed immutable contexts whose kernel object payload is an
opaque caller-owned generic; it introduces no process/MM trait or orphan-rule
edge. Capable policy similarly consumes a validated number and normalized
ordinary/no-audit/set-ID operation over an explicit actor/target namespace;
only commoncap success creates the context which stacked modules may further
deny. Fork and user-namespace lifecycle notifications use an infallible
successful-publication context over exact source/published credentials and an
opaque consumer target, while visibility ordering and callback dispatch remain
consumer-owned. Inode-permission and file-open policy contexts follow the same leaf
boundary: they bind the exact actor, independently selected DAC snapshot,
target-owner namespace, and opaque caller-owned object to normalized access or
open facts. File-open normalization distinguishes ordinary data access and
reserved access mode 3 descriptions with no persistent read/write data
access. Mode 3 retains its earlier `MAY_READ | MAY_WRITE` admission fact
indirectly: it can carry a successful created-and-unnamed `O_TMPFILE` result
despite exposing no persistent write access. `O_PATH` is not a file-open policy
event: the pinned Linux topology completes `FMODE_PATH` setup and returns before
`security_file_open`, so the VFS/FD consumer owns path-only semantics and skips
this context and hook dispatch. The contexts do not own VFS identity, lookup,
security registry/dispatch, or the open transaction. The nightly
`allocator_api` requirement is a fallible-allocation toolchain constraint, not
a dependency on `kspin` or kernel synchronization.

Credential 0.1 freezes one canonical namespace-entry constructor and one
canonical filesystem-snapshot accessor. Pre-release compatibility spellings
are deliberately absent so kernel adapters converge on the same public
contract before package publication.

VFS, FD, and MM accept typed caller snapshots rather than depending on a
credential, signal, or generic mechanism package. The initial MM crate is an
independent leaf: credential, VFS, usercopy, and generic mapping mechanisms are
connected by the embedding kernel rather than dependency cycles.

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

The MM crate owns checked Linux-visible ranges, mapping-generation contracts,
pin admission/accounting, invalidation values, stale fault-completion policy,
pure remap/memlock arithmetic, and a bounded Linux v6.12 userfaultfd policy
profile. That profile owns transactional API negotiation, anonymous-private
MISSING registration, canonical same-handler interval-delta and mapping-refresh
plans, and COPY/ZEROPAGE mode/progress rules. The adapter supplies ordered VMA
snapshots and bounded output storage, while interval subset/extension/bridge
policy stays in the MM crate. Mapping-ID storage, VMA indexing, frames, page
tables, TLBs, file/page-cache mechanisms, and the concrete bounded fault broker
remain below it. Its `FaultPort` trait and stateless `UffdFaultPolicy` produce
typed permits; they do not duplicate the lower broker's queue, claim, waiter,
readiness, credit, cancellation, terminal, or close state.

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
