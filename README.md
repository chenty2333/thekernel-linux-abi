# TheKernel Linux ABI

`thekernel-linux-abi` is the monorepo for reusable, `no_std` Linux ABI support
owned by TheKernel. It is deliberately separate from generic ArceOS
mechanisms and from TheKernel's syscall and evaluator layers.

The 0.1.0 line contains ten packages:

- `thekernel-linux-usercopy` 0.1.0: explicit-context, bounded, fallible access
  to a caller-provided userspace memory implementation.
- `thekernel-linux-process` 0.1.0: explicit-domain, bounded process lifecycle
  state with a caller-defined, reference-owned immutable zombie payload.
- `thekernel-linux-signal` 0.1.0: bounded process/thread pending queues,
  architecture signal frames, generation-safe one-shot actions, quiescent
  teardown, and transactional context/mask/alternate-stack restore. Every
  userspace action/frame copy receives an explicit usercopy context.
- `thekernel-linux-vfs` 0.1.0: immutable path contexts, strict `openat2`
  scoping, bounded pathwalk policy, Linux DAC/create rules, and
  generation-revalidated mutation transactions.
- `thekernel-linux-fd` 0.1.0: bounded FD/OFD state, reservation and close
  transactions, retained readiness registration, epoll delivery, and finite
  epoll-graph validation.
- `thekernel-linux-cred` 0.1.0: typed kernel/user IDs, immutable credentials
  and namespace maps, exact-old-bound ordinary and exec transitions, strict
  Linux file-capability parsing, and typed commoncap policy contexts.
- `thekernel-linux-mm` 0.1.0: checked ranges and mapping generations, bounded
  owner/global pin accounting, cross-VMA revalidation, typed invalidation and
  fault seams, Linux v6.12 MISSING-only userfaultfd policy with canonical
  partial-registration planning, and arithmetic-only remap/memlock planners.
- `thekernel-linux-io-uring` 0.1.0: checked shared-ring geometry and
  SQE/registration decoding, bounded generation-safe
  request/completion/cancellation state, and registered-file leases with
  explicit close and drain transitions.
- `thekernel-linux-packet` 0.1.0: normalized AF_PACKET protocol/address values,
  stale-safe bind publication, RAW/DGRAM ordinary receive decisions,
  exact Linux outgoing policy, mapping of endpoint-owned destructive aggregate
  statistics, and strict unsupported-option reporting without packet-buffer
  or device ownership.
- `thekernel-linux-seccomp` 0.1.0: a Linux v6.12 classic-BPF profile over the
  generic `thekernel-axcbpf` mechanism, immutable bounded filter ancestry,
  aggregate live-program accounting, action precedence, and prepared
  task-state transitions.

Signal depends on usercopy. Seccomp depends on the separately packaged
`thekernel-axcbpf` 0.1.0 mechanism package. Process remains independent; task
ownership and process-to-signal or process-to-seccomp integration stay with
the caller rather than becoming hidden workspace-global state.

The workspace name is not a facade package. The MM package exposes policy and
lifecycle contracts, including reusable userfaultfd negotiation/registration
rules; it is not a page-table, fault-broker, FD/readiness implementation, or a
claim that a consumer already exposes the complete syscall. Real-consumer and
dual-architecture gates remain required before a release tag.

## Development

The repository pins the same nightly used by its initial TheKernel consumer.
The usercopy, VFS, FD, MM, io_uring, and packet crates are additionally checked
against stable Rust 1.85 or newer. The process, signal, credential, and seccomp
crates are explicitly nightly-only because preserving fallible standard `Arc`
allocation currently requires `allocator_api`; none inherits or claims a
stable `rust-version`. The policy-neutral `thekernel-axcbpf` dependency itself
supports Rust 1.85.

Before the first registry release, the workspace resolves `thekernel-axcbpf`
from a sibling `../thekernel-ax` checkout. CI pins that checkout to the
package/release commit recorded in `crates/seccomp/VENDOR.md`;
`scripts/test-package.sh` also proves its crate tree is identical to the
reviewed implementation commit, rejects source drift, and packages the
dependency from its real Git worktree. The path is development wiring only and
must not survive in a normalized seccomp archive.

```bash
cargo test --workspace --all-features
cargo check -p thekernel-linux-usercopy --no-default-features --locked
cargo check -p thekernel-linux-signal --no-default-features --locked
cargo check -p thekernel-linux-vfs --no-default-features --locked
cargo check -p thekernel-linux-fd --no-default-features --locked
cargo check -p thekernel-linux-cred --no-default-features --locked
cargo check -p thekernel-linux-mm --no-default-features --locked
cargo check -p thekernel-linux-io-uring --no-default-features --locked
cargo check -p thekernel-linux-packet --no-default-features --locked
cargo check -p thekernel-linux-seccomp --no-default-features --locked
CARGO_TOOLCHAIN=nightly-2025-05-20 ./scripts/ci.sh
PACKAGE_ALLOW_DIRTY=1 CARGO_TOOLCHAIN=nightly-2025-05-20 \
  ./scripts/test-package.sh
```

## Boundaries

- Generic scheduling, filesystem, network, page-table, and driver mechanisms
  stay in their `ax-*` or other upstream/fork lines.
- Linux ABI crates do not read an implicit current task, global FD table, or
  global filesystem context.
- Signal usercopy is always caller-supplied. Standard and real-time pending
  queues are bounded and their shared accounting is refunded on every terminal
  path; the crate does not turn delivery pressure into an unbounded queue.
  One-shot actions cannot wrap into ABA reuse, and endpoint cancellation waits
  for an already-started delivery before returning. Bare-metal registry
  snapshots and destruction use an explicit sleepable lifecycle boundary.
- VFS and FD policy consume caller-supplied stable handles and snapshots. They
  do not choose generic filesystem walkers, source-waker storage, locks, task
  globals, or concrete RCU/indexing algorithms.
- Credential policy is an independent leaf. It owns immutable Linux identity,
  namespace-map, transition, and commoncap values, but not credential slots,
  security-hook dispatch, process/VFS/MM objects, locks, syscalls, or errno
  mapping.
- MM policy consumes caller-owned address-space/mapping identities and
  immutable mapping snapshots. It owns bounded pin admission/accounting and
  generation validation plus Linux userfaultfd policy, but not VMA storage,
  frames, page tables, TLBs, concrete fault queues, readiness, tasks, VFS
  objects, locks, raw pointers, or usercopy.
- io_uring policy owns checked setup/enter/SQE/registration values, request and
  registered-file generations, bounded leases, terminal completion credits,
  serialized CQ publication, cancellable/uncancellable execution hand-off,
  cancellation races, and close state. The
  embedding kernel still owns shared-page atomic access, UAPI copyin/copyout,
  mmap and FD lifetimes, VFS/readiness adapters, signal-mask restoration,
  execution, waiting, and errno conversion.
- Packet policy owns normalized protocol/address values, generation-tagged
  bind plans, ordinary RAW/DGRAM view and outgoing decisions, ignore-outgoing
  state, and typed mapping of endpoint-owned destructive statistics. It does
  not own packet taps/buffers, live/resettable counters, devices, queues,
  allocation, waiters/readiness, capabilities/namespaces, usercopy, FDs,
  TPACKET shared memory, fanout, or send execution.
- Seccomp policy consumes `thekernel-axcbpf` for generic classic-BPF
  verification and execution. It owns the Linux input/opcode profile,
  immutable filter ancestry, aggregate accounting, action selection, and
  task-state transition values, but not usercopy, task/thread-group locks,
  install permissions, signal/ptrace/audit handling, listener FDs, readiness,
  or group-wide TSYNC commit.
- Pathwalk, descriptor, watch, ready-queue, graph, and recovery work are all
  finite. Epoll payload preparation is lock-external and recovery is
  generation-tagged and incrementally bounded. Unsupported exclusive selection
  is rejected rather than simulated.
- Syscall decoding, evaluator policy, and benchmark profiles stay in
  TheKernel.
- Unsupported functionality is reported honestly; a package name is not a
  claim of complete Linux parity.

The pre-publication package gate builds seccomp together with an exact packaged
`thekernel-axcbpf` source artifact and tests only those unpacked archives. This
does not pretend that the dependency already exists on crates.io. A final
`cargo publish --dry-run` for seccomp remains deferred until
`thekernel-axcbpf` 0.1.0 is visible to an ordinary registry client.

See [GOVERNANCE.md](GOVERNANCE.md), [CONTRIBUTING.md](CONTRIBUTING.md),
[PROVENANCE.md](PROVENANCE.md), and [RELEASING.md](RELEASING.md).

## License

Apache License 2.0. Vendored and derived sources retain their original
authorship and provenance records.
