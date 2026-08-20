# TheKernel Linux ABI

`thekernel-linux-abi` is the monorepo for reusable, `no_std` Linux ABI support
owned by TheKernel. It is deliberately separate from generic ArceOS mechanisms
and from TheKernel's syscall and evaluator layers.

The 0.1.0 source line contains eleven packages:

- `thekernel-linux-usercopy` 0.1.0: explicit-context, bounded, fallible access
  to a caller-provided userspace memory implementation.
- `thekernel-linux-process` 0.1.0: explicit-domain, bounded process lifecycle
  state with a caller-defined, reference-owned immutable zombie payload.
- `thekernel-linux-rseq` 0.1.0: a safe policy leaf for the Linux v6.6
  restartable-sequence ABI, registration lifecycle, event publication, and
  pure restart decisions.
- `thekernel-linux-signal` 0.1.0: bounded process/thread pending queues,
  architecture signal frames, generation-safe one-shot actions, quiescent
  teardown, and transactional context/mask/alternate-stack restore.
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
  pin accounting, cross-VMA revalidation, typed invalidation and fault seams,
  userfaultfd policy, and arithmetic-only remap/memlock planners.
- `thekernel-linux-io-uring` 0.1.0: checked shared-ring geometry and
  SQE/registration decoding, bounded generation-safe request/completion state,
  and registered-file leases with explicit close and drain transitions.
- `thekernel-linux-packet` 0.1.0: normalized AF_PACKET values, stale-safe bind
  publication, RAW/DGRAM receive decisions, outgoing policy, and typed mapping
  of endpoint-owned aggregate statistics.
- `thekernel-linux-seccomp` 0.1.0: a Linux v6.12 classic-BPF profile over the
  generic `thekernel-axcbpf` mechanism, immutable bounded filter ancestry,
  aggregate live-program accounting, action precedence, and prepared task
  transitions.

Signal depends on usercopy. Seccomp depends on the separately packaged
`thekernel-axcbpf` 0.1.0 mechanism package. Process and rseq remain independent
policy leaves; task ownership and cross-subsystem integration stay with the
caller rather than becoming hidden workspace-global state.

The workspace name is not a facade package. Package names describe ownership
boundaries, not complete Linux syscall parity. A real-consumer x86_64 gate
remains required before a release tag.

## Development

The workspace uses the rolling `nightly` toolchain used by its initial
TheKernel consumer. Usercopy, VFS, FD, MM, io_uring, packet, and rseq are also
checked against Rust 1.85. Process, signal, credential, and seccomp remain
nightly-only because preserving fallible standard `Arc` allocation currently
requires `allocator_api`; none claims a stable `rust-version`.

Before the first registry release, the workspace resolves `thekernel-axcbpf`
from a sibling `../thekernel-ax` checkout. CI checks out an explicit mechanism
revision. The release package test additionally verifies the reviewed and
release commits recorded for the axcbpf package, rejects source drift, and
packages the dependency from its real Git worktree. The path is development
wiring only and must not survive in a normalized seccomp archive.

The pull-request front door is:

```bash
./scripts/ci.sh all
```

It runs one nightly workspace quality pass plus one Rust-1.85 compatibility
pass for the stable crates. Individual tiers remain available as
`./scripts/ci.sh quality` and `./scripts/ci.sh msrv`.

Release-only rustdoc, archive, and publish-dry-run checks are separate:

```bash
./scripts/ci.sh release
```

The seccomp package proof uses the exact released `thekernel-axcbpf` source,
provided through `AXCBPF_SOURCE_ROOT`; routine source quality continues to use
the current sibling mechanism checkout. See `RELEASING.md` for the required
revision and command.

`thekernel-linux-rseq` is covered by workspace tests, no-default-feature checks,
Rust 1.85, Clippy, and rustdoc. It is not yet included in package/publish helper
lists because its release metadata and provenance asset set are incomplete;
that source crate must not be described as release-qualified yet.

## Boundaries

- Generic scheduling, filesystem, network, page-table, and driver mechanisms
  stay in their `ax-*` or other upstream/fork lines.
- Linux ABI crates do not read an implicit current task, global FD table, or
  global filesystem context.
- Signal usercopy is always caller-supplied. Standard and real-time pending
  queues are bounded and their shared accounting is refunded on every terminal
  path. One-shot actions cannot wrap into ABA reuse, and endpoint cancellation
  waits for an already-started delivery before returning.
- VFS and FD policy consume caller-supplied stable handles and snapshots. They
  do not choose generic filesystem walkers, source-waker storage, locks, task
  globals, or concrete RCU/indexing algorithms.
- Credential policy owns immutable Linux identity, namespace-map, transition,
  and commoncap values, but not credential slots, security-hook dispatch,
  process/VFS/MM objects, locks, syscalls, or errno mapping.
- MM policy consumes caller-owned address-space identities and immutable
  mapping snapshots. It owns bounded pin admission/accounting and generation
  validation plus Linux userfaultfd policy, but not VMA storage, frames, page
  tables, TLBs, concrete fault queues, readiness, tasks, locks, or usercopy.
- io_uring policy owns checked setup/enter/SQE/registration values, request and
  registered-file generations, bounded leases, terminal completion credits,
  cancellation races, and close state. The embedding kernel still owns shared
  page access, UAPI copyin/copyout, mmap and FD lifetimes, execution, waiting,
  and errno conversion.
- Packet policy owns normalized protocol/address values, generation-tagged
  bind plans, ordinary RAW/DGRAM view and outgoing decisions, and typed mapping
  of endpoint-owned statistics. It does not own packet buffers, devices,
  queues, allocation, readiness, capabilities, usercopy, FDs, TPACKET shared
  memory, fanout, or send execution.
- Rseq policy owns ABI values, bounded registration/event state, and pure
  restart classifications. It does not perform `rseq(2)`, usercopy, signature
  reads, saved-IP writes, IRQ masking, scheduling, or task ownership.
- Seccomp policy consumes `thekernel-axcbpf` for generic classic-BPF
  verification and execution. It owns Linux input/opcode policy, immutable
  ancestry, accounting, action selection, and task-state transition values,
  but not usercopy, task locks, install permissions, signal/ptrace/audit
  handling, listener FDs, readiness, or group-wide TSYNC commit.
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
