# TheKernel Linux ABI

`thekernel-linux-abi` is the monorepo for reusable, `no_std` Linux ABI support
owned by TheKernel. It is deliberately separate from generic ArceOS
mechanisms and from TheKernel's syscall and evaluator layers.

The 0.1.0 line contains five packages:

- `thekernel-linux-usercopy` 0.1.0: explicit-context, bounded, fallible access
  to a caller-provided userspace memory implementation.
- `thekernel-linux-process` 0.1.0: explicit-domain, bounded process lifecycle
  state with a caller-defined zombie payload.
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

Signal depends on usercopy. Process remains independent; task ownership and
process-to-signal integration stay with the caller rather than becoming hidden
workspace-global state.

The workspace name is not a facade package. Credential and MM crates will be
added only after their Linux-visible contracts pass the semantic, failure,
concurrency, and dual-architecture gates documented in this repository.

## Development

The repository pins the same nightly used by its initial TheKernel consumer.
The usercopy, VFS, and FD crates are additionally checked against stable Rust
1.85 or newer. The process and signal crates are explicitly nightly-only
because preserving fallible standard `Arc` allocation currently requires
`allocator_api`; neither inherits or claims a stable `rust-version`.

```bash
cargo test --workspace --all-features
cargo check -p thekernel-linux-usercopy --no-default-features --locked
cargo check -p thekernel-linux-signal --no-default-features --locked
cargo check -p thekernel-linux-vfs --no-default-features --locked
cargo check -p thekernel-linux-fd --no-default-features --locked
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
- Pathwalk, descriptor, watch, ready-queue, graph, and recovery work are all
  finite. Epoll payload preparation is lock-external and recovery is
  generation-tagged and incrementally bounded. Unsupported exclusive selection
  is rejected rather than simulated.
- Syscall decoding, evaluator policy, and benchmark profiles stay in
  TheKernel.
- Unsupported functionality is reported honestly; a package name is not a
  claim of complete Linux parity.

See [GOVERNANCE.md](GOVERNANCE.md), [CONTRIBUTING.md](CONTRIBUTING.md),
[PROVENANCE.md](PROVENANCE.md), and [RELEASING.md](RELEASING.md).

## License

Apache License 2.0. Vendored and derived sources retain their original
authorship and provenance records.
