# Patch ledger

This ledger records semantic changes relative to the immutable
`starry-process 0.2.0` archive identified in `VENDOR.md`.

## TheKernel pre-migration maintenance

- Replace weak-map membership scans with bounded intrusive PID/TID registries.
- Add fallible prepare/commit admission and allocation-free rollback.
- Add durable zombie state, wait accounting, child subreapers, and explicit
  reap behavior.
- Add fallible bounded snapshots and lock-free-callback iteration.

## `thekernel-linux-process 0.1.0`

- Replace the internal `PROCESS_REGISTRY` and `INIT_PROC` singletons with one
  caller-owned `ProcessDomain<Z>` and explicit `ProcessRegistry<Z>`.
- Bind every process, group, and session to one registry and reject cross-domain
  operations. Independent kernels/tests may reuse PID values without sharing
  lifecycle state.
- Route fork, exit, and reap through the owning domain; require the registry
  argument for child, group, and session enumeration.
- Replace `ZombieSnapshot { wait_status, uid, self_usage, child_usage }` and
  `ProcessUsage` with an opaque generic payload `Z` published at most once.
  Linux wait encoding, credentials, resource accounting, and errno mapping are
  now kernel-adapter policy.
- Make duplicate zombie-payload publication explicit and idempotently report
  duplicate process-exit transitions.

## Why 0.1.0 remains nightly-only

The package preserves the established contract that allocating a process,
session, group, thread node, or registry owner can report
`ProcessError::NoMemory`. Standard `alloc::sync::Arc` is also the ownership
type consumed by TheKernel and by `intrusive-collections`.

Rust's fallible `Arc::try_new` still requires the `allocator_api` feature on the
pinned consumer toolchain. `allocator-api2` supplies stable fallible `Box` and
collection allocation, but it does not supply a layout-compatible standard
`Arc`; converting such a box into `alloc::sync::Arc` performs a new infallible
allocation. A custom reference-counted pointer would change public ownership
types and consumer interoperability. Pre-reserving unrelated memory cannot
guarantee that the later `Arc` allocation succeeds and would only fake the OOM
contract. Therefore 0.1.0 explicitly requires `nightly-2025-05-20` instead of
claiming a stable `rust-version`.
