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
  `ProcessUsage` with an opaque generic payload `Z` that must be supplied to
  the successful zombie transition.
  Linux wait encoding, credentials, resource accounting, and errno mapping are
  now kernel-adapter policy.
- Make duplicate process-exit transitions idempotent without overwriting the
  first durable payload.
- Validate a live TID before changing the stored exit code; return a typed
  `ThreadExitOutcome`, and record the first group-exit code atomically.
- Compare-and-replace child parent pointers during exit so a racing ancestor
  cannot overwrite a newer reparent decision.
- Register session and process-group identities in the domain, enforce unique
  SID/PGID liveness, and prevent stale empty-group Arcs from being revived.
- Bound total thread membership across the domain and refund every admission,
  rollback, removal, and exit path exactly once.
- Bind unpublished initial-thread authority to `ProcessAdmission`; provide a
  joint process/initial-thread publication transaction, and make every live
  thread commit revalidate publication and zombie/reap state.
- Count pending thread reservations during exit so admission and zombie
  publication have one lock-serialized winner.
- Revalidate exact process identity under the registry lock instead of reading
  an intrusive link while concurrent tree rotations are in flight.
- Use checked bounded increments for process, group, session, and thread
  charges. Every release is non-wrapping, so a duplicate internal refund keeps
  zero at zero and fails closed instead of creating effective infinity.
- Refund the already-reserved domain thread charge if the defensive per-group
  checked increment rejects publication.
- Replace the final public exit/thread invariant assertions with idempotent or
  typed outcomes; lifecycle input cannot reach a panic/expect path.
- Enable `kspin/smp` in the workspace dependency so standalone/concurrent tests
  use real locks instead of the single-core no-lock specialization.

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
