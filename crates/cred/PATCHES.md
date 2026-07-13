# Extraction and semantic ledger

## TheKernel source behavior retained

- Distinguish kernel-global IDs from IDs visible through one user namespace,
  and reserve the all-ones value as invalid internally.
- Bound each UID/GID map to 340 extents and reject zero length, arithmetic
  overflow, or overlap in either namespace-visible or kernel-global ranges.
- Build complete forward and reverse map indexes before making an immutable
  map available to a caller.
- Resolve a child map through its parent and reject a child row that pretends a
  discontinuous parent mapping is contiguous.
- Keep effective capabilities within permitted capabilities, ambient within
  permitted and inheritable, and every set within the supported capability
  mask.
- Keep committed credential values immutable and make `no_new_privs`
  monotonic across a prepared transition.
- Apply namespace capabilities in the correct direction: same namespace,
  descendants, and immediate-child owner authority, never upward or sideways.

## 0.1.0 extraction changes

- Replace raw IDs and kernel-local `AxError` values with typed IDs and a
  non-exhaustive, adapter-mapped `CredError`.
- Split the concrete mutable `UserNamespace` into a lock-neutral domain/map
  core and a caller-provided synchronized wrapper/topology view.
- Use fallible `Vec` and `Arc` construction so allocation failure is explicit
  and occurs before a consumer publishes state.
- Separate pure credential/capability invariants and topology authorization
  from process state, locks, global registries, syscalls, and errno mapping.
- Move immutable namespace hierarchy/owner facts and UID/GID/setgroups
  publication state into a lock-neutral core. Publication borrows a fully
  built replacement and clones it into an unused slot, so no caller or prior
  map owner can be destroyed by the guarded operation.
- Declare the `allocator_api` nightly requirement without inventing a `kspin`
  dependency; synchronization remains a consumer decision.

## Deliberately not extracted or frozen

- embedding user-namespace allocation, lifetime limits, synchronization,
  procfs identity, and signal-pending accounting;
- credential-slot synchronization, generation handling, and task attachment;
- executable leases, file-capability parsing, set-ID/exec derivation,
  dumpability and parent-death-signal effects;
- security-hook registry storage, dispatch, and kernel object contexts;
- VFS DAC adapters, process/signal/scheduler/IPC authorization adapters, MM,
  and syscall/usercopy glue; and
- kernel errno values, concrete lock types, hash maps, RCU, or epoch schemes.
