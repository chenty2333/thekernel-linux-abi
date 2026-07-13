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
- Bind ordinary replacement release to the exact old credential `Arc`, keep
  old/proposed owners opaque behind borrowed views, and derive the coupled
  dumpability/parent-death reset decision before consumer publication.
- Apply namespace capabilities in the correct direction: same namespace,
  descendants, and immediate-child owner authority, never upward or sideways.
- Parse Linux file-capability revisions 1, 2, and 3 with exact size,
  endianness, flag, mask, and namespaced-root validation.
- Apply Linux signal permission to one exact immutable actor/target pair,
  including UID matching, `CAP_KILL`, same-thread-group admission, and the
  `SIGCONT` same-session exception before stacked policy dispatch.

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
- Normalize `security.capability` wire records into a field-private checked
  value without importing a VFS, xattr store, process object, or kernel errno.
- Replace independently supplied set-ID/mapped booleans with a field-private
  exec input over mode, paired inode IDs, typed mount/trace/readability facts,
  and one coherent immutable UID/GID map snapshot.
- Produce a complete immutable credential through checked `CapabilitySets`
  and crate-private `ExecClearsKeepCaps`, then bind exec release to the exact
  old `Arc` while returning process/MM side effects only as typed values.
- Restrict the raw transition constructor and exec-only transition mode to the
  crate; ordinary consumers receive a dedicated exact-old-bound proposal that
  cannot replace the user namespace or select an exec relaxation.
- Replace kernel-object-specific ptrace/scheduler contexts and caller-supplied
  ownership booleans with immutable generic contexts; retain opaque object
  identity for stacked hooks while extracting pure commoncap rules.
- Normalize signal-zero versus nonzero requests, source class, and delivery
  scope into field-private values; return an opaque successful core token that
  cannot be rebound to a different credential before a consumer hook runs.
- Declare the `allocator_api` nightly requirement without inventing a `kspin`
  dependency; synchronization remains a consumer decision.

## Deliberately not extracted or frozen

- embedding user-namespace allocation, lifetime limits, synchronization,
  procfs identity, and signal-pending accounting;
- credential-slot synchronization, generation handling, and task attachment;
- executable leases, xattr lookup, credential writer/publication locks, and
  application of dumpability, MM-owner, ptrace, and parent-death effects;
- security-hook registry storage, dispatch, boot freeze, notification phases,
  and concrete kernel object wrappers;
- VFS DAC adapters, process/signal/scheduler/IPC authorization adapters, MM,
  and syscall/usercopy glue; and
- kernel errno values, concrete lock types, hash maps, RCU, or epoch schemes.
