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
- Replace the kernel-local mutable capability draft and syscall-local set-ID
  and `capset` matrices with field-private immutable next-state planners. Bind
  each decision to an explicit old credential and typed consumer-provided
  authority, retain Linux's distinct ID-family versus FSID commoncap fixup
  paths and `setres*` early no-op, and enforce the inheritable bounding-set
  constraint independently of `CAP_SETPCAP`.
- Extend the immutable securebits value domain through Linux v6.18's advisory
  exec value/lock pairs. Export its unprivileged mask and enforce supported-bit
  and lock monotonicity locally while leaving capability admission, stacked
  hooks, and publication in the embedding consumer.
- Replace raw capable options and unvalidated numbers with a typed operation,
  bounded `CapabilityNumber`, and field-private successful commoncap context.
  Bind the caller-supplied immutable actor and target namespace without
  `current()` lookup so an embedding registry can run commoncap first and then
  stop stacked module dispatch at the first denial.
- Replace adapter-local raw key permission arithmetic with a validated four-
  lane mask and non-empty typed access request. Select exactly one filesystem-
  identity lane, add possessor rights cumulatively only when the embedding
  kernel proves possession of the exact key, and leave serial lookup,
  possession traversal, request authority, hook dispatch, and errno mapping
  outside the policy leaf.
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
- Preserve Linux commoncap's separate identity predicates: effective-ID/group
  change controls unsafe downgrade and ambient clearing, while secure-exec
  additionally compares the final effective IDs with the prior real IDs.
- Restrict the raw transition constructor and exec-only transition mode to the
  crate; ordinary consumers receive a dedicated exact-old-bound proposal that
  cannot replace the user namespace or select an exec relaxation.
- Replace kernel-object-specific ptrace/scheduler contexts and caller-supplied
  ownership booleans with immutable generic contexts; retain opaque object
  identity for stacked hooks while extracting pure commoncap rules.
- Normalize signal-zero versus nonzero requests, source class, and delivery
  scope into field-private values; return an opaque successful core token that
  cannot be rebound to a different credential before a consumer hook runs.
- Add infallible fork and user-namespace credential-publication contexts which
  borrow the exact source/published core values and one opaque consumer target.
  Derive the target namespace from the published credential while leaving
  pre-publication module-state preparation/authorization, visibility ordering,
  callback dispatch, and concurrency discipline in the embedding kernel.
- Add field-private inode-permission and file-open values which bind the exact
  actor separately from the DAC snapshot actually selected for the operation,
  retain target-owner namespace and opaque object identity, reject empty or
  unknown permission bits, and normalize ordinary access, Linux's reserved
  no-data access mode 3, open mutation, creation, and unnamed `O_TMPFILE` facts
  without importing VFS or descriptor flags. Omit `O_PATH` from the hook
  payload because Linux returns its path-only description before
  `security_file_open`. Keep mode 3's read/write admission distinct from its
  no-data persistent description so it may retain a successful unnamed-create
  result.
- Add an inode-setattr leaf contract with field-private, typed chmod/chown
  intents and a normalized hook-point proposal. Preserve UID/GID omission as
  separate `Option` fields, keep implicit set-ID mode cleanup distinct from
  post-hook core preparation, and replace raw `ATTR_KILL_PRIV` with a typed
  privilege-cleanup effect. Keep the fallible `InodeSetattrContext` distinct
  from the successful-only `InodePostSetattrContext`; the embedding kernel owns
  writable-mount and inode locking order, `may_setattr`, DAC/commoncap
  preparation, privilege-provider transactions, backend publication, linear
  post-hook preflight, notification, and errno mapping.
- Preserve Linux's distinct regular-file `inode_create`, directory
  `inode_mkdir`, and special-node `inode_mknod` topology with separate typed
  contexts. Each context binds caller-owned parent and prospective named-entry
  identities to the actor, selected DAC snapshot, destination-owner namespace,
  and consumer-prepared final normalized mode. The mknod operation additionally
  requires an `rdev` exactly for character and block devices and forbids it for
  FIFO and socket nodes; symlink, hard-link, and unnamed temporary-file
  operations enter distinct contracts or no named-create hook.
- Add the distinct Linux `inode_symlink` contract over the same frozen actor,
  DAC snapshot, destination-owner namespace, parent, and prospective entry,
  plus an opaque borrowed target payload. Keep target encoding, pathname
  decoding, destination stability, dispatch, and publication in the embedding
  kernel; do not invent a mode or device-number fact absent from this hook.
- Add the distinct Linux `inode_link` contract over an exact opaque source
  object, destination parent, and prospective entry together with the frozen
  actor, independently selected DAC snapshot, and filesystem-owner namespace.
  Keep protected-hardlink ownership/`CAP_FOWNER` policy, cross-filesystem
  rejection, destination stability, dispatch, and same-source publication in
  the embedding kernel; do not reuse symlink target or new-inode mode facts.
- Add distinct Linux `inode_unlink` and `inode_rmdir` contracts over an opaque
  existing victim entry and its exact parent together with the frozen actor,
  selected DAC snapshot, and filesystem-owner namespace. Keep writable-mount,
  sticky-directory, type, append/immutable, mountpoint, backend-emptiness,
  dispatch, notification, and publication rules in the embedding kernel, and
  do not encode the hook family as a forgeable boolean.
- Add a Linux `inode_rename` leaf contract which freezes the actor, selected
  DAC snapshot, filesystem-owner namespace, and four independently typed old
  parent/entry and new parent/entry identities. Preserve the pinned LSM hook's
  flag-free signature: ordinary, no-replace, and whiteout operations have one
  forward leaf dispatch, while an exchange remains an adapter-owned reverse-
  then-forward dispatch with denial short-circuiting. Keep raw flag decoding,
  flag-combination validation, path hooks, admission, lookup, transaction,
  backend mutation, and notification outside this crate.
- Add one typed inode-xattr leaf context whose operation preserves Linux's
  distinct get, list, set, and remove shapes. Borrow exact raw name bytes and
  opaque set-value bytes, accept Linux's 1-through-255-byte name domain without
  imposing UTF-8 while rejecting embedded NUL, validate zero/create/replace set
  flags, and derive a `security.capability` wire-value class from exact bytes
  without importing a parsed capability, xattr-store, VFS, kernel, or provider
  type. Keep namespace policy, DAC admission, mount and value/list size checks,
  lookup, storage, registry dispatch, post-set notification, publication, and
  errno mapping in the embedding consumer.
- Remove duplicate pre-release namespace-entry and filesystem-snapshot
  spellings before freezing 0.1, leaving one canonical consumer path for each
  operation.
- Declare the `allocator_api` nightly requirement without inventing a `kspin`
  dependency; synchronization remains a consumer decision.

## Deliberately not extracted or frozen

- embedding user-namespace allocation, lifetime limits, synchronization,
  procfs identity, and signal-pending accounting;
- credential-slot synchronization, generation handling, task attachment, and
  application of planner output to a consumer-owned unpublished builder;
- executable leases, xattr lookup, credential writer/publication locks, and
  application of dumpability, MM-owner, ptrace, and parent-death effects;
- security-hook registry storage, dispatch, boot freeze, publication-phase
  enforcement, notification scheduling, and concrete kernel object wrappers;
- VFS object/location identity, DAC and protected-hardlink adapters,
  open/link/rename transactions, process/signal/scheduler/IPC authorization
  adapters, MM, and syscall/usercopy glue; and
- kernel errno values, concrete lock types, hash maps, RCU, or epoch schemes.
