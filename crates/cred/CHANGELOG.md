# Changelog

## 0.1.0 - 2026-07-13

- Extract distinct kernel-global and namespace-visible UID/GID types from the
  transactional Credential v2 baseline.
- Add bounded immutable UID/GID maps with checked forward and reverse indexes,
  parent-map resolution, and fallible snapshots.
- Add immutable credential and capability-set values with checked effective,
  permitted, inheritable, bounding, ambient, securebits, group, and
  `no_new_privs` invariants.
- Add an opaque ordinary-transition proposal which inherits the old user
  namespace, excludes exec-only invariant relaxations, owns the exact old
  credential `Arc`, and releases its proposed owner only after a pointer
  identity check.
- Add allocation-free, exact-old-borrowing planners for the complete Linux
  `setuid`/`setgid`/`setre*`/`setres*`/`setfs*` transition families. Require
  explicit typed `CAP_SETUID` or `CAP_SETGID` hook results, apply mapped-root
  UID and FSUID commoncap fixups in their distinct Linux operation families,
  preserve silent unchanged FSID refusal and the Linux v6.18 `setres*` early
  no-op for distinct filesystem IDs, and convert plans into the existing
  `PreparedCredential` only after exact-old `Arc` identity validation.
- Add a typed `capset` request and authority-bound planner which enforces
  effective/permitted admission, non-growing permitted authority, both
  inheritable constraints (including the unconditional bounding-set gate),
  and ambient reconciliation while preserving bounding and securebits.
- Add an allocation-free content-write set-ID cleanup planner over a checked
  low-`0o7777` mode and typed consumer-owned `CAP_FSETID` decision. Return the
  exact cleanup effect and complete next mode while keeping VFS identity,
  xattr removal, metadata/data transactions, and errno mapping consumer-owned.
- Add validated `CapabilitySets` helpers for ordinary securebits and
  `KEEP_CAPS` changes, including Linux v6.18's advisory exec value/lock pairs
  and `SECURE_ALL_UNPRIVILEGED`, so consumers no longer need a field-public
  mutable capability draft. Keep `CAP_SETPCAP`, unprivileged changed-bit
  admission, hook dispatch, and exact-old publication consumer-owned.
- Derive ordinary-transition dumpability and parent-death effects from
  effective/filesystem ID changes and Linux `cred_cap_issubset()` instead of
  requiring a kernel adapter to reconstruct that policy.
- Add namespace-capability decisions over immutable caller-provided namespace
  topology without owning a process registry.
- Add a bounded `CapabilityNumber`, normalized ordinary/no-audit/set-ID
  operation metadata, and a field-private successful commoncap context which
  binds the exact actor and target namespace before stacked deny-first policy
  dispatch without consulting a current task.
- Add a lock-neutral user-namespace domain and map state for bounded hierarchy,
  creator ownership, one-write UID/GID publication from borrowed immutable
  replacements, snapshot-stable empty maps, and irreversible `setgroups`
  policy.
- Add an allocation-free parser and checked normalized value for Linux
  `security.capability` revisions 1, 2, and 3, including exact sizes,
  little-endian words, flags, capability masks, and namespaced root IDs.
- Add typed, field-private exec inputs which derive set-ID intent from mode,
  paired inode ownership, and one coherent UID/GID map snapshot rather than
  accepting caller-supplied transition booleans.
- Add an opaque exec proposal which owns the exact old credential `Arc`,
  releases its validated proposed `Arc` only after a pointer-identity check,
  and carries typed dumpability, aux-identity, ptrace-revalidation, and
  commoncap decisions without owning process or MM publication.
- Keep commoncap's pre-downgrade `id_changed` predicate distinct from final
  secure-exec state, including unchanged pre-existing effective identities,
  setgid to a supplementary group, and set-ID transitions back to a real ID.
- Add typed ptrace/traceme contexts with opaque caller-owned object payloads,
  typed scheduler operations whose ownership relation is derived internally,
  and policy-neutral commoncap authorization errors preserving `EPERM` versus
  `EACCES` adapter choices.
- Add typed userspace signal sources and thread/thread-group delivery scopes,
  a bounded validated Linux signal number, and an opaque core-authorization
  proof which retains the exact immutable actor/target pair through policy
  context construction.
- Add successful-only fork and user-namespace credential-publication contexts
  over exact source/published credentials and an opaque consumer-owned target.
  Derive the target namespace from the published credential and keep every
  fallible preparation, authorization, visibility transaction, registry, and
  callback scheduling decision in the embedding kernel.
- Add policy-neutral inode-permission and file-open contexts over an exact
  actor, independently selected DAC snapshot, target-owner namespace, and
  opaque caller-owned object; normalize non-empty read/write/execute access,
  ordinary file access, reserved ioctl-oriented no-data access mode 3,
  append, truncate, created, and unnamed `O_TMPFILE` facts without accepting
  raw descriptor flags or owning VFS dispatch. Deliberately omit `O_PATH`
  because Linux returns its path-only description before `security_file_open`.
  Preserve mode 3's `MAY_WRITE` open admission so a no-data description can
  still record a successful unnamed `O_TMPFILE` creation.
- Add typed chmod/chown inode-setattr intent and hook-point proposal values.
  Preserve omitted UID/GID fields independently from explicitly requested
  current values, reject non-mode bits, and represent selected file-privilege
  cleanup without raw iattr flags. Add distinct fallible pre-setattr and
  infallible post-setattr contexts over caller-owned old and committed object
  snapshots, while leaving DAC preparation, locking, backend mutation,
  registry preflight/dispatch, and errno mapping to the embedding kernel.
- Add separate field-private contexts for Linux-style regular-file
  `inode_create`, directory `inode_mkdir`, and FIFO/character/block/socket
  `inode_mknod` hooks. Bind caller-owned parent and prospective named-entry
  objects to the actor, independently selected DAC snapshot,
  destination-owner namespace, consumer-prepared final low `0o7777` mode, and
  checked device-number pairing without admitting symlink, hard-link, or
  unnamed `O_TMPFILE` operations.
- Add a separate field-private `inode_symlink` context which freezes the exact
  actor, DAC snapshot, destination-owner namespace, parent, prospective entry,
  and opaque borrowed target payload without imposing target encoding or
  inventing mode/device facts that Linux does not pass to this hook.
- Add a separate field-private `inode_link` context which freezes the exact
  actor, independently selected DAC snapshot, filesystem-owner namespace,
  existing source object, destination parent, and prospective entry without
  importing protected-hardlink policy, cross-filesystem checks, lookup,
  transaction, or publication mechanisms.
- Add distinct field-private `inode_unlink` and `inode_rmdir` contexts which
  bind the exact actor, selected DAC snapshot, filesystem-owner namespace,
  parent directory, and opaque existing victim entry without collapsing the
  two Linux hooks into a caller-provided directory flag or importing
  `may_delete`, lookup, backend, notification, or publication mechanisms.
- Add a field-private `inode_rename` leaf context which binds the exact actor,
  selected DAC snapshot, filesystem-owner namespace, and four independently
  typed old-parent, old-entry, new-parent, and new-entry identities. Keep the
  leaf payload flag-free like Linux's LSM hook: ordinary, no-replace, and
  whiteout use one forward context, while exchange ordering remains an
  explicit reverse-then-forward consumer dispatch with first-denial
  short-circuiting.
- Add a typed inode-xattr contract with distinct get, list, set, and remove
  operations over borrowed raw names and exact opaque set-value bytes. Accept
  Linux's full 1-through-255-byte name domain without requiring UTF-8 while
  rejecting embedded NUL, and validate zero/create/replace set flags while
  rejecting their contradictory combination and unknown bits. Classify the
  exact byte name `security.capability` without exposing parsed capability,
  kernel, VFS, store, or provider types, and bind the operation to the actor,
  selected DAC snapshot, target-owner namespace, and opaque target identity.
- Add field-private policy-neutral socket contexts matching Linux v6.18's
  create/post-create/pair, bind/connect, listen/accept, send/receive message,
  local/peer name, get/set option, shutdown, Unix stream-connect, and Unix
  may-send leaf roles. Borrow immutable actors and opaque consumer snapshots,
  reject flagged create types, retain consumer-clamped backlog and raw shutdown
  direction, preserve send size without inventing a separate flags field, and
  preserve receive size plus its explicit raw flags. Keep fd/OFD lookup,
  address import, transport types, security-module registry state, dispatch,
  locking, and errno mapping outside the crate.
- Add field-private policy-neutral contexts matching Linux v6.18's
  `mmap_file`, `mmap_addr`, and `file_mprotect` leaves. Strictly normalize
  `PROT_NONE` plus read/write/execute combinations while rejecting unknown
  protection bits, preserve the complete raw mapping-flags word, keep
  requested and effective protection distinct, and distinguish an anonymous
  target from an exact borrowed file paired with its filesystem-owner
  namespace. Bind address policy to the exact image and final selected address
  only, and mprotect policy to the exact pre-change VMA, while leaving fd/OFD
  lookup, address selection, mmap locking and transactions, VMA mutation,
  registry dispatch, and errno mapping outside the crate.
- Remove the pre-release `try_with_user_ns` and `fs_dac_credentials`
  compatibility aliases before the 0.1 API freeze; consumers use
  `try_with_user_namespace` and `fs_credential_snapshot` exclusively.
- Introduce non-exhaustive `CredError` values so adapters retain control of
  errno mapping.
- Keep namespace locks, lifetime admission, procfs identity, and signal
  accounting in the kernel extension, preserving independence from process,
  VFS, signal, FD, MM, usercopy, `kspin`, and syscall mechanisms.
- Declare and test the package as nightly-only while fallible standard `Arc`
  allocation requires `allocator_api`.
- Record the exact TheKernel baseline, RFC contract, and Linux/FreeBSD research
  snapshots used for this new extraction.
