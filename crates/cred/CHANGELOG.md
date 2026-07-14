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
- Derive ordinary-transition dumpability and parent-death effects from
  effective/filesystem ID changes and Linux `cred_cap_issubset()` instead of
  requiring a kernel adapter to reconstruct that policy.
- Add namespace-capability decisions over immutable caller-provided namespace
  topology without owning a process registry.
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
- Add policy-neutral inode-permission and file-open contexts over an exact
  actor, independently selected DAC snapshot, target-owner namespace, and
  opaque caller-owned object; normalize non-empty read/write/execute access,
  ordinary file access, reserved ioctl-oriented no-data access mode 3,
  append, truncate, created, and unnamed `O_TMPFILE` facts without accepting
  raw descriptor flags or owning VFS dispatch. Deliberately omit `O_PATH`
  because Linux returns its path-only description before `security_file_open`.
  Preserve mode 3's `MAY_WRITE` open admission so a no-data description can
  still record a successful unnamed `O_TMPFILE` creation.
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
