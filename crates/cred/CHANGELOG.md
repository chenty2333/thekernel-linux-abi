# Changelog

## 0.1.0 - 2026-07-13

- Extract distinct kernel-global and namespace-visible UID/GID types from the
  transactional Credential v2 baseline.
- Add bounded immutable UID/GID maps with checked forward and reverse indexes,
  parent-map resolution, and fallible snapshots.
- Add immutable credential and capability-set values with checked effective,
  permitted, inheritable, bounding, ambient, securebits, group, and
  `no_new_privs` invariants.
- Add namespace-capability decisions over immutable caller-provided namespace
  topology without owning a process registry.
- Add a lock-neutral user-namespace domain and map state for bounded hierarchy,
  creator ownership, one-write UID/GID publication from borrowed immutable
  replacements, snapshot-stable empty maps, and irreversible `setgroups`
  policy.
- Add an allocation-free parser and checked normalized value for Linux
  `security.capability` revisions 1, 2, and 3, including exact sizes,
  little-endian words, flags, capability masks, and namespaced root IDs.
- Introduce non-exhaustive `CredError` values so adapters retain control of
  errno mapping.
- Keep namespace locks, lifetime admission, procfs identity, and signal
  accounting in the kernel extension, preserving independence from process,
  VFS, signal, FD, MM, usercopy, `kspin`, and syscall mechanisms.
- Declare and test the package as nightly-only while fallible standard `Arc`
  allocation requires `allocator_api`.
- Record the exact TheKernel baseline, RFC contract, and Linux/FreeBSD research
  snapshots used for this new extraction.
