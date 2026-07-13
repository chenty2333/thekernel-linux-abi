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
  topology without owning a concrete namespace or process registry.
- Introduce non-exhaustive `CredError` values so adapters retain control of
  errno mapping.
- Keep the crate independent of process, VFS, signal, FD, MM, usercopy,
  `kspin`, syscall, and concrete publication mechanisms.
- Declare and test the package as nightly-only while fallible standard `Arc`
  allocation requires `allocator_api`.
- Record the exact TheKernel baseline, RFC contract, and Linux/FreeBSD research
  snapshots used for this new extraction.
