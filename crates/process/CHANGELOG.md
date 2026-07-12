# Changelog

## 0.1.0 - release candidate

- Replace the crate-owned process registry and init singleton with an explicit
  `ProcessDomain` and `ProcessRegistry`.
- Make durable zombie state a caller-defined generic payload.
- Preserve bounded, fallible process/thread admission and rollback.
- Preserve subreaper reparenting, session/group topology, and allocation-free
  PID/TID iteration.
- Declare and test the package as nightly-only while fallible standard `Arc`
  allocation requires `allocator_api`.
