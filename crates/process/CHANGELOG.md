# Changelog

## 0.1.0 - release candidate

- Replace the crate-owned process registry and init singleton with an explicit
  `ProcessDomain` and `ProcessRegistry`.
- Make durable zombie state a caller-defined generic payload.
- Preserve bounded, fallible process/thread admission and rollback.
- Preserve subreaper reparenting, session/group topology, and allocation-free
  PID/TID iteration.
- Require the zombie payload in the exit transition; add typed thread-exit and
  atomic group-exit-code semantics.
- Enforce domain-unique live group/session identities and a domain-wide thread
  membership bound.
- Exercise admission, removal, reparenting, exit, and reap concurrently with
  `kspin/smp` enabled.
- Declare and test the package as nightly-only while fallible standard `Arc`
  allocation requires `allocator_api`.
