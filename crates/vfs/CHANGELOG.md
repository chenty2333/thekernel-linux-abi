# Changelog

## 0.1.0 - 2026-07-12

- Add explicit immutable pathname-operation contexts.
- Add strict Linux `openat2()` resolve policy and typed topology events.
- Add bounded pathname-walk accounting with checked arithmetic.
- Add Linux DAC, capability, sticky-directory, and create-attribute policy.
- Add Linux protected-hardlink source policy with exact permission-probe and
  owner/own-namespace capability fallback ordering.
- Add exact-snapshot, move-only chmod/chown plans with omission-aware owner
  requests, `CAP_CHOWN`/`CAP_FOWNER`/`CAP_FSETID` policy, two-phase SGID
  handling, sparse backend updates, and committed post-hook facts.
- Add fallible generation-revalidated mutation transactions with an explicit
  final admission phase, at-most-once publication, and rollback.
- Support `no_std`, Rust 1.85, RISC-V 64, and LoongArch 64 consumers.
