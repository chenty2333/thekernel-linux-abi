# Changelog

## 0.1.0 - 2026-07-19

- Add a Linux v6.12 seccomp classic-BPF profile over the independent
  `thekernel-axcbpf` mechanism, including the exact 64-byte syscall snapshot
  layout and RISC-V 64 and LoongArch64 audit-architecture values.
- Validate programs of one through 4096 instructions with aligned,
  in-bounds word loads, forward-only control flow, all-path scratch
  initialization, checked immediate arithmetic, and explicit rejection of
  packet loads, ancillary extensions, and `BPF_MOD`.
- Add immutable filter ancestry with Linux v6.12's 32768-instruction path
  limit over the unblinded post-cBPF-to-eBPF migration length, a
  four-instruction ancestor penalty, signed action precedence, newest-filter
  data on equal-precedence results, and exact identity-based ancestry checks.
- Keep source length, converted path charge, and logical live-byte accounting
  distinct; cover `RET_K`, register division, reversible and non-reversible
  conditional expansion, and the exactly-32768 acceptance boundary without
  claiming JIT-hardening or native-code-memory parity.
- Add an explicit aggregate logical live-program byte budget, fallible
  publication preparation, cross-budget splice rejection, final-owner refunds,
  and iterative deep-chain teardown.
- Add task-local disabled, strict, and filter states, stale-safe single-task
  publication, and non-mutating per-sibling TSYNC eligibility/preparation.
- Keep usercopy, task and thread-group locking, `no_new_privs` and capability
  admission, signal/ptrace/audit work, listener FDs, notification queues,
  syscall restart, errno conversion, and group-wide TSYNC commit in the
  embedding kernel.
- Support `no_std`, `forbid(unsafe_code)`, the pinned TheKernel nightly,
  RISC-V 64, and LoongArch64 consumers.
