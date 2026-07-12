# Changelog

## 0.1.0 - 2026-07-12

- Add fixed-capacity FD-table reservation, publication, dup/fork, and
  transactional close semantics with generation-tagged identities.
- Keep alloc-enabled kernel-sized FD tables heap-backed and fallibly
  preallocated, including fork copies, so construction never requires an
  `O(capacity)` stack temporary; expose ordered visible-entry iteration.
- Separate descriptor-local state from shared OFD offset, status, and async
  owner state.
- Add finite watch accounting and fallible two-phase aggregate source
  registration with exact cancellation rollback.
- Add bounded epoll LT/ET/ONESHOT delivery, copyout-fault replay, concurrent
  wake coalescing, explicit rescan recovery, and stale-token rejection.
- Keep arbitrary payload preparation outside IRQ-safe epoll locks with a
  generation-checked delivery prepare/commit transaction that returns
  unpublished ownership on every failure.
- Expose the exact interest generation from an in-flight delivery token so a
  consumer can rearm and level-recheck the right source without treating
  duplicate user data as identity.
- Make defensive epoll recovery incremental and convergent with persistent,
  generation-tagged rescan state and an explicit per-call work budget.
- Add bounded epoll graph cycle, nesting, reverse-parent, capacity, and walk
  validation.
- Reject unsupported exclusive wake selection honestly.
- Support `no_std`, Rust 1.85, RISC-V 64, and LoongArch 64 consumers.
