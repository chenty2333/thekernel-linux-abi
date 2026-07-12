# Changelog

## 0.1.0

- Add fixed-capacity FD-table reservation, publication, dup/fork, and
  transactional close semantics with generation-tagged identities.
- Separate descriptor-local state from shared OFD offset, status, and async
  owner state.
- Add finite watch accounting and fallible two-phase aggregate source
  registration with exact cancellation rollback.
- Add bounded epoll LT/ET/ONESHOT delivery, copyout-fault replay, concurrent
  wake coalescing, explicit rescan recovery, and stale-token rejection.
- Add bounded epoll graph cycle, nesting, reverse-parent, capacity, and walk
  validation.
- Reject unsupported exclusive wake selection honestly.
- Support `no_std`, Rust 1.85, RISC-V 64, and LoongArch 64 consumers.
