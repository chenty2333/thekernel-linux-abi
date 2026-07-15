# Changelog

## 0.1.0 - 2026-07-15

- Add strict initial setup validation, checked SQ/CQ geometry, mmap-region
  resolution, explicit shared-ring ownership offsets, and the four proved
  `SINGLE_MMAP`, `NODROP`, `SUBMIT_STABLE`, and `POLL_32BITS` feature bits.
- Decode only `GETEVENTS` enter flags and validate the exact legacy signal-mask
  size while leaving mask installation/restoration to the signal adapter.
- Preserve one private 64-byte SQE copy and its `user_data`, classify opcodes
  against Linux stable v6.12.35, and decode `NOP`, positioned `READ`/`WRITE`,
  one-shot `POLL_ADD`, and default user-data `ASYNC_CANCEL` without importing
  raw C unions or dereferencing userspace memory.
- Add strict fixed-file register/unregister and probe header decoding while
  distinguishing malformed input, pinned-UAPI unsupported operations,
  well-formed unsupported registered buffers, and unknown operations.
- Add bounded generation-safe request admission which reserves terminal CQ
  capacity before publication and preserves one terminal owner across
  execution, cancellation, and close races.
- Add an opcode-directed executor hand-off: one-shot poll remains cancellable,
  while positioned I/O crosses an explicit uncancellable boundary before VFS
  side effects; failed hand-off returns the prepared proof for rollback.
- Add serialized two-phase CQE publication/reap transactions with validated
  userspace head progress, pre-publication rollback, and no silent completion
  drop or overtaking tail.
- Add a bounded registered-file table with lookup-visible generations,
  non-reused table epochs, aggregate lease admission, retained leases, one-time
  publication, recovery-carrying errors, incremental whole-table retirement,
  and explicit close progress.
- Keep shared-memory atomics, mmap, UAPI/usercopy, FD/VFS/readiness adapters,
  MM pins, workers, execution, waiting, signals, and errno mapping in the
  embedding kernel.
- Support dependency-free `no_std`, `forbid(unsafe_code)`, Rust 1.85, RISC-V
  64, and LoongArch64 consumers.
