# Extraction and semantic ledger

## Linux-visible contracts retained

- Validate setup/enter flags, reserved fields, legacy signal-mask size, bounded
  queue depths, power-of-two geometry, and Linux mmap offsets before ring
  publication.
- Treat SQ/CQ counters as wrapping monotonic values while rejecting producer or
  consumer progress outside the published queue capacity.
- Copy an SQE once after acquire-observing the SQ tail and publish a complete
  CQE before release-advancing the CQ tail.
- Reserve terminal completion capacity for accepted one-shot work so a
  completion cannot be silently discarded after execution starts.
- Give cancellation, normal completion, and forced teardown exactly one
  terminal winner.
- Keep a registered-file owner alive after whole-table retirement begins until
  every request holding that slot generation releases its lease.

## 0.1.0 extraction changes

- Replace raw shared-memory and C-union access with checked setup values, an
  identity-preserving caller-provided `[u8; 64]` copy, and typed registration
  header values.
- Introduce caller-owned nonzero ring and fixed-file registration-epoch
  identities plus ring/table/slot/generation-bound tokens with non-wrapping
  reuse.
- Make request-slot and terminal-CQ admission one explicit fallible
  reservation before a request becomes executable.
- Distinguish cancellable retained poll execution from irreversible positioned
  VFS execution, and make the atomic hand-off return prepared ownership when
  cancellation or close wins first.
- Separate terminal claim, CQE preparation, serialized shared-ring
  publication, and reap accounting so an in-progress CQE write cannot be
  overtaken and no fallible or consumer-controlled work occurs under a hidden
  crate lock.
- Represent registered-file lookup as a retained lease and return retired
  ownership only after the exact table/slot generation's last lease is
  released; charge every lease to an explicit aggregate table budget and
  return owners/leases from every failed ownership-consuming operation.
- Model stop-admission, cancellation/drain, completion consumption, resource
  retirement, and final close as observable progress rather than a best-effort
  destructor side effect.
- Accept only the first proved opcode/flag subset and reject unsupported
  behavior explicitly instead of emulating it synchronously under an async
  interface.
- Pin Linux v6.12.35 opcode and registration ranges so probe and error mapping
  distinguish implemented, known unsupported, and unknown operations without
  duplicating magic limits in the consumer.

## Deliberately not extracted or frozen

- shared-page allocation, mmap objects, acquire/release atomic operations,
  UAPI structs, raw pointers, usercopy, and architecture address types;
- FD lookup, VFS I/O, retained readiness registration, task waiting, signals,
  workers, execution scheduling, MM pins, and errno/result conversion;
- native async/io-wq workers, `SQPOLL`, `IOPOLL`, registered buffers and their
  long-term pin lifetime, linked/multishot requests, personalities, timeouts,
  buffer selection, and the remaining Linux operations/registration commands;
  and
- concrete lock, queue, map, allocator, RCU/epoch, or reclamation choices.
