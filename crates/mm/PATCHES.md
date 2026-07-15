# Extraction and semantic ledger

## TheKernel behavior retained

- Reject zero, unaligned, and overflowing ranges before mutation.
- Treat file/COW/shared/linear remap state as one affine relationship between
  virtual origin and backing cursor.
- Preserve one whole-operation old/new remap anchor pair for every fragment.
- Charge memlock only for newly locked bytes in an already-partially-locked
  range.
- Keep page-table, file, frame, task, usercopy, and raw ABI work in the
  embedding kernel.

## 0.1.0 extraction changes

- Replace architecture `VirtAddr` and implicit page-size constants with
  checked raw integer adapters and private range invariants.
- Introduce caller-owned nonzero address-space/mapping identities and
  non-wrapping generations; the crate validates but never allocates generic VM
  identity mechanism state.
- Make invalidation reasons explicit, including discard without VMA removal.
- Replace implicit current-address-space pins with a complete typed request and
  explicit per-owner/global accounting.
- Add a fixed-capacity policy sidecar whose reservations charge before blocking
  work, roll back on stale/access failure, and cannot wrap tokens into ABA
  reuse.
- Separate system-wide pin charges from per-address-space policy records so a
  consumer can enforce one aggregate bound without moving locks, frame types,
  or mechanism ownership into this crate.
- Support one pin crossing multiple VMAs/backends through ordered contiguous
  expected-generation checks rather than binding the request to one snapshot.
- Permit overlapping read pins while rejecting any overlap involving a write,
  avoiding safe-API mutable alias claims.
- Add explicit mutation, close, and teardown admission instead of warning and
  clearing live pin state.
- Keep the fault surface to typed values, finite policy admission, stale reply
  validation, and a lower port trait. Concrete broker queues, waiters,
  observers, wakeups, readiness, and coalescing remain generic VM mechanisms.
- Export canonical affine-origin relocation so consumers can remove duplicate
  syscall/backend arithmetic.

## Deliberately not extracted or frozen

- VMA tree/index layout, mapping-ID storage, page tables, TLB/ASID operations,
  frames, page-cache pins, physical scatter/gather segments, and dirty release;
- concrete fault broker storage, waiter/coalescing mechanics, observers,
  readiness, userfaultfd FD/queue semantics, and task wakeups;
- files, mounts, credentials, security registry/dispatch, signals, processes,
  syscalls, usercopy, raw pointers, and architecture/HAL address types; and
- kernel locks, RCU/epoch implementation, allocator choice, and errno mapping.
