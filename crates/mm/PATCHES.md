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
  validation, and a lower port trait. Fault identity uses an absolute page plus
  caller-owned mapping/fault epoch, so a surviving VMA split does not make an
  unchanged page relative to a new range start. Admission checks current
  access and distinguishes a quota-consuming new request from an exact
  lower-broker request which only adds a waiter. The full broker snapshot must
  equal the fault request; no fabricated lower load is used to bypass request
  quotas. Resolver/completion revalidates identity and coverage without
  rejecting a page install solely because a later protection change will make
  the retried fault fail. Concrete broker queues, waiter limits, observers,
  wakeups, readiness, and coalescing remain generic VM mechanisms.
- Add Linux v6.12 userfaultfd policy without importing a second queue:
  transactional API negotiation, bounded MISSING registration ownership,
  constant-stack multi-VMA preflight/commit, mixed-handler mapping
  split/trim/grow refresh, canonical subset/extension/bridge registration
  deltas with fail-closed lineage checks, fragment-refresh/fault-epoch
  projection, source-bound preflight of in-place tail growth without a
  post-grow mapping snapshot, strict source-bound canonical union for adjacent
  fragments covered by one post-state VMA, shared REGISTER/UNREGISTER
  VMA-profile validation, and COPY/ZEROPAGE mode/progress classification all
  remain above the generic `FaultPort` broker.
- Export canonical affine-origin relocation so consumers can remove duplicate
  syscall/backend arithmetic.

## Deliberately not extracted or frozen

- VMA tree/index layout, mapping-ID storage, page tables, TLB/ASID operations,
  frames, page-cache pins, physical scatter/gather segments, and dirty release;
- concrete fault broker storage, waiter/coalescing mechanics, observers,
  readiness, userfaultfd FD/read/copyout implementation, and task wakeups;
- files, mounts, credentials, security registry/dispatch, signals, processes,
  syscalls, usercopy, raw pointers, and architecture/HAL address types; and
- kernel locks, RCU/epoch implementation, allocator choice, and errno mapping.
