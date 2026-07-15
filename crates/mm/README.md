# thekernel-linux-mm

`thekernel-linux-mm` is a `no_std`, `forbid(unsafe_code)` Linux-visible memory
management policy core. It provides checked values and bounded lifecycle
sidecars that a kernel adapter can consume without importing a page table,
frame allocator, VFS object, task, implicit current address space, usercopy
implementation, raw pointer, HAL address type, or lock.

Version 0.1.0 provides:

- checked nonzero `UserRange` and page-aligned `PageRange` values with explicit
  caller-selected page size, overflow rejection, and page-covering plans;
- caller-owned `AddressSpaceId`, `MappingId`, and non-wrapping
  `MappingGeneration` values;
- immutable mapping snapshots, exact expected-generation revalidation, and
  typed invalidations for protect, unmap, remap, COW, fork, truncate, discard,
  filesystem invalidation, exec, and teardown;
- field-private `PinRequest` values carrying access, duration, use, range, and
  accounting owner;
- a fixed-capacity, allocation-free pin policy registry with per-owner and
  per-registry pages, bytes, and token quotas;
- a separate fixed-capacity `PinBudget` whose opaque charges enforce one real
  system-wide page, byte, and token bound across independent address spaces;
- two-phase reservation/publication, rollback on failed generation or access
  revalidation, read/read overlap, write-exclusive overlap, mutation admission,
  non-wrapping tokens, and explicit close/teardown states;
- cross-VMA pin publication through ordered `revalidate_next` calls, so an SG
  I/O range is not incorrectly forced into one backend or mapping snapshot;
- generation-safe `FaultKey`, typed fault requests/dispositions, finite
  capacity admission values, stale-reply validation, and a `FaultPort` seam for
  a lower generic broker; and
- arithmetic-only page-covering, memlock, affine-origin, and remap-fragment
  planners, including canonical low-address rebasing and one whole-remap
  backend anchor pair for every fragment.

## Layer boundary

The generic VM/ax layer owns mapping identity storage, frame/page-cache pin
counters, range leases, page-table cursors, TLB invalidation, physical scatter
segments, observer registration, and the concrete bounded fault broker. This
crate consumes immutable identities and mechanism facts; it does not allocate
those identities or implement those mechanisms.

The kernel adapter owns VMA indexing and locks, COW/file fault execution, frame
and page-cache pins, dirty-on-unpin work, filesystem invalidation, security
hooks, signals, errno mapping, and publication into page tables. Syscall code
owns raw ABI decoding and all userspace copyin/copyout.

`FaultPort` is only a dependency-inversion seam. The crate does not contain a
queue, waiter table, observer list, wakeup implementation, readiness source, or
userfaultfd file. Version 0.1.0 therefore does not claim userfaultfd support.

## Pin transaction

The consumer follows this sequence:

1. freeze the current address-space identity and build a `PinRequest`;
2. reserve a `PinBudgetCharge` from the consumer's system-shared budget before
   acquiring any lower pin ownership;
3. call `PinRegistry::reserve` to charge owner/per-registry quotas and reserve
   a unique address-space token before blocking work;
4. snapshot and fault each covered mapping without holding the VMA/page-table
   lock across blocking work, breaking COW before writable exposure;
5. call `revalidate_next` for every contiguous covered mapping segment in
   ascending order while holding the consumer's topology publication
   serialization;
6. publish lower frame/page-cache pins and call `commit` only after the whole
   page range has revalidated; and
7. after synchronous completion, verified async completion, or cancellation,
   release lower frame/page-cache ownership, the registry token, and finally
   the system charge.

Any `revalidate_next` generation, range, or access failure removes the pending
record and refunds both quotas; the consumer still drops any lower partial
frame/page-cache pins it prepared. An abandoned reservation must be explicitly
cancelled; forced teardown cancels all unpublished reservations and waits for
active mechanism pins to release. Mapping mutations ask `admit_mutation` before
changing an overlapping range. System charges are intentionally separate from
registry teardown so the embedding kernel can keep them alive until its last
mechanism owner has actually released.

## Error and stability contract

`MmError` is a stable typed policy error. The embedding adapter maps it to the
correct syscall-specific Linux errno or signal; the crate does not freeze one
errno for operations whose Linux call sites intentionally differ.

The 0.1 contract freezes checked arithmetic, identity/generation matching,
bounded accounting, rollback, overlap, mutation, close/teardown, stale fault
completion, and remap geometry. It does not freeze a VMA tree, lock, RCU/epoch
scheme, page-table implementation, frame type, physical-address format,
filesystem interface, or fault-broker storage layout.

See `VENDOR.md`, `PATCHES.md`, and `NOTICE` for exact provenance and research
anchors.
