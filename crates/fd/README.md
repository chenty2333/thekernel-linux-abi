# thekernel-linux-fd

`thekernel-linux-fd` is a `no_std` Linux-visible policy core for descriptor,
open-file-description, retained readiness, and epoll lifecycles. It deliberately
does not obtain a global current task, copy userspace memory, choose a kernel
lock, or expose raw generic-driver event bits as Linux ABI values.

Version 0.1.0 provides:

- a caller-owned fixed-capacity `FdTable` with separate descriptor-local flags
  and shared OFD handles;
- generation-tagged reservation/publication and ABA-safe close operations;
- transactional close-range and close-on-exec batches whose storage is
  admitted before table mutation;
- explicit shared OFD offset/status/async-owner state;
- finite per-owner watch accounting and two-phase aggregate source arming;
- retained registration update/cancel ownership with partial-arm rollback;
- a fixed-capacity epoll interest/ready core with LT, ET, ONESHOT, coalescing,
  copyout-fault replay, post-copy recheck, and stale-generation rejection;
- finite epoll graph, reverse-parent, nesting, cycle, and walk-budget checks;
  and
- an explicit bounded-rescan seam for an unexpected ready-queue invariant
  failure, never periodic scanning or hidden busy polling.

## Layer boundary

Generic wake-source slot ownership belongs in `thekernel-axpoll`. This crate
owns Linux FD/OFD identity and readiness rules over those source registrations.
The kernel adapter supplies stable handles, synchronization, source planning,
check-arm-check orchestration, userspace copyout, timeout/signal handling, and
typed error-to-errno mapping. Syscall entry code should only decode arguments,
freeze a context/table snapshot, invoke the adapter, and copy results.

Every epoll mutation is externally serialized. Removed/replaced interests and
subscriptions are returned to the adapter so cancellation, waker destruction,
and file destruction occur outside short IRQ-safe locks. `EpollGraph` and
`EpollCore` publication must be one adapter transaction; if the second
publication fails, the first is rolled back before releasing the graph lock.

`EPOLLEXCLUSIVE` is rejected in 0.1.0. A single-instance core cannot honestly
implement cross-epoll exclusive selection; it will only be admitted after the
source layer supplies that mechanism. io_uring is likewise not claimed, though
stable generations, aggregate subscriptions, cancellation, and MM-pin seams
are intentionally usable by a future implementation.

## Resource and failure contract

All descriptor, interest, ready-item, graph-node, graph-edge, reverse-parent,
source-registration, and graph-walk limits are finite. `usize::MAX` is rejected
where it could accidentally mean “unlimited.” No full registry silently
replaces an owner, no allocation failure mutates visible state, and delivery
serial exhaustion leaves the ready item queued.

Normal ready publication admits one queue item per interest at construction.
If that invariant is nevertheless violated, the event remains in entry state,
`needs_rescan()` becomes true, and the adapter must call `rescan_ready()` with
an explicit work budget. The crate never falls back to an unbounded scan or
busy loop.

## Stability

The observable lifetime, rollback, cancellation, bit-filtering, and bounded
resource contracts are the 0.1 API. Internal maps, queue layout, locks,
reclamation strategy, RCU/epoch use, and per-CPU caching are deliberately not
fixed and may evolve during 0.x after profiling.

See `VENDOR.md`, `PATCHES.md`, and `NOTICE` for exact provenance and research
anchors.
