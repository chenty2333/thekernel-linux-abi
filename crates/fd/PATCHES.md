# Extraction and semantic ledger

## TheKernel source behavior retained

- Keep numeric descriptors separate from shared open file descriptions.
- Share OFDs across dup/fork while copying descriptor-local close-on-exec state.
- Identify epoll interests by OFD plus the descriptor used for `ADD`.
- Preserve error/hangup readiness independently of requested normal bits.
- Follow check-arm-check registration and generation-based stale wake rejection.
- Reject nested epoll cycles and excessive path depth before publication.
- Coalesce ready notifications without allocating in the wake path.

## 0.1.0 extraction changes

- Replace implicit task/file-table lookup with caller-owned bounded state and
  explicit stable identities.
- Split descriptor reservation from publication and return unpublished
  ownership on every failure.
- Pre-admit close transaction and ready-queue storage.
- Replace fire-and-forget waker installation with retained aggregate
  registrations, finite accounting, and cancellation on every terminal path.
- Remove the fixed public eight-source aggregate size; callers declare and pay
  for an object's actual maximum topology before arming.
- Carry delivered readiness in the opaque delivery token so a userspace
  copyout fault can restore the exact event plus concurrent wakeups.
- Keep a ready item queued when delivery generation allocation fails.
- Add generation-tagged finite graph storage, unique reverse-parent accounting,
  cycle/depth checks, and a bounded graph-walk budget.
- Reject `EPOLLEXCLUSIVE` until cross-instance source selection exists.

## Deliberately not frozen

- concrete kernel file, lock, task, waker, and errno types;
- map/list/tree choice and ready-queue layout;
- RCU, epoch reclamation, deferred destruction, and per-CPU caches;
- raw syscall structs and generic driver event bit representations;
- a public `Pollable` trait or one-token aggregate fiction; and
- io_uring request/completion or MM pin implementations.
