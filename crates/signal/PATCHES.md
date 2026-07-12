# Patch ledger

This ledger records changes relative to `starry-signal 0.3.0` identified in
`VENDOR.md`.

## TheKernel pre-migration maintenance

- Bound standard signals to fixed inline slots and real-time signals to
  intrusive FIFO nodes with exact per-user/global account refunds.
- Make endpoint creation and immutable thread-registry publication fallible and
  rollback-safe.
- Return restartability and publication ownership metadata with delivery.
- Validate alternate-stack arithmetic and publish handler context only after
  every userspace write succeeds.
- Make sigreturn restore transactional and filter privileged architecture state.

## `thekernel-linux-signal 0.1.0`

- Rename the package/library while retaining exact upstream provenance.
- Replace implicit `starry-vm` provider selection with an explicit
  `UserMemoryContext` on raw-action reads/writes, signal-frame reads, handler
  frame construction, and pending-signal delivery.
- Make every 64-bit signal-frame ABI alignment hole explicit and zeroed before
  whole-frame usercopy. Keep raw `SignalInfo` storage private so safe values
  cannot carry uninitialized padding into userspace.
- Give each thread endpoint one unique process-registry identity. Explicit
  cancellation linearizes with publication, prevents post-cancel queueing,
  drains private pending state, and refunds every real-time queue charge.
- Make the two-phase registration commit fallible so concurrent cancellation
  cannot be reversed by a stale admission token.
- Quiesce complete handler delivery during endpoint cancellation; teardown
  cannot return while an already-started copyout can still publish context or
  mask state.
- Make `SA_RESETHAND` a generation-checked delivery claim. Copyout failure
  rolls back, concurrent action replacement wins, and generation exhaustion
  reports `SignalActionUpdateError::GenerationExhausted` without wrapping.
- Serialize the real alternate-stack snapshot into every signal frame and
  prepare validated `uc_stack` updates for sigreturn. Consumers supply address,
  minimum-size, and active-stack policy; Linux-compatible non-copy restore
  errors are observable but squashed. Keep `SS_AUTODISARM` unsupported until
  its delivery/reset lifecycle is implemented end to end.
- Depend only on `thekernel-linux-usercopy` inside this Linux ABI workspace;
  process ownership remains an explicit caller concern.
- Keep `kspin/smp` enabled for standalone tests and package builds.
- Pin the maintained `axcpu` line and the compatible x86_64 support crate used
  by the declared nightly so fresh and unpacked package resolution cannot
  silently select an incompatible API.
- Accept unaligned Linux `rt_sigaction` and signal-frame user addresses through
  the explicit usercopy context.
- Give every queue account and process thread registry an immutable finite
  ceiling, reject `usize::MAX`, and return typed capacity/configuration errors.
- Reject bare-metal builds without `multitask` so usercopy, allocation, and
  immutable-registry destruction never run under `SpinNoIrq`.
- Protect the immutable registry owner with the sleepable kernel mutex, and
  detach manager-held registration `Arc`s before dropping short IRQ-safe
  guards. No registry snapshot clone or final entry destruction runs with
  interrupts disabled.
- Add one-shot prepared/deferred signal-send tokens. Process-directed sends
  fallibly retain a bounded exact registration cohort before an embedding
  security transaction; process and thread commits recheck identity and move
  fixed queue state without allocation, sleepable registry locking, or
  arbitrary destruction. Deferred ownership is released by the caller after
  its outer IRQ-disabled guards.
- Resolve thread-directed preparation through the sleepable process snapshot
  and retain the exact active registry entry. Cancelling and later
  re-registering the same manager cannot make an old prepared token valid.
- Declare the package nightly-only: `Arc::try_new` preserves real OOM errors;
  allocator pre-reservation is not treated as a substitute.
