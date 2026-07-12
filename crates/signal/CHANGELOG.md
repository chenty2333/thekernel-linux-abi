# Changelog

## 0.1.0 - release candidate

- Preserve bounded standard/real-time pending queues and exact account refunds.
- Preserve fallible endpoint registration and disposition-transition rollback.
- Require an explicit user-memory context for action and signal-frame copies.
- Initialize and assert every 64-bit ABI frame padding byte before usercopy.
- Add unique thread registration plus publication-linearized cancellation and
  exact queued-record refunds during concurrent teardown.
- Make registration commit fallible so a stale admission token reports
  `Cancelled` instead of resurrecting an endpoint after teardown.
- Quiesce already-started handler delivery before cancellation returns.
- Make one-shot action reset copyout-transactional and generation checked,
  with explicit exhaustion instead of ABA wraparound.
- Preserve the real `uc_stack` snapshot in signal frames and make alternate
  stack restoration validated, diagnostic, and part of the infallible
  sigreturn commit. `SS_AUTODISARM` remains honestly unsupported.
- Preserve transactional sigreturn validation and architecture state filtering.
- Accept unaligned Linux signal ABI pointers through explicit byte-address
  usercopy.
- Add finite queue-account and process-thread-registry configuration with
  typed rejection of effective infinity and capacity exhaustion.
- Require the sleepable `multitask` synchronization feature on bare-metal
  targets instead of running usercopy/allocation under an IRQ-off spin guard.
- Move immutable thread-registry snapshots to the sleepable kernel mutex and
  release registration `Arc` ownership only after IRQ-safe guards are gone.
- Test real SMP publication, queue accounting, frame placement, and restore
  behavior on the pinned nightly toolchain.
