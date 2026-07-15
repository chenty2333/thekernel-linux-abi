# Changelog

## 0.1.0 - 2026-07-15

- Add checked userspace/page ranges, page covering, and stable mapping identity
  and generation values without architecture address types.
- Add immutable mapping snapshots, expected-generation revalidation, and typed
  invalidation ranges/reasons including resident-page discard.
- Add typed pin access/duration/use/owner requests and a fixed-capacity policy
  registry with per-owner/per-registry page, byte, and token accounting.
- Add an allocation-free, fixed-capacity system pin budget with domain-safe,
  non-wrapping charge tokens so independent address-space registries share one
  real aggregate bound.
- Add rollback-safe reservation, cross-VMA ordered revalidation, read/read
  coexistence, write-exclusive overlap, mutation admission, close/teardown,
  and non-wrapping tokens.
- Add generation-safe fault keys, typed requests/dispositions, finite admission
  values, stale-completion validation, and a lower broker port trait without
  claiming a concrete broker or userfaultfd implementation.
- Add a Linux v6.12 userfaultfd policy core: copyout-aware one-shot API
  negotiation, a no-optional-feature initial profile, anonymous-private
  MISSING registration, O(1)-stack all-or-none multi-VMA registration and
  mixed-handler mapping-refresh transactions, allocation-free intersection
  queries, a canonical same-handler partial-registration delta planner,
  fail-closed mapping-lineage revalidation, non-wrapping sealed-revision
  retirement, stateless fault permits, and checked COPY/ZEROPAGE signed-prefix
  results.
- Add affine relocation, whole-remap fragment geometry, page-covering, and
  incremental memlock planners.
- Support dependency-free `no_std`, `forbid(unsafe_code)`, Rust 1.85, RISC-V 64,
  and LoongArch64 consumers.
