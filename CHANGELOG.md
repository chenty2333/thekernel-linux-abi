# Changelog

All notable workspace releases are recorded here. Each crate also maintains a
crate-local change and provenance ledger.

## 0.1.0 - 2026-07-13

- Establish the Linux ABI monorepo governance, provenance, release, and CI
  baseline.
- Release `thekernel-linux-usercopy` 0.1.0 with explicit-context, bounded,
  Linux-compatible unaligned usercopy.
- Release `thekernel-linux-process` 0.1.0 with explicit domain/registry
  ownership, mandatory `Arc`-retained generic zombie snapshots, unique
  job-control identities,
  checked non-wrapping accounting, and SMP concurrency gates.
- Release `thekernel-linux-signal` 0.1.0 as a nightly package with
  explicit-context usercopy, bounded pending queues, exact shared-account
  refunds, cancellation-safe two-phase thread registration and delivery
  quiescence, generation-safe one-shot actions, transactional
  context/mask/alternate-stack restore, sleepable registry ownership, and
  dual-architecture gates.
- Release `thekernel-linux-vfs` 0.1.0 with immutable path contexts, strict
  resolve policy, bounded traversal, Linux DAC/create rules, and rollback-safe
  mutation publication.
- Release `thekernel-linux-fd` 0.1.0 with bounded FD/OFD state, retained
  registration accounting, transactional close/publication, epoll delivery,
  finite graph validation, lock-external payload preparation, and convergent
  generation-tagged recovery budgets.
- Release `thekernel-linux-cred` 0.1.0 as an independent nightly leaf with
  typed kernel/user IDs, immutable credentials and bounded namespace maps,
  exact-old-bound ordinary and exec transitions, strict file-capability
  parsing, and typed commoncap contexts without process, VFS, FD, MM, usercopy,
  or synchronization dependencies.
- Release `thekernel-linux-mm` 0.1.0 as a dependency-free stable policy core
  with checked ranges/identities, generation-safe invalidation and fault
  values, bounded pin accounting and lifecycle, cross-VMA revalidation,
  Linux v6.12 MISSING-only userfaultfd negotiation, canonical partial-range
  registration, resolver policy, and remap/memlock planners without page-table,
  VFS, task, usercopy, raw-pointer, or concrete fault-broker dependencies.
- Gate every package archive with provenance checks, rustdoc warnings,
  registry-only normalized manifests, dual-architecture builds, unpacked
  tests, and independent publication dry-runs.
