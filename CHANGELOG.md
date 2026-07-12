# Changelog

All notable workspace releases are recorded here. Each crate also maintains a
crate-local change and provenance ledger.

## Unreleased

- Establish the Linux ABI monorepo governance, provenance, release, and CI
  baseline.
- Prepare `thekernel-linux-usercopy` 0.1.0 as the first release candidate.
- Prepare `thekernel-linux-process` 0.1.0 with explicit domain/registry
  ownership, mandatory generic zombie snapshots, unique job-control identities,
  domain-wide thread accounting, and SMP concurrency gates.
- Prepare `thekernel-linux-signal` 0.1.0 as a nightly release candidate with
  explicit-context usercopy, bounded pending queues, exact shared-account
  refunds, cancellation-safe two-phase thread registration and delivery
  quiescence, generation-safe one-shot actions, transactional
  context/mask/alternate-stack restore, and dual-architecture gates.
- Prepare `thekernel-linux-vfs` 0.1.0 with immutable path contexts, strict
  resolve policy, bounded traversal, Linux DAC/create rules, and rollback-safe
  mutation publication.
- Prepare `thekernel-linux-fd` 0.1.0 with bounded FD/OFD state, retained
  registration accounting, transactional close/publication, epoll delivery,
  finite graph validation, and explicit recovery budgets.
