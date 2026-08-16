# Governance

## Scope

This repository owns reusable Linux ABI policy and lifecycle code used by
TheKernel. It does not own generic ArceOS mechanisms, syscall dispatch,
evaluator behavior, or benchmark-specific policy.

## Maintainers

TheKernel maintainers review and release the workspace. A release requires at
least one maintainer approval, green required CI, a complete provenance
record, and verification in a real x86_64 TheKernel consumer.

## Decision process

Changes are made as small, independently revertible checkpoints. Public API
changes must state:

1. the Linux-visible contract being represented;
2. ownership, lifetime, allocation, and lock rules;
3. cancellation, teardown, and rollback behavior;
4. the error distinctions preserved for the kernel adapter; and
5. whether the change is compatible within the current 0.x minor line.

Disagreements are resolved using code and test evidence. Benchmark results can
motivate investigation but do not override safety or Linux-visible semantics.

## Public API policy

Public surfaces remain minimal and sealed where practical. A module is not
published merely to reserve a name. New crates require standalone tests,
failure-path coverage, and at least one in-tree consumer before release.
