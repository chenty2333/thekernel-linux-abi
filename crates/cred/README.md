# thekernel-linux-cred

`thekernel-linux-cred` is an independent, allocation-aware credential policy
leaf for `no_std` Linux ABI kernels. The 0.1.0 extraction slice provides:

- distinct kernel-global and namespace-visible UID/GID types;
- immutable, bidirectional user-namespace ID maps with bounded extent counts;
- immutable credential and capability-set values whose invariants are checked
  before publication by a consumer; and
- namespace-capability topology decisions over an immutable caller-provided
  namespace view.

The crate does not own a concrete user namespace, namespace lifetime or signal
accounting, a credential publication slot, a process, VFS object, signal
queue, address space, security-hook registry, exec transition, syscall, or
errno type. A kernel adapter owns those objects and passes frozen values into
this crate. In particular, `thekernel-linux-cred` does not depend on the
process, VFS, signal, FD, MM, usercopy, `kspin`, or other kernel mechanism
crates.

## Toolchain

Version 0.1.0 is intentionally nightly-only and is tested with
`nightly-2025-05-20`. Fallible `Arc` allocation uses Rust's `allocator_api` so
allocation failure remains `CredError::NoMemory` rather than a panic or abort.
There is no stable `rust-version` claim for this package. The nightly
requirement is not a synchronization dependency; consumers select and own
their publication and locking mechanism.

## Provenance

This first extraction is based on TheKernel's transactional Credential v2
implementation at commit
`38ed3c257e833a5d92c5246935adf071eb3df283`. Its contract is TheKernel RFC
0001 at commit `c5207dc09b5524eb67c53d181c28dfdf696415b2`.
`VENDOR.md`, `PATCHES.md`, and `NOTICE` record the exact research snapshots,
the independent-leaf boundary, and the behavior deliberately left in the
kernel adapter.
