# thekernel-linux-signal

`thekernel-linux-signal` provides bounded Linux signal queues, process/thread
signal managers, architecture signal frames, alternate-stack handling, and
transactional signal restore validation.

The caller owns every `ProcessSignalManager`, queue account, and thread
endpoint. There is no crate-global signal domain or implicit current process.
Thread IDs are unique within one process registry; registration is
rollback-safe, and explicit cancellation stops later publication while
draining and refunding thread-private queued records. Cancellation also
quiesces a delivery that already started, so handler context and mask updates
cannot complete after endpoint teardown returns.

Registration is a two-phase operation. `try_register(tid)` returns an
admission token; dropping that token rolls the admission back, while
`commit()` activates it. `commit()` is fallible and returns
`ThreadRegistrationError::Cancelled` if concurrent teardown cancelled the
admission first. An embedding kernel must call `cancel_registration()` during
thread teardown before releasing the endpoint.

Every userspace action/frame copy receives an explicit
`UserMemoryContext`; the crate never obtains the current task or address space.
Its only TheKernel Linux ABI workspace dependency is
`thekernel-linux-usercopy`.

All supported 64-bit signal-frame alignment holes are represented by explicit
zeroed fields before an object is written to userspace. `SignalInfo` keeps its
raw storage private so safe construction preserves the fully initialized-byte
invariant. Signal return first copies and validates an owned frame, filters
privileged processor state, validates `uc_stack` through caller-supplied
address/minimum-size policy, and only then commits context, mask, and any valid
alternate-stack update. As on Linux, non-copy `restore_altstack()` errors are
recorded on `PreparedSignalRestore` but do not reject machine-context restore.
`SS_AUTODISARM` is not advertised in 0.1.0.

`SA_RESETHAND` delivery uses one non-duplicable claim per disposition
generation. Copyout failure rolls the claim back, a concurrent replacement
invalidates it, and generation exhaustion is a typed error rather than an ABA
wrap. Signal frames expose the actual interrupted alternate-stack snapshot,
including computed `SS_ONSTACK` state.

Version 0.1.0 is nightly-only because fallible `Arc::try_new` queue and
endpoint allocation requires `allocator_api`. It is tested with
`nightly-2025-05-20` and does not claim a stable `rust-version`.

The 0.1.0 release-supported target matrix is hosted x86_64 plus bare-metal
RISC-V 64 and LoongArch64. The inherited AArch64 frame module remains
source-only on this release line because the pinned `axcpu` and nightly pair
does not build that target.

Enable `multitask` in a kernel so action/registry publication uses the
sleepable `axsync::Mutex`. `kspin/smp` remains enabled in every build,
including standalone and unpacked-package concurrency tests.

See `VENDOR.md` and `PATCHES.md` for source identity and semantic changes.
