# thekernel-linux-cred

`thekernel-linux-cred` is an independent, allocation-aware credential policy
leaf for `no_std` Linux ABI kernels. The 0.1.0 extraction slice provides:

- distinct kernel-global and namespace-visible UID/GID types;
- immutable, bidirectional user-namespace ID maps with bounded extent counts;
- immutable user-namespace hierarchy/owner facts plus lock-neutral, one-write
  UID/GID map and irreversible `setgroups` publication state;
- allocation-free parsing and normalized, validated values for Linux
  `security.capability` revisions 1, 2, and 3;
- pure set-ID/file-capability exec derivation into an opaque proposal bound to
  the exact old credential snapshot, plus typed dumpability, aux-identity,
  ptrace-revalidation, and commoncap decisions;
- typed ptrace, traceme, and scheduler authorization contexts over immutable
  credentials and caller-owned opaque object identities, with policy-neutral
  commoncap decisions and no caller-supplied ownership shortcut;
- typed signal source, delivery-scope, and validated-number values plus an
  opaque core-authorization proof bound to the exact actor/target credentials
  and caller-owned target identity;
- typed inode-permission and file-open contexts which bind the exact actor,
  separately selected DAC snapshot, target-owner namespace, caller-owned
  object identity, and normalized non-empty access/open facts, including
  Linux's reserved ioctl-oriented no-data access mode 3;
- immutable credential and capability-set values whose invariants are checked
  before publication by a consumer;
- ordinary transitions represented by an opaque proposal bound to the exact
  old Linux credential `Arc`, with borrowed old/proposed views and typed
  dumpability/parent-death effects; and
- namespace-capability topology decisions over an immutable caller-provided
  namespace view.

The crate owns a concrete namespace *policy core*, but not the embedding
namespace wrapper, synchronization, lifetime admission, procfs identity, or
signal queue/accounting extension. It also does not own a credential publication
slot, process, VFS object, signal queue, address space, security-hook registry
or dispatch, executable lease, exec publication transaction, xattr store,
VFS identity, open transaction, syscall, or errno type. In particular, the
generic inode/file contexts neither look up an object nor decide whether a
normal `O_CREAT` or unnamed `O_TMPFILE` transaction succeeded. A kernel adapter
selects the lock, prebuilds immutable replacement maps outside it, and attaches
the remaining objects. Map publication borrows that caller-owned replacement
and clones it into an empty slot, so the guarded operation neither retires nor
destroys map ownership. In particular,
`thekernel-linux-cred` does not depend on the process, VFS, signal, FD, MM,
usercopy, `kspin`, or other kernel mechanism crates.

`FileOpenAccess::NoData` describes the persistent mode-3 file description, not
its earlier Linux `ACC_MODE` permission admission. It therefore reports neither
read nor write data access while still allowing a consumer to record a
successful `O_TMPFILE` transaction as both created and unnamed: Linux admits
mode 3 with `MAY_READ | MAY_WRITE` before producing a no-data description.

`O_PATH` is deliberately absent from `FileOpenAccess` and
`FileOpenOperation`. In the pinned Linux topology, `do_dentry_open()` completes
an `FMODE_PATH` description and returns before `security_file_open`; a consumer
therefore keeps path-only semantics in its VFS/FD layers and skips file-open
context construction and hook dispatch.

`InodePermissionAccess` in this 0.1 vertical slice carries only a normalized,
non-empty read/write/execute request. It does not claim the complete Linux
`security_inode_permission` mask: qualifiers such as `MAY_APPEND`, `MAY_OPEN`,
`MAY_ACCESS`, `MAY_CHDIR`, and `MAY_NOT_BLOCK` remain adapter-owned until a
later hook contract represents their policy and nonblocking semantics. The
append fact in `FileOpenOperation` is an independent file-open event and does
not widen the inode-permission payload.

The exact-old check deliberately covers the Linux credential core only. A
consumer that wraps one core in multiple kernel-owned composite credentials
must bind the exact outer credential or publication slot in its own token as
well; this crate neither sees nor looks up that extension state.

The 0.1 public surface uses one canonical spelling for namespace entry and one
for filesystem-credential snapshots. Pre-release compatibility spellings were
removed before the API freeze so new consumers do not accidentally depend on
duplicate entry points.

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
