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
- distinct fallible pre-setattr and infallible post-setattr contexts over a
  typed chmod/chown intent, omission-preserving ownership fields, normalized
  hook-point mode, and typed file-privilege cleanup without importing raw
  iattr masks, core DAC preparation, backend mutation, or registry dispatch;
- distinct typed `inode_create`, `inode_mkdir`, `inode_mknod`, `inode_symlink`,
  `inode_link`, `inode_unlink`, `inode_rmdir`, and `inode_rename` contexts over
  caller-owned source, parent, prospective-entry, and existing-entry
  identities, consumer-prepared final mode bits, checked FIFO/socket versus
  character/block device-number facts, and the exact borrowed symlink target;
- a typed inode-xattr context over borrowed raw names of 1 through 255 bytes
  and opaque value bytes, validated create/replace flags, and an exact-byte
  `security.capability` value class without an xattr store or provider type;
- field-private socket security contexts matching Linux v6.18's create,
  post-create, pair, address, listen/accept, message, name, option, shutdown,
  and Unix-domain leaf roles over immutable actors and borrowed opaque objects;
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
slot, process, VFS object, signal queue, address space, socket transport,
security-hook registry or dispatch, executable lease, exec publication
transaction, xattr store, VFS identity, open transaction, syscall, or errno
type. In particular, the generic inode/file contexts neither look up an object
nor decide whether a normal `O_CREAT` or unnamed `O_TMPFILE` transaction
succeeded, and socket contexts neither resolve an fd nor operate a transport.
A kernel adapter selects the lock, prebuilds immutable replacement maps outside
it, and attaches the remaining objects. Map publication borrows that
caller-owned replacement and clones it into an empty slot, so the guarded
operation neither retires nor destroys map ownership. In particular,
`thekernel-linux-cred` does not depend on the process, VFS, signal, FD, MM,
usercopy, `kspin`, or other kernel mechanism crates.

Inode attribute security keeps the Linux hook point separate from the later
core and backend preparation. `InodeSetattrIntent` selects a typed chmod or
chown family. Chmod carries a checked low-`0o7777` requested mode. Chown carries
independent `Option<Kuid>` and `Option<Kgid>` values so an omitted field is
never collapsed into an explicitly requested current owner; both fields may be
omitted while a non-directory request still carries set-ID or file-privilege
cleanup. `InodeSetattrProposal` is the frozen iattr-equivalent input observed by
the fallible hook: its optional mode and owner fields have not yet passed the
consumer's Linux-style `setattr_prepare`, and `Kill` records selected privilege
cleanup rather than claiming that cleanup already succeeded.

`InodeSetattrContext` binds that proposal to the exact old object snapshot,
immutable actor, independently selected DAC snapshot, and object-owner
namespace. `InodePostSetattrContext` is a separate type for an infallible
notification after successful backend publication and binds the admitted
proposal to the consumer's exact committed object/outcome snapshot. This crate
does not make post dispatch infallible by itself: the embedding registry must
preflight module state before mutation and carry its own linear admission token
through publication. Writable-mount ordering, inode/metadata locking,
`may_setattr`, owner/capability/SGID checks, privilege cleanup, provider
transactions, backend updates, and errno mapping remain consumer-owned.

Named-entry security follows Linux's hook topology rather than collapsing
every namespace addition into one umbrella operation. `InodeCreateContext`
represents only a named regular file, `InodeMkdirContext` only a named
directory, and `InodeMknodContext` FIFO, character-device, block-device, or
socket nodes.
`InodeCreateMode` carries the consumer-prepared final low `0o7777` mode bits;
the context kind supplies the file type. This normalized fact follows Linux's
hook-family topology without claiming byte-for-byte identity with each raw
Linux `umode_t` payload. Character and block operations require a
caller-normalized `rdev`, while FIFO and socket operations forbid one.
`InodeSymlinkContext` instead carries the exact opaque target payload which the
consumer will store; it deliberately has no mode or device number because
Linux's `inode_symlink` hook has neither. `InodeLinkContext` is a separate hard-
link contract which freezes the exact existing source object in addition to the
destination parent and prospective entry. It carries no new inode mode, device
number, or symlink target. The consumer remains responsible for source
eligibility (including protected-hardlink ownership/`CAP_FOWNER` policy),
cross-filesystem rejection, destination revalidation, and publishing a new name
for that same source. Unnamed `O_TMPFILE` creation is not a named inode-create
event.

Removal likewise keeps Linux's hook topology explicit. `InodeUnlinkContext`
and `InodeRmdirContext` each bind the frozen actor and DAC snapshot to a
distinct parent object and opaque existing-entry object; the latter is where a
consumer binds the final name to the exact victim inode snapshot. The two
contexts do not accept a caller-selected `is_dir` flag and carry no invented
mode, link-count, last-link, mountpoint, notification, or backend-emptiness
facts. Writable-mount and `may_delete`-style admission, path-level hooks,
backend support, publication, timestamps, and errno mapping remain with the
embedding VFS transaction.

`InodeRenameContext` binds all four ordered Linux LSM leaf roles separately:
old parent, old source entry, new parent, and new destination entry. It does
not carry rename flags. In the pinned Linux topology, the
`security_inode_rename` wrapper sees `RENAME_NOREPLACE`, `RENAME_EXCHANGE`, and
`RENAME_WHITEOUT`, while an `inode_rename` LSM leaf receives only those four
objects. Ordinary, no-replace, and whiteout operations therefore dispatch one
forward leaf context. An exchange adapter must explicitly dispatch a reverse
context first, short-circuit on its denial, and then dispatch the forward
context. Raw flag decoding and validation, path-level hooks, target
presence/absence rules, DAC/sticky and ancestry checks, backend mutation, and
notification remain outside this independent credential leaf.

`InodeXattrOperation` preserves the four get, list, set, and remove hook
families without flattening absent payloads into empty values. Named operations
borrow exact bytes, impose no UTF-8 requirement, and accept Linux's full
1-through-255-byte name domain after the syscall terminator is removed, while
rejecting embedded NUL. Set operations borrow the exact opaque value bytes and
carry `XattrSetFlags`, which accepts only zero, create, or replace and rejects
the contradictory create-plus-replace combination and unknown bits. The set
constructor derives `XattrValueClass::SecurityCapability` only for the exact
`b"security.capability"` bytes; this is a policy-facing wire-value
classification, not a parsed `FileCapabilities`, provider object, or VFS type.

`InodeXattrContext` binds that borrowed operation to the exact actor,
independently selected DAC snapshot, target-owner namespace, and opaque target
object. Namespace visibility and authority, DAC admission, lookup, mount
writability, value/list size limits, xattr storage, provider transactions,
pre/post hook dispatch, and errno mapping remain in the embedding consumer.

Socket security follows the Linux v6.18 leaf topology without importing a
socket implementation. `SocketCreateSpec` preserves raw family/protocol and
kernel-origin facts but accepts only a base socket type after descriptor flags
have been validated and removed. The same spec is retained across
`SocketCreateContext` and `SocketPostCreateContext`; pair and accept contexts
keep both endpoint roles independently typed. Bind/connect borrow an exact
prepared address plus its hook-visible length. Listen accepts a nonnegative
`SocketListenBacklog` only after the consumer has applied its network-namespace
cap, while shutdown deliberately retains raw `how`.

Message contexts borrow a consumer-prepared opaque message snapshot and retain
the hook-visible size. The prepared send snapshot must itself freeze the
normalized/raw `msghdr` flags because Linux's `socket_sendmsg` leaf has no
separate flags argument. `SocketReceiveMessageContext` additionally retains
the separate raw flags present in the `socket_recvmsg` leaf prototype. Local
and peer name hooks remain distinct, as do get-option and set-option. Unix
stream connect preserves connecting, listening, and newly accepted roles;
Unix may-send preserves sending and receiving roles. Address import, fd/OFD
pinning, backlog policy, transport locking, module registry state, dispatch,
and errno mapping all remain consumer-owned.

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
