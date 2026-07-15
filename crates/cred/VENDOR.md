# Source and research record

## TheKernel extraction baseline

- Repository: <https://github.com/chenty2333/TheKernel>
- Source baseline:
  `38ed3c257e833a5d92c5246935adf071eb3df283`
- Baseline subject: `cred: integrate transactional credential v2`
- License: Apache-2.0
- Relevant maintained paths:
  - `kernel/src/task/idmap.rs`
  - `kernel/src/task/creds.rs`
  - `kernel/src/task/thread_cred.rs`
  - `kernel/src/task/process.rs`
  - `kernel/src/task/access.rs`
  - `kernel/src/task/exec_cred.rs`
  - `kernel/src/task/security.rs`
  - `kernel/src/file/executable.rs`
  - `kernel/src/syscall/task/ctl.rs`
- Design contract: TheKernel RFC 0001,
  `docs/rfcs/0001-credential-v2.md`, introduced by commit
  `c5207dc09b5524eb67c53d181c28dfdf696415b2`.

This crate is a new extraction and therefore has no pre-existing registry
package, upstream crate manifest, archive checksum, or Cargo VCS record to
preserve. The active package manifest is the original manifest for this new
package; inventing `Cargo.toml.orig` or `.cargo_vcs_info.json` would
misrepresent its provenance.

The ordinary-transition ownership closure was additionally checked against
TheKernel commit `608efde9902a6ef57ff81d9602074af144e28b63`, especially the
remaining capability draft, set-ID transition matrix, mapped-root capability
fixups, and syscall-local `capset` admission in the maintained paths above.

The baseline contains the full in-kernel Credential v2 integration. Version
0.1.0 of this crate extracts the independent value and topology-policy slice:
typed IDs and ID maps, immutable credential/capability values,
namespace-capability decisions, and a lock-neutral concrete namespace core for
hierarchy, owner, map, and setgroups state. It also extracts strict normalized
parsing of Linux file-capability revisions 1, 2, and 3, and pure exec
credential derivation into an exact-old-bound immutable proposal. Namespace
synchronization, lifetime admission, procfs identity, signal accounting, xattr
storage, executable leases, credential/process/MM publication, security-hook
registry/dispatch, and subsystem adapters remain outside this crate. A typed
capable context freezes the exact actor, target namespace, validated capability,
and normalized Linux option class only after commoncap admission; it introduces
no current-task lookup or registry edge. Successful-only fork/user-namespace
publication contexts similarly expose exact borrowed core facts and an opaque
consumer target without owning visibility or notification dispatch. Typed
ptrace, traceme, and scheduler contexts keep exact caller-owned object payloads
opaque while the crate supplies only commoncap policy. Typed inode-permission,
file-open, and named-entry contexts likewise retain an exact actor,
independently selected DAC snapshot, target-owner namespace, and opaque VFS
identities. Named-entry contexts preserve Linux's separate
create/mkdir/mknod/symlink/link/unlink/rmdir/rename hook roles; the symlink
context additionally borrows the exact opaque target payload, the link context
borrows the exact existing source object, removal contexts borrow an opaque
existing victim entry separately from its parent, and rename retains all four
ordered old-parent/entry and new-parent/entry roles. The rename leaf accepts no
flags: the consumer owns Linux's one-way ordinary/no-replace/whiteout dispatch
and reverse-then-forward exchange dispatch. Target decoding, protected-hardlink
and `may_delete` admission, raw rename-flag validation, cross-filesystem checks,
and publication remain with the consumer. The inode-xattr leaf similarly
borrows exact name bytes with no UTF-8 requirement plus exact set-value bytes,
enforces Linux's NUL-free 1-through-255-byte name domain, validates
create/replace flags, and classifies the exact `security.capability` bytes
without importing a provider, store, or parsed kernel capability type; lookup,
admission, storage, dispatch, and publication remain with the consumer. The
file-open payload deliberately has no `O_PATH` variant:
the pinned Linux `do_dentry_open()` path completes `FMODE_PATH` setup and
returns before `security_file_open`. They do not extract concrete inode/file
types, object lookup, registry/dispatch, or open-transaction ownership from the
kernel. Socket security contexts likewise borrow consumer-owned socket,
address, and prepared-message snapshots while retaining only the normalized or
raw scalar facts visible at each Linux leaf. They do not extract fd lookup,
transport operations, network namespace policy, socket locking, or hook
registry state. Memory-mapping security contexts similarly borrow opaque file,
image, and pre-change VMA identities while retaining only strict protection,
lossless mapping flags, filesystem/image-owner namespaces, and final-address
facts visible at the three pinned leaves. They do not extract fd/OFD lookup,
address selection, MM locks or transactions, VMA mutation, page-table work, or
registry state.

## RFC 0001 research snapshots

The Credential v2 contract was checked on 2026-07-11 against:

- Linux `dd3210c47e8d3ac6b4e9141fc68acc03b38c0ba3`, especially
  `include/linux/cred.h`, `kernel/cred.c`, `include/linux/uidgid.h`,
  `include/linux/user_namespace.h`, `kernel/user_namespace.c`,
  `kernel/signal.c`, `fs/open.c`, `fs/namei.c`, `security/commoncap.c`,
  `security/security.c`, `include/linux/lsm_hooks.h`, and
  `include/linux/lsm_hook_defs.h`, `include/linux/security.h`, and
  `include/uapi/linux/fs.h`; and
- FreeBSD `86691d52a6d3796ad36ba474cf0a9493f6d99202`, especially
  `sys/sys/ucred.h`, `sys/kern/kern_prot.c`, and
  `sys/security/mac/mac_framework.c`.

Linux is GPL-2.0-only and FreeBSD is BSD-licensed. This package independently
implements observable semantics and general architecture in Rust; it does not
copy their source.

The set-ID and `capset` planners were rechecked on 2026-07-15 against Linux
v6.18 commit `7d0a66e4bb9081d75c82ec4957c50034cb0ea449`, especially
`kernel/sys.c`, `kernel/capability.c`, `security/commoncap.c`,
`include/uapi/linux/securebits.h`, and `include/linux/capability.h`. This check
retains the `setres*` early no-op, the separate `LSM_SETID_ID`/`RE`/`RES` UID
fixup and `LSM_SETID_FS` filesystem-capability fixup families, both commoncap
inheritable constraints, the old-FSID return convention, Linux v6.18's
advisory exec securebits, and their unprivileged changed-bit admission mask.
Linux is GPL-2.0-only; this crate expresses those observable policies
independently as typed Rust inputs and plans while leaving capability and hook
admission in the consumer.

## Linux v6.18 socket-hook research snapshot

The socket security leaf topology was checked on 2026-07-15 against Linux
v6.18 commit `7d0a66e4bb9081d75c82ec4957c50034cb0ea449`, especially:

- `include/linux/lsm_hook_defs.h` for the exact `socket_*`,
  `unix_stream_connect`, and `unix_may_send` leaf prototypes;
- `security/security.c` for wrapper-to-leaf dispatch;
- `net/socket.c` for socket-type flag removal, pre/post-create ordering,
  socket-pair/accept roles, network-namespace backlog clamping, prepared
  message sizes and flags, name/option ordering, and raw shutdown `how`; and
- `net/unix/af_unix.c` for connecting/listening/accepted stream roles and
  sending/receiving datagram roles.

Linux is GPL-2.0-only. This package independently expresses the observable
hook topology as field-private Rust values and borrowed opaque generics; it
does not copy Linux implementation code or expose Linux internal structures.

## Linux v6.18 memory-mapping-hook research snapshot

The memory-mapping security leaf topology was checked on 2026-07-15 against
Linux v6.18 commit `7d0a66e4bb9081d75c82ec4957c50034cb0ea449`, especially:

- `include/linux/lsm_hook_defs.h` for the exact `mmap_file`, `mmap_addr`, and
  `file_mprotect` leaf prototypes;
- `security/security.c` for requested/effective mmap protection derivation,
  anonymous null-file handling, raw flags, and wrapper-to-leaf dispatch;
- `mm/mmap.c` for final-address selection before `mmap_addr` dispatch; and
- `mm/mprotect.c` for requested/effective protection and per-pre-change-VMA
  `file_mprotect` dispatch before VMA and page-table mutation.

Linux is GPL-2.0-only. This package independently expresses the observable
leaf inputs as field-private Rust values and borrowed opaque generics; it does
not copy Linux implementation code or expose Linux file, MM, or VMA types.

## Independent-leaf boundary

`thekernel-linux-cred` has no dependency edge to process, VFS, signal, FD, MM,
network transport, usercopy, `kspin`, or a syscall/errno package. Consumers own
namespace locks, lifetime/resource admission and extensions, credential slots,
security-hook registries, VFS/socket/MM object identity and transactions,
exec/MM effects, and cross-subsystem publication. Future MM or network policy may
depend on this leaf; this leaf must not depend back on MM, network transport,
or another consumer.
