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
  - `kernel/src/task/process.rs`
  - `kernel/src/task/access.rs`
  - `kernel/src/task/exec_cred.rs`
  - `kernel/src/task/security.rs`
  - `kernel/src/file/executable.rs`
- Design contract: TheKernel RFC 0001,
  `docs/rfcs/0001-credential-v2.md`, introduced by commit
  `c5207dc09b5524eb67c53d181c28dfdf696415b2`.

This crate is a new extraction and therefore has no pre-existing registry
package, upstream crate manifest, archive checksum, or Cargo VCS record to
preserve. The active package manifest is the original manifest for this new
package; inventing `Cargo.toml.orig` or `.cargo_vcs_info.json` would
misrepresent its provenance.

The baseline contains the full in-kernel Credential v2 integration. Version
0.1.0 of this crate extracts the independent value and topology-policy slice:
typed IDs and ID maps, immutable credential/capability values,
namespace-capability decisions, and a lock-neutral concrete namespace core for
hierarchy, owner, map, and setgroups state. It also extracts strict normalized
parsing of Linux file-capability revisions 1, 2, and 3, and pure exec
credential derivation into an exact-old-bound immutable proposal. Namespace
synchronization, lifetime admission, procfs identity, signal accounting, xattr
storage, executable leases, credential/process/MM publication, security-hook
registry/dispatch, and subsystem adapters remain outside this crate. Typed
ptrace, traceme, and scheduler contexts keep exact caller-owned object payloads
opaque while the crate supplies only commoncap policy. Typed inode-permission
and file-open contexts likewise retain an exact actor, independently selected
DAC snapshot, target-owner namespace, opaque VFS identity, and normalized
operation facts. The file-open payload deliberately has no `O_PATH` variant:
the pinned Linux `do_dentry_open()` path completes `FMODE_PATH` setup and
returns before `security_file_open`. They do not extract concrete inode/file
types, object lookup, registry/dispatch, or open-transaction ownership from the
kernel.

## RFC 0001 research snapshots

The Credential v2 contract was checked on 2026-07-11 against:

- Linux `dd3210c47e8d3ac6b4e9141fc68acc03b38c0ba3`, especially
  `include/linux/cred.h`, `kernel/cred.c`, `include/linux/uidgid.h`,
  `include/linux/user_namespace.h`, `kernel/user_namespace.c`,
  `kernel/signal.c`, `fs/open.c`, `security/commoncap.c`, `security/security.c`,
  `include/linux/lsm_hooks.h`, and `include/linux/lsm_hook_defs.h`; and
- FreeBSD `86691d52a6d3796ad36ba474cf0a9493f6d99202`, especially
  `sys/sys/ucred.h`, `sys/kern/kern_prot.c`, and
  `sys/security/mac/mac_framework.c`.

Linux is GPL-2.0-only and FreeBSD is BSD-licensed. This package independently
implements observable semantics and general architecture in Rust; it does not
copy their source.

## Independent-leaf boundary

`thekernel-linux-cred` has no dependency edge to process, VFS, signal, FD, MM,
usercopy, `kspin`, or a syscall/errno package. Consumers own namespace locks,
lifetime/resource admission and extensions, credential slots, security-hook
registries, VFS object identity and open transactions, exec/MM effects, and
cross-subsystem publication. Future MM policy may depend on this leaf; this
leaf must not depend back on MM or another consumer.
