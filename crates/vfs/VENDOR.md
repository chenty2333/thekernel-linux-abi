# Source and research record

## TheKernel extraction baseline

- Repository: <https://github.com/chenty2333/TheKernel>
- Source baseline: `dbbaea9ff0ee6c63bdfb9d9828d4a8d25ba8d0b1`
- License: Apache-2.0
- Relevant maintained paths:
  - `kernel/src/file/permission.rs`
  - `kernel/src/syscall/fs/fd_ops.rs`
  - `third_party/rust-patches/axfs-ng/src/highlevel/fs.rs`
- Design contract: TheKernel RFC 0002, commit
  `5f5619c` on the `codex/ecosystem-0.1` integration line.

The crate is a new extraction and therefore has no pre-existing registry
package, upstream crate manifest, archive checksum, or Cargo VCS record to
preserve. The active package manifest is the original manifest for this new
package; inventing a vendor `Cargo.toml.orig` would misrepresent provenance.

## Contract research snapshots

Observable behavior and ownership ideas were checked on 2026-07-12 against:

- Linux `44696aa3a489d2baf58efa61b37833f100072bee`, especially `fs/namei.c`,
  `include/linux/namei.h`, and `include/uapi/linux/openat2.h`;
- FreeBSD `62e22d7cfc1ca1c25bede6aaeca370c163a9a1ef`, especially
  `sys/kern/vfs_lookup.c` and `sys/sys/namei.h`;
- Fuchsia/Zircon `8fe57fc696e6ccd1d8f7f48959116d17db467eaa`; and
- Asterinas `37411049265056135a5e18c8c75a0c3d16b18579`.

Linux is GPL-2.0-only and FreeBSD is BSD-licensed. This package reimplements
observable contracts and general architecture in Rust; it does not copy their
source. Fuchsia/Zircon and Asterinas were used only for broader handle,
ownership, and fault-isolation design comparison.
