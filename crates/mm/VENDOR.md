# Source and research record

## TheKernel extraction baseline

- Repository: <https://github.com/chenty2333/TheKernel>
- Source baseline: `dbbaea9ff0ee6c63bdfb9d9828d4a8d25ba8d0b1`
- Clean integration reference: `e2d71c70dcca88e4955dfd59571077f24db7808e`
- License: Apache-2.0
- Relevant maintained paths:
  - `kernel/src/mm/`
  - `kernel/src/syscall/mm/mmap.rs`
  - `kernel/src/syscall/mm/mincore.rs`
  - `kernel/src/syscall/mm/process_vm.rs`
- Contract: TheKernel RFC 0004 at
  `0e24cb7acc37eab762db97b1dbdbb73924679a19`.
- Local architecture baseline reviewed: `TheKernel Feature Layering System
  Design`, dated 2026-07-10.

The package is a new policy extraction and has no pre-existing registry
archive, upstream crate manifest, checksum, or Cargo VCS record to preserve.
The active package manifest is the original manifest for this new package;
inventing a vendor `Cargo.toml.orig` would misrepresent provenance.

The 0.1 implementation re-expresses the RFC contract as independent checked
values, policy state, and arithmetic planners. It does not copy TheKernel's
concrete page-table, frame, VFS, task, usercopy, address, or lock types.

## Contract research snapshots

Observable lifetime and ownership contracts were checked by RFC 0004 on
2026-07-12 against:

- Linux `44696aa3a489d2baf58efa61b37833f100072bee`, especially `mm/gup.c`,
  `include/linux/mmu_notifier.h`, `mm/mmu_notifier.c`, `fs/userfaultfd.c`,
  `mm/userfaultfd.c`, and `include/uapi/linux/userfaultfd.h`;
- Fuchsia/Zircon `8fe57fc696e6ccd1d8f7f48959116d17db467eaa`, especially page-source,
  pager-dispatcher, pinned-VM-object, and paged-VM-object implementations; and
- Asterinas `37411049265056135a5e18c8c75a0c3d16b18579`, especially VMAR fault,
  fork, interval-set, and VM-space implementations.

Linux is GPL-2.0-only, the reviewed Zircon source uses an MIT-style license,
and the reviewed Asterinas files are MPL-2.0. This package reimplements public
contracts and general architecture in Rust; it does not copy their source.
