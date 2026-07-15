# Source and research record

## TheKernel consumer baseline

- Repository: <https://github.com/chenty2333/TheKernel>
- Consumer baseline: `f9e30c9f72e3f267621c2d36aafc83e65ab76568`
- License: Apache-2.0
- Relevant maintained paths:
  - `kernel/src/syscall/fs/io_uring.rs`
  - `kernel/src/syscall/fs/io.rs`
  - `kernel/src/file/desc.rs`
  - `kernel/src/file/pollable.rs`
  - `kernel/src/mm/`

The consumer baseline is the exact TheKernel commit from which the first
adapter is being built; it is not a claim that integration was complete at
that commit. The package is a new policy extraction and has no pre-existing
registry archive, upstream crate manifest, checksum, or Cargo VCS record to
preserve. The active package manifest is the original manifest for this new
package; inventing a vendor `Cargo.toml.orig` would misrepresent provenance.

The 0.1 implementation defines independent checked values and bounded
lifecycle state. It does not copy TheKernel's concrete shared-page, syscall,
usercopy, mmap, FD, VFS, readiness, MM-pin, task, lock, or executor types.

## Contract research snapshots

Observable ABI and lifecycle contracts were checked on 2026-07-15 against:

- Linux stable `v6.12.35`, commit
  `783cd2c3dca8b6c434e955b84c20c8940588dc68`, especially
  `include/uapi/linux/io_uring.h`, `io_uring/io_uring.c`,
  `io_uring/register.c`, `io_uring/rsrc.c`, `io_uring/cancel.c`,
  `io_uring/poll.c`, and `io_uring/rw.c`;
- liburing `2.8`, commit
  `80272cbeb42bcd0b39a75685a50b0009b77cd380`, especially `src/setup.c`,
  `src/queue.c`, `src/register.c`, and the public io_uring headers; and
- Asterinas commit `435916bf0714a61e0fd1ebab5f6486532dedd8e4`, reviewed as
  a Rust Linux-ABI-kernel comparison. No io_uring implementation was present
  in that snapshot, so it is a negative capability comparison rather than an
  implementation source.

Linux kernel sources are GPL-2.0-only, with Linux UAPI material carrying its
own syscall-note/MIT expression. The reviewed liburing library sources are
MIT-licensed, with the repository also carrying LGPL-2.1 material. Asterinas
is MPL-2.0. This package reimplements public contracts and general architecture
in Rust; it does not copy source from any research snapshot.
