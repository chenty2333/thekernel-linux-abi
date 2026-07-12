# Source and research record

## TheKernel extraction baseline

- Repository: <https://github.com/chenty2333/TheKernel>
- Source baseline: `dbbaea9ff0ee6c63bdfb9d9828d4a8d25ba8d0b1`
- License: Apache-2.0
- Relevant maintained paths:
  - `kernel/src/file/fd_table.rs`
  - `kernel/src/file/desc.rs`
  - `kernel/src/file/epoll.rs`
  - `kernel/src/file/pollable.rs`
  - `kernel/src/syscall/io_mpx/`
- Design contract: TheKernel RFC 0003, commit `3849af2` on the
  `codex/ecosystem-0.1` integration line.

The package is a new extraction and therefore has no pre-existing registry
archive, upstream crate manifest, checksum, or Cargo VCS record to preserve.
The active package manifest is the original manifest for this new package;
inventing a vendor `Cargo.toml.orig` would misrepresent provenance.

## TheKernel retained-registration experiment

The contract records these local history anchors:

- `a5ecd54047288c63510defd954ee3e283583f950`: bounded cancellable per-source
  registrations;
- `87815fde7a4219b91641559c3618c947dc7b4934`: fixed-capacity aggregate
  rollback; and
- `cc09058dc94bd0c3599e3f5538a55a8981026af5`: pipe, net, VFS, timer, signal,
  epoll, timeout, and close consumer experiment.

The 0.1 extraction keeps the observed lifecycle lessons but removes the
experiment's arbitrary public eight-source aggregate limit.

## Contract research snapshots

Observable behavior and ownership ideas were checked on 2026-07-12 against:

- Linux `44696aa3a489d2baf58efa61b37833f100072bee`, especially
  `fs/eventpoll.c`, `fs/select.c`, and `io_uring/poll.c`;
- FreeBSD `62e22d7cfc1ca1c25bede6aaeca370c163a9a1ef`, especially
  `sys/kern/kern_event.c`; and
- `thekernel-ax` commit `f0f9f3a8769c262b9aa827d86710f0d6b7665fd5`
  for the first independently packaged generic `PollSet` contract.

Linux is GPL-2.0-only and FreeBSD is BSD-licensed. This package reimplements
observable contracts and general architecture in Rust; it does not copy their
source.
