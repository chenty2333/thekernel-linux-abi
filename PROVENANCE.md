# Provenance Policy

Every migrated registry crate records:

- the immutable upstream package/version and archive checksum;
- the source repository and Cargo-recorded source commit;
- the original authors and license;
- the exact original manifest as `Cargo.toml.orig`;
- a `VENDOR.md` narrative and a maintained patch ledger; and
- the local changes that establish TheKernel's public contract.

A new extraction with no upstream registry identity instead records the exact
TheKernel source commit and paths, contract/RFC commit, research snapshots,
authors, and license. Its active manifest is the original manifest; maintainers
must not invent an upstream archive, `Cargo.toml.orig`, or Cargo VCS record.
Research-derived contracts must also distinguish policy/value reimplementation
from lower mechanism source: a port trait or planner is not provenance for a
concrete queue, page table, frame, VFS, task, or usercopy implementation.
The `thekernel-linux-io-uring` record additionally pins the Linux kernel and
liburing snapshots used for ABI and memory-ordering research, an Asterinas
snapshot used as a negative capability comparison, and the first TheKernel
consumer baseline. Those references do not imply copied implementation or
ownership of mapped-page atomics, FD/VFS/readiness adapters, or execution.
The first `thekernel-linux-mm` userfaultfd policy slice pins Linux v6.12
`adc218676eef25575469234709c2d87185ca223a` for UAPI and state-transition
research. It reimplements those public contracts without copying Linux code
and does not move the concrete queue, waiter, readiness, page installer,
usercopy, FD, or syscall adapter into the crate.

The `thekernel-linux-seccomp` record pins its initial TheKernel consumer
baseline, Linux v6.12 `adc218676eef25575469234709c2d87185ca223a`, and the
Apache-2.0 `thekernel-axcbpf` 0.1.0 mechanism implementation at
`a2b4f6f7e0bfbb1ca4bdf4fef45e104185749705` and its tree-identical package
release commit `5c34536fd766b5f84f2fb8e6b18a2ab340659582`. The generic dependency owns the
ordinary classic-BPF verifier/interpreter; the Linux-ABI package reimplements
only the seccomp profile, filter ancestry, bounded accounting, action
selection, and reusable task-state policy. Neither provenance record implies
copied Linux implementation nor ownership of usercopy, task/thread-group
locking, signals, ptrace, audit, listener FDs, readiness, or all-or-none TSYNC
publication.

Original metadata remains in Git even when it is excluded as package source.
Published packages include the human-readable provenance and patch ledger, but
exclude the vendored upstream Cargo marker and manifest. Cargo reserves those
filenames and may synthesize package-local replacements: `Cargo.toml.orig` is
the active crate manifest before Cargo normalization, and
`.cargo_vcs_info.json` records this repository revision. The package test
distinguishes those generated files from the byte-for-byte upstream records.

Renaming a package never rewrites upstream authorship or implies that local
changes came from upstream. Rebase work begins from the recorded immutable
archive, not from a similarly named branch.
