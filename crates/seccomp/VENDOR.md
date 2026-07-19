# Source and research record

## TheKernel consumer baseline

- Repository: <https://github.com/chenty2333/TheKernel>
- Consumer baseline: `0c6d5e68acd274f2950ec1a66fdb7787f1ab291c`
- License: Apache-2.0
- Package authors:
  - 朝倉水希 <asakuramizu111@gmail.com>
  - Mivik <mivikq@gmail.com>
  - 陈天意 <hi@tychen.cc>
- Relevant maintained paths:
  - `kernel/src/syscall/sys.rs`
  - `kernel/src/syscall/dispatch.rs`
  - `kernel/src/syscall/task/ctl.rs`
  - `kernel/src/task/`
  - `kernel/src/signal/`
  - `kernel/src/bpf/`

The consumer baseline is the exact TheKernel commit from which the first
seccomp adapter work began. Its existing `kernel/src/bpf/` implementation is
an eBPF subsystem and is not reused as a classic-BPF verifier. The baseline is
not a claim that the seccomp syscall, actions, task inheritance, or consumer
integration were complete at that commit.

This package is a new policy extraction and has no pre-existing registry
archive, upstream crate manifest, checksum, or Cargo VCS record to preserve.
The active package manifest is the original manifest for this new package;
inventing a vendor `Cargo.toml.orig` would misrepresent provenance.

The 0.1 implementation defines independent checked values, immutable policy
state, and bounded accounting. It does not copy TheKernel's task, credential,
signal, ptrace, syscall, usercopy, audit, FD, readiness, lock, or executor
types.

## Generic mechanism dependency

- Package: `thekernel-axcbpf` 0.1.0
- Repository: <https://github.com/chenty2333/thekernel-ax>
- Reviewed implementation commit: `a2b4f6f7e0bfbb1ca4bdf4fef45e104185749705`
- Package/release commit: `5c34536fd766b5f84f2fb8e6b18a2ab340659582`
- License: Apache-2.0
- Maintained path: `crates/thekernel-axcbpf/`

`thekernel-axcbpf` owns the ordinary classic-BPF instruction representation,
structural verification, immutable program storage, input trait, and
allocation-free A/X/M interpreter. This seccomp package depends on its exact
registry version and adds only the Linux seccomp opcode/input profile and
policy state. The two commits have the same `crates/thekernel-axcbpf` tree; the
later commit closes repository-level publication gates without changing the
crate source. The dependency is packaged and tested separately from that exact
release commit during the coordinated pre-publication gate; its source is not
copied into this package archive.

## Linux contract research snapshot

Observable UAPI and policy contracts were checked on 2026-07-19 against the
Linux v6.12 tag, commit `adc218676eef25575469234709c2d87185ca223a`, especially:

- `include/uapi/linux/seccomp.h`;
- `include/uapi/linux/filter.h`;
- `include/uapi/linux/audit.h`;
- `kernel/seccomp.c`;
- `kernel/bpf/core.c`;
- `net/core/filter.c`; and
- `tools/testing/selftests/seccomp/seccomp_bpf.c`.

The reviewed contracts include the 64-byte `seccomp_data` layout, classic-BPF
profile restrictions, program and ancestry limits, immutable newest-first
filter stacking, signed action precedence, equal-action data selection,
strict/filter mode transitions, inheritance, and TSYNC ancestry eligibility.
In particular, `seccomp_attach_filter()` checks `filter->prog->len` only after
`bpf_prog_create_from_user()` has prepared the program. On the reviewed eBPF
migration path, `bpf_migrate_filter()` replaces the source length with the
length calculated by `bpf_convert_filter()`: a three-instruction cBPF
prologue, opcode-dependent expansion, and then runtime/JIT selection.

Version 0.1 records only that v6.12 unblinded migration length. The review also
confirmed that constant blinding can replace immediate operations with longer
BPF instruction sequences before a successful JIT, while native `jited_len`
and the byte-valued `bpf_jit_limit` are separate from seccomp's 32768 path
formula. The package therefore does not claim exact accounting for
`bpf_jit_harden`, direct cBPF-JIT architectures, or native executable memory.

Linux is GPL-2.0-only, with Linux UAPI headers carrying their own syscall-note
license expressions. This package reimplements public contracts and general
architecture in Rust; it does not copy Linux implementation source.
