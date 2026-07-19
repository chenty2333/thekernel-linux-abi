# Release Process

Each crate has an independent 0.x version. Incompatible public API changes
bump the minor version; compatible fixes bump the patch version.

## Checklist

1. Confirm the release commit is clean and all provenance assets are present.
2. Run `CARGO_TOOLCHAIN=1.85.0 ./scripts/ci.sh` for stable packages and
   `CARGO_TOOLCHAIN=nightly-2025-05-20 ./scripts/ci.sh` for the complete
   workspace. Both gates enforce the lockfile; stable includes MM, io_uring,
   and packet, while nightly also covers process, signal, credentials, and
   seccomp.
3. Let `scripts/test-package.sh` unpack every archive, verify provenance files,
   reject dependency `path`, `git`, or `workspace` leakage from the
   Cargo-normalized manifest, and test the unpacked source. Cargo-generated
   `[lib]` and `[[test]]` target paths are package-local and intentionally
   allowed.
4. Require rustdoc with warnings denied, hosted semantic/concurrency tests,
   no-default-feature builds, and RISC-V 64 plus LoongArch64 builds.
5. Build registry-only adapters and real TheKernel consumers for both
   architectures. A workspace-only compile is not a consumer gate.
6. Update the workspace and crate `CHANGELOG.md`, README, and patch ledger.
7. Run `scripts/test-publish-dry-run.sh`. Its default set is the eight
   independently resolvable packages: usercopy, process, VFS, FD, credentials,
   MM, io_uring, and packet. Signal and seccomp remain deferred until their
   first dependencies are visible in the registry.
8. Publish only with explicit maintainer authorization. A passing dry-run is
   not authorization to upload, tag, or create a release.
9. Download each released archive, record its checksum, audit its normalized
   manifest again, and rerun its tests as a registry consumer.

## Dependency order

The 0.1.0 registry order begins with the eight independent packages: usercopy,
process, VFS, FD, MM, credentials, io_uring, and packet. Signal follows usercopy
because its registry manifest depends on that published version. Seccomp
follows the separate `thekernel-axcbpf` 0.1.0 release from the `thekernel-ax`
repository.
Credentials and seccomp require the pinned nightly for fallible
`allocator_api`; neither claims a stable `rust-version`. MM, io_uring, packet,
and seccomp remain unpublished until their semantic, package, real-consumer,
and dual-architecture gates all pass. No empty `thekernel-linux-abi` facade is
published.

Before the first upload, the nightly package gate builds signal together with
the packaged usercopy archive and patches the unpacked signal test to that
archive. This proves the source/package relationship without pretending the
unpublished dependency already exists in the registry.

The same gate packages the reviewed `thekernel-axcbpf` commit from its real Git
checkout with that crate's Rust 1.85.0 release toolchain, then packages the
exact `thekernel-linux-seccomp` source against a temporary local registry
source. It verifies that seccomp's registry-form lock checksum equals that real
axcbpf archive, removes only that registry source/checksum while patching to
the unpacked archive, and runs the seccomp tests and no-default-feature check
offline. This is a pre-publication source/package proof, not a registry dry-run.

After an explicitly authorized usercopy upload, wait until version 0.1.0 is
actually visible to an ordinary registry client. Do not hide this propagation
delay behind an unbounded retry loop. Then run:

```bash
SIGNAL_REGISTRY_READY=1 CARGO_TOOLCHAIN=nightly-2025-05-20 \
  ./scripts/test-publish-dry-run.sh thekernel-linux-signal
```

Only that registry-only signal dry-run closes its publication gate. If it
cannot resolve usercopy from the registry, wait and retry manually; do not use
a workspace path or source patch for the final dry-run.

After an explicitly authorized `thekernel-axcbpf` upload, wait until 0.1.0 is
visible to an ordinary registry client, then run:

```bash
AXCBPF_REGISTRY_READY=1 CARGO_TOOLCHAIN=nightly-2025-05-20 \
  ./scripts/test-publish-dry-run.sh thekernel-linux-seccomp
```

Only that registry-only seccomp dry-run closes its publication gate. Do not
set `AXCBPF_REGISTRY_READY` while relying on a path patch or sibling checkout.
