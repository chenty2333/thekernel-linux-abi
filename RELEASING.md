# Release Process

Each crate has an independent 0.x version. Incompatible public API changes
bump the minor version; compatible fixes bump the patch version.

## Checklist

1. Confirm the release commit is clean and all provenance assets are present.
2. Run `CARGO_TOOLCHAIN=1.85.0 ./scripts/ci.sh` for stable packages and
   `CARGO_TOOLCHAIN=nightly-2025-05-20 ./scripts/ci.sh` for the complete
   workspace. Both gates enforce the lockfile; stable includes MM and
   io_uring, while nightly also covers process, signal, and credentials.
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
7. Run `scripts/test-publish-dry-run.sh`. Its default set is the seven
   independently resolvable packages: usercopy, process, VFS, FD, credentials,
   MM, and io_uring.
8. Publish only with explicit maintainer authorization. A passing dry-run is
   not authorization to upload, tag, or create a release.
9. Download each released archive, record its checksum, audit its normalized
   manifest again, and rerun its tests as a registry consumer.

## Dependency order

The 0.1.0 registry order is usercopy, process, VFS, FD, MM, credentials,
io_uring, then signal. Signal is last because its registry manifest depends on
the published usercopy version; the other seven packages are independent.
Credentials require the pinned nightly for fallible `allocator_api`, but do
not depend on `kspin` or another workspace package. MM and io_uring remain
unpublished until their semantic, package, real-consumer, and dual-architecture
gates all pass. No empty `thekernel-linux-abi` facade is published.

Before the first upload, the nightly package gate builds signal together with
the packaged usercopy archive and patches the unpacked signal test to that
archive. This proves the source/package relationship without pretending the
unpublished dependency already exists in the registry.

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
