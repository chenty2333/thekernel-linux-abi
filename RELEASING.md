# Release Process

Each crate has an independent 0.x version. Incompatible public API changes
bump the minor version; compatible fixes bump the patch version.

## Checklist

1. Confirm the release commit is clean and all provenance assets are present.
2. Run `./scripts/ci.sh` with stable for stable packages and with the pinned
   TheKernel nightly for the complete workspace.
3. Run `./scripts/test-package.sh`; inspect the unpacked package inventory.
4. Build registry-only consumers and TheKernel consumers for RISC-V and
   LoongArch.
5. Update `CHANGELOG.md` and the crate patch ledger.
6. Run `cargo publish --dry-run -p <package>`.
7. Publish only with explicit maintainer authorization.
8. Download the released archive, record its checksum, and rerun its tests.

## Dependency order

The 0.1.0 registry order is usercopy, process, VFS, FD, then signal. Signal is
last because its registry manifest depends on the published usercopy version;
the other three packages are independent. Future credential and MM packages
are published only after their respective semantic and real-consumer gates.
No empty `thekernel-linux-abi` facade is published.
