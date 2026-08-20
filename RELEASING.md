# Release Process

Each crate has an independent 0.x version. Incompatible public API changes bump
the minor version; compatible fixes bump the patch version.

## Checklist

1. Confirm the release commit is clean and all provenance assets are present.
2. Run `./scripts/ci.sh all`. This is the same quality and MSRV gate used by
   pull-request CI: the rolling nightly covers the complete workspace, while
   Rust 1.85 covers crates that claim stable support.
3. Check out the exact `thekernel-axcbpf` release source separately and set
   `AXCBPF_SOURCE_ROOT` to that checkout. The ordinary sibling
   `../thekernel-ax` remains the current integration input for source tests.
4. Run `./scripts/ci.sh release`. It reruns the source gates, denies rustdoc
   warnings, unpacks the packages currently supported by the release tooling,
   rejects dependency `path`, `git`, or `workspace` leakage from normalized
   manifests, tests those archives, and performs the available registry
   publish dry-runs.
5. Require hosted x86_64 semantic/concurrency tests and a real TheKernel
   consumer. A workspace-only compile is not a consumer gate.
6. Update the workspace and crate `CHANGELOG.md`, README, and patch ledger.
7. Publish only with explicit maintainer authorization. A passing dry-run is
   not authorization to upload, tag, or create a release.
8. Download each released archive, record its checksum, audit its normalized
   manifest again, and rerun its tests as a registry consumer.

For the current 0.1.0 classic-BPF dependency, a local release check uses:

```bash
AXCBPF_SOURCE_ROOT=/path/to/thekernel-ax-at-5c34536fd766b5f84f2fb8e6b18a2ab340659582 \
  ./scripts/ci.sh release
```

The release workflow materializes this exact checkout independently. This is
necessary because the current `thekernel-ax` integration branch contains newer
unreleased `thekernel-axcbpf` source under the same pre-release package line;
that newer tree is valid for compatibility testing but is not the archive
identity consumed by the 0.1.0 seccomp release proof.

`thekernel-linux-rseq` is part of workspace quality, no-default-feature,
Rust-1.85, and rustdoc coverage. It is not yet included in the repository's
package/publish helpers because its release metadata and provenance asset set
are not complete. Do not describe it as release-qualified until that separate
gap is closed.

## Dependency order

The independently resolvable 0.1.0 packages currently covered by the publish
dry-run helper are usercopy, process, VFS, FD, MM, credentials, io_uring, and
packet. Signal follows usercopy because its registry manifest depends on that
published version. Seccomp follows the separate `thekernel-axcbpf` 0.1.0
release from the `thekernel-ax` repository.

Credentials and seccomp require the rolling nightly for fallible
`allocator_api`; neither claims a stable `rust-version`. MM, io_uring, packet,
and seccomp remain unpublished until their semantic, package, and real-consumer
gates all pass. No empty `thekernel-linux-abi` facade is published.

Before the first upload, the nightly package gate builds signal together with
the packaged usercopy archive and patches the unpacked signal test to that
archive. This proves the source/package relationship without pretending the
unpublished dependency already exists in the registry.

The same gate packages the reviewed `thekernel-axcbpf` commit from its real Git
checkout with that crate's Rust 1.85.0 release toolchain, then packages the exact
`thekernel-linux-seccomp` source against a temporary local registry source. It
verifies the lock checksum against that real axcbpf archive and runs the
unpacked seccomp tests offline. This is a pre-publication source/package proof,
not a registry dry-run.

After an explicitly authorized usercopy upload, wait until version 0.1.0 is
visible to an ordinary registry client, then run:

```bash
SIGNAL_REGISTRY_READY=1 CARGO_TOOLCHAIN=nightly \
  ./scripts/test-publish-dry-run.sh thekernel-linux-signal
```

After an explicitly authorized `thekernel-axcbpf` upload, wait until 0.1.0 is
visible to an ordinary registry client, then run:

```bash
AXCBPF_REGISTRY_READY=1 CARGO_TOOLCHAIN=nightly \
  ./scripts/test-publish-dry-run.sh thekernel-linux-seccomp
```

Only those registry-only dry-runs close the respective publication gates. Do
not set the readiness variables while relying on a path patch or sibling
checkout.
