# Provenance Policy

Every migrated or derived crate records:

- the immutable upstream package/version and archive checksum;
- the source repository and Cargo-recorded source commit;
- the original authors and license;
- the exact original manifest as `Cargo.toml.orig`;
- a `VENDOR.md` narrative and a maintained patch ledger; and
- the local changes that establish TheKernel's public contract.

Original metadata remains in Git even when it is excluded from the crates.io
archive. Published packages include the human-readable provenance and patch
ledger, but exclude upstream Cargo marker files and the original manifest so
Cargo cannot confuse them with active package metadata.

Renaming a package never rewrites upstream authorship or implies that local
changes came from upstream. Rebase work begins from the recorded immutable
archive, not from a similarly named branch.
