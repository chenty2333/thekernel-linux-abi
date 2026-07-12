# TheKernel Linux ABI

`thekernel-linux-abi` is the monorepo for reusable, `no_std` Linux ABI support
owned by TheKernel. It is deliberately separate from generic ArceOS
mechanisms and from TheKernel's syscall and evaluator layers.

The release candidates currently contain two independent leaf packages:

- `thekernel-linux-usercopy` 0.1.0: explicit-context, bounded, fallible access
  to a caller-provided userspace memory implementation.
- `thekernel-linux-process` 0.1.0: explicit-domain, bounded process lifecycle
  state with a caller-defined zombie payload.

The workspace name is not a facade package. Credential, VFS, FD/readiness,
and MM crates will be added only after their Linux-visible contracts pass the
semantic, failure, concurrency, and dual-architecture gates documented in
this repository.

## Development

The repository pins the same nightly used by its initial TheKernel consumer.
The usercopy crate is additionally checked against stable Rust 1.85 or newer.
The process crate is explicitly nightly-only because preserving fallible
standard `Arc` allocation currently requires `allocator_api`; it does not
inherit or claim a stable `rust-version`.

```bash
cargo test --workspace --all-features
cargo check -p thekernel-linux-usercopy --no-default-features
./scripts/ci.sh
PACKAGE_ALLOW_DIRTY=1 ./scripts/test-package.sh
```

## Boundaries

- Generic scheduling, filesystem, network, page-table, and driver mechanisms
  stay in their `ax-*` or other upstream/fork lines.
- Linux ABI crates do not read an implicit current task, global FD table, or
  global filesystem context.
- Syscall decoding, evaluator policy, and benchmark profiles stay in
  TheKernel.
- Unsupported functionality is reported honestly; a package name is not a
  claim of complete Linux parity.

See [GOVERNANCE.md](GOVERNANCE.md), [CONTRIBUTING.md](CONTRIBUTING.md),
[PROVENANCE.md](PROVENANCE.md), and [RELEASING.md](RELEASING.md).

## License

Apache License 2.0. Vendored and derived sources retain their original
authorship and provenance records.
