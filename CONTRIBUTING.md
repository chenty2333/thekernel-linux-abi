# Contributing

Contributions are welcome when they preserve the repository's layer and
ownership boundaries.

Before submitting a change:

1. explain whether it is generic mechanism, Linux ABI policy, or adapter glue;
2. keep provenance/branding edits separate from semantic edits;
3. avoid implicit kernel globals and infallible allocation on user-triggered
   paths;
4. add semantic, rollback, and concurrency tests proportional to the change;
5. run the relevant direct commands, normally `cargo +nightly fmt --all --
   --check`, workspace Clippy/tests, and the Rust 1.85 tests for stable crates;
   and
6. update the affected crate changelog and patch ledger.

Package-unpack and publish dry-runs are release preparation commands and are
not part of every source-only pull request. The manual `Release Check` workflow
shows each of them as an independent step.

Unless explicitly stated otherwise, intentionally submitted contributions are
licensed under Apache-2.0 as described by the repository license.
