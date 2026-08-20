# Contributing

Contributions are welcome when they preserve the repository's layer and
ownership boundaries.

Before submitting a change:

1. explain whether it is generic mechanism, Linux ABI policy, or adapter glue;
2. keep provenance/branding edits separate from semantic edits;
3. avoid implicit kernel globals and infallible allocation on user-triggered
   paths;
4. add semantic, rollback, and concurrency tests proportional to the change;
5. run `./scripts/ci.sh all`; and
6. update the affected crate changelog and patch ledger.

Package-unpack and publish dry-runs belong to `./scripts/ci.sh release` and are
required when preparing a release, not for every source-only pull request.

Unless explicitly stated otherwise, intentionally submitted contributions are
licensed under Apache-2.0 as described by the repository license.
