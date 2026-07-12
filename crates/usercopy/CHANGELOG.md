# Changelog

## 0.1.0 - unreleased

- Migrate the maintained `starry-vm` user-memory leaf under TheKernel package
  and Rust library identity. Existing consumers may preserve the old extern
  name through a Cargo dependency alias during migration.
- Replace the implicit global `VmImpl::new()` provider with explicit
  `UserMemoryContext` parameters.
- Preserve checked address arithmetic, a 128 KiB NUL-search bound, and
  fallible owned allocation.
- Separate usercopy errors from TheKernel's errno adapter.
