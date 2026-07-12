# Patch ledger

This ledger records semantic changes relative to the `starry-vm 0.3.0`
archive identified in `VENDOR.md`.

## TheKernel pre-migration maintenance

- Make owned snapshots use `try_reserve` and report allocation failure.
- Reject pointer arithmetic overflow.
- Bound NUL-terminated snapshots to 128 KiB and report `TooLong`.
- Keep byte access behind a provider trait.

## `thekernel-linux-usercopy 0.1.0`

- Rename the package and Rust library; source-level consumers may temporarily
  retain the `starry_vm` extern name through a Cargo dependency alias.
- Replace `extern_trait` and `VmImpl::new()` with explicit
  `UserMemoryContext<'_, M>` ownership.
- Make the provider safety contract state that every byte is initialized on a
  successful read and that no user address is directly dereferenced.
- Use a crate-owned error type so errno mapping remains kernel adapter policy.
- Require `bytemuck::NoUninit` for safe typed writes; retain an unsafe typed
  write for adapters that can prove padding initialization.
- Keep owned allocation behind an additive `alloc` feature with no default
  features.
- Add an explicitly unsafe bounded NUL loader for raw pointer arrays whose
  representations cannot satisfy `bytemuck::Pod`.
- Add independent-provider, bounds, access, overflow, no_std, and unpacked
  package tests.
