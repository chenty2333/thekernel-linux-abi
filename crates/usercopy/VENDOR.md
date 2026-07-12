# Vendored source record: `starry-vm` to `thekernel-linux-usercopy`

## Immutable upstream baseline

- Registry package: `starry-vm` `0.3.0`
- crates.io archive SHA-256:
  `3596dd192ef0b8c6790c5d3d1c69746c3f94afef46907a5314f1a478917daf53`
- Repository: <https://github.com/Starry-OS/starry-vm>
- Cargo-recorded source commit:
  `13a9296f82ce2d0fd1143cbabca3598948bfffd9`
- Authors: 朝倉水希 `<asakuramizu111@gmail.com>` and Mivik
  `<mivikq@gmail.com>`
- License: Apache-2.0
- Original manifest: `Cargo.toml.orig`, SHA-256
  `8573823b18252e8c8da10e1bc1c7a20cee27057c5d159027715da797a73015e2`
- Original Cargo source record: `.cargo_vcs_info.json`, SHA-256
  `c623c05c243abb71faf51a8449fed0e535331cfea155e3835368944630efe345`
- Original license file: `LICENSE`, SHA-256
  `58d1e17ffe5109a7ae296caafcadfdbe6a7d176f0bc4ab01e12a689b0499d8bd`

The archive checksum is the immutable comparison baseline. The package rename
does not rewrite upstream identity or attribute TheKernel changes to StarryOS.

## Maintained TheKernel source lineage

The source was migrated from TheKernel commit
`dbbaea9ff0ee6c63bdfb9d9828d4a8d25ba8d0b1`. Its vendored patch record named:

- `9d4a3351c25dc92f0b03969b1f375d3f476bf47d` for pinned-toolchain import;
- `aa98717bf6232df2ad584475d962e442f3ad2427` for local manifest cleanup;
- `d38fb1b96d108942e8c52218a7d934db1a24fe72` for bounded, fallible owned
  snapshots and checked address arithmetic; and
- `cb0b0757a7efed8ca5d09fdf4ef3f2ef58dd5cf4` for restoration of immutable
  provenance and upstream tests.

The original source exposed a process-global implementation selected through
`extern_trait` and constructed by `VmImpl::new()`. The 0.1 TheKernel package
removes that hidden dependency and requires one explicit operation context.
Cargo dependency aliases provide temporary source compatibility without
publishing the old Rust library identity. The detailed maintained delta is
recorded in `PATCHES.md`.
