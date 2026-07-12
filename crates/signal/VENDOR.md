# Vendored source record: `starry-signal`

- Registry package: `starry-signal` `0.3.0`
- crates.io archive SHA-256:
  `f72adf2bff529986c36c6b3920332afbefd0f6f6178855347f1bac15f4304d37`
- Repository: <https://github.com/Starry-OS/starry-signal>
- Cargo-recorded source commit:
  `0a39846c582895555816145f47f82ceb0c89aa62`
- Original manifest SHA-256:
  `e0eaa00fb0430f9a29f19ea632bf3bce0a27cbf37536c1fa81054b10aae4ff53`
- Original Cargo source record SHA-256:
  `4f0f5db3891f208616ae362c6ea0e0c63d7cc7ac2dc2b774c7b1b9a08171a11f`
- License file SHA-256:
  `58d1e17ffe5109a7ae296caafcadfdbe6a7d176f0bc4ab01e12a689b0499d8bd`
- Published authors: Mivik `<mivikq@gmail.com>` and 朝倉水希
  `<asakuramizu111@gmail.com>`
- License: Apache-2.0

`Cargo.toml.orig`, `.cargo_vcs_info.json`, and `LICENSE` are byte-for-byte
records from the published archive. The implementation began from TheKernel's
patched source at commit `dbbaea9ff0ee6c63bdfb9d9828d4a8d25ba8d0b1`.

The 0.1.0 reset-action and alternate-stack contracts were checked against
Linux commit `dd3210c47e8d3ac6b4e9141fc68acc03b38c0ba3`:

- `kernel/signal.c` SHA-256
  `c8e3ea51d8cbbd5467477cefcd4c524dddae896925163ce44e043c9453b75a8d`;
- `include/linux/sched/signal.h` SHA-256
  `5f0fee62369f31213a3a5e11bbe1db2631e108fab38f7b1416947c78a5cfcd4b`;
- `include/uapi/linux/signal.h` SHA-256
  `4744021d82b90e0dd5bbad5283c98361aad73510127d19c2bd4103c7d21234d8`.

Those files are semantic references, not copied source. In particular Linux
`restore_altstack()` squashes non-copy validation failures; 0.1.0 preserves
that observable behavior while explicitly declining `SS_AUTODISARM` until an
embedding consumer implements delivery-time reset and restore end to end.

That maintained line already supplied bounded intrusive real-time queues,
fixed standard-signal slots, fallible/rollback-safe thread registration,
shared queue accounts, restart metadata, alternate-stack overflow checks, and
transactional frame restore. `PATCHES.md` records this package's boundary
changes; the crate name is not a claim of complete Linux signal parity.
