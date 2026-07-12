# Vendored source record: `starry-process`

## Immutable published baseline

- Registry package: `starry-process` `0.2.0`
- crates.io archive SHA-256:
  `88fa031a95c25b7bcfe8883f9f53238c9053a2a89f790bb1a7c35d080c6d3b65`
- Repository declared by the package:
  <https://github.com/Starry-OS/starry-process>
- Source commit recorded by Cargo:
  `ab4fd0e8f91587ca18d3d2ab3e79dcf88b4200a8`
- Cargo VCS dirty flag: absent
- Original manifest SHA-256:
  `c0a12a23f90b64b4ac43f31ed298c680896383014662b95979243ae8d91967d5`
- Original Cargo source record SHA-256:
  `41b72a2b6bf0faa83d0daf7d919a11ed96eb5c34a27cb243ddbe25df3c2cfd24`
- Published authors: 朝倉水希 `<asakuramizu111@gmail.com>`
- Published license expression: `MIT OR Apache-2.0`

`Cargo.toml.orig` and `.cargo_vcs_info.json` are exact records from the
published archive. The archive checksum is the immutable comparison baseline.

## License anomaly

The `0.2.0` archive and its exact source commit contain no license file despite
declaring `MIT OR Apache-2.0`. The included `LICENSE` is the Apache-2.0 text
recovered from upstream commit
`ad905ce0f555026609fd874c6ef58fca6d510162`, the immediate child of the
release commit whose purpose was to add that license. No absent MIT text was
synthesized. This derived package is distributed under Apache-2.0.

## TheKernel migration baseline

The implementation began from TheKernel's patched `starry-process` at source
commit `dbbaea9ff0ee6c63bdfb9d9828d4a8d25ba8d0b1`. That line had already added:

- fallible process and thread prepare/commit admission with rollback;
- bounded intrusive PID/TID registries and allocation-free iteration;
- fallible process, group, session, child, and thread snapshots;
- durable zombie state and child-subreaper reparenting; and
- explicit membership capacity and allocation errors.

The independent package keeps those contracts while removing the crate-owned
global registry/init identity and moving Linux-specific zombie fields into a
caller-defined payload. See `PATCHES.md` for the semantic delta.
