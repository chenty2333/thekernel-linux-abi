# Changelog

## 0.1.0 - 2026-07-20

- Add dependency-free `no_std` RAW/DGRAM socket types and canonical host-order
  disabled/all/exact packet-protocol selection with explicit network-order
  conversion boundaries.
- Add validated wildcard/exact interface indexes, canonical bounded hardware
  addresses, forward-compatible packet types, normalized `SockAddrLl`, and a
  bind-only request which excludes Linux-ignored address fields.
- Add non-wrapping generation-tagged prepare/publish bind and rebind state,
  zero-protocol inheritance, stale-plan rejection, and caller-supplied
  normalized get-name metadata.
- Add pure RAW/DGRAM frame views and `MSG_PEEK`/`MSG_TRUNC` copy, return-length,
  output-flag, and queue-consumption decisions, including ordinary
  claim-before-copy versus PEEK retain-on-copy-fault ordering.
- Add `PACKET_IGNORE_OUTGOING`, Linux's `ETH_P_ALL`-only outgoing decision,
  strict known-unsupported/unknown option classification, and an exact typed
  mapping of the Layer 1 endpoint's single destructive aggregate statistics
  snapshot without invented drop attribution.
- Keep packet buffers, taps, device registries, queue storage, locks, waiters,
  readiness, usercopy, FD/task/namespace state, TPACKET, fanout, and errno
  conversion in their owning layers.
- Add host tests, rustdoc/clippy gates, package provenance, stable Rust 1.85,
  RISC-V 64, and LoongArch64 checks.
