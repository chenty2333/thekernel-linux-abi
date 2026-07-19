# thekernel-linux-packet

`thekernel-linux-packet` is a dependency-free, `no_std`, `forbid(unsafe_code)`
Layer 2 policy core for the first ordinary-queue slice of Linux `AF_PACKET`.
It accepts copied scalar values and caller-owned device facts; it never reads
userspace memory, a current task, an FD table, a network namespace, a device
registry, or a packet buffer.

Version 0.1.0 provides:

- strict `SOCK_RAW` and `SOCK_DGRAM` selection;
- one canonical host-order protocol selector with `Disabled`, `All`, and
  validated `Exact` states, while network byte order appears only in explicitly
  named conversion functions and the socket integer keeps Linux's low-16-bit
  cast behavior;
- validated `InterfaceIndex`, canonical bounded link addresses, forward-
  compatible packet-type bytes, and normalized `SockAddrLl` values;
- bind-only decoding which consumes only family, protocol, and interface so
  ignored `sockaddr_ll` fields cannot make bind stricter than Linux;
- non-wrapping, stale-safe prepare/publish bind and rebind state, including
  Linux's zero-bind-protocol inheritance rule;
- normalized `getsockname` construction from a caller-provided exact device
  snapshot rather than an implicit registry lookup;
- pure RAW/DGRAM packet views and `MSG_PEEK`/`MSG_TRUNC` copy, return-length,
  output-truncation, and queue-consumption decisions;
- `PACKET_IGNORE_OUTGOING` plus explicit delivery policy that preserves
  Linux's `ETH_P_ALL`-only outgoing tap exception;
- an exact typed mapping from the endpoint's single destructive aggregate
  statistics snapshot, retaining filter rejection/error diagnostics without
  inventing unavailable queue-versus-staging drop attribution; and
- strict known-unsupported versus unknown packet-option errors.

## Layer boundary

The crate owns Linux-visible values and state transitions. A Layer 1 network
mechanism owns device taps, borrowed packet snapshots, packet-buffer lifetime,
bounded queues, waiters, fanout dispatch, transmit admission, and driver
completion. The TheKernel adapter owns capability and namespace checks,
usercopy, raw struct-size validation, FD/OFD lifetime, device lookup and
generation leases, queue locking, readiness, cmsg construction, and errno
mapping.

Bind publication is intentionally two phase:

1. copy only the bind-consumed address fields and build `PacketBindRequest`;
2. call `prepare_bind` and retain its exact expected generation;
3. prepare or replace the lower packet tap/device lease, rolling it back on
   failure; and
4. under the socket publication gate, call `publish_bind`.

If another writer changed the binding, publication returns `StaleBindPlan`
without changing core state. The adapter then rolls back the lower prepared
mechanism and retries only according to its bounded syscall policy.

`get_name` returns a normalized `SockAddrLl`. It never performs an implicit
native-endian conversion: adapters use `protocol_network_order` only at the
copyout boundary. Exact bindings require matching caller-owned link metadata;
wildcard bindings return zero hardware type and an empty address.

## Receive and statistics contract

`FrameLayout` validates a full link frame and network-header offset. RAW views
begin at byte zero; DGRAM views begin at the network header. A caller supplies
the post-filter captured length, then `receive_decision` determines copy length,
successful return length, output `MSG_TRUNC`, and whether `MSG_PEEK` retains the
queue entry. The adapter applies that disposition before usercopy: ordinary
receive claims/removes the record first and does not requeue it on `EFAULT`,
while `MSG_PEEK` never claims it and therefore retains it on `EFAULT`. Waiting,
signal interruption, nonblocking mode, queue ownership, and usercopy remain
outside this pure decision.

The Layer 1 endpoint is the sole live counter and reset owner. Successfully
staged frames enter its aggregates after filter acceptance; selector-matched
staging failures may instead enter `packets` and `drops` before a filter can
run. It produces exactly one destructive snapshot for `PACKET_STATISTICS`.
`PacketStatistics::from_destructive_snapshot` maps its already-aggregated
`packets`, `drops`, `filter_rejected`, and `filter_errors` fields without
storing or resetting counters a second time. The two filter diagnostics
contribute to neither Linux-visible total. The current endpoint does not expose
queue-versus-staging drop reasons or a saturation marker, so this crate
deliberately does not synthesize them. The adapter owns copyout width and
failure ordering for the concrete UAPI struct.

## Deliberate 0.1 limits

This package does not implement packet taps, ordinary queue storage, send
execution, capabilities, namespaces, multicast/promiscuous memberships,
`PACKET_AUXDATA`, timestamps, socket filters, `PACKET_RX_RING`,
`PACKET_TX_RING`, any TPACKET version, mmap, fanout, AF_XDP, readiness, or
drop cmsgs. Every known option outside ignore-outgoing and statistics is
rejected explicitly rather than silently accepted. Package existence is not a
claim that a consumer exposes `AF_PACKET` yet.

The package supports stable Rust 1.85, RISC-V 64, and LoongArch64 consumers.
See `VENDOR.md`, `PATCHES.md`, and `NOTICE` for provenance and research
boundaries.
