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
- a saturating typed mapping from the endpoint's single destructive statistics
  snapshot, distinguishing accepted packets, queue-full drops,
  allocation-failure drops, and filter rejects while excluding filter rejects
  from Linux packet/drop totals; and
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
queue entry. Waiting, signal interruption, nonblocking mode, queue ownership,
and usercopy remain outside this pure decision.

The Layer 1 endpoint is the sole live counter and reset owner. It records a
packet only after filter acceptance and produces exactly one destructive
snapshot for `PACKET_STATISTICS`. `PacketStatistics::from_destructive_snapshot`
maps that result without storing or resetting counters a second time.
Accepted, queue-full, and allocation-failure events contribute to the Linux
packet total; the two failure categories contribute to drops. Filter rejects
are a separate diagnostic counter and contribute to neither. Aggregate
overflow saturates and sets a diagnostic marker rather than failing the packet
path. The adapter owns copyout width and failure ordering for the concrete UAPI
struct.

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
