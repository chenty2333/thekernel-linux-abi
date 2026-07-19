# Extraction and semantic ledger

## Linux-visible contracts reimplemented

- Accept only AF_PACKET `SOCK_RAW` and `SOCK_DGRAM` base types in this slice.
- Normalize socket and `sockaddr_ll` protocols into one host-order disabled,
  all, or exact state; convert network order only at named input/output seams
  and retain Linux's low-16-bit cast of the `socket(2)` protocol integer.
- Treat a zero bind protocol as retaining the socket's effective protocol.
- Bind and rebind by interface/protocol while ignoring the other
  `sockaddr_ll` fields, as Linux does.
- Include the link header in RAW views and remove it from DGRAM views.
- Make `MSG_PEEK` retain a queue entry and make input `MSG_TRUNC` return the
  complete captured length while independently reporting output truncation.
  Ordinary receive claims before usercopy and remains consumed on `EFAULT`;
  `MSG_PEEK` retains the entry on the same failure.
- Deliver locally observed outgoing packets only to `ETH_P_ALL` sockets, then
  suppress them when `PACKET_IGNORE_OUTGOING` is enabled. An exact protocol
  may still receive a later looped-back incoming HOST copy.
- Classify the statistics option as destructive while leaving the single reset
  and live counters in the queue-owning endpoint; map its packet/drop
  aggregates exactly and exclude filter rejection/error diagnostics.

## 0.1.0 extraction changes

- Replace raw native-endian protocol integers with a canonical selector and
  explicit `from_network_order`/`to_network_order` APIs.
- Separate bind input from complete `SockAddrLl`, preventing output-only or
  ignored fields from creating stricter validation.
- Canonicalize unused hardware-address bytes so equality and copyout cannot
  expose stale storage.
- Preserve unknown packet-type bytes because the field is ignored on input
  and is an extensible output vocabulary.
- Split bind into prepare and exact-generation publication so an adapter may
  perform fallible tap/device work first and reject a stale writer without
  partial core mutation.
- Require get-name link metadata as an immutable caller snapshot matching the
  exact bound interface; no global device lookup is hidden in the crate.
- Separate packet layout, captured snap length, copy length, syscall return
  length, output truncation, and queue disposition into a pure decision whose
  claim-before-copy ordering is explicit.
- Map the endpoint's packet/drop aggregates and filter diagnostics exactly.
  Do not infer accepted counts, drop reasons, or saturation state that the
  destructive Layer 1 snapshot does not expose.
- Classify the pinned `SOL_PACKET` option vocabulary while implementing only
  ignore-outgoing set/get and destructive statistics get.

## Deliberately not extracted or frozen

- CAP_NET_RAW and security-hook checks, user/network namespaces, task and
  credential state, syscall ordering, raw user pointers, usercopy, fd/OFD
  ownership, and errno mapping;
- device identities and generations, tap registration/quiescence, packet
  snapshots, packet buffers, queues, allocation, locks, RCU/epoch strategy,
  live/resettable counters, waiter storage, wakeups, readiness, and driver
  ingress/egress mechanics;
- send execution, sockaddr length/truncation copyout, cmsgs, timestamps,
  checksum/VLAN metadata, socket-filter attachment, and auxiliary data;
- memberships, promiscuous mode, TPACKET RX/TX rings, mmap ownership, fanout,
  AF_XDP, long-term pins, DMA, IOMMU, and completion timelines; and
- concrete Linux errno selection for a typed validation or unsupported-policy
  result.
