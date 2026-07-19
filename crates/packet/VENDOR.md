# Source and research record

## TheKernel consumer baseline

- Repository: <https://github.com/chenty2333/TheKernel>
- Consumer baseline: `13553e723f33b67970f1ec00f65941e95a15230e`
- License: Apache-2.0
- Relevant maintained paths:
  - `kernel/src/syscall/net/socket.rs`
  - `kernel/src/syscall/net/`
  - `kernel/src/file/`
  - `crates/axnet-ng/`

At this baseline TheKernel deliberately rejects `AF_PACKET` during socket
creation. The baseline is therefore an integration starting point, not a
claim that a packet socket adapter, device tap, queue, or syscall already
exists.

This package is a new Layer 2 policy implementation and has no pre-existing
registry archive, upstream crate manifest, checksum, or Cargo VCS record to
preserve. Its active package manifest is the original manifest; inventing a
vendor `Cargo.toml.orig` would misrepresent provenance. No TheKernel queue,
device, task, FD, usercopy, or syscall implementation is copied into it.

## Linux contract research snapshot

Observable AF_PACKET contracts were checked on 2026-07-20 against Linux v6.12,
commit `adc218676eef25575469234709c2d87185ca223a`, especially:

- `include/uapi/linux/if_packet.h`;
- `net/packet/af_packet.c`;
- `net/core/dev.c`;
- `net/core/filter.c`;
- `Documentation/networking/packet_mmap.rst`; and
- `tools/testing/selftests/net/psock_tpacket.c` and `psock_fanout.c`.

The reviewed first-stage contracts include RAW versus cooked DGRAM views,
network-order protocol input and its low-16-bit syscall cast,
zero/all/exact protocol selection, bind/rebind,
`sockaddr_ll`, early filter snap length, `MSG_PEEK`, `MSG_TRUNC`,
`PACKET_IGNORE_OUTGOING`, destructive packet/drop statistics, and known packet
option classification. TPACKET and fanout sources were reviewed only to define
an explicit unsupported boundary for this version.

Linux implementation and selftest sources are GPL-2.0-only. Linux UAPI headers
carry `GPL-2.0 WITH Linux-syscall-note`. This Apache-2.0 package reimplements
public observable values and policy in original Rust; it does not copy Linux
implementation or test source.

## Independent comparison snapshots

- gVisor commit `ddf37c50b366dca506b0facc9b1c3da85d83c00a`, Apache-2.0,
  especially `pkg/tcpip/transport/packet/endpoint.go`,
  `pkg/sentry/socket/netstack/packetmmap/endpoint.go`, and
  `test/syscalls/linux/packet_mmap.cc`;
- libpcap commit `73c514ad282191a64f3de6b07cb4b41249ed3b55`, BSD-style
  license, especially its Linux packet-socket consumer path.

These projects were independent compatibility and test-coverage references,
not implementation donors. The first-stage crate does not port their Go/C/C++
source, packet queues, mmap state, or tests. gVisor's reviewed packet-mmap path
also does not provide complete TPACKET_V3 parity and is not treated as the
Linux behavior oracle.
