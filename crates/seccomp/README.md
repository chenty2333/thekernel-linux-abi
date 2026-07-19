# thekernel-linux-seccomp

`thekernel-linux-seccomp` is a `no_std` Linux seccomp policy core. It consumes
the policy-neutral `thekernel-axcbpf` mechanism and owns:

- the seccomp-only opcode profile and native-endian 64-byte syscall input;
- immutable, bounded filter chains with Linux action precedence;
- aggregate live-program byte accounting with final-owner refunds;
- explicit per-task mode, inheritance, and thread-sync eligibility rules; and
- Linux UAPI values used by a kernel adapter.

It deliberately does not dereference userspace, own task/thread-group locks,
deliver signals, stop tasks, allocate file descriptors, or implement seccomp
user notification. A consumer copies an entire `sock_fprog`, prepares a
verified immutable program before its publication gate, and then atomically
publishes the resulting `FilterChain` to one task. The core can validate and
prepare an eligible sibling state for thread synchronization, but the consumer
must provide the stable thread-set gate, preallocate every filter and
`no_new_privs` transition, and perform the all-or-nothing group commit.

The shared Layer 1 interpreter has no backwards branches and performs no allocation. Filter
installation is bounded by Linux's 4096-instruction per-program limit and
32768-instruction path accounting, including the four-instruction stacking
penalty for every inherited program. Every new immutable node is also charged
to an explicit shared `FilterBudget`; clone and fork share the existing charge,
and the final owner refunds it. Maximum-depth and concurrent-final-owner tests
exercise iterative teardown on a 64 KiB host thread stack.
