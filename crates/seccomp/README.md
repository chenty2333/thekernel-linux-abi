# thekernel-linux-seccomp

`thekernel-linux-seccomp` is a `no_std` Linux seccomp policy core. It owns:

- validation and allocation-free execution of the seccomp classic-BPF subset;
- immutable, bounded filter chains with Linux action precedence;
- explicit per-task mode, inheritance, and thread-sync eligibility rules; and
- Linux UAPI values used by a kernel adapter.

It deliberately does not dereference userspace, own task/thread-group locks,
deliver signals, stop tasks, allocate file descriptors, or implement seccomp
user notification. A consumer copies an entire `sock_fprog`, prepares a
verified immutable program before its publication gate, and then atomically
publishes the resulting `FilterChain` to one task or an eligible thread group.

The interpreter has no backwards branches and performs no allocation. Filter
installation is bounded by Linux's 4096-instruction per-program limit and
32768-instruction path accounting, including the four-instruction stacking
penalty for every inherited program.
