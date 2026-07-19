# Extraction and semantic ledger

## Linux-visible contracts retained

- Present the original raw syscall number, audit architecture, post-syscall
  instruction pointer, and six raw arguments through the native-endian
  64-byte `seccomp_data` view.
- Accept only the Linux seccomp classic-BPF profile: aligned in-bounds word
  loads, sixteen scratch words, bounded forward control flow, and no packet,
  indirect, ancillary, halfword, byte, MSH, or modulo operations.
- Bound one program to 4096 instructions and a stacked filter path to 32768
  instructions, charging four extra instructions for each inherited program.
- Evaluate immutable filters newest to oldest, select the most restrictive
  signed full action, and retain the newest filter's data and metadata on a
  precedence tie.
- Treat exact immutable-node ancestry, rather than bytecode equality, as the
  filter relationship used for thread-synchronization eligibility.
- Keep strict and filter mode transitions irreversible and expose exact
  immutable snapshots for caller-controlled fork, clone, and exec ownership.

## 0.1.0 extraction changes

- Move policy-neutral classic-BPF instruction validation and A/X/M execution
  to the Apache-2.0 `thekernel-axcbpf` Layer 1 dependency; keep the narrower
  Linux seccomp opcode and input policy in this Layer 2 package.
- Replace raw `sock_filter` pointers with caller-owned immutable instruction
  vectors or slices and fallible verification before publication.
- Represent a filter stack as exact immutable ancestry. Appending returns a
  prepared child which a consumer can publish only after revalidating the
  expected task-local leaf.
- Charge each live program and chain node to an explicit shared logical-byte
  budget. Forked or cloned references share an existing charge, failed
  preparation rolls it back, cross-budget ancestry is rejected, and the final
  owner refunds it.
- Iteratively detach uniquely owned ancestors during destruction so a legal
  maximum-depth chain cannot recurse through thousands of kernel-stack
  frames; shared ancestry stops the walk at the first retained node.
- Model TSYNC only as per-sibling eligibility and preparation. The consumer
  must freeze thread publication, validate a stable group snapshot,
  preallocate every task and `no_new_privs` transition, and commit the complete
  group without partial failure.
- Preserve raw action values and classify every Linux v6.12 action without
  claiming that the package implements signal delivery, tracing, logging, or
  user-notification lifecycles. Unknown actions never become `ALLOW`.

## Deliberately not extracted or frozen

- userspace `sock_fprog` copyin, syscall/prctl argument ordering, errno mapping,
  raw pointers, architecture trap frames, and syscall restart/recheck policy;
- task and process objects, task-local and thread-group locks, fork/clone/exec
  plumbing, `no_new_privs`, capabilities, namespaces, and security hooks;
- strict-mode syscall enforcement, `SIGSYS` construction and delivery,
  process/thread termination, ptrace stops, audit rate limiting, and logging;
- user-notification listener FDs, queues, readiness, cancellation, responses,
  and single-completion ownership;
- process-wide TSYNC serialization, sibling enumeration, all-or-none state and
  credential publication, positive failing-TID reporting, and ESRCH mapping;
  and
- JITs, eBPF, BTF, maps, helpers, packet sockets, socket-filter attachment,
  concrete locks, schedulers, executors, or RCU/epoch reclamation.
