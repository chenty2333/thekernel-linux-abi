# thekernel-linux-process

`thekernel-linux-process` provides bounded process, thread-group, session, and
zombie lifecycle state without a crate-owned singleton. A kernel explicitly
owns a `ProcessDomain<Z>`; its `ProcessRegistry<Z>` is passed to topology
queries, and independent domains may safely reuse the same PID values.

The generic `Z` is an opaque, caller-defined durable zombie payload. This
crate does not define Linux wait-status encoding, UID snapshots, CPU usage, or
errno mapping. A Linux ABI adapter can define one payload containing exactly
the state its `wait*`, procfs, accounting, and permission paths require.

## Toolchain

Version 0.1.0 is intentionally **nightly-only** and is tested with
`nightly-2025-05-20`. It uses `Arc::try_new` through Rust's `allocator_api`
feature so process-object allocation can return `ProcessError::NoMemory`.
There is no `rust-version` claim for this package. See `PATCHES.md` for the
stable-allocation alternatives considered and rejected.

```rust
use thekernel_linux_process::{ExitOutcome, ProcessDomain};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LinuxZombie {
    wait_status: i32,
    uid: u32,
}

let domain = ProcessDomain::<LinuxZombie>::try_new().unwrap();
let init = domain.try_new_init(1, None).unwrap();
let child_admission = domain.prepare_fork(&init, 2, Some(17)).unwrap();
let child = child_admission.process().clone();
child_admission.commit();

assert_eq!(
    domain.exit(
        &child,
        LinuxZombie {
            wait_status: 0,
            uid: 0,
        },
        drop,
    ),
    Ok(ExitOutcome::BecameZombie),
);
assert!(domain.reap(&child).unwrap());
```

## Consumer migration

A kernel adapter defines aliases such as `Process<LinuxZombieSnapshot>` and
owns one explicitly initialized domain. Historical calls change as follows:

- `Process::try_new_init(...)` becomes `PROCESS_DOMAIN.try_new_init(...)`;
- `parent.prepare_fork(...)` becomes `PROCESS_DOMAIN.prepare_fork(&parent, ...)`;
- `process.exit(...)` becomes `PROCESS_DOMAIN.exit(&process, snapshot, ...)`,
  making the durable wait/security snapshot mandatory before zombie state;
- `process.reap()` becomes `PROCESS_DOMAIN.reap(&process)`;
- session/group creation and group moves become domain operations over unique,
  liveness-checked identities;
- `exit_thread` returns `ThreadExitOutcome`, while `group_exit(code)` records
  the group code atomically;
- child, process-group, and session snapshots receive
  `PROCESS_DOMAIN.registry()`; and
- the historical `ZombieSnapshot` and `ProcessUsage` fields move into the
  kernel's `LinuxZombieSnapshot`/accounting adapter.

The adapter must serialize fork admission/commit against exit for the same
parent with its existing process-lifecycle lock. The crate does not obtain a
current task or hide that kernel lock.

Domain capacity now bounds total reserved/live thread memberships across all
processes, not merely each process in isolation. `kspin/smp` is mandatory even
for the unpacked standalone package, and concurrent admission, removal,
reparent, exit, and reap tests exercise the real inter-CPU locks.

See `VENDOR.md` and `PATCHES.md` for the immutable StarryOS source lineage.
