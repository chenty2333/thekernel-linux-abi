# Extraction and semantic ledger

## TheKernel source behavior retained

- Select owner, group, or other mode bits exclusively.
- Treat UID 0 as unprivileged after effective DAC capabilities are dropped.
- Keep `CAP_DAC_READ_SEARCH` and `CAP_DAC_OVERRIDE` behavior distinct.
- Require at least one file execute bit for the override capability to bypass
  an execute denial.
- Apply `CAP_FOWNER` to sticky-directory mutation checks.
- Apply SGID inheritance and `CAP_FSETID` before umask.
- Observe symlinks, magic links, mount crossings, absolute restarts, and root
  escape attempts during the real generic pathwalk.

## 0.1.0 extraction changes

- Replace TheKernel-specific `Location`, raw UID/GID, capability bit numbers,
  `AxError`, and `linux-raw-sys` types with generic stable handles, typed IDs,
  typed capabilities, and adapter-mapped errors.
- Replace syscall-local `Openat2PathwalkPolicy` with strict flag decoding and
  typed actions that can express `RESOLVE_IN_ROOT` restart/clamp behavior.
- Add explicit, checked budgets for every user-triggered walk counter.
- Add `PathContext` so credentials, namespace, root/cwd, hook context, and
  limits cannot be implicitly resampled during one operation.
- Add `MutationTransaction` so every post-reservation error rolls back and a
  successful mutation publishes at most once after generation revalidation.

## Deliberately not frozen

- cache data structures, RCU/refwalk, epoch reclamation, and per-CPU state;
- concrete filesystem location and namespace types;
- POSIX ACL storage or LSM implementation topology;
- syscall argument structs and errno types; and
- mount ID-mapping algorithms.
