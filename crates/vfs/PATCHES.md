# Extraction and semantic ledger

## TheKernel source behavior retained

- Select owner, group, or other mode bits exclusively.
- Treat UID 0 as unprivileged after effective DAC capabilities are dropped.
- Keep `CAP_DAC_READ_SEARCH` and `CAP_DAC_OVERRIDE` behavior distinct.
- Require at least one file execute bit for the override capability to bypass
  an execute denial.
- Apply `CAP_FOWNER` to sticky-directory mutation checks.
- Preserve `may_linkat()` protected-hardlink ordering, including mapped source
  IDs, safe-source shape, a consumer-run source permission hook, and owner or
  own-user-namespace `CAP_FOWNER` fallback.
- Apply SGID inheritance and `CAP_FSETID` before umask.
- Preserve chmod/chown hook ordering: requested chmod mode reaches the hook
  before SGID stripping, while chown set-ID removal is derived before the hook
  and rechecked against an explicitly requested final GID afterwards.
- Preserve independent UID/GID omission; a fully omitted chown performs no
  synthetic owner write or `CAP_CHOWN` check, but an implicit mode still
  requires owner or `CAP_FOWNER` authority.
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
- Add `MutationTransaction` so every post-reservation error rolls back, final
  policy admission runs after generation revalidation, and a successful
  mutation publishes at most once.
- Add an explicit protected-hardlink credential extension and callback-based
  source permission seam without importing a security registry or VFS object.
- Add move-only chmod/chown plans which retain the exact metadata snapshot and
  request across an external pre-hook, then produce sparse backend updates and
  committed mode/owner facts without importing TheKernel metadata, errno,
  timestamp, xattr, or credential-hook types.

## Deliberately not frozen

- cache data structures, RCU/refwalk, epoch reclamation, and per-CPU state;
- concrete filesystem location and namespace types;
- POSIX ACL storage or LSM implementation topology;
- killpriv provider discovery and privilege-xattr mutation;
- syscall argument structs and errno types; and
- mount ID-mapping algorithms.
