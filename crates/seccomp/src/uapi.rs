//! Linux seccomp and classic-BPF UAPI constants used by the policy core.

/// `seccomp()` operation: enter strict mode.
pub const SECCOMP_SET_MODE_STRICT: u32 = 0;
/// `seccomp()` operation: install a filter.
pub const SECCOMP_SET_MODE_FILTER: u32 = 1;
/// `seccomp()` operation: query an action.
pub const SECCOMP_GET_ACTION_AVAIL: u32 = 2;
/// `seccomp()` operation: query notification structure sizes.
pub const SECCOMP_GET_NOTIF_SIZES: u32 = 3;

/// Synchronize an installed filter to eligible sibling threads.
pub const SECCOMP_FILTER_FLAG_TSYNC: u32 = 1 << 0;
/// Request audit logging for non-allow results from this filter.
pub const SECCOMP_FILTER_FLAG_LOG: u32 = 1 << 1;
/// Disable speculative-execution mitigation for this filter installation.
pub const SECCOMP_FILTER_FLAG_SPEC_ALLOW: u32 = 1 << 2;
/// Create a seccomp user-notification listener.
pub const SECCOMP_FILTER_FLAG_NEW_LISTENER: u32 = 1 << 3;
/// Make a failed thread synchronization return `ESRCH` instead of a TID.
pub const SECCOMP_FILTER_FLAG_TSYNC_ESRCH: u32 = 1 << 4;
/// Use a killable listener wait after a user notification is received.
pub const SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV: u32 = 1 << 5;

/// All flags defined by Linux 6.12.
pub const SECCOMP_FILTER_FLAG_MASK: u32 = SECCOMP_FILTER_FLAG_TSYNC
    | SECCOMP_FILTER_FLAG_LOG
    | SECCOMP_FILTER_FLAG_SPEC_ALLOW
    | SECCOMP_FILTER_FLAG_NEW_LISTENER
    | SECCOMP_FILTER_FLAG_TSYNC_ESRCH
    | SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV;

/// Action mask including the full 16-bit action field.
pub const SECCOMP_RET_ACTION_FULL: u32 = 0xffff_0000;
/// Historical action mask without the kill-process bit.
pub const SECCOMP_RET_ACTION: u32 = 0x7fff_0000;
/// Action-specific low-order data mask.
pub const SECCOMP_RET_DATA: u32 = 0x0000_ffff;
/// Terminate the entire thread group with `SIGSYS`.
pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
/// Terminate the calling thread with `SIGSYS`.
pub const SECCOMP_RET_KILL_THREAD: u32 = 0x0000_0000;
/// Deliver a synchronous `SIGSYS` trap.
pub const SECCOMP_RET_TRAP: u32 = 0x0003_0000;
/// Skip the syscall and return the low-order errno.
pub const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
/// Delegate the syscall to a user-notification listener.
pub const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
/// Report a ptrace seccomp event.
pub const SECCOMP_RET_TRACE: u32 = 0x7ff0_0000;
/// Audit-log and execute the syscall.
pub const SECCOMP_RET_LOG: u32 = 0x7ffc_0000;
/// Execute the syscall.
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

/// Maximum classic-BPF instructions in one program.
pub const BPF_MAXINSNS: usize = 4096;
/// Number of classic-BPF scratch words.
pub const BPF_MEMWORDS: usize = 16;
/// Maximum Linux seccomp path cost in classic-BPF instructions.
pub const MAX_INSNS_PER_PATH: usize = 32_768;
/// Per-ancestor path penalty used by Linux when stacking filters.
pub const FILTER_PATH_PENALTY: usize = 4;

/// Linux audit architecture value for little-endian RV64.
pub const AUDIT_ARCH_RISCV64: u32 = 0xc000_00f3;
/// Linux audit architecture value for little-endian LoongArch64.
pub const AUDIT_ARCH_LOONGARCH64: u32 = 0xc000_0102;

/// Size of Linux `struct seccomp_data` on supported 64-bit ABIs.
pub const SECCOMP_DATA_SIZE: usize = 64;

pub(crate) const BPF_CLASS_MASK: u16 = 0x07;
pub(crate) const BPF_SIZE_MASK: u16 = 0x18;
pub(crate) const BPF_MODE_MASK: u16 = 0xe0;
pub(crate) const BPF_OP_MASK: u16 = 0xf0;
pub(crate) const BPF_SRC_MASK: u16 = 0x08;
pub(crate) const BPF_RVAL_MASK: u16 = 0x18;

pub(crate) const BPF_LD: u16 = 0x00;
pub(crate) const BPF_LDX: u16 = 0x01;
pub(crate) const BPF_ST: u16 = 0x02;
pub(crate) const BPF_STX: u16 = 0x03;
pub(crate) const BPF_ALU: u16 = 0x04;
pub(crate) const BPF_JMP: u16 = 0x05;
pub(crate) const BPF_RET: u16 = 0x06;
pub(crate) const BPF_MISC: u16 = 0x07;

pub(crate) const BPF_W: u16 = 0x00;
pub(crate) const BPF_IMM: u16 = 0x00;
pub(crate) const BPF_ABS: u16 = 0x20;
pub(crate) const BPF_MEM: u16 = 0x60;
pub(crate) const BPF_LEN: u16 = 0x80;

pub(crate) const BPF_ADD: u16 = 0x00;
pub(crate) const BPF_SUB: u16 = 0x10;
pub(crate) const BPF_MUL: u16 = 0x20;
pub(crate) const BPF_DIV: u16 = 0x30;
pub(crate) const BPF_OR: u16 = 0x40;
pub(crate) const BPF_AND: u16 = 0x50;
pub(crate) const BPF_LSH: u16 = 0x60;
pub(crate) const BPF_RSH: u16 = 0x70;
pub(crate) const BPF_NEG: u16 = 0x80;
pub(crate) const BPF_XOR: u16 = 0xa0;

pub(crate) const BPF_JA: u16 = 0x00;
pub(crate) const BPF_JEQ: u16 = 0x10;
pub(crate) const BPF_JGT: u16 = 0x20;
pub(crate) const BPF_JGE: u16 = 0x30;
pub(crate) const BPF_JSET: u16 = 0x40;

pub(crate) const BPF_K: u16 = 0x00;
pub(crate) const BPF_X: u16 = 0x08;
pub(crate) const BPF_A: u16 = 0x10;
pub(crate) const BPF_TAX: u16 = 0x00;
pub(crate) const BPF_TXA: u16 = 0x80;
