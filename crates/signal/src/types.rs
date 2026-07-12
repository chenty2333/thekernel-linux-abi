use core::{fmt, mem};

use derive_more::{BitAnd, BitAndAssign, BitOr, BitOrAssign, Not};
use linux_raw_sys::general::{SI_KERNEL, SS_DISABLE, SS_ONSTACK, kernel_sigset_t, siginfo_t};
use strum::{EnumIter, FromRepr, IntoEnumIterator};

use crate::DefaultSignalAction;

/// Signal number.
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, FromRepr, EnumIter)]
pub enum Signo {
    SIGHUP = 1,
    SIGINT = 2,
    SIGQUIT = 3,
    SIGILL = 4,
    SIGTRAP = 5,
    SIGABRT = 6,
    SIGBUS = 7,
    SIGFPE = 8,
    SIGKILL = 9,
    SIGUSR1 = 10,
    SIGSEGV = 11,
    SIGUSR2 = 12,
    SIGPIPE = 13,
    SIGALRM = 14,
    SIGTERM = 15,
    SIGSTKFLT = 16,
    SIGCHLD = 17,
    SIGCONT = 18,
    SIGSTOP = 19,
    SIGTSTP = 20,
    SIGTTIN = 21,
    SIGTTOU = 22,
    SIGURG = 23,
    SIGXCPU = 24,
    SIGXFSZ = 25,
    SIGVTALRM = 26,
    SIGPROF = 27,
    SIGWINCH = 28,
    SIGIO = 29,
    SIGPWR = 30,
    SIGSYS = 31,
    SIGRTMIN = 32,
    SIGRT1 = 33,
    SIGRT2 = 34,
    SIGRT3 = 35,
    SIGRT4 = 36,
    SIGRT5 = 37,
    SIGRT6 = 38,
    SIGRT7 = 39,
    SIGRT8 = 40,
    SIGRT9 = 41,
    SIGRT10 = 42,
    SIGRT11 = 43,
    SIGRT12 = 44,
    SIGRT13 = 45,
    SIGRT14 = 46,
    SIGRT15 = 47,
    SIGRT16 = 48,
    SIGRT17 = 49,
    SIGRT18 = 50,
    SIGRT19 = 51,
    SIGRT20 = 52,
    SIGRT21 = 53,
    SIGRT22 = 54,
    SIGRT23 = 55,
    SIGRT24 = 56,
    SIGRT25 = 57,
    SIGRT26 = 58,
    SIGRT27 = 59,
    SIGRT28 = 60,
    SIGRT29 = 61,
    SIGRT30 = 62,
    SIGRT31 = 63,
    SIGRT32 = 64,
}

impl Signo {
    pub fn is_realtime(&self) -> bool {
        *self >= Signo::SIGRTMIN
    }

    pub fn default_action(&self) -> DefaultSignalAction {
        match self {
            Signo::SIGHUP => DefaultSignalAction::Terminate,
            Signo::SIGINT => DefaultSignalAction::Terminate,
            Signo::SIGQUIT => DefaultSignalAction::CoreDump,
            Signo::SIGILL => DefaultSignalAction::CoreDump,
            Signo::SIGTRAP => DefaultSignalAction::CoreDump,
            Signo::SIGABRT => DefaultSignalAction::CoreDump,
            Signo::SIGBUS => DefaultSignalAction::CoreDump,
            Signo::SIGFPE => DefaultSignalAction::CoreDump,
            Signo::SIGKILL => DefaultSignalAction::Terminate,
            Signo::SIGUSR1 => DefaultSignalAction::Terminate,
            Signo::SIGSEGV => DefaultSignalAction::CoreDump,
            Signo::SIGUSR2 => DefaultSignalAction::Terminate,
            Signo::SIGPIPE => DefaultSignalAction::Terminate,
            Signo::SIGALRM => DefaultSignalAction::Terminate,
            Signo::SIGTERM => DefaultSignalAction::Terminate,
            Signo::SIGSTKFLT => DefaultSignalAction::Terminate,
            Signo::SIGCHLD => DefaultSignalAction::Ignore,
            Signo::SIGCONT => DefaultSignalAction::Continue,
            Signo::SIGSTOP => DefaultSignalAction::Stop,
            Signo::SIGTSTP => DefaultSignalAction::Stop,
            Signo::SIGTTIN => DefaultSignalAction::Stop,
            Signo::SIGTTOU => DefaultSignalAction::Stop,
            Signo::SIGURG => DefaultSignalAction::Ignore,
            Signo::SIGXCPU => DefaultSignalAction::CoreDump,
            Signo::SIGXFSZ => DefaultSignalAction::CoreDump,
            Signo::SIGVTALRM => DefaultSignalAction::Terminate,
            Signo::SIGPROF => DefaultSignalAction::Terminate,
            Signo::SIGWINCH => DefaultSignalAction::Ignore,
            Signo::SIGIO => DefaultSignalAction::Terminate,
            Signo::SIGPWR => DefaultSignalAction::Terminate,
            Signo::SIGSYS => DefaultSignalAction::CoreDump,
            // POSIX real-time signals default to process termination.
            _ => DefaultSignalAction::Terminate,
        }
    }
}

/// Signal set. Compatible with `struct sigset_t` in libc.
#[derive(Default, Clone, Copy, Not, BitOr, BitOrAssign, BitAnd, BitAndAssign)]
#[repr(transparent)]
pub struct SignalSet(u64);

impl SignalSet {
    fn signo_bit(signo: Signo) -> u64 {
        1 << (signo as u8 - 1)
    }

    /// Adds a signal to the set.
    pub fn add(&mut self, signal: Signo) -> bool {
        let bit = Self::signo_bit(signal);
        if self.0 & bit != 0 {
            return false;
        }
        self.0 |= bit;
        true
    }

    /// Removes a signal from the set.
    pub fn remove(&mut self, signal: Signo) -> bool {
        let bit = Self::signo_bit(signal);
        if self.0 & bit == 0 {
            return false;
        }
        self.0 &= !bit;
        true
    }

    /// Checks if the set contains a signal.
    pub fn has(&self, signal: Signo) -> bool {
        (self.0 & Self::signo_bit(signal)) != 0
    }

    /// Returns `true` if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.0 == 0
    }

    /// Dequeues the a signal in `mask` from this set, if any.
    pub fn dequeue(&mut self, mask: &SignalSet) -> Option<Signo> {
        let bits = self.0 & mask.0;
        if bits == 0 {
            None
        } else {
            let signal = bits.trailing_zeros();
            self.0 &= !(1 << signal);
            Signo::from_repr((signal + 1) as u8)
        }
    }
}

impl From<SignalSet> for kernel_sigset_t {
    fn from(value: SignalSet) -> Self {
        // SAFETY: `kernel_sigset_t` always has the same layout as `[c_ulong; 1]`.
        unsafe { mem::transmute::<u64, kernel_sigset_t>(value.0) }
    }
}

impl From<kernel_sigset_t> for SignalSet {
    fn from(value: kernel_sigset_t) -> Self {
        // SAFETY: `kernel_sigset_t` always has the same layout as `[c_ulong; 1]`.
        Self(unsafe { mem::transmute::<kernel_sigset_t, u64>(value) })
    }
}

impl fmt::Debug for SignalSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_set();
        for signo in Signo::iter() {
            if self.has(signo) {
                debug.entry(&signo);
            }
        }
        debug.finish()
    }
}

/// Signal information. Compatible with `struct siginfo` in libc.
#[derive(Clone)]
#[repr(C, align(8))]
pub struct SignalInfo([u8; 128]);

impl SignalInfo {
    pub fn new_kernel(signo: Signo) -> Self {
        let mut result = Self([0; 128]);
        result.set_signo(signo);
        result.set_code(SI_KERNEL as _);
        result
    }

    pub fn new_user(signo: Signo, code: i32, pid: u32) -> Self {
        let mut result = Self([0; 128]);
        result.set_signo(signo);
        result.set_code(code);
        result.set_pid(pid);
        result
    }

    pub fn signo(&self) -> Signo {
        self.try_signo()
            .expect("kernel SignalInfo has a valid signo")
    }

    /// Validates a raw ABI signal number without panicking.
    pub fn try_signo(&self) -> Option<Signo> {
        // SAFETY: si_signo is part of the common integer header shared by all
        // siginfo_t union variants, and every byte in SignalInfo is initialized.
        let raw = unsafe { self.as_raw().__bindgen_anon_1.__bindgen_anon_1.si_signo };
        u8::try_from(raw).ok().and_then(Signo::from_repr)
    }

    pub fn set_signo(&mut self, signo: Signo) {
        self.raw_mut().__bindgen_anon_1.__bindgen_anon_1.si_signo = signo as _;
    }

    pub fn code(&self) -> i32 {
        // SAFETY: si_code is part of the initialized common integer header.
        unsafe { self.as_raw().__bindgen_anon_1.__bindgen_anon_1.si_code }
    }

    pub fn set_code(&mut self, code: i32) {
        self.raw_mut().__bindgen_anon_1.__bindgen_anon_1.si_code = code;
    }

    pub fn pid(&self) -> u32 {
        // SAFETY: callers use this accessor for SI_USER/SI_QUEUE-style records
        // whose initialized _kill payload contains an integer PID.
        unsafe {
            self.as_raw()
                .__bindgen_anon_1
                .__bindgen_anon_1
                ._sifields
                ._kill
                ._pid as u32
        }
    }

    pub fn set_pid(&mut self, pid: u32) {
        self.raw_mut()
            .__bindgen_anon_1
            .__bindgen_anon_1
            ._sifields
            ._kill
            ._pid = pid as _;
    }

    pub fn errno(&self) -> i32 {
        // SAFETY: The union layout matches Linux's siginfo_t definition. bindgen keeps
        // this layout, so it is safe to read the errno field through the
        // anonymous union.
        unsafe { self.as_raw().__bindgen_anon_1.__bindgen_anon_1.si_errno }
    }

    /// Returns the raw Linux ABI record.
    pub fn as_raw(&self) -> &siginfo_t {
        // SAFETY: the storage has exactly siginfo_t's asserted size and
        // alignment. linux_raw_sys models the record entirely with integer
        // scalars, arrays, and unions, so every fully initialized byte pattern
        // is a valid raw record.
        unsafe { &*self.0.as_ptr().cast::<siginfo_t>() }
    }

    fn raw_mut(&mut self) -> &mut siginfo_t {
        // SAFETY: as_raw's layout argument also applies to this exclusive view.
        unsafe { &mut *self.0.as_mut_ptr().cast::<siginfo_t>() }
    }
}

const _: [(); mem::size_of::<siginfo_t>()] = [(); mem::size_of::<SignalInfo>()];
const _: [(); mem::align_of::<siginfo_t>()] = [(); mem::align_of::<SignalInfo>()];

impl fmt::Debug for SignalInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignalInfo")
            .field("signo", &self.signo())
            .field("code", &self.code())
            .finish()
    }
}

/// Signal stack. Compatible with `struct sigaltstack` in libc.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignalStack {
    pub sp: usize,
    pub flags: u32,
    // Linux's 64-bit stack_t has an explicit four-byte alignment hole before
    // ss_size. Keeping those bytes as a field prevents kernel stack contents
    // from leaking when a complete signal frame is copied to userspace.
    __padding: u32,
    pub size: usize,
}

impl Default for SignalStack {
    fn default() -> Self {
        Self {
            sp: 0,
            flags: SS_DISABLE,
            __padding: 0,
            size: 0,
        }
    }
}

impl SignalStack {
    /// Creates a fully initialized Linux alternate-stack record.
    pub const fn new(sp: usize, flags: u32, size: usize) -> Self {
        Self {
            sp,
            flags,
            __padding: 0,
            size,
        }
    }

    /// Normalizes the `uc_stack` record supplied by `rt_sigreturn`.
    ///
    /// Version 0.1 supports the Linux disabled, enabled, and visible
    /// `SS_ONSTACK` modes. `SS_AUTODISARM` is intentionally not advertised:
    /// consumers must reject it at `sigaltstack(2)` until delivery-time reset
    /// and restore semantics are implemented end to end.
    pub(crate) fn prepare_restore(&self) -> Result<Self, SignalStackRestoreError> {
        if self.flags != 0 && self.flags != SS_DISABLE && self.flags != SS_ONSTACK {
            return Err(SignalStackRestoreError::InvalidFlags);
        }
        if self.flags == SS_DISABLE {
            return Ok(Self::default());
        }
        if self.sp.checked_add(self.size).is_none() {
            return Err(SignalStackRestoreError::AddressOverflow);
        }
        Ok(*self)
    }

    /// Checks if signal stack is disabled.
    pub fn disabled(&self) -> bool {
        self.flags == SS_DISABLE
    }

    /// Returns the exclusive top of the configured alternate stack.
    ///
    /// A userspace-provided base and length are not trusted to fit in the
    /// address space. Callers must treat `None` as an unusable stack instead
    /// of allowing integer wraparound to select a kernel or low address.
    pub fn checked_top(&self) -> Option<usize> {
        (!self.disabled())
            .then(|| self.sp.checked_add(self.size))
            .flatten()
    }

    /// Implements Linux's overflow-safe `on_sig_stack()` range predicate.
    /// The exclusive base/inclusive-top shape matches the kernel rule for a
    /// downward-growing stack pointer.
    pub fn contains_sp(&self, sp: usize) -> bool {
        !self.disabled() && sp > self.sp && sp.wrapping_sub(self.sp) <= self.size
    }

    /// Returns the flags Linux exposes when querying `sigaltstack(2)` at the
    /// supplied userspace stack pointer.
    pub fn flags_at(&self, sp: usize) -> u32 {
        if self.disabled() {
            SS_DISABLE
        } else if self.contains_sp(sp) {
            SS_ONSTACK
        } else {
            0
        }
    }

    /// Checks that a complete object range remains within this alternate
    /// stack. This is used before publishing a nested signal frame.
    pub fn contains_range(&self, start: usize, len: usize) -> bool {
        if self.disabled() || start < self.sp {
            return false;
        }
        let Some(end) = start.checked_add(len) else {
            return false;
        };
        self.checked_top().is_some_and(|top| end <= top)
    }
}

/// Why a saved `uc_stack` record was not applied by `rt_sigreturn`.
///
/// Linux deliberately squashes non-copy `restore_altstack()` errors. The
/// reusable crate follows that observable rule: this value is retained in a
/// prepared restore for diagnostics while context and mask restoration can
/// still commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalStackRestoreError {
    /// The frame contains unsupported or contradictory `SS_*` flags.
    InvalidFlags,
    /// `ss_sp + ss_size` wraps the 64-bit userspace address space.
    AddressOverflow,
    /// The sigreturn syscall is executing on the currently configured stack.
    ActiveStack,
    /// The candidate is smaller than the consumer's architecture minimum.
    TooSmall,
    /// The candidate is outside the consumer's valid userspace range.
    InvalidAddress,
}

const _: [(); 24] = [(); mem::size_of::<SignalStack>()];
const _: [(); 8] = [(); mem::align_of::<SignalStack>()];
const _: [(); 0] = [(); mem::offset_of!(SignalStack, sp)];
const _: [(); 8] = [(); mem::offset_of!(SignalStack, flags)];
const _: [(); 16] = [(); mem::offset_of!(SignalStack, size)];
