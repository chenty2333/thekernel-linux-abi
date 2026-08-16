use axcpu::uspace::UserContext;

use crate::{SignalSet, SignalStack, arch::SignalContextError};

/// The exact x86_64 legacy floating-point image exposed by `fxsave`.
///
/// The current target does not advertise `OSXSAVE`, so the signal ABI carries
/// the legacy 512-byte image rather than an XSAVE area.  This type is an
/// owned byte image on purpose: the signal crate does not inspect or validate
/// CPU state and leaves restore/commit to its embedding architecture layer.
#[repr(C, align(16))]
#[derive(Clone, PartialEq, Eq)]
pub struct LegacyFpState64 {
    bytes: [u8; Self::SIZE],
}

impl LegacyFpState64 {
    /// Size of one legacy FXSAVE image.
    pub const SIZE: usize = 512;

    /// Creates an owned image from its exact object bytes.
    pub const fn from_bytes(bytes: [u8; Self::SIZE]) -> Self {
        Self { bytes }
    }

    /// Alias documenting that the input is copied into owned storage.
    pub const fn from_owned_bytes(bytes: [u8; Self::SIZE]) -> Self {
        Self::from_bytes(bytes)
    }

    /// Returns a shared view of the complete owned image.
    pub const fn as_bytes(&self) -> &[u8; Self::SIZE] {
        &self.bytes
    }

    /// Copies the complete image into an owned byte array.
    pub const fn to_bytes(&self) -> [u8; Self::SIZE] {
        self.bytes
    }

    /// Consumes the image and returns its exact owned bytes.
    pub const fn into_bytes(self) -> [u8; Self::SIZE] {
        self.bytes
    }

    /// Alias documenting that the returned value owns all bytes.
    pub const fn into_owned_bytes(self) -> [u8; Self::SIZE] {
        self.into_bytes()
    }
}

impl Default for LegacyFpState64 {
    fn default() -> Self {
        Self::from_bytes([0; Self::SIZE])
    }
}

impl core::fmt::Debug for LegacyFpState64 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("LegacyFpState64")
            .field(&self.bytes.len())
            .finish()
    }
}

impl From<[u8; LegacyFpState64::SIZE]> for LegacyFpState64 {
    fn from(bytes: [u8; LegacyFpState64::SIZE]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl From<LegacyFpState64> for [u8; LegacyFpState64::SIZE] {
    fn from(image: LegacyFpState64) -> Self {
        image.into_bytes()
    }
}

core::arch::global_asm!(
    "
.section .text
.code64
.balign 4096
.global thekernel_linux_signal_trampoline
thekernel_linux_signal_trampoline:
    mov rax, 0xf
    syscall

.fill 4096 - (. - thekernel_linux_signal_trampoline), 1, 0
"
);

#[repr(C)]
#[derive(Clone)]
pub struct MContext {
    r8: usize,
    r9: usize,
    r10: usize,
    r11: usize,
    r12: usize,
    r13: usize,
    r14: usize,
    r15: usize,
    rdi: usize,
    rsi: usize,
    rbp: usize,
    rbx: usize,
    rdx: usize,
    rax: usize,
    rcx: usize,
    rsp: usize,
    rip: usize,
    eflags: usize,
    cs: u16,
    gs: u16,
    fs: u16,
    ss: u16,
    err: usize,
    trapno: usize,
    oldmask: usize,
    cr2: usize,
    fpstate: usize,
    _reserved1: [usize; 8],
}

impl MContext {
    pub fn new(uctx: &UserContext) -> Self {
        Self {
            r8: uctx.r8 as _,
            r9: uctx.r9 as _,
            r10: uctx.r10 as _,
            r11: uctx.r11 as _,
            r12: uctx.r12 as _,
            r13: uctx.r13 as _,
            r14: uctx.r14 as _,
            r15: uctx.r15 as _,
            rdi: uctx.rdi as _,
            rsi: uctx.rsi as _,
            rbp: uctx.rbp as _,
            rbx: uctx.rbx as _,
            rdx: uctx.rdx as _,
            rax: uctx.rax as _,
            rcx: uctx.rcx as _,
            rsp: uctx.rsp as _,
            rip: uctx.rip as _,
            eflags: uctx.rflags as _,
            cs: uctx.cs as _,
            gs: 0,
            fs: 0,
            ss: uctx.ss as _,
            err: uctx.error_code as _,
            trapno: uctx.vector as _,
            oldmask: 0,
            cr2: 0,
            fpstate: 0,
            _reserved1: [0; 8],
        }
    }

    /// Builds the context fields that are published in a signal delivery.
    /// `oldmask` is retained for the legacy sigcontext ABI while `fpstate`
    /// points at the separately published FXSAVE payload.
    pub(crate) fn for_delivery(uctx: &UserContext, sigmask: SignalSet, fpstate: usize) -> Self {
        let mut context = Self::new(uctx);
        context.oldmask = sigmask.bits() as _;
        context.fpstate = fpstate;
        context
    }

    pub(crate) fn prepare_restore(
        &self,
        current: &UserContext,
    ) -> Result<UserContext, SignalContextError> {
        // TheKernel currently supports only the native 64-bit userspace ABI.
        // Never copy a kernel or compatibility selector out of a user frame.
        if self.cs & 0b11 != 0b11 || self.cs as u64 != current.cs || self.ss as u64 != current.ss {
            return Err(SignalContextError::InvalidProcessorState);
        }

        let mut restored = *current;
        restored.r8 = self.r8 as _;
        restored.r9 = self.r9 as _;
        restored.r10 = self.r10 as _;
        restored.r11 = self.r11 as _;
        restored.r12 = self.r12 as _;
        restored.r13 = self.r13 as _;
        restored.r14 = self.r14 as _;
        restored.r15 = self.r15 as _;
        restored.rdi = self.rdi as _;
        restored.rsi = self.rsi as _;
        restored.rbp = self.rbp as _;
        restored.rbx = self.rbx as _;
        restored.rdx = self.rdx as _;
        restored.rax = self.rax as _;
        restored.rcx = self.rcx as _;
        restored.rsp = self.rsp as _;
        restored.rip = self.rip as _;

        // Match Linux's FIX_EFLAGS model: condition/debug/alignment state is
        // user-restorable, while IOPL, IF and reserved bits remain trusted.
        const USER_RFLAGS_MASK: u64 = (1 << 0) // CF
            | (1 << 2) // PF
            | (1 << 4) // AF
            | (1 << 6) // ZF
            | (1 << 7) // SF
            | (1 << 8) // TF
            | (1 << 10) // DF
            | (1 << 11) // OF
            | (1 << 16) // RF
            | (1 << 18); // AC
        restored.rflags =
            (current.rflags & !USER_RFLAGS_MASK) | (self.eflags as u64 & USER_RFLAGS_MASK);

        // cs/ss, trap vector, error code and TLS bases are kernel-owned and
        // intentionally preserved from `current`.
        Ok(restored)
    }

    /// Replaces the saved instruction pointer.
    pub fn set_program_counter(&mut self, pc: usize) {
        self.rip = pc;
    }

    /// Replaces the saved stack pointer.
    pub fn set_stack_pointer(&mut self, sp: usize) {
        self.rsp = sp;
    }

    /// Replaces the saved RFLAGS value.
    pub fn set_processor_flags(&mut self, flags: usize) {
        self.eflags = flags;
    }

    /// Returns the saved RFLAGS value.
    pub fn processor_flags(&self) -> usize {
        self.eflags
    }

    /// Replaces the saved code segment selector.
    pub fn set_code_segment(&mut self, cs: u16) {
        self.cs = cs;
    }

    /// Returns the saved user stack-segment selector.
    pub const fn stack_segment(&self) -> u16 {
        self.ss
    }

    /// Returns the legacy sigcontext blocked-mask field.
    pub const fn old_mask(&self) -> usize {
        self.oldmask
    }

    /// Returns the userspace address of the legacy FXSAVE image.
    pub const fn fpstate(&self) -> usize {
        self.fpstate
    }

    /// Replaces the userspace pointer to the legacy FXSAVE image.
    pub fn set_fpstate(&mut self, address: usize) {
        self.fpstate = address;
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct UContext {
    pub flags: usize,
    pub link: usize,
    pub stack: SignalStack,
    pub mcontext: MContext,
    pub sigmask: SignalSet,
}

impl UContext {
    pub fn new(uctx: &UserContext, sigmask: SignalSet, stack: SignalStack) -> Self {
        Self {
            flags: UC_SIGCONTEXT_SS | UC_STRICT_RESTORE_SS,
            link: 0,
            stack,
            mcontext: MContext::for_delivery(uctx, sigmask, 0),
            sigmask,
        }
    }

    /// Builds a context with its separately published legacy FXSAVE address.
    pub(crate) fn with_fpstate(
        uctx: &UserContext,
        sigmask: SignalSet,
        stack: SignalStack,
        fpstate: usize,
    ) -> Self {
        Self {
            flags: UC_SIGCONTEXT_SS | UC_STRICT_RESTORE_SS,
            link: 0,
            stack,
            mcontext: MContext::for_delivery(uctx, sigmask, fpstate),
            sigmask,
        }
    }
}

/// `ucontext_t.uc_flags` bit indicating that sigcontext contains `ss`.
pub const UC_SIGCONTEXT_SS: usize = 2;
/// `ucontext_t.uc_flags` bit requesting strict user `ss` restoration.
pub const UC_STRICT_RESTORE_SS: usize = 4;
/// The x86_64 Linux ABI does not advertise this flag for the legacy image.
pub const UC_FP_XSTATE: usize = 1;

const _: [(); 8] = [(); core::mem::align_of::<MContext>()];
const _: [(); 256] = [(); size_of::<MContext>()];
const _: [(); 150] = [(); core::mem::offset_of!(MContext, ss)];
const _: [(); 168] = [(); core::mem::offset_of!(MContext, oldmask)];
const _: [(); 184] = [(); core::mem::offset_of!(MContext, fpstate)];
const _: [(); 16] = [(); core::mem::align_of::<LegacyFpState64>()];
const _: [(); 512] = [(); size_of::<LegacyFpState64>()];
const _: [(); 40] = [(); core::mem::offset_of!(UContext, mcontext)];
const _: [(); 296] = [(); core::mem::offset_of!(UContext, sigmask)];
const _: [(); 304] = [(); size_of::<UContext>()];
