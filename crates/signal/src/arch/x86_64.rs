use axcpu::uspace::UserContext;

use crate::{arch::SignalContextError, SignalSet, SignalStack};

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

/// The standard-format XSAVE prefix needed to carry xstate component 9.
///
/// Linux places PKRU at its architectural standard-format offset, 2688 bytes
/// from the start of the XSAVE area.  The signal layer deliberately owns this
/// prefix rather than deriving an offset from CPUID: the task xstate policy is
/// selected by the embedding x86 layer, and a user frame must be validated
/// against that selected policy before it reaches `XRSTOR`.
#[repr(C, align(64))]
#[derive(Clone, PartialEq, Eq)]
pub struct XsavePkruState64 {
    bytes: [u8; Self::SIZE],
}

impl XsavePkruState64 {
    /// XSAVE component number assigned to PKRU by x86.
    pub const PKRU_COMPONENT: u32 = 9;
    /// Bit in `xstate_bv` denoting that the PKRU component is present.
    pub const PKRU_XFEATURE: u64 = 1 << Self::PKRU_COMPONENT;
    /// Offset of the 64-byte XSAVE header after the legacy FXSAVE region.
    pub const HEADER_OFFSET: usize = LegacyFpState64::SIZE;
    /// Size of the standard XSAVE header.
    pub const HEADER_SIZE: usize = 64;
    /// Standard-format offset of the eight-byte PKRU component.
    pub const PKRU_OFFSET: usize = 2688;
    /// Size of the PKRU component, including its architecturally reserved high word.
    pub const PKRU_SIZE: usize = 8;
    /// Exact byte prefix needed to validate and extract component 9.
    pub const SIZE: usize = Self::PKRU_OFFSET + Self::PKRU_SIZE;

    /// Creates an owned image from the XSAVE bytes needed for PKRU restore.
    pub const fn from_bytes(bytes: [u8; Self::SIZE]) -> Self {
        Self { bytes }
    }

    /// Returns the exact owned XSAVE prefix.
    pub const fn as_bytes(&self) -> &[u8; Self::SIZE] {
        &self.bytes
    }

    /// Returns the user-controlled xstate bitmap.
    pub fn xstate_bv(&self) -> u64 {
        self.read_u64(Self::HEADER_OFFSET)
    }

    /// Returns the XSAVE format bitmap.
    pub fn xcomp_bv(&self) -> u64 {
        self.read_u64(Self::HEADER_OFFSET + 8)
    }

    /// Returns the PKRU value when the component is present.
    pub fn pkru(&self) -> Option<u32> {
        (self.xstate_bv() & Self::PKRU_XFEATURE != 0).then(|| self.read_u32(Self::PKRU_OFFSET))
    }

    /// Validates the subset of an XSAVE signal image that is relevant before
    /// an x86 embedding restores its state.
    ///
    /// `allowed_xfeatures` must be the task's enabled user XSAVE mask, not
    /// the host's broad CPUID mask.  An absent component 9 denotes x86's
    /// initial PKRU value (zero).  This avoids preserving stale PKRU when a
    /// signal frame intentionally omits the component.
    pub fn validate_pkru_for_rt_sigreturn(
        &self,
        allowed_xfeatures: u64,
    ) -> Result<PkruRestore, XsavePkruValidationError> {
        let xstate_bv = self.xstate_bv();
        if xstate_bv & !allowed_xfeatures != 0 {
            return Err(XsavePkruValidationError::UnsupportedXfeature);
        }
        if self.xcomp_bv() != 0 {
            return Err(XsavePkruValidationError::NonStandardFormat);
        }
        if self.bytes[Self::HEADER_OFFSET + 16..Self::HEADER_OFFSET + Self::HEADER_SIZE]
            .iter()
            .any(|&byte| byte != 0)
        {
            return Err(XsavePkruValidationError::ReservedHeader);
        }
        if xstate_bv & Self::PKRU_XFEATURE == 0 {
            return Ok(PkruRestore::Reset);
        }
        if allowed_xfeatures & Self::PKRU_XFEATURE == 0 {
            return Err(XsavePkruValidationError::PkruNotEnabled);
        }
        if self.read_u32(Self::PKRU_OFFSET + 4) != 0 {
            return Err(XsavePkruValidationError::ReservedPkruBits);
        }
        Ok(PkruRestore::Restore(self.read_u32(Self::PKRU_OFFSET)))
    }

    fn read_u32(&self, offset: usize) -> u32 {
        u32::from_le_bytes(self.bytes[offset..offset + 4].try_into().unwrap())
    }

    fn read_u64(&self, offset: usize) -> u64 {
        u64::from_le_bytes(self.bytes[offset..offset + 8].try_into().unwrap())
    }
}

impl Default for XsavePkruState64 {
    fn default() -> Self {
        Self::from_bytes([0; Self::SIZE])
    }
}

impl core::fmt::Debug for XsavePkruState64 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("XsavePkruState64")
            .field("xstate_bv", &self.xstate_bv())
            .field("xcomp_bv", &self.xcomp_bv())
            .field("pkru", &self.pkru())
            .finish()
    }
}

/// The PKRU action extracted from a validated `rt_sigreturn` XSAVE image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkruRestore {
    /// Component 9 was absent, so restore x86's initial PKRU value of zero.
    Reset,
    /// Restore this validated PKRU value with `WRPKRU` or an equivalent xstate restore.
    Restore(u32),
}

impl PkruRestore {
    /// Returns the PKRU value that must be installed.
    pub const fn value(self) -> u32 {
        match self {
            Self::Reset => 0,
            Self::Restore(value) => value,
        }
    }
}

/// Why the PKRU-relevant portion of an XSAVE signal image is not restorable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XsavePkruValidationError {
    /// The frame requests an xstate component outside the task's enabled mask.
    UnsupportedXfeature,
    /// The frame uses compacted or supervisor XSAVE layout, not Linux's standard user layout.
    NonStandardFormat,
    /// Reserved XSAVE header bytes were nonzero.
    ReservedHeader,
    /// The frame contained PKRU although component 9 is disabled for this task.
    PkruNotEnabled,
    /// The upper 32 bits of xstate component 9 were nonzero.
    ReservedPkruBits,
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
