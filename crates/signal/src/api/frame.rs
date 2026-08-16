//! x86_64 signal-frame data plane.
//!
//! This module deliberately has no signal-manager state.  It owns the Linux
//! visible frame layout, its userspace copy boundaries, and the transactional
//! preparation of a signal return.  A manager supplies its current context,
//! alternate-stack snapshot, and validation policy, then commits the returned
//! token in its own state domain.

use core::mem::{self, offset_of};

use axcpu::uspace::UserContext;
use thekernel_linux_usercopy::{
    UserCopyError, UserMemory, UserMemoryContext, VmMutPtr, VmPtr, VmResult,
};

use crate::{
    SignalInfo, SignalSet, SignalStack, SignalStackRestoreError, Signo,
    arch::{LegacyFpState64, SignalContextError, UContext},
};

/// x86_64's red zone, which an asynchronous signal frame must not overwrite.
pub const SIGNAL_RED_ZONE: usize = 128;

/// Alignment required by the x86_64 Linux signal-frame data object.
pub const SIGNAL_FRAME_ALIGNMENT: usize = 16;

/// Size of the fixed Linux-visible signal frame, excluding the legacy FXSAVE
/// payload and the restorer word.
pub const SIGNAL_FIXED_FRAME_SIZE: usize = mem::size_of::<SignalFrame>();

/// Alignment of the separately published legacy FXSAVE payload.
pub const SIGNAL_FPSTATE_ALIGNMENT: usize = 16;

/// Size of the separately published legacy FXSAVE payload.
pub const SIGNAL_FPSTATE_SIZE: usize = LegacyFpState64::SIZE;

/// Why a signal frame could not be placed on the selected stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalFrameLayoutError {
    /// A stack arithmetic operation wrapped the userspace address space.
    AddressOverflow,
    /// The selected alternate stack cannot contain the complete frame and
    /// restorer word (or the nested delivery's preserved red zone).
    OutsideAlternateStack,
}

/// Why the floating-point image selected by `rt_sigreturn` could not be
/// copied into an owned restore token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FpStateRestoreError {
    /// The non-null userspace pointer is not 16-byte aligned.
    Misaligned,
    /// The complete 512-byte image could not be copied from userspace.
    Copyin(UserCopyError),
}

/// Short alias for callers that refer to the restored FP payload directly.
pub type FpRestoreError = FpStateRestoreError;

/// The CPU-independent floating-point action returned by signal restore.
///
/// `Reset` represents the Linux null `fpstate` pointer. `Image` owns the
/// exact bytes supplied by userspace; no CPU validation or restore is done by
/// this crate.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FpRestore {
    /// Reset the task's legacy floating-point state.
    Reset,
    /// Restore this owned legacy FXSAVE image in the embedding architecture.
    Image(LegacyFpState64),
}

impl FpRestore {
    /// Returns a reset token without allocating or touching CPU state.
    pub const fn reset() -> Self {
        Self::Reset
    }

    /// Returns an image restore token.
    pub const fn image(image: LegacyFpState64) -> Self {
        Self::Image(image)
    }

    /// Alias for [`Self::image`] using restore-oriented terminology.
    pub const fn restore(image: LegacyFpState64) -> Self {
        Self::Image(image)
    }

    /// Returns whether this token requests a reset rather than an image.
    pub const fn is_reset(&self) -> bool {
        matches!(self, Self::Reset)
    }

    /// Returns the owned image, if this token requests one.
    pub const fn as_image(&self) -> Option<&LegacyFpState64> {
        match self {
            Self::Reset => None,
            Self::Image(image) => Some(image),
        }
    }

    /// Returns the owned image, if this token requests one.
    pub fn into_image(self) -> Option<LegacyFpState64> {
        match self {
            Self::Reset => None,
            Self::Image(image) => Some(image),
        }
    }
}

/// Which stack origin is used for one signal delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalFrameStack {
    /// Deliver on the interrupted ordinary userspace stack, preserving its
    /// 128-byte red zone.
    Normal,
    /// Deliver on an alternate stack for the first time.  The frame starts
    /// from the exclusive top and does not reserve a red zone below that top.
    FreshAltStack,
    /// Deliver while already executing on the alternate stack, preserving the
    /// interrupted handler's 128-byte red zone.
    NestedAltStack,
}

/// The checked addresses occupied by a signal frame and its entry word.
///
/// The published user stack pointer points at the restorer word.  The frame
/// itself starts eight bytes above it, so the x86_64 handler entry invariant is
/// `rsp % 16 == 8` while `frame_start % 16 == 0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignalFrameLayout {
    frame_start: usize,
    published_sp: usize,
    siginfo: usize,
    ucontext: usize,
    fpstate: usize,
    stack: SignalFrameStack,
}

impl SignalFrameLayout {
    /// Computes a checked frame placement for `interrupted_sp`.
    pub fn new(
        interrupted_sp: usize,
        configured_stack: &SignalStack,
        stack: SignalFrameStack,
    ) -> Result<Self, SignalFrameLayoutError> {
        let origin = match stack {
            SignalFrameStack::Normal | SignalFrameStack::NestedAltStack => interrupted_sp
                .checked_sub(SIGNAL_RED_ZONE)
                .ok_or(SignalFrameLayoutError::AddressOverflow)?,
            SignalFrameStack::FreshAltStack => configured_stack
                .checked_top()
                .ok_or(SignalFrameLayoutError::AddressOverflow)?,
        };

        let unaligned_start = origin
            .checked_sub(SIGNAL_FPSTATE_SIZE)
            .and_then(|address| address.checked_sub(SIGNAL_FIXED_FRAME_SIZE))
            .ok_or(SignalFrameLayoutError::AddressOverflow)?;
        let frame_start = unaligned_start & !(SIGNAL_FRAME_ALIGNMENT - 1);
        let fpstate = frame_start
            .checked_add(SIGNAL_FIXED_FRAME_SIZE)
            .ok_or(SignalFrameLayoutError::AddressOverflow)?;
        let published_sp = frame_start
            .checked_sub(mem::size_of::<usize>())
            .ok_or(SignalFrameLayoutError::AddressOverflow)?;
        let siginfo = frame_start
            .checked_add(offset_of!(SignalFrame, siginfo))
            .ok_or(SignalFrameLayoutError::AddressOverflow)?;
        let ucontext = frame_start
            .checked_add(offset_of!(SignalFrame, ucontext))
            .ok_or(SignalFrameLayoutError::AddressOverflow)?;

        // The restorer word, frame, and (for nested delivery) preserved red
        // zone must all remain in the configured alternate stack.  Fresh
        // delivery starts at the top, so the range ends at that top.  Nested
        // delivery ends at the interrupted stack pointer, covering the red
        // zone between the frame and the interrupted handler.
        if matches!(
            stack,
            SignalFrameStack::FreshAltStack | SignalFrameStack::NestedAltStack
        ) {
            let end = match stack {
                SignalFrameStack::FreshAltStack => configured_stack
                    .checked_top()
                    .ok_or(SignalFrameLayoutError::AddressOverflow)?,
                SignalFrameStack::NestedAltStack => interrupted_sp,
                SignalFrameStack::Normal => unreachable!(),
            };
            let span = end
                .checked_sub(published_sp)
                .ok_or(SignalFrameLayoutError::AddressOverflow)?;
            if !configured_stack.contains_range(published_sp, span) {
                return Err(SignalFrameLayoutError::OutsideAlternateStack);
            }
        }

        Ok(Self {
            frame_start,
            published_sp,
            siginfo,
            ucontext,
            fpstate,
            stack,
        })
    }

    /// Returns the first byte of the ABI frame.
    pub const fn frame_start(&self) -> usize {
        self.frame_start
    }

    /// Returns the user stack pointer installed for handler entry.
    pub const fn published_sp(&self) -> usize {
        self.published_sp
    }

    /// Returns the user pointer passed as the handler's `siginfo` argument.
    pub const fn siginfo(&self) -> usize {
        self.siginfo
    }

    /// Returns the user pointer passed as the handler's `ucontext` argument.
    pub const fn ucontext(&self) -> usize {
        self.ucontext
    }

    /// Returns the first byte of the separately published legacy FXSAVE
    /// payload.
    pub const fn fpstate(&self) -> usize {
        self.fpstate
    }

    /// Alias for [`Self::fpstate`] emphasizing that this is a start address.
    pub const fn fpstate_start(&self) -> usize {
        self.fpstate
    }

    /// Returns the exclusive end of the fixed frame object.
    pub const fn fixed_frame_end(&self) -> usize {
        self.frame_start + SIGNAL_FIXED_FRAME_SIZE
    }

    /// Returns the exclusive end of the fixed frame and payload region.
    pub const fn payload_end(&self) -> usize {
        self.fpstate + SIGNAL_FPSTATE_SIZE
    }

    /// Returns the exclusive end of the legacy FXSAVE payload.
    pub const fn fpstate_end(&self) -> usize {
        self.payload_end()
    }

    /// Returns the stack origin used by this placement.
    pub const fn stack(&self) -> SignalFrameStack {
        self.stack
    }
}

/// The userspace ABI frame created for a signal handler.
///
/// This contains only Linux-visible signal state.  Kernel trap metadata is
/// not serialized into userspace and therefore cannot be forged by
/// `sigreturn`.  x86_64 enters the handler with the restorer word immediately
/// below this 16-byte-aligned object.
#[repr(C, align(16))]
#[derive(Clone)]
pub struct SignalFrame {
    ucontext: UContext,
    siginfo: SignalInfo,
}

const _: [(); SIGNAL_FRAME_ALIGNMENT] = [(); mem::align_of::<SignalFrame>()];
const _: [(); mem::size_of::<SignalFrame>()] =
    [(); offset_of!(SignalFrame, siginfo) + mem::size_of::<SignalInfo>()];

impl SignalFrame {
    pub(crate) fn new_with_fpstate(
        uctx: &UserContext,
        sigmask: SignalSet,
        stack: SignalStack,
        siginfo: SignalInfo,
        fpstate: usize,
    ) -> Self {
        Self {
            ucontext: UContext::with_fpstate(uctx, sigmask, stack, fpstate),
            siginfo,
        }
    }

    /// Returns the Linux-visible user context stored in this frame.
    pub fn ucontext(&self) -> &UContext {
        &self.ucontext
    }

    /// Returns a mutable Linux-visible user context, as a signal handler sees
    /// it.
    pub fn ucontext_mut(&mut self) -> &mut UContext {
        &mut self.ucontext
    }

    /// Copies a complete signal frame from userspace into an owned value.
    ///
    /// The userspace pointer is treated as an unaligned byte address.  The
    /// provider must initialize every byte on success; a faulting or partial
    /// read never yields an owned frame.
    pub fn read_from_user<M: UserMemory + ?Sized>(
        memory: &mut UserMemoryContext<'_, M>,
        ptr: *const Self,
    ) -> VmResult<Self> {
        let frame = ptr.vm_read_uninit(memory)?;
        // SAFETY: UserMemory returns `Ok` only after initializing every byte of
        // the destination.  SignalFrame and all nested ABI records contain
        // only initialized integer/byte storage; every ABI alignment hole is
        // represented by an explicit zeroed field.  Restoration validates the
        // machine fields before publication and never interprets siginfo.
        Ok(unsafe { frame.assume_init() })
    }

    /// Copies a complete frame to its userspace address.
    ///
    /// Construction of this type initializes all bytes, including the
    /// explicit ABI padding fields, so the unchecked object copy is bounded
    /// to the frame's exact representation.
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn write_to_user<M: UserMemory + ?Sized>(
        &self,
        memory: &mut UserMemoryContext<'_, M>,
        ptr: *mut Self,
    ) -> VmResult {
        // SAFETY: SignalFrame has no implicit outer padding and its nested
        // records initialize every ABI padding byte before construction.
        unsafe { ptr.vm_write_unchecked(memory, self.clone()) }
    }
}

/// A frame placement and its fully initialized contents, ready for one
/// userspace publication.
#[must_use = "publishing or dropping the prepared frame completes delivery"]
pub struct PreparedSignalFrame {
    layout: SignalFrameLayout,
    frame: SignalFrame,
    fpstate: LegacyFpState64,
    restorer: usize,
    handler: usize,
    signo: Signo,
    interrupted: UserContext,
}

impl PreparedSignalFrame {
    /// Returns the checked frame addresses before publication.
    pub const fn layout(&self) -> SignalFrameLayout {
        self.layout
    }

    /// Returns the fully initialized frame snapshot.
    pub fn frame(&self) -> &SignalFrame {
        &self.frame
    }

    /// Returns the owned legacy FXSAVE snapshot that will be published.
    pub fn fpstate(&self) -> &LegacyFpState64 {
        &self.fpstate
    }

    /// Copies the frame and restorer word to userspace exactly once.
    ///
    /// The returned published token owns the new machine context.  Callers
    /// must install it only after this method succeeds.  A copyout failure
    /// consumes the prepared token and leaves the caller's context untouched.
    pub fn publish<M: UserMemory + ?Sized>(
        self,
        memory: &mut UserMemoryContext<'_, M>,
    ) -> Result<PublishedSignalFrame, SignalFramePublishError> {
        let frame_ptr = self.layout.frame_start as *mut SignalFrame;
        // Publish from the highest object downward. This keeps the fixed
        // frame's user pointer valid before the restorer becomes reachable.
        // SAFETY: LegacyFpState64 has no padding beyond its initialized byte
        // array, and the userspace pointer is treated as an opaque byte address
        // by the usercopy provider.
        unsafe {
            (self.layout.fpstate as *mut LegacyFpState64)
                .vm_write_unchecked(memory, self.fpstate.clone())
        }
        .map_err(SignalFramePublishError::Fpstate)?;
        self.frame
            .write_to_user(memory, frame_ptr)
            .map_err(SignalFramePublishError::Frame)?;
        (self.layout.published_sp as *mut usize)
            .vm_write(memory, self.restorer)
            .map_err(SignalFramePublishError::Restorer)?;

        let mut context = self.interrupted;
        context.set_ip(self.handler);
        context.set_sp(self.layout.published_sp);
        context.set_arg0(self.signo as _);
        context.set_arg1(self.layout.siginfo);
        context.set_arg2(self.layout.ucontext);

        Ok(PublishedSignalFrame {
            layout: self.layout,
            context,
        })
    }
}

/// Why one-time signal-frame publication failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalFramePublishError {
    /// The legacy FXSAVE payload could not be copied to userspace.
    Fpstate(UserCopyError),
    /// The frame object could not be copied to userspace.
    Frame(UserCopyError),
    /// The restorer word could not be copied to userspace.
    Restorer(UserCopyError),
}

/// A successfully copied signal frame whose new context can be installed once.
#[must_use = "installing or dropping the published frame completes delivery"]
pub struct PublishedSignalFrame {
    layout: SignalFrameLayout,
    context: UserContext,
}

impl PublishedSignalFrame {
    /// Returns the context that corresponds to the copied frame.
    pub const fn context(&self) -> &UserContext {
        &self.context
    }

    /// Returns the copied frame placement.
    pub const fn layout(&self) -> SignalFrameLayout {
        self.layout
    }

    /// Installs the published handler context exactly once.
    pub fn install(self, current: &mut UserContext) {
        *current = self.context;
    }

    /// Alias for [`Self::install`] useful to adapters that call publication a
    /// commit.
    pub fn commit(self, current: &mut UserContext) {
        self.install(current);
    }
}

/// Prepares a complete x86_64 signal-frame delivery without touching
/// userspace or manager state.
pub fn prepare_signal_frame(
    interrupted: &UserContext,
    restore_blocked: SignalSet,
    configured_stack: SignalStack,
    stack: SignalFrameStack,
    siginfo: SignalInfo,
    handler: usize,
    restorer: usize,
) -> Result<PreparedSignalFrame, SignalFrameLayoutError> {
    prepare_signal_frame_with_fp_snapshot(
        interrupted,
        restore_blocked,
        configured_stack,
        stack,
        siginfo,
        handler,
        restorer,
        LegacyFpState64::default,
    )
}

/// Prepares a signal frame with a caller-owned legacy FXSAVE snapshot.
///
/// The callback is invoked only after checked layout arithmetic succeeds, so
/// a layout failure cannot consume or otherwise observe the caller's CPU
/// snapshot operation. The callback itself is intentionally CPU-agnostic.
#[allow(clippy::too_many_arguments)]
pub fn prepare_signal_frame_with_fp_snapshot(
    interrupted: &UserContext,
    restore_blocked: SignalSet,
    configured_stack: SignalStack,
    stack: SignalFrameStack,
    siginfo: SignalInfo,
    handler: usize,
    restorer: usize,
    snapshot: impl FnOnce() -> LegacyFpState64,
) -> Result<PreparedSignalFrame, SignalFrameLayoutError> {
    let layout = SignalFrameLayout::new(interrupted.sp(), &configured_stack, stack)?;
    let mut visible_stack = configured_stack;
    visible_stack.flags = configured_stack.flags_at(interrupted.sp());
    let fpstate = snapshot();
    Ok(PreparedSignalFrame {
        layout,
        frame: SignalFrame::new_with_fpstate(
            interrupted,
            restore_blocked,
            visible_stack,
            siginfo.clone(),
            layout.fpstate(),
        ),
        fpstate,
        restorer,
        handler,
        signo: siginfo.signo(),
        interrupted: *interrupted,
    })
}

/// Alias for [`prepare_signal_frame`] with a verb emphasizing that no state
/// has been published yet.
pub fn prepare_delivery_frame(
    interrupted: &UserContext,
    restore_blocked: SignalSet,
    configured_stack: SignalStack,
    stack: SignalFrameStack,
    siginfo: SignalInfo,
    handler: usize,
    restorer: usize,
) -> Result<PreparedSignalFrame, SignalFrameLayoutError> {
    prepare_signal_frame(
        interrupted,
        restore_blocked,
        configured_stack,
        stack,
        siginfo,
        handler,
        restorer,
    )
}

/// Byte-array variant of [`prepare_signal_frame_with_fp_snapshot`] for
/// embedding roots that expose a raw `fxsave` snapshot callback.
#[allow(clippy::too_many_arguments)]
pub fn prepare_signal_frame_with_fp_bytes(
    interrupted: &UserContext,
    restore_blocked: SignalSet,
    configured_stack: SignalStack,
    stack: SignalFrameStack,
    siginfo: SignalInfo,
    handler: usize,
    restorer: usize,
    snapshot: impl FnOnce() -> [u8; LegacyFpState64::SIZE],
) -> Result<PreparedSignalFrame, SignalFrameLayoutError> {
    prepare_signal_frame_with_fp_snapshot(
        interrupted,
        restore_blocked,
        configured_stack,
        stack,
        siginfo,
        handler,
        restorer,
        || LegacyFpState64::from_bytes(snapshot()),
    )
}

/// A fully validated signal return that can be committed without failure.
#[must_use = "committing or dropping the prepared restore completes sigreturn"]
pub struct PreparedSignalRestore {
    context: UserContext,
    blocked: SignalSet,
    stack: Option<SignalStack>,
    stack_error: Option<SignalStackRestoreError>,
    fp_restore: FpRestore,
}

impl PreparedSignalRestore {
    /// Returns the validated candidate user context.
    pub const fn context(&self) -> &UserContext {
        &self.context
    }

    /// Returns the validated alternate-stack update, if one will be applied.
    pub const fn stack(&self) -> Option<&SignalStack> {
        self.stack.as_ref()
    }

    /// Returns a Linux-compatible, squashed `restore_altstack()` error.
    pub const fn stack_error(&self) -> Option<SignalStackRestoreError> {
        self.stack_error
    }

    /// Returns the sanitized signal mask that will be committed.
    pub const fn blocked(&self) -> SignalSet {
        self.blocked
    }

    /// Returns the CPU-independent floating-point action to commit.
    pub const fn fp_restore(&self) -> &FpRestore {
        &self.fp_restore
    }

    /// Consumes the prepared restore and returns its floating-point token.
    /// The context and manager state remain uncommitted; use
    /// [`Self::commit_context`] or a manager commit method when both are
    /// needed.
    pub fn into_fp_restore(self) -> FpRestore {
        self.fp_restore
    }

    /// Alias for [`Self::into_fp_restore`] for manager adapters that use
    /// take-style token naming.
    pub fn take_fp_restore(self) -> FpRestore {
        self.into_fp_restore()
    }

    /// Commits the prepared context to a caller-owned context exactly once.
    /// Manager-owned mask and alternate-stack state remain the caller's
    /// responsibility.
    pub fn commit_context(self, current: &mut UserContext) -> FpRestore {
        *current = self.context;
        self.fp_restore
    }

    /// Splits the one-shot token for a manager that owns mask and stack state.
    pub(crate) fn into_parts_with_fp(
        self,
    ) -> (UserContext, SignalSet, Option<SignalStack>, FpRestore) {
        (self.context, self.blocked, self.stack, self.fp_restore)
    }
}

/// Prepares an owned signal frame for `rt_sigreturn` without publishing any
/// context, mask, or alternate-stack state.
///
/// The supplied predicates and callback keep address-space and policy checks
/// out of this reusable data plane.  Invalid alternate-stack restoration is
/// intentionally squashed into `stack_error`, matching Linux's non-copy
/// `restore_altstack()` behavior.
pub fn prepare_signal_restore(
    current: &UserContext,
    frame: SignalFrame,
    valid_program_counter: impl FnOnce(usize) -> bool,
    valid_stack_pointer: impl FnOnce(usize) -> bool,
    current_stack: SignalStack,
    validate_stack: impl FnOnce(
        &SignalStack,
        usize,
        &SignalStack,
    ) -> Result<(), SignalStackRestoreError>,
) -> Result<PreparedSignalRestore, SignalContextError> {
    prepare_signal_restore_with_fp(
        current,
        frame,
        valid_program_counter,
        valid_stack_pointer,
        current_stack,
        validate_stack,
        FpRestore::Reset,
    )
}

/// Prepares an owned signal return with an already copied FP action.
///
/// This is the two-phase boundary used by an embedding root: usercopy and
/// policy validation happen here, while the root later consumes the returned
/// [`FpRestore`] and performs architecture-specific validation/commit.
pub fn prepare_signal_restore_with_fp(
    current: &UserContext,
    frame: SignalFrame,
    valid_program_counter: impl FnOnce(usize) -> bool,
    valid_stack_pointer: impl FnOnce(usize) -> bool,
    current_stack: SignalStack,
    validate_stack: impl FnOnce(
        &SignalStack,
        usize,
        &SignalStack,
    ) -> Result<(), SignalStackRestoreError>,
    fp_restore: FpRestore,
) -> Result<PreparedSignalRestore, SignalContextError> {
    let context = frame.ucontext.mcontext.prepare_restore(current)?;
    if !valid_program_counter(context.ip()) {
        return Err(SignalContextError::InvalidProgramCounter);
    }
    if !valid_stack_pointer(context.sp()) {
        return Err(SignalContextError::InvalidStackPointer);
    }

    let mut blocked = frame.ucontext.sigmask;
    blocked.remove(Signo::SIGKILL);
    blocked.remove(Signo::SIGSTOP);

    let candidate = frame.ucontext.stack.prepare_restore();
    let (stack, stack_error) = match candidate {
        Ok(candidate) => match validate_stack(&current_stack, current.sp(), &candidate) {
            Ok(()) => (Some(candidate), None),
            Err(error) => (None, Some(error)),
        },
        Err(error) => (None, Some(error)),
    };

    Ok(PreparedSignalRestore {
        context,
        blocked,
        stack,
        stack_error,
        fp_restore,
    })
}

/// Copies and prepares a complete signal return frame from userspace.
pub fn copyin_and_prepare_restore<M: UserMemory + ?Sized>(
    memory: &mut UserMemoryContext<'_, M>,
    ptr: *const SignalFrame,
    current: &UserContext,
    valid_program_counter: impl FnOnce(usize) -> bool,
    valid_stack_pointer: impl FnOnce(usize) -> bool,
    current_stack: SignalStack,
    validate_stack: impl FnOnce(
        &SignalStack,
        usize,
        &SignalStack,
    ) -> Result<(), SignalStackRestoreError>,
) -> Result<PreparedSignalRestore, SignalFrameRestoreError> {
    let frame =
        SignalFrame::read_from_user(memory, ptr).map_err(SignalFrameRestoreError::Copyin)?;
    let fp_restore = read_fp_restore(memory, frame.ucontext.mcontext.fpstate())?;
    prepare_signal_restore_with_fp(
        current,
        frame,
        valid_program_counter,
        valid_stack_pointer,
        current_stack,
        validate_stack,
        fp_restore,
    )
    .map_err(SignalFrameRestoreError::Context)
}

/// Copies and prepares a signal return frame whose fixed frame starts at the
/// current user `rsp`. On x86_64 the restorer has already popped `pretcode`,
/// so `rsp` points directly at `ucontext`; callers must not add eight bytes.
pub fn copyin_and_prepare_restore_at_rsp<M: UserMemory + ?Sized>(
    memory: &mut UserMemoryContext<'_, M>,
    current_rsp: usize,
    current: &UserContext,
    valid_program_counter: impl FnOnce(usize) -> bool,
    valid_stack_pointer: impl FnOnce(usize) -> bool,
    current_stack: SignalStack,
    validate_stack: impl FnOnce(
        &SignalStack,
        usize,
        &SignalStack,
    ) -> Result<(), SignalStackRestoreError>,
) -> Result<PreparedSignalRestore, SignalFrameRestoreError> {
    copyin_and_prepare_restore(
        memory,
        current_rsp as *const SignalFrame,
        current,
        valid_program_counter,
        valid_stack_pointer,
        current_stack,
        validate_stack,
    )
}

fn read_fp_restore<M: UserMemory + ?Sized>(
    memory: &mut UserMemoryContext<'_, M>,
    fpstate: usize,
) -> Result<FpRestore, SignalFrameRestoreError> {
    if fpstate == 0 {
        return Ok(FpRestore::Reset);
    }
    if fpstate & (SIGNAL_FPSTATE_ALIGNMENT - 1) != 0 {
        return Err(SignalFrameRestoreError::Fpstate(
            FpStateRestoreError::Misaligned,
        ));
    }
    let image = (fpstate as *const LegacyFpState64)
        .vm_read_uninit(memory)
        .map_err(FpStateRestoreError::Copyin)
        .map_err(SignalFrameRestoreError::Fpstate)?;
    // SAFETY: usercopy reports success only after initializing every byte of
    // the exact 512-byte destination object.
    Ok(FpRestore::Image(unsafe { image.assume_init() }))
}

/// Why copying or validating a signal return frame failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalFrameRestoreError {
    /// The complete frame could not be copied from userspace.
    Copyin(UserCopyError),
    /// The frame's non-null legacy FXSAVE pointer was malformed or faulted.
    Fpstate(FpStateRestoreError),
    /// The owned frame failed architectural or caller-supplied validation.
    Context(SignalContextError),
}
