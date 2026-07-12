use alloc::{alloc::AllocError, sync::Arc, vec::Vec};
use core::{
    alloc::Layout,
    mem::offset_of,
    sync::atomic::{AtomicBool, Ordering},
};

use axcpu::uspace::UserContext;
use kspin::SpinNoIrq;
use thekernel_linux_usercopy::{UserMemory, UserMemoryContext, VmMutPtr, VmPtr, VmResult};

#[cfg(all(feature = "multitask", target_os = "none"))]
use axsync::Mutex as DeliveryMutex;
#[cfg(not(all(feature = "multitask", target_os = "none")))]
use kspin::SpinNoIrq as DeliveryMutex;

use super::{ProcessSignalManager, RegisteredThread};
use crate::{
    DefaultSignalAction, DequeuedSignal, DetachedSignal, PendingSignals, PreparedSignal,
    SignalAction, SignalActionFlags, SignalDisposition, SignalInfo, SignalOSAction, SignalSet,
    SignalStack, SignalStackRestoreError, Signo,
    arch::{SignalContextError, UContext},
};

/// Result of publishing one thread-directed signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadSignalSendOutcome {
    pub published: bool,
    pub wake: bool,
}

/// Why a thread endpoint could not be registered with its process manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadRegistrationError {
    /// Allocating the registry entry or immutable replacement failed.
    NoMemory,
    /// This endpoint already owns a pending or active registration.
    AlreadyRegistered,
    /// Another live endpoint in the process already owns this thread ID.
    TidInUse,
    /// The admission was cancelled before it could be committed.
    Cancelled,
}

impl From<AllocError> for ThreadRegistrationError {
    fn from(_: AllocError) -> Self {
        Self::NoMemory
    }
}

/// The userspace ABI frame created for a signal handler.
///
/// This contains only Linux-visible signal state. Kernel trap metadata is not
/// serialized into userspace and therefore cannot be forged by `sigreturn`.
#[repr(C)]
#[derive(Clone)]
pub struct SignalFrame {
    ucontext: UContext,
    siginfo: SignalInfo,
}

impl SignalFrame {
    fn new(
        uctx: &UserContext,
        sigmask: SignalSet,
        stack: SignalStack,
        siginfo: SignalInfo,
    ) -> Self {
        Self {
            ucontext: UContext::new(uctx, sigmask, stack),
            siginfo,
        }
    }

    /// Returns the Linux-visible user context stored in this frame.
    pub fn ucontext(&self) -> &UContext {
        &self.ucontext
    }

    /// Returns a mutable Linux-visible user context, as a signal handler sees it.
    pub fn ucontext_mut(&mut self) -> &mut UContext {
        &mut self.ucontext
    }

    /// Copies a complete signal frame from userspace into an owned value.
    pub fn read_from_user<M: UserMemory + ?Sized>(
        memory: &mut UserMemoryContext<'_, M>,
        ptr: *const Self,
    ) -> VmResult<Self> {
        let frame = ptr.vm_read_uninit(memory)?;
        // SAFETY: VmPtr returns `Ok` only after UserMemory initialized every byte of
        // the destination. SignalFrame and every architecture's UContext and
        // MContext are repr(C) records made solely from integer scalars and
        // integer/byte arrays. SignalStack explicitly stores its ABI alignment
        // bytes, SignalSet is a transparent u64, and SignalInfo is fully
        // initialized byte storage; none contains bool, a Rust enum, a
        // reference, or NonZero state. Restoration never interprets
        // frame.siginfo (in particular, it never calls SignalInfo::signo), and
        // prepare_restore validates every machine field that has architectural
        // constraints before publication.
        Ok(unsafe { frame.assume_init() })
    }
}

const _: [(); core::mem::size_of::<SignalFrame>()] =
    [(); core::mem::offset_of!(SignalFrame, siginfo) + core::mem::size_of::<SignalInfo>()];

/// A fully validated signal return that can be committed without failure.
pub struct PreparedSignalRestore {
    context: UserContext,
    blocked: SignalSet,
    stack: Option<SignalStack>,
    stack_error: Option<SignalStackRestoreError>,
}

impl PreparedSignalRestore {
    /// Returns the validated candidate user context.
    pub fn context(&self) -> &UserContext {
        &self.context
    }

    /// Returns the validated alternate-stack update, if one will be applied.
    pub fn stack(&self) -> Option<&SignalStack> {
        self.stack.as_ref()
    }

    /// Returns a Linux-compatible, squashed `restore_altstack()` error.
    pub fn stack_error(&self) -> Option<SignalStackRestoreError> {
        self.stack_error
    }
}

pub struct DeliveredSignal {
    pub info: SignalInfo,
    pub os_action: SignalOSAction,
    pub restartable_handler: bool,
}

/// Thread-level signal manager.
pub struct ThreadSignalManager {
    /// The process-level signal manager
    proc: Arc<ProcessSignalManager>,

    /// The pending signals
    pending: SpinNoIrq<PendingSignals>,
    /// The set of signals currently blocked from delivery.
    blocked: SpinNoIrq<SignalSet>,
    /// Temporarily preserved mask while a synchronous wait unblocks signals.
    real_blocked: SpinNoIrq<Option<SignalSet>>,
    /// The stack used by signal handlers
    stack: SpinNoIrq<SignalStack>,

    /// Quiesces a complete userspace delivery against endpoint teardown.
    /// Kernel multitask consumers use a sleepable mutex because frame copyout
    /// must never run with interrupts disabled.
    delivery: DeliveryMutex<()>,

    /// Serializes publication against explicit endpoint cancellation.
    lifecycle: SpinNoIrq<()>,
    registration: SpinNoIrq<Option<Arc<RegisteredThread>>>,
    accepting_signals: AtomicBool,

    possibly_has_signal: AtomicBool,
}

/// Deactivates a newly registered endpoint if the owning thread fails to
/// finish construction. Successful lifecycle publication disarms the token.
///
/// Dropping an uncommitted token deactivates the registry entry and clears the
/// manager-owned admission slot if it still has the same identity. The
/// registry's next immutable publication compacts the inactive entry.
#[must_use = "dropping the token rolls back thread-signal registration"]
pub struct ThreadSignalRegistration {
    entry: Arc<RegisteredThread>,
    thread: Arc<ThreadSignalManager>,
    rollback: bool,
}

impl ThreadSignalRegistration {
    /// Activates the admitted endpoint unless teardown cancelled it first.
    pub fn commit(mut self) -> Result<(), ThreadRegistrationError> {
        let update = self.thread.proc.action_update.lock();
        let lifecycle = self.thread.lifecycle.lock();
        let still_admitted = self
            .thread
            .registration
            .lock()
            .as_ref()
            .is_some_and(|entry| Arc::ptr_eq(entry, &self.entry));
        if !still_admitted {
            drop(lifecycle);
            drop(update);
            return Err(ThreadRegistrationError::Cancelled);
        }
        self.thread.accepting_signals.store(true, Ordering::Release);
        self.entry.activate();
        self.rollback = false;
        drop(lifecycle);
        drop(update);
        Ok(())
    }
}

impl Drop for ThreadSignalRegistration {
    fn drop(&mut self) {
        if self.rollback {
            self.entry.deactivate();
            let mut registration = self.thread.registration.lock();
            if registration
                .as_ref()
                .is_some_and(|entry| Arc::ptr_eq(entry, &self.entry))
            {
                registration.take();
            }
        }
    }
}

impl ThreadSignalManager {
    /// Fallibly constructs an unregistered thread signal endpoint.
    /// Registration is separate so callers can finish building the owning
    /// thread object before making even a weak child entry observable.
    pub fn try_new(proc: Arc<ProcessSignalManager>) -> Result<Arc<Self>, AllocError> {
        Arc::try_new(Self {
            proc,

            pending: SpinNoIrq::new(PendingSignals::default()),
            blocked: SpinNoIrq::new(SignalSet::default()),
            real_blocked: SpinNoIrq::new(None),
            stack: SpinNoIrq::new(SignalStack::default()),

            delivery: DeliveryMutex::new(()),

            lifecycle: SpinNoIrq::new(()),
            registration: SpinNoIrq::new(None),
            accepting_signals: AtomicBool::new(false),

            possibly_has_signal: AtomicBool::new(false),
        })
    }

    /// Fallibly publishes this endpoint in its process signal registry.
    pub fn try_register(
        self: &Arc<Self>,
        tid: u32,
    ) -> Result<ThreadSignalRegistration, ThreadRegistrationError> {
        let entry = RegisteredThread::try_new(tid, self)?;
        let update = self.proc.action_update.lock();
        if self.registration.lock().is_some() {
            return Err(ThreadRegistrationError::AlreadyRegistered);
        }
        let registry = self.proc.children_registry_snapshot();
        let len = registry.as_deref().map_or(0, Vec::len);
        let capacity = len
            .checked_add(1)
            .ok_or(ThreadRegistrationError::NoMemory)?;
        let mut replacement = Vec::new();
        replacement
            .try_reserve_exact(capacity)
            .map_err(|_| ThreadRegistrationError::NoMemory)?;
        if let Some(registry) = registry.as_deref() {
            for registered in registry {
                if registered.is_live() {
                    if registered.claims_tid(tid) {
                        return Err(ThreadRegistrationError::TidInUse);
                    }
                    replacement.push(registered.clone());
                }
            }
        }
        replacement.push(entry.clone());
        let replacement =
            Arc::try_new(replacement).map_err(|_| ThreadRegistrationError::NoMemory)?;

        *self.registration.lock() = Some(entry.clone());

        let previous = {
            let mut children = self.proc.children.lock();
            children.replace(replacement)
        };

        // The immutable registry and all of its owned Arcs are allocated and
        // destroyed outside the publication spin lock. The shared update
        // mutex serializes this pointer swap with disposition transitions.
        drop(update);
        drop(previous);
        drop(registry);
        Ok(ThreadSignalRegistration {
            entry,
            thread: self.clone(),
            rollback: true,
        })
    }

    /// Cancels this endpoint and drains all thread-private pending records.
    ///
    /// Publication and cancellation share a short lifecycle lock. Once this
    /// method returns, a sender that had not already linearized cannot publish
    /// another record. It also waits for a delivery that already started, so
    /// no handler context or mask update can complete after teardown returns.
    /// A later `try_register` may publish the endpoint again.
    pub fn cancel_registration(&self) -> bool {
        let delivery = self.delivery.lock();
        let update = self.proc.action_update.lock();
        let lifecycle = self.lifecycle.lock();
        self.accepting_signals.store(false, Ordering::Release);
        let registration = self.registration.lock().take();
        let cancelled = registration.is_some();
        if let Some(entry) = registration.as_ref() {
            entry.deactivate();
        }
        let detached = self.pending.lock().take_all();
        self.possibly_has_signal.store(false, Ordering::Release);
        drop(lifecycle);
        drop(update);
        drop(delivery);
        drop(registration);
        drop(detached);
        cancelled
    }

    /// Returns whether this endpoint currently accepts directed signals.
    pub fn is_registered(&self) -> bool {
        self.accepting_signals.load(Ordering::Acquire)
    }

    /// Dequeues a signal from the thread's pending signals.
    #[must_use]
    pub fn dequeue_signal(&self, mask: &SignalSet) -> Option<SignalInfo> {
        self.dequeue_thread_signal_owned(mask)
            .map(DequeuedSignal::into_info)
            .or_else(|| self.proc.dequeue_signal(mask))
    }

    fn dequeue_thread_signal_owned(&self, mask: &SignalSet) -> Option<DequeuedSignal> {
        {
            let mut pending = self.pending.lock();
            let signal = pending.dequeue_signal(mask);
            if pending.set.is_empty() {
                self.possibly_has_signal.store(false, Ordering::Release);
            }
            signal
        }
    }

    pub fn process(&self) -> &Arc<ProcessSignalManager> {
        &self.proc
    }

    pub fn handle_signal<M: UserMemory + ?Sized>(
        &self,
        memory: &mut UserMemoryContext<'_, M>,
        uctx: &mut UserContext,
        restore_blocked: SignalSet,
        sig: &SignalInfo,
        action: &SignalAction,
    ) -> Option<SignalOSAction> {
        let signo = sig.signo();
        debug!("Handle signal: {signo:?}");
        match action.disposition {
            SignalDisposition::Default => match signo.default_action() {
                DefaultSignalAction::Terminate => Some(SignalOSAction::Terminate),
                DefaultSignalAction::CoreDump => Some(SignalOSAction::CoreDump),
                DefaultSignalAction::Stop => Some(SignalOSAction::Stop),
                DefaultSignalAction::Ignore => None,
                DefaultSignalAction::Continue => Some(SignalOSAction::Continue),
            },
            SignalDisposition::Ignore => None,
            SignalDisposition::Handler(handler) => {
                let layout = Layout::new::<SignalFrame>();
                let interrupted_sp = uctx.sp();
                let stack = self.stack.lock().clone();
                let mut visible_stack = stack.clone();
                visible_stack.flags = stack.flags_at(interrupted_sp);
                let already_on_altstack = stack.contains_sp(interrupted_sp);
                let use_altstack = action.flags.contains(SignalActionFlags::ONSTACK)
                    && !stack.disabled()
                    && !already_on_altstack;
                let sp = if use_altstack {
                    let Some(top) = stack.checked_top() else {
                        return Some(SignalOSAction::CoreDump);
                    };
                    top
                } else {
                    interrupted_sp
                };

                let Some(frame_start) = sp.checked_sub(layout.size()) else {
                    return Some(SignalOSAction::CoreDump);
                };
                let aligned_sp = frame_start & !(layout.align() - 1);
                let Some(siginfo_ptr) = aligned_sp.checked_add(offset_of!(SignalFrame, siginfo))
                else {
                    return Some(SignalOSAction::CoreDump);
                };
                let Some(ucontext_ptr) = aligned_sp.checked_add(offset_of!(SignalFrame, ucontext))
                else {
                    return Some(SignalOSAction::CoreDump);
                };

                #[cfg(target_arch = "x86_64")]
                let Some(published_sp) = aligned_sp.checked_sub(core::mem::size_of::<usize>())
                else {
                    return Some(SignalOSAction::CoreDump);
                };
                #[cfg(not(target_arch = "x86_64"))]
                let published_sp = aligned_sp;

                if use_altstack || already_on_altstack {
                    let Some(frame_span) = sp.checked_sub(published_sp) else {
                        return Some(SignalOSAction::CoreDump);
                    };
                    if !stack.contains_range(published_sp, frame_span) {
                        return Some(SignalOSAction::CoreDump);
                    }
                }

                let frame_ptr = aligned_sp as *mut SignalFrame;
                let frame = SignalFrame::new(uctx, restore_blocked, visible_stack, sig.clone());
                // SAFETY: SignalFrame has no implicit outer padding (asserted
                // above). Every architecture record makes each ABI alignment
                // hole an explicit zeroed field, SignalStack does the same,
                // and SignalInfo represents every ABI byte as initialized
                // storage. Therefore every source byte is
                // initialized before it crosses into userspace.
                if unsafe { frame_ptr.vm_write_unchecked(memory, frame) }.is_err() {
                    return Some(SignalOSAction::CoreDump);
                }

                let restorer = action.restorer.unwrap_or(self.proc.default_restorer);
                #[cfg(target_arch = "x86_64")]
                {
                    if (published_sp as *mut usize)
                        .vm_write(memory, restorer)
                        .is_err()
                    {
                        return Some(SignalOSAction::CoreDump);
                    }
                }

                // Publish the new execution context only after every user
                // write has succeeded. A failed frame/restorer copy therefore
                // cannot leave a partially installed handler context.
                uctx.set_ip(handler);
                uctx.set_sp(published_sp);
                uctx.set_arg0(signo as _);
                uctx.set_arg1(siginfo_ptr);
                uctx.set_arg2(ucontext_ptr);
                #[cfg(not(target_arch = "x86_64"))]
                uctx.set_ra(restorer);

                let mut add_blocked = action.mask;
                if !action.flags.contains(SignalActionFlags::NODEFER) {
                    add_blocked.add(signo);
                }

                *self.blocked.lock() |= add_blocked;
                Some(SignalOSAction::Handler)
            }
        }
    }

    #[cold]
    fn check_signals_slow<M: UserMemory + ?Sized>(
        &self,
        memory: &mut UserMemoryContext<'_, M>,
        uctx: &mut UserContext,
        restore_blocked: Option<SignalSet>,
    ) -> Option<DeliveredSignal> {
        let blocked = self.blocked.lock();
        let mask = !*blocked;
        let restore_blocked = restore_blocked.unwrap_or_else(|| *blocked);
        drop(blocked);

        loop {
            let (queued, action, reset_claim) = {
                let mut actions = self.proc.actions.lock();
                let queued = self
                    .dequeue_thread_signal_owned(&mask)
                    .or_else(|| self.proc.dequeue_signal_owned(&mask))?;
                let (action, reset_claim) = actions.claim_delivery(queued.signo());
                (queued, action, reset_claim)
            };
            let sig = queued.into_info();
            let restartable = matches!(action.disposition, SignalDisposition::Handler(_))
                && action.flags.contains(SignalActionFlags::RESTART);

            let os_action = self.handle_signal(memory, uctx, restore_blocked, &sig, &action);
            if let Some(reset_claim) = reset_claim {
                self.proc.actions.lock().finish_delivery(
                    reset_claim,
                    matches!(os_action, Some(SignalOSAction::Handler)),
                );
            }

            if let Some(os_action) = os_action {
                break Some(DeliveredSignal {
                    info: sig,
                    os_action,
                    restartable_handler: restartable && os_action == SignalOSAction::Handler,
                });
            }
        }
    }

    /// Checks pending signals and handle them.
    ///
    /// Returns the signal number and the action the OS should take, if any.
    pub fn check_signals<M: UserMemory + ?Sized>(
        &self,
        memory: &mut UserMemoryContext<'_, M>,
        uctx: &mut UserContext,
        restore_blocked: Option<SignalSet>,
    ) -> Option<DeliveredSignal> {
        let delivery = self.delivery.lock();
        if !self.accepting_signals.load(Ordering::Acquire) {
            return None;
        }
        // Fast path
        if !self.possibly_has_signal.load(Ordering::Acquire)
            && !self.proc.possibly_has_signal.load(Ordering::Acquire)
        {
            return None;
        }
        let delivered = self.check_signals_slow(memory, uctx, restore_blocked);
        drop(delivery);
        delivered
    }

    /// Validates an owned signal frame without publishing any state.
    ///
    /// The caller must copy the complete frame from userspace before calling
    /// this method. Address predicates keep kernel address-space policy out of
    /// this reusable signal crate.
    pub fn prepare_restore(
        &self,
        current: &UserContext,
        frame: SignalFrame,
        valid_program_counter: impl FnOnce(usize) -> bool,
        valid_stack_pointer: impl FnOnce(usize) -> bool,
        validate_stack: impl FnOnce(
            &SignalStack,
            usize,
            &SignalStack,
        ) -> Result<(), SignalStackRestoreError>,
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

        let current_stack = self.stack.lock().clone();
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
        })
    }

    /// Commits a previously validated signal restore without failure.
    pub fn commit_restore(&self, uctx: &mut UserContext, prepared: PreparedSignalRestore) {
        let mut blocked = self.blocked.lock();
        let mut stack = self.stack.lock();
        *uctx = prepared.context;
        *blocked = prepared.blocked;
        if let Some(restored) = prepared.stack {
            *stack = restored;
        }
        self.possibly_has_signal.store(true, Ordering::Release);
    }

    /// Sends a signal, preparing any queue record outside spin locks.
    ///
    /// Returns publication and wakeup state separately.
    ///
    /// The preparation closure is skipped for ignored signals and coalesced
    /// standard signals, and is never called under a pending/actions lock.
    #[must_use = "the caller must handle queue-admission failure"]
    pub fn try_send_signal_with<E>(
        &self,
        sig: SignalInfo,
        prepare: impl FnOnce(SignalInfo) -> Result<PreparedSignal, E>,
    ) -> Result<ThreadSignalSendOutcome, E> {
        let signo = sig.signo();
        if !self.accepting_signals.load(Ordering::Acquire) {
            return Ok(ThreadSignalSendOutcome {
                published: false,
                wake: false,
            });
        }
        let blocked = self.signal_blocked(signo);
        if self.proc.signal_ignored(signo) && !blocked && !self.signal_real_blocked(signo) {
            return Ok(ThreadSignalSendOutcome {
                published: false,
                wake: false,
            });
        }

        if !signo.is_realtime() {
            let lifecycle = self.lifecycle.lock();
            if !self.accepting_signals.load(Ordering::Acquire) {
                drop(lifecycle);
                return Ok(ThreadSignalSendOutcome {
                    published: false,
                    wake: false,
                });
            }
            if self.pending.lock().set.has(signo) {
                let wake = !self.signal_blocked(signo);
                self.possibly_has_signal.store(true, Ordering::Release);
                drop(lifecycle);
                return Ok(ThreadSignalSendOutcome {
                    published: false,
                    wake,
                });
            }
        }

        let prepared = prepare(sig)?;
        let lifecycle = self.lifecycle.lock();
        if !self.accepting_signals.load(Ordering::Acquire) {
            drop(lifecycle);
            drop(prepared);
            return Ok(ThreadSignalSendOutcome {
                published: false,
                wake: false,
            });
        }
        let outcome = {
            let actions = self.proc.actions.lock();
            let blocked = self.signal_blocked(signo);
            let ignored = ProcessSignalManager::action_ignored(&actions, signo);
            if ignored && !blocked && !self.signal_real_blocked(signo) {
                Err(prepared)
            } else {
                let mut pending = self.pending.lock();
                Ok((pending.publish(prepared), !blocked))
            }
        };
        let (outcome, wake) = match outcome {
            Ok(outcome) => outcome,
            Err(prepared) => {
                drop(lifecycle);
                // Drop a node made obsolete by a disposition transition only
                // after releasing every signal-state spin guard.
                drop(prepared);
                return Ok(ThreadSignalSendOutcome {
                    published: false,
                    wake: false,
                });
            }
        };
        self.possibly_has_signal.store(true, Ordering::Release);
        let added = outcome.added;
        drop(lifecycle);
        let published = outcome.finish();
        debug_assert_eq!(published, added);
        Ok(ThreadSignalSendOutcome { published, wake })
    }

    /// Sends a signal through the allocation-free fallback path.
    #[must_use]
    pub fn send_unqueued_signal(&self, sig: SignalInfo) -> bool {
        match self.try_send_signal_with(sig, |sig| {
            Ok::<_, core::convert::Infallible>(PreparedSignal::unqueued(sig))
        }) {
            Ok(outcome) => outcome.wake,
            Err(error) => match error {},
        }
    }

    /// Gets the blocked signals.
    pub fn blocked(&self) -> SignalSet {
        *self.blocked.lock()
    }

    /// Sets the blocked signals. Return the old value.
    pub fn set_blocked(&self, mut set: SignalSet) -> SignalSet {
        set.remove(Signo::SIGKILL);
        set.remove(Signo::SIGSTOP);
        self.possibly_has_signal.store(true, Ordering::Release);
        let mut guard = self.blocked.lock();
        let old = *guard;
        *guard = set;
        old
    }

    /// Checks if a signal is blocked.
    pub fn signal_blocked(&self, signo: Signo) -> bool {
        self.blocked.lock().has(signo)
    }

    pub fn signal_real_blocked(&self, signo: Signo) -> bool {
        self.real_blocked.lock().is_some_and(|set| set.has(signo))
    }

    pub fn set_real_blocked(&self, set: Option<SignalSet>) {
        *self.real_blocked.lock() = set;
    }

    /// Gets the signal stack.
    pub fn stack(&self) -> SignalStack {
        self.stack.lock().clone()
    }

    /// Sets the signal stack.
    pub fn set_stack(&self, stack: SignalStack) {
        *self.stack.lock() = stack;
    }

    /// Gets current pending signals.
    pub fn pending(&self) -> SignalSet {
        self.pending.lock().set | self.proc.pending()
    }

    /// Detaches all thread-private pending records under the lock and destroys
    /// them after releasing it.
    pub fn flush_pending(&self) {
        let detached = {
            let mut pending = self.pending.lock();
            let detached = pending.take_all();
            self.possibly_has_signal.store(false, Ordering::Release);
            detached
        };
        drop(detached);
    }

    /// Detaches every thread-directed instance of one signal and releases
    /// queue ownership after dropping the pending lock.
    pub fn flush_signal(&self, signo: Signo) {
        let detached = {
            let mut pending = self.pending.lock();
            let detached = pending.take_signal(signo);
            if pending.set.is_empty() {
                self.possibly_has_signal.store(false, Ordering::Release);
            }
            detached
        };
        drop(detached);
    }

    pub(crate) fn detach_signal_into(&self, signo: Signo, detached: &mut DetachedSignal) {
        let mut pending = self.pending.lock();
        pending.detach_signal_into(signo, detached);
        if pending.set.is_empty() {
            self.possibly_has_signal.store(false, Ordering::Release);
        }
    }
}

impl Drop for ThreadSignalManager {
    fn drop(&mut self) {
        self.accepting_signals.store(false, Ordering::Release);
        if let Some(entry) = self.registration.lock().take() {
            entry.deactivate();
        }
    }
}
