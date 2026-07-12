use alloc::{
    alloc::AllocError,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{
    array,
    sync::atomic::{AtomicBool, AtomicU8, Ordering},
};

use kspin::SpinNoIrq;

#[cfg(all(feature = "multitask", target_os = "none"))]
use axsync::Mutex;
#[cfg(not(all(feature = "multitask", target_os = "none")))]
use kspin::SpinNoIrq as Mutex;

use crate::{
    DefaultSignalAction, DeferredSignalPublication, DequeuedSignal, DetachedSignal, PendingSignals,
    PreparedSignal, PreparedSignalPublicationOutcome, SignalAction, SignalActionFlags,
    SignalDisposition, SignalInfo, SignalSet, Signo, api::ThreadSignalManager,
};

#[derive(Debug, PartialEq, Eq)]
struct ResetClaim {
    generation: u64,
}

/// A claim on one `SA_RESETHAND` disposition generation.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ResetDeliveryClaim {
    signo: Signo,
    claim: ResetClaim,
}

/// Signal actions used to initialize one process signal manager.
///
/// After construction, callers query and replace actions through
/// [`ProcessSignalManager`]. Keeping the mutable table private makes action
/// generation and one-shot delivery claims impossible to bypass.
pub struct SignalActions {
    actions: [SignalAction; 64],
    generations: [u64; 64],
    reset_claims: [Option<ResetClaim>; 64],
}

impl Default for SignalActions {
    fn default() -> Self {
        Self {
            actions: array::from_fn(|_| SignalAction::default()),
            generations: [0; 64],
            reset_claims: array::from_fn(|_| None),
        }
    }
}

impl SignalActions {
    fn index(signo: Signo) -> usize {
        signo as usize - 1
    }

    fn reset_claim_is_current(&self, index: usize) -> bool {
        self.reset_claims[index]
            .as_ref()
            .is_some_and(|claim| claim.generation == self.generations[index])
    }

    fn effective_action(&self, signo: Signo) -> SignalAction {
        let index = Self::index(signo);
        if self.reset_claim_is_current(index) {
            SignalAction::default()
        } else {
            self.actions[index]
        }
    }

    fn replace(
        &mut self,
        signo: Signo,
        action: SignalAction,
    ) -> Result<SignalAction, SignalActionUpdateError> {
        let index = Self::index(signo);
        let old = self.effective_action(signo);
        let generation = self.generations[index]
            .checked_add(1)
            .ok_or(SignalActionUpdateError::GenerationExhausted)?;
        self.generations[index] = generation;
        self.actions[index] = action;
        Ok(old)
    }

    pub(crate) fn claim_delivery(
        &mut self,
        signo: Signo,
    ) -> (SignalAction, Option<ResetDeliveryClaim>) {
        let index = Self::index(signo);
        if self.reset_claim_is_current(index) {
            return (SignalAction::default(), None);
        }

        let action = self.actions[index];
        let reset = matches!(action.disposition, SignalDisposition::Handler(_))
            && action.flags.contains(SignalActionFlags::RESETHAND);
        if !reset {
            return (action, None);
        }

        let claim = ResetClaim {
            generation: self.generations[index],
        };
        self.reset_claims[index] = Some(ResetClaim {
            generation: claim.generation,
        });
        (action, Some(ResetDeliveryClaim { signo, claim }))
    }

    pub(crate) fn finish_delivery(&mut self, reservation: ResetDeliveryClaim, commit: bool) {
        let index = Self::index(reservation.signo);
        if self.reset_claims[index].as_ref() != Some(&reservation.claim) {
            return;
        }
        self.reset_claims[index] = None;
        if commit && self.generations[index] == reservation.claim.generation {
            self.actions[index] = SignalAction::default();
        }
    }

    fn snapshot(&self) -> Self {
        Self {
            actions: array::from_fn(|index| {
                if self.reset_claim_is_current(index) {
                    SignalAction::default()
                } else {
                    self.actions[index]
                }
            }),
            generations: [0; 64],
            reset_claims: array::from_fn(|_| None),
        }
    }
}

/// One preallocated entry in the process thread-signal registry.
///
/// Registry snapshots retain entries, never thread endpoints. Rollback only
/// marks it cancelled; stale or dead entries are compacted while the next
/// snapshot is built outside every spin lock.
pub(crate) struct RegisteredThread {
    tid: u32,
    thread: Weak<ThreadSignalManager>,
    state: AtomicU8,
}

const REGISTRATION_PENDING: u8 = 0;
const REGISTRATION_ACTIVE: u8 = 1;
const REGISTRATION_CANCELLED: u8 = 2;

impl RegisteredThread {
    pub(crate) fn try_new(
        tid: u32,
        thread: &Arc<ThreadSignalManager>,
    ) -> Result<Arc<Self>, alloc::alloc::AllocError> {
        Arc::try_new(Self {
            tid,
            thread: Arc::downgrade(thread),
            state: AtomicU8::new(REGISTRATION_PENDING),
        })
    }

    pub(crate) fn activate(&self) {
        self.state.store(REGISTRATION_ACTIVE, Ordering::Release);
    }

    pub(crate) fn deactivate(&self) {
        self.state.store(REGISTRATION_CANCELLED, Ordering::Release);
    }

    pub(crate) fn is_live(&self) -> bool {
        self.state.load(Ordering::Acquire) != REGISTRATION_CANCELLED
            && self.thread.strong_count() != 0
    }

    pub(crate) fn claims_tid(&self, tid: u32) -> bool {
        self.tid == tid && self.is_live()
    }

    fn upgrade(&self) -> Option<(u32, Arc<ThreadSignalManager>)> {
        if self.state.load(Ordering::Acquire) != REGISTRATION_ACTIVE {
            return None;
        }
        self.thread.upgrade().map(|thread| (self.tid, thread))
    }
}

pub(crate) type ThreadRegistry = Vec<Arc<RegisteredThread>>;

/// Result of publishing one process-directed signal.
///
/// `published` distinguishes a record owned by this send from an ignored or
/// coalesced signal. `wake_tid` retains the historical wakeup selection used
/// by kernel integrations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessSignalSendOutcome {
    pub published: bool,
    pub wake_tid: Option<u32>,
}

struct PreparedRouteEntry {
    tid: u32,
    thread: Arc<ThreadSignalManager>,
}

/// Bounded process-directed routing state prepared before a wider security
/// spin transaction.
///
/// Construction may take the process registry's sleepable mutex, allocate a
/// finite vector, clone endpoint ownership, and destroy an old registry
/// snapshot. [`publish`](Self::publish) only borrows these retained endpoints
/// and mutates IRQ-safe signal state. The resulting deferred value retains
/// this token until the caller explicitly finishes outside its outer lock.
#[must_use = "publish the prepared route or discard it outside spin locks"]
pub struct PreparedProcessSignalSend {
    process: Arc<ProcessSignalManager>,
    signo: Signo,
    endpoints: Vec<PreparedRouteEntry>,
}

/// Fixed process-signal mutation plus ownership deferred beyond an outer
/// security spin transaction.
pub type DeferredProcessSignalPublication = DeferredSignalPublication<
    PreparedSignalPublicationOutcome<ProcessSignalSendOutcome>,
    PreparedProcessSignalSend,
>;

impl PreparedProcessSignalSend {
    /// Returns the signal number bound to this transaction.
    pub const fn signo(&self) -> Signo {
        self.signo
    }

    fn blocked_by_any_thread(&self) -> bool {
        self.endpoints.iter().any(|entry| {
            entry.thread.is_registered()
                && (entry.thread.signal_blocked(self.signo)
                    || entry.thread.signal_real_blocked(self.signo))
        })
    }

    fn wake_thread(&self) -> Option<u32> {
        self.endpoints.iter().find_map(|entry| {
            (entry.thread.is_registered() && !entry.thread.signal_blocked(self.signo))
                .then_some(entry.tid)
        })
    }

    /// Publishes an already allocated record using only fixed IRQ-safe state
    /// mutations.
    ///
    /// Cancellation is rechecked against every retained endpoint. Endpoints
    /// registered after preparation belong to a later routing generation; a
    /// process-directed record remains pending if the retained wake candidate
    /// disappears, so teardown cannot lose the signal.
    pub fn publish(self, prepared: PreparedSignal) -> DeferredProcessSignalPublication {
        if self.signo != prepared.signo() {
            return DeferredSignalPublication::new(
                PreparedSignalPublicationOutcome::SignoMismatch,
                self,
                Some(prepared),
            );
        }

        let process = &self.process;
        let blocked_by_any_thread = self.blocked_by_any_thread();
        if process.signal_ignored(self.signo) && !blocked_by_any_thread {
            return DeferredSignalPublication::new(
                PreparedSignalPublicationOutcome::Applied(ProcessSignalSendOutcome {
                    published: false,
                    wake_tid: None,
                }),
                self,
                Some(prepared),
            );
        }

        let already_pending =
            !self.signo.is_realtime() && process.pending.lock().set.has(self.signo);
        let (published, unused) = if already_pending {
            (false, Some(prepared))
        } else {
            let outcome = {
                let actions = process.actions.lock();
                if ProcessSignalManager::action_ignored(&actions, self.signo)
                    && !blocked_by_any_thread
                {
                    Err(prepared)
                } else {
                    let mut pending = process.pending.lock();
                    Ok(pending.publish(prepared))
                }
            };
            match outcome {
                Ok(outcome) => outcome.into_parts(),
                Err(prepared) => {
                    return DeferredSignalPublication::new(
                        PreparedSignalPublicationOutcome::Applied(ProcessSignalSendOutcome {
                            published: false,
                            wake_tid: None,
                        }),
                        self,
                        Some(prepared),
                    );
                }
            }
        };

        process.possibly_has_signal.store(true, Ordering::Release);
        let wake_tid = self.wake_thread();
        DeferredSignalPublication::new(
            PreparedSignalPublicationOutcome::Applied(ProcessSignalSendOutcome {
                published,
                wake_tid,
            }),
            self,
            unused,
        )
    }
}

/// Why a process signal disposition could not be replaced atomically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalActionUpdateError {
    /// Allocating a fallible thread-registry snapshot failed.
    NoMemory,
    /// The per-signal generation space is exhausted.
    ///
    /// Reusing a generation would let an old `SA_RESETHAND` delivery claim
    /// overwrite a newer disposition, so exhaustion is reported explicitly.
    GenerationExhausted,
}

/// Default finite process-local thread endpoint ceiling.
pub const SIGNAL_THREAD_REGISTRY_LIMIT: usize = 65_536;

/// Invalid process-signal-manager resource configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignalManagerConfigError {
    /// `usize::MAX` was rejected rather than treated as an unbounded registry.
    UnboundedThreadRegistry,
}

impl From<AllocError> for SignalActionUpdateError {
    fn from(_: AllocError) -> Self {
        Self::NoMemory
    }
}

/// Process-level signal manager.
pub struct ProcessSignalManager {
    /// The process-level shared pending signals
    pending: SpinNoIrq<PendingSignals>,

    /// The signal actions and one-shot delivery generations.
    pub(crate) actions: SpinNoIrq<SignalActions>,

    /// The default restorer function.
    pub(crate) default_restorer: usize,

    /// Thread-level signal managers. Kernel targets use the sleepable mutex so
    /// snapshot `Arc` acquisition never runs with interrupts disabled.
    pub(crate) children: Mutex<Option<Arc<ThreadRegistry>>>,

    /// Serializes registry publication with action transitions. On kernel
    /// targets this is a sleepable mutex when the crate's `multitask` feature
    /// is enabled, so immutable snapshots are allocated without holding a
    /// SpinNoIrq guard. Hosted tests retain the spin fallback.
    pub(crate) action_update: Mutex<()>,

    thread_limit: usize,

    pub(crate) possibly_has_signal: AtomicBool,
}

impl ProcessSignalManager {
    pub(crate) fn action_ignored(actions: &SignalActions, signo: Signo) -> bool {
        match actions.effective_action(signo).disposition {
            SignalDisposition::Ignore => true,
            SignalDisposition::Default => {
                matches!(signo.default_action(), DefaultSignalAction::Ignore)
            }
            _ => false,
        }
    }

    /// Creates a process signal manager with the default finite thread limit.
    pub fn new(actions: SignalActions, default_restorer: usize) -> Self {
        Self::with_validated_thread_limit(actions, default_restorer, SIGNAL_THREAD_REGISTRY_LIMIT)
    }

    /// Creates a process signal manager with a caller-selected finite thread
    /// endpoint limit.
    pub fn try_with_thread_limit(
        actions: SignalActions,
        default_restorer: usize,
        thread_limit: usize,
    ) -> Result<Self, SignalManagerConfigError> {
        if thread_limit == usize::MAX {
            return Err(SignalManagerConfigError::UnboundedThreadRegistry);
        }
        Ok(Self::with_validated_thread_limit(
            actions,
            default_restorer,
            thread_limit,
        ))
    }

    fn with_validated_thread_limit(
        actions: SignalActions,
        default_restorer: usize,
        thread_limit: usize,
    ) -> Self {
        Self {
            pending: SpinNoIrq::new(PendingSignals::default()),
            actions: SpinNoIrq::new(actions),
            default_restorer,
            children: Mutex::new(None),
            action_update: Mutex::new(()),
            thread_limit,
            possibly_has_signal: AtomicBool::new(false),
        }
    }

    /// Returns the immutable process-local endpoint ceiling.
    pub const fn thread_limit(&self) -> usize {
        self.thread_limit
    }

    pub(crate) fn children_registry_snapshot(&self) -> Option<Arc<ThreadRegistry>> {
        self.children.lock().clone()
    }

    /// Returns the currently effective action for one signal.
    pub fn action(&self, signo: Signo) -> SignalAction {
        self.actions.lock().effective_action(signo)
    }

    /// Copies the effective action table for a new, independent process.
    /// In-flight `SA_RESETHAND` claims are materialized as default actions.
    pub fn actions_snapshot(&self) -> SignalActions {
        self.actions.lock().snapshot()
    }

    fn try_children_snapshot(&self) -> Result<Vec<Arc<ThreadSignalManager>>, AllocError> {
        let registry = self.children_registry_snapshot();
        let len = registry.as_deref().map_or(0, Vec::len);
        let mut snapshot = Vec::new();
        snapshot.try_reserve_exact(len).map_err(|_| AllocError)?;

        if let Some(registry) = registry.as_deref() {
            for entry in registry {
                if let Some((_, child)) = entry.upgrade() {
                    snapshot.push(child);
                }
            }
        }
        drop(registry);
        Ok(snapshot)
    }

    /// Atomically replaces one disposition with respect to signal
    /// publication. Switching to an ignored disposition also detaches that
    /// signal from the process and every registered thread before the action
    /// gate is released. Account Arcs and RT nodes are destroyed afterwards.
    pub fn try_replace_action(
        &self,
        signo: Signo,
        action: SignalAction,
    ) -> Result<SignalAction, SignalActionUpdateError> {
        let update = self.action_update.lock();
        let children = self.try_children_snapshot()?;
        let mut detached = DetachedSignal::empty();
        let old_action = {
            let mut actions = self.actions.lock();
            let old_action = actions.replace(signo, action)?;
            if Self::action_ignored(&actions, signo) {
                let empty = {
                    let mut pending = self.pending.lock();
                    pending.detach_signal_into(signo, &mut detached);
                    pending.set.is_empty()
                };
                if empty {
                    self.possibly_has_signal.store(false, Ordering::Release);
                }
                for child in &children {
                    child.detach_signal_into(signo, &mut detached);
                }
            }
            old_action
        };

        // Neither queue nodes nor strong endpoint snapshots are destroyed
        // while an actions, registry, or pending SpinNoIrq guard is held.
        drop(update);
        drop(detached);
        drop(children);
        Ok(old_action)
    }

    pub(crate) fn dequeue_signal_owned(&self, mask: &SignalSet) -> Option<DequeuedSignal> {
        {
            let mut guard = self.pending.lock();
            let result = guard.dequeue_signal(mask);
            if guard.set.is_empty() {
                self.possibly_has_signal.store(false, Ordering::Release);
            }
            result
        }
    }

    pub(crate) fn dequeue_signal(&self, mask: &SignalSet) -> Option<SignalInfo> {
        self.dequeue_signal_owned(mask)
            .map(DequeuedSignal::into_info)
    }

    /// Checks if a signal is ignored by the process.
    pub fn signal_ignored(&self, signo: Signo) -> bool {
        Self::action_ignored(&self.actions.lock(), signo)
    }

    /// Checks if syscalls interrupted by the given signal can be restarted.
    pub fn can_restart(&self, signo: Signo) -> bool {
        self.actions
            .lock()
            .effective_action(signo)
            .flags
            .contains(SignalActionFlags::RESTART)
    }

    fn blocked_by_any_thread(&self, signo: Signo) -> bool {
        let registry = self.children_registry_snapshot();
        let blocked = registry.as_deref().is_some_and(|registry| {
            registry.iter().any(|entry| {
                entry.upgrade().is_some_and(|(_, thread)| {
                    thread.signal_blocked(signo) || thread.signal_real_blocked(signo)
                })
            })
        });
        drop(registry);
        blocked
    }

    fn wake_thread_for(&self, signo: Signo) -> Option<u32> {
        let registry = self.children_registry_snapshot();
        let result = registry.as_deref().and_then(|registry| {
            registry.iter().find_map(|entry| {
                let (tid, thread) = entry.upgrade()?;
                (!thread.signal_blocked(signo)).then_some(tid)
            })
        });
        drop(registry);
        result
    }

    /// Prepares a bounded process-directed send in sleepable context.
    ///
    /// This is the fallible half of the authorization/publication protocol.
    /// The returned token owns every endpoint reference and the process
    /// manager reference that must survive the fixed publication half.
    pub fn try_prepare_signal_send(
        self: &Arc<Self>,
        signo: Signo,
    ) -> Result<PreparedProcessSignalSend, AllocError> {
        let registry = self.children_registry_snapshot();
        let capacity = registry.as_deref().map_or(0, Vec::len);
        let mut endpoints = Vec::new();
        endpoints
            .try_reserve_exact(capacity)
            .map_err(|_| AllocError)?;
        if let Some(registry) = registry.as_deref() {
            for entry in registry {
                if let Some((tid, thread)) = entry.upgrade() {
                    endpoints.push(PreparedRouteEntry { tid, thread });
                }
            }
        }
        drop(registry);
        Ok(PreparedProcessSignalSend {
            process: Arc::clone(self),
            signo,
            endpoints,
        })
    }

    /// Sends a signal, preparing any owned queue record outside spin locks.
    ///
    /// The preparation closure is skipped for ignored signals and coalesced
    /// standard signals. It is never invoked while an actions, children, or
    /// pending SpinNoIrq guard is held.
    ///
    /// Returns publication and wakeup state separately. This distinction is
    /// required by preallocated kernel notifications: an ignored or
    /// coalesced signal must not be mistaken for an owned pending record.
    #[must_use = "the caller must handle queue-admission failure"]
    pub fn try_send_signal_with<E>(
        &self,
        sig: SignalInfo,
        prepare: impl FnOnce(SignalInfo) -> Result<PreparedSignal, E>,
    ) -> Result<ProcessSignalSendOutcome, E> {
        let signo = sig.signo();
        if self.signal_ignored(signo) && !self.blocked_by_any_thread(signo) {
            return Ok(ProcessSignalSendOutcome {
                published: false,
                wake_tid: None,
            });
        }

        let already_pending = !signo.is_realtime() && self.pending.lock().set.has(signo);
        let mut published = false;
        if !already_pending {
            let prepared = prepare(sig)?;
            let blocked_by_any_thread = self.blocked_by_any_thread(signo);
            let outcome = {
                let actions = self.actions.lock();
                if Self::action_ignored(&actions, signo) && !blocked_by_any_thread {
                    Err(prepared)
                } else {
                    let mut pending = self.pending.lock();
                    Ok(pending.publish(prepared))
                }
            };
            // A disposition transition can make a prepared node unnecessary.
            // Release it only after the action and pending guards are gone.
            let outcome = match outcome {
                Ok(outcome) => outcome,
                Err(prepared) => {
                    drop(prepared);
                    return Ok(ProcessSignalSendOutcome {
                        published: false,
                        wake_tid: None,
                    });
                }
            };
            // A racing standard sender may have filled the fixed slot after
            // preflight. Release its unused charge outside the pending lock.
            published = outcome.finish();
        }
        self.possibly_has_signal.store(true, Ordering::Release);
        Ok(ProcessSignalSendOutcome {
            published,
            wake_tid: self.wake_thread_for(signo),
        })
    }

    /// Sends a signal through the allocation-free fallback path.
    #[must_use]
    pub fn send_unqueued_signal(&self, sig: SignalInfo) -> Option<u32> {
        match self.try_send_signal_with(sig, |sig| {
            Ok::<_, core::convert::Infallible>(PreparedSignal::unqueued(sig))
        }) {
            Ok(outcome) => outcome.wake_tid,
            Err(error) => match error {},
        }
    }

    /// Gets currently pending signals.
    pub fn pending(&self) -> SignalSet {
        self.pending.lock().set
    }

    /// Detaches all pending records under the lock and destroys them after
    /// releasing it.
    pub fn flush_pending(&self) {
        let detached = {
            let mut pending = self.pending.lock();
            let detached = pending.take_all();
            self.possibly_has_signal.store(false, Ordering::Release);
            detached
        };
        drop(detached);
    }

    /// Detaches every process-directed instance of one signal and releases
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
}

#[cfg(test)]
mod tests {
    use super::{SignalActionUpdateError, SignalActions};
    use crate::{SignalAction, SignalActionFlags, SignalDisposition, Signo};

    fn reset_action(handler: usize) -> SignalAction {
        SignalAction {
            disposition: SignalDisposition::Handler(handler),
            flags: SignalActionFlags::RESETHAND,
            ..SignalAction::default()
        }
    }

    #[test]
    fn reset_claim_abort_can_retry_without_reusing_an_outstanding_identity() {
        let signo = Signo::SIGTERM;
        let mut actions = SignalActions::default();
        actions.replace(signo, reset_action(1)).unwrap();

        let (_, first) = actions.claim_delivery(signo);
        assert!(matches!(
            actions.effective_action(signo).disposition,
            SignalDisposition::Default
        ));
        actions.finish_delivery(first.unwrap(), false);
        assert!(matches!(
            actions.effective_action(signo).disposition,
            SignalDisposition::Handler(1)
        ));

        let (_, second) = actions.claim_delivery(signo);
        actions.finish_delivery(second.unwrap(), true);
        assert!(matches!(
            actions.effective_action(signo).disposition,
            SignalDisposition::Default
        ));
    }

    #[test]
    fn action_generation_exhaustion_is_explicit_and_non_mutating() {
        let signo = Signo::SIGTERM;
        let index = SignalActions::index(signo);
        let mut actions = SignalActions::default();
        actions.actions[index] = reset_action(1);
        actions.generations[index] = u64::MAX;

        assert!(matches!(
            actions.replace(signo, reset_action(2)),
            Err(SignalActionUpdateError::GenerationExhausted)
        ));
        assert_eq!(actions.generations[index], u64::MAX);
        assert!(matches!(
            actions.effective_action(signo).disposition,
            SignalDisposition::Handler(1)
        ));
    }
}
