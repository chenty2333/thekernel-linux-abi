use alloc::vec::Vec;
use core::num::NonZeroU64;

use crate::{IORING_MAX_CQ_ENTRIES, IORING_MAX_ENTRIES, IoUringError, RingId};

/// Operation class retained for cancellation, diagnostics, and close policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestOperation {
    /// `IORING_OP_NOP`.
    Nop,
    /// Positional `IORING_OP_READ`.
    Read,
    /// Positional `IORING_OP_WRITE`.
    Write,
    /// One-shot `IORING_OP_POLL_ADD`.
    PollAdd,
    /// `IORING_OP_ASYNC_CANCEL`.
    AsyncCancel,
    /// An SQE which must complete with a typed unsupported/invalid result.
    Rejected(u8),
}

impl RequestOperation {
    const fn cancellation_mode(self) -> CancellationMode {
        match self {
            Self::PollAdd => CancellationMode::Cancellable,
            Self::Nop | Self::Read | Self::Write | Self::AsyncCancel | Self::Rejected(_) => {
                CancellationMode::Uncancellable
            }
        }
    }
}

/// Whether an issued execution mechanism can still honor terminal cancel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancellationMode {
    /// The adapter can detach/abort the lower mechanism before completing
    /// `Cancelled` or `Closing`.
    Cancellable,
    /// Execution crossed an irreversible VFS/effect boundary; only its
    /// ordinary executor completion may win terminal ownership.
    Uncancellable,
}

/// Immutable request metadata copied before admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestDescriptor {
    user_data: u64,
    operation: RequestOperation,
}

impl RequestDescriptor {
    /// Builds metadata for one copied SQE.
    pub const fn new(user_data: u64, operation: RequestOperation) -> Self {
        Self {
            user_data,
            operation,
        }
    }

    /// Opaque value copied to the terminal CQE.
    pub const fn user_data(self) -> u64 {
        self.user_data
    }

    /// Operation class used by policy and diagnostics.
    pub const fn operation(self) -> RequestOperation {
        self.operation
    }
}

/// Generation-scoped identity of one accepted request-table slot.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RequestId {
    ring: RingId,
    slot: u32,
    generation: NonZeroU64,
}

impl RequestId {
    const fn new(ring: RingId, slot: u32, generation: NonZeroU64) -> Self {
        Self {
            ring,
            slot,
            generation,
        }
    }

    /// Ring which owns this request identity.
    pub const fn ring(self) -> RingId {
        self.ring
    }

    /// Bounded request-table slot.
    pub const fn slot(self) -> u32 {
        self.slot
    }

    /// Nonzero generation of the occupied slot.
    pub const fn generation(self) -> u64 {
        self.generation.get()
    }
}

/// Externally visible state of one live request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestState {
    /// Terminal CQ credit and a slot are reserved, but SQ consumption has not
    /// yet been committed.
    Reserved,
    /// SQ consumption was committed and execution has not started.
    Prepared,
    /// The adapter handed the request to an execution mechanism with this
    /// cancellation contract.
    Issued(CancellationMode),
    /// Exactly one path owns the request's terminal transition.
    TerminalClaimed,
    /// A complete CQE is waiting for shared-ring publication.
    CompletionPending,
    /// A CQE plan is being written and release-published by the adapter.
    Publishing,
}

/// Ring admission and teardown phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestLifecycle {
    /// New requests may reserve terminal capacity.
    Open,
    /// Admission is closed while existing work reaches a terminal state.
    Closing,
    /// No executor owns work; unpublished and published completions may be
    /// discarded because no userspace mapping can consume them.
    Draining,
    /// All request and completion ownership has ended.
    Closed,
}

/// Why a path won terminal ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalCause {
    /// The execution mechanism produced its ordinary result.
    Completed,
    /// A cancellation request won before ordinary completion.
    Cancelled,
    /// Final-close processing won before ordinary completion.
    Closing,
    /// Admission succeeded but later preparation produced a terminal error.
    PreparationFailed,
}

/// Selector supported by the initial one-shot cancellation contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancelSelector {
    /// Select the oldest cancellable request with matching `user_data`.
    UserData(u64),
    /// Select one exact generation-scoped request.
    Request(RequestId),
}

/// One complete Linux CQE value, independent of shared-memory layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Completion {
    user_data: u64,
    result: i32,
    flags: u32,
}

impl Completion {
    /// Builds a complete terminal CQE value.
    pub const fn new(user_data: u64, result: i32, flags: u32) -> Self {
        Self {
            user_data,
            result,
            flags,
        }
    }

    /// Opaque request value.
    pub const fn user_data(self) -> u64 {
        self.user_data
    }

    /// Linux CQE result, including a negated errno when appropriate.
    pub const fn result(self) -> i32 {
        self.result
    }

    /// Linux CQE flags.
    pub const fn flags(self) -> u32 {
        self.flags
    }
}

/// Reversible pre-admission ownership of one request slot and terminal credit.
#[derive(Debug)]
#[must_use = "a request reservation must be committed or rolled back"]
pub struct RequestReservation {
    id: RequestId,
    descriptor: RequestDescriptor,
}

impl RequestReservation {
    /// Identity reserved for the future accepted request.
    pub const fn id(&self) -> RequestId {
        self.id
    }

    /// Immutable copied request metadata.
    pub const fn descriptor(&self) -> RequestDescriptor {
        self.descriptor
    }
}

/// Proof that SQ consumption was committed for one accepted request.
#[derive(Debug)]
#[must_use = "an accepted request must be issued or completed"]
pub struct PreparedRequest {
    id: RequestId,
    descriptor: RequestDescriptor,
}

impl PreparedRequest {
    /// Exact accepted request identity.
    pub const fn id(&self) -> RequestId {
        self.id
    }

    /// Immutable copied request metadata.
    pub const fn descriptor(&self) -> RequestDescriptor {
        self.descriptor
    }
}

/// Proof that an adapter execution mechanism owns one accepted request.
#[derive(Debug)]
#[must_use = "issued work must eventually claim a terminal transition"]
pub struct IssuedRequest {
    id: RequestId,
    descriptor: RequestDescriptor,
    cancellation_mode: CancellationMode,
}

impl IssuedRequest {
    /// Exact issued request identity suitable for an external completion key.
    pub const fn id(&self) -> RequestId {
        self.id
    }

    /// Immutable copied request metadata.
    pub const fn descriptor(&self) -> RequestDescriptor {
        self.descriptor
    }

    /// Cancellation contract atomically published at execution hand-off.
    pub const fn cancellation_mode(&self) -> CancellationMode {
        self.cancellation_mode
    }
}

/// Failed execution hand-off with the prepared proof returned for cleanup.
#[derive(Debug)]
pub struct RequestIssueError {
    error: IoUringError,
    prepared: PreparedRequest,
}

impl RequestIssueError {
    /// Typed race/stale-state failure.
    pub const fn error(&self) -> IoUringError {
        self.error
    }

    /// Prepared identity and descriptor which were not handed to execution.
    pub const fn prepared(&self) -> &PreparedRequest {
        &self.prepared
    }

    /// Recovers the proof for adapter-side prepared-resource rollback.
    pub fn into_prepared(self) -> PreparedRequest {
        self.prepared
    }
}

/// Unique ownership of one request's terminal transition.
#[derive(Debug)]
#[must_use = "terminal ownership must be converted into a completion"]
pub struct TerminalPermit {
    id: RequestId,
    descriptor: RequestDescriptor,
    cause: TerminalCause,
}

impl TerminalPermit {
    /// Request whose terminal transition is owned.
    pub const fn id(&self) -> RequestId {
        self.id
    }

    /// Immutable metadata used to build its CQE.
    pub const fn descriptor(&self) -> RequestDescriptor {
        self.descriptor
    }

    /// Winning terminal path.
    pub const fn cause(&self) -> TerminalCause {
        self.cause
    }
}

/// Generation-safe handle for one complete but unpublished CQE.
#[derive(Debug)]
#[must_use = "a completed request must be published or explicitly drained"]
pub struct CompletionToken {
    id: RequestId,
}

impl CompletionToken {
    /// Request represented by the pending CQE.
    pub const fn id(&self) -> RequestId {
        self.id
    }
}

/// Lock-external plan for one CQE write followed by CQ-tail release-store.
#[derive(Debug)]
#[must_use = "a CQE publication must be committed after release-storing its tail"]
pub struct CompletionPublication {
    id: RequestId,
    completion: Completion,
    slot: u32,
    new_tail: u32,
}

impl CompletionPublication {
    /// Complete value to write before publishing the new tail.
    pub const fn completion(&self) -> Completion {
        self.completion
    }

    /// CQ array slot at which the complete value must be written.
    pub const fn slot(&self) -> u32 {
        self.slot
    }

    /// Monotonic wrapping CQ tail to release-store after the CQE write.
    pub const fn new_tail(&self) -> u32 {
        self.new_tail
    }
}

/// Bounded snapshot used by close and diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestProgress {
    lifecycle: RequestLifecycle,
    reserved: u32,
    prepared: u32,
    issued: u32,
    uncancellable_issued: u32,
    terminal_claimed: u32,
    completion_pending: u32,
    publishing: u32,
    terminal_credits: u32,
    published: u32,
}

impl RequestProgress {
    /// Current admission/teardown phase.
    pub const fn lifecycle(self) -> RequestLifecycle {
        self.lifecycle
    }

    /// Reversible reservations not yet reflected in SQ head.
    pub const fn reserved(self) -> u32 {
        self.reserved
    }

    /// Accepted requests not handed to execution.
    pub const fn prepared(self) -> u32 {
        self.prepared
    }

    /// Requests owned by an external execution mechanism.
    pub const fn issued(self) -> u32 {
        self.issued
    }

    /// Issued requests which close/cancel must wait for rather than complete.
    pub const fn uncancellable_issued(self) -> u32 {
        self.uncancellable_issued
    }

    /// Requests with a winning terminal path but no complete CQE yet.
    pub const fn terminal_claimed(self) -> u32 {
        self.terminal_claimed
    }

    /// Complete CQEs not yet published to the shared ring.
    pub const fn completion_pending(self) -> u32 {
        self.completion_pending
    }

    /// CQE publication transactions currently outside the policy core.
    pub const fn publishing(self) -> u32 {
        self.publishing
    }

    /// All charged terminal credits, including published CQEs not yet reaped.
    pub const fn terminal_credits(self) -> u32 {
        self.terminal_credits
    }

    /// CQEs visible between the validated CQ head and the core's CQ tail.
    pub const fn published(self) -> u32 {
        self.published
    }

    /// Every request-table slot has reached its terminal publication/drain.
    pub const fn requests_empty(self) -> bool {
        self.reserved == 0
            && self.prepared == 0
            && self.issued == 0
            && self.terminal_claimed == 0
            && self.completion_pending == 0
            && self.publishing == 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EntryState {
    Reserved,
    Prepared,
    Issued(CancellationMode),
    TerminalClaimed(TerminalCause),
    CompletionPending(Completion),
    Publishing(Completion),
}

impl EntryState {
    const fn public(self) -> RequestState {
        match self {
            Self::Reserved => RequestState::Reserved,
            Self::Prepared => RequestState::Prepared,
            Self::Issued(mode) => RequestState::Issued(mode),
            Self::TerminalClaimed(_) => RequestState::TerminalClaimed,
            Self::CompletionPending(_) => RequestState::CompletionPending,
            Self::Publishing(_) => RequestState::Publishing,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RequestEntry {
    descriptor: RequestDescriptor,
    sequence: NonZeroU64,
    state: EntryState,
}

#[derive(Debug)]
struct RequestSlot {
    generation: Option<NonZeroU64>,
    entry: Option<RequestEntry>,
}

/// Fixed-capacity, generation-safe request and terminal-CQ policy registry.
///
/// The embedding kernel supplies external synchronization. Construction is the
/// only allocation point; all admission, completion, cancellation, reaping,
/// and close operations are allocation-free.
#[derive(Debug)]
pub struct RequestRegistry {
    ring: RingId,
    capacity: u32,
    slots: Vec<RequestSlot>,
    free_slots: Vec<u32>,
    next_sequence: Option<NonZeroU64>,
    lifecycle: RequestLifecycle,
    cq_entries: u32,
    cq_head: u32,
    cq_tail: u32,
    terminal_credits: u32,
    publication_in_flight: Option<RequestId>,
}

impl RequestRegistry {
    /// Allocates a bounded request table and configures terminal CQ capacity.
    pub fn new(ring: RingId, request_capacity: u32, cq_entries: u32) -> Result<Self, IoUringError> {
        if request_capacity == 0 || request_capacity > IORING_MAX_ENTRIES {
            return Err(IoUringError::RequestCapacityExceeded);
        }
        if cq_entries == 0 || !cq_entries.is_power_of_two() || cq_entries > IORING_MAX_CQ_ENTRIES {
            return Err(IoUringError::InvalidQueueGeometry);
        }
        let capacity = usize::try_from(request_capacity).map_err(|_| IoUringError::Overflow)?;
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(capacity)
            .map_err(|_| IoUringError::AllocationFailed)?;
        for _ in 0..capacity {
            slots.push(RequestSlot {
                generation: NonZeroU64::new(1),
                entry: None,
            });
        }
        let mut free_slots = Vec::new();
        free_slots
            .try_reserve_exact(capacity)
            .map_err(|_| IoUringError::AllocationFailed)?;
        for slot in (0..request_capacity).rev() {
            free_slots.push(slot);
        }
        Ok(Self {
            ring,
            capacity: request_capacity,
            slots,
            free_slots,
            next_sequence: NonZeroU64::new(1),
            lifecycle: RequestLifecycle::Open,
            cq_entries,
            cq_head: 0,
            cq_tail: 0,
            terminal_credits: 0,
            publication_in_flight: None,
        })
    }

    /// Ring scope carried by every generated token.
    pub const fn ring(&self) -> RingId {
        self.ring
    }

    /// Fixed request-slot capacity allocated at construction.
    pub fn capacity(&self) -> u32 {
        self.capacity
    }

    /// Maximum simultaneously published completion entries.
    pub const fn cq_entries(&self) -> u32 {
        self.cq_entries
    }

    /// Last validated userspace CQ head.
    pub const fn completion_head(&self) -> u32 {
        self.cq_head
    }

    /// Core-owned CQ tail represented by returned publication plans.
    pub const fn completion_tail(&self) -> u32 {
        self.cq_tail
    }

    /// Reserves a request slot and terminal CQ credit before SQ admission.
    ///
    /// `CompletionQueueFull` is retryable without advancing the shared SQ
    /// head. The returned reservation remains reversible until committed.
    pub fn reserve(
        &mut self,
        descriptor: RequestDescriptor,
    ) -> Result<RequestReservation, IoUringError> {
        if self.lifecycle != RequestLifecycle::Open {
            return Err(match self.lifecycle {
                RequestLifecycle::Open => unreachable!(),
                RequestLifecycle::Closing => IoUringError::Closing,
                RequestLifecycle::Draining => IoUringError::Draining,
                RequestLifecycle::Closed => IoUringError::Closed,
            });
        }
        if self.terminal_credits >= self.cq_entries {
            return Err(IoUringError::CompletionQueueFull);
        }
        let sequence = self
            .next_sequence
            .ok_or(IoUringError::GenerationExhausted)?;
        let slot_index = match self.free_slots.last() {
            Some(slot) => *slot,
            None => {
                return Err(if self.slots.iter().any(|slot| slot.entry.is_some()) {
                    IoUringError::RequestCapacityExceeded
                } else {
                    IoUringError::GenerationExhausted
                });
            }
        };
        let slot = self
            .slots
            .get(usize::try_from(slot_index).map_err(|_| IoUringError::Overflow)?)
            .ok_or(IoUringError::RequestCapacityExceeded)?;
        if slot.entry.is_some() {
            return Err(IoUringError::InvalidRequestState);
        }
        let generation = slot.generation.ok_or(IoUringError::GenerationExhausted)?;
        let id = RequestId::new(self.ring, slot_index, generation);

        self.terminal_credits = self
            .terminal_credits
            .checked_add(1)
            .ok_or(IoUringError::Overflow)?;
        self.next_sequence = sequence.get().checked_add(1).and_then(NonZeroU64::new);
        let popped = self
            .free_slots
            .pop()
            .ok_or(IoUringError::RequestCapacityExceeded)?;
        if popped != slot_index {
            return Err(IoUringError::InvalidRequestState);
        }
        let slot = self
            .slots
            .get_mut(usize::try_from(slot_index).map_err(|_| IoUringError::Overflow)?)
            .ok_or(IoUringError::RequestCapacityExceeded)?;
        slot.entry = Some(RequestEntry {
            descriptor,
            sequence,
            state: EntryState::Reserved,
        });
        Ok(RequestReservation { id, descriptor })
    }

    /// Rolls back admission before the adapter advances shared SQ head.
    pub fn rollback(&mut self, reservation: RequestReservation) -> Result<(), IoUringError> {
        self.require_state(reservation.id, RequestState::Reserved)?;
        self.clear_slot(reservation.id)?;
        self.refund_credits(1)
    }

    /// Commits SQ consumption for a previously reserved request.
    pub fn commit(
        &mut self,
        reservation: RequestReservation,
    ) -> Result<PreparedRequest, IoUringError> {
        let entry = self.entry_mut(reservation.id)?;
        if entry.state != EntryState::Reserved {
            return Err(IoUringError::InvalidRequestState);
        }
        entry.state = EntryState::Prepared;
        Ok(PreparedRequest {
            id: reservation.id,
            descriptor: entry.descriptor,
        })
    }

    /// Transfers a prepared request to the adapter's execution mechanism.
    pub fn issue(&mut self, prepared: PreparedRequest) -> Result<IssuedRequest, RequestIssueError> {
        let entry = match self.entry_mut(prepared.id) {
            Ok(entry) => entry,
            Err(error) => return Err(RequestIssueError { error, prepared }),
        };
        if entry.state != EntryState::Prepared {
            let error = if matches!(
                entry.state,
                EntryState::TerminalClaimed(_)
                    | EntryState::CompletionPending(_)
                    | EntryState::Publishing(_)
            ) {
                IoUringError::TerminalAlreadyClaimed
            } else {
                IoUringError::InvalidRequestState
            };
            return Err(RequestIssueError { error, prepared });
        }
        let cancellation_mode = entry.descriptor.operation.cancellation_mode();
        entry.state = EntryState::Issued(cancellation_mode);
        Ok(IssuedRequest {
            id: prepared.id,
            descriptor: entry.descriptor,
            cancellation_mode,
        })
    }

    /// Returns an immutable snapshot of one exact live request.
    pub fn request(
        &self,
        id: RequestId,
    ) -> Result<(RequestDescriptor, RequestState), IoUringError> {
        let entry = self.entry(id)?;
        Ok((entry.descriptor, entry.state.public()))
    }

    /// Claims the sole terminal transition for prepared or issued work.
    pub fn claim_terminal(
        &mut self,
        id: RequestId,
        cause: TerminalCause,
    ) -> Result<TerminalPermit, IoUringError> {
        let entry = self.entry_mut(id)?;
        match entry.state {
            EntryState::Prepared => {
                entry.state = EntryState::TerminalClaimed(cause);
                Ok(TerminalPermit {
                    id,
                    descriptor: entry.descriptor,
                    cause,
                })
            }
            EntryState::Issued(CancellationMode::Uncancellable)
                if cause != TerminalCause::Completed =>
            {
                Err(IoUringError::RequestUncancellable)
            }
            EntryState::Issued(_) => {
                entry.state = EntryState::TerminalClaimed(cause);
                Ok(TerminalPermit {
                    id,
                    descriptor: entry.descriptor,
                    cause,
                })
            }
            EntryState::TerminalClaimed(_)
            | EntryState::CompletionPending(_)
            | EntryState::Publishing(_) => Err(IoUringError::TerminalAlreadyClaimed),
            EntryState::Reserved => Err(IoUringError::InvalidRequestState),
        }
    }

    /// Atomically selects and claims one cancellable request.
    ///
    /// `exclude` is normally the `ASYNC_CANCEL` request itself. Duplicate user
    /// data values select the oldest still-cancellable admission.
    pub fn claim_cancel(
        &mut self,
        selector: CancelSelector,
        exclude: Option<RequestId>,
    ) -> Result<TerminalPermit, IoUringError> {
        if let CancelSelector::Request(id) = selector {
            if Some(id) == exclude {
                return Err(IoUringError::CancellationTargetNotFound);
            }
            return match self.claim_terminal(id, TerminalCause::Cancelled) {
                Err(
                    IoUringError::UnknownRequest
                    | IoUringError::TerminalAlreadyClaimed
                    | IoUringError::RequestUncancellable,
                ) => Err(IoUringError::CancellationTargetNotFound),
                result => result,
            };
        }

        let mut candidate: Option<(NonZeroU64, RequestId)> = None;
        for (slot_index, slot) in self.slots.iter().enumerate() {
            let Some(entry) = slot.entry else {
                continue;
            };
            let generation = slot.generation.ok_or(IoUringError::GenerationExhausted)?;
            let id = RequestId::new(
                self.ring,
                u32::try_from(slot_index).map_err(|_| IoUringError::Overflow)?,
                generation,
            );
            if Some(id) == exclude || !selector.matches(entry.descriptor) {
                continue;
            }
            match entry.state {
                EntryState::Prepared | EntryState::Issued(CancellationMode::Cancellable) => {
                    if candidate
                        .map(|(sequence, _)| entry.sequence < sequence)
                        .unwrap_or(true)
                    {
                        candidate = Some((entry.sequence, id));
                    }
                }
                EntryState::TerminalClaimed(_)
                | EntryState::CompletionPending(_)
                | EntryState::Publishing(_) => {}
                EntryState::Reserved => {}
                EntryState::Issued(CancellationMode::Uncancellable) => {}
            }
        }
        if let Some((_, id)) = candidate {
            self.claim_terminal(id, TerminalCause::Cancelled)
        } else {
            Err(IoUringError::CancellationTargetNotFound)
        }
    }

    /// Converts unique terminal ownership into a complete pending CQE.
    pub fn finish_terminal(
        &mut self,
        permit: TerminalPermit,
        result: i32,
        flags: u32,
    ) -> Result<CompletionToken, IoUringError> {
        let entry = self.entry_mut(permit.id)?;
        if entry.state != EntryState::TerminalClaimed(permit.cause) {
            return Err(IoUringError::InvalidRequestState);
        }
        entry.state = EntryState::CompletionPending(Completion::new(
            entry.descriptor.user_data,
            result,
            flags,
        ));
        Ok(CompletionToken { id: permit.id })
    }

    /// Starts the sole CQE write/tail publication transaction.
    ///
    /// The adapter must write `publication.completion()` completely at
    /// `publication.slot()`, release-store `publication.new_tail()`, and then
    /// call `commit_publication`. Other publication and reap operations remain
    /// blocked while the plan is outside this core.
    pub fn publish(
        &mut self,
        token: &CompletionToken,
    ) -> Result<CompletionPublication, IoUringError> {
        if self.lifecycle == RequestLifecycle::Draining {
            return Err(IoUringError::Draining);
        }
        if self.lifecycle == RequestLifecycle::Closed {
            return Err(IoUringError::Closed);
        }
        if self.publication_in_flight.is_some() {
            return Err(IoUringError::PublicationInFlight);
        }
        let entry = self.entry(token.id)?;
        let EntryState::CompletionPending(completion) = entry.state else {
            return Err(IoUringError::CompletionNotPending);
        };
        if self.published_count()? >= self.cq_entries {
            return Err(IoUringError::CompletionQueueFull);
        }
        let slot = self.cq_tail & (self.cq_entries - 1);
        let new_tail = self.cq_tail.wrapping_add(1);
        self.entry_mut(token.id)?.state = EntryState::Publishing(completion);
        self.publication_in_flight = Some(token.id);
        Ok(CompletionPublication {
            id: token.id,
            completion,
            slot,
            new_tail,
        })
    }

    /// Commits core accounting after the adapter release-stored the plan tail.
    pub fn commit_publication(
        &mut self,
        publication: CompletionPublication,
    ) -> Result<(), IoUringError> {
        if self.publication_in_flight != Some(publication.id) {
            return Err(IoUringError::PublicationInFlight);
        }
        let expected_slot = self.cq_tail & (self.cq_entries - 1);
        let expected_tail = self.cq_tail.wrapping_add(1);
        if publication.slot != expected_slot || publication.new_tail != expected_tail {
            return Err(IoUringError::InvalidQueueGeometry);
        }
        let entry = self.entry(publication.id)?;
        if entry.state != EntryState::Publishing(publication.completion) {
            return Err(IoUringError::InvalidRequestState);
        }
        self.clear_slot(publication.id)?;
        self.cq_tail = publication.new_tail;
        self.publication_in_flight = None;
        Ok(())
    }

    /// Rolls a plan back before any shared CQ tail release-store occurred.
    pub fn rollback_publication(
        &mut self,
        publication: CompletionPublication,
    ) -> Result<CompletionToken, IoUringError> {
        if self.publication_in_flight != Some(publication.id) {
            return Err(IoUringError::PublicationInFlight);
        }
        let entry = self.entry_mut(publication.id)?;
        if entry.state != EntryState::Publishing(publication.completion) {
            return Err(IoUringError::InvalidRequestState);
        }
        entry.state = EntryState::CompletionPending(publication.completion);
        self.publication_in_flight = None;
        Ok(CompletionToken { id: publication.id })
    }

    /// Validates userspace CQ consumption and refunds exactly those credits.
    ///
    /// Backward, forged-forward, and over-consuming heads are rejected without
    /// changing accounting. Credits for unpublished completions are never
    /// refunded here.
    pub fn observe_completion_head(&mut self, user_head: u32) -> Result<u32, IoUringError> {
        if self.publication_in_flight.is_some() {
            return Err(IoUringError::PublicationInFlight);
        }
        let consumed = user_head.wrapping_sub(self.cq_head);
        if consumed > self.published_count()? {
            return Err(IoUringError::CorruptCompletionHead);
        }
        self.cq_head = user_head;
        self.refund_credits(consumed)?;
        Ok(consumed)
    }

    /// Stops new reservations while preserving all existing terminal owners.
    pub fn begin_close(&mut self) -> Result<RequestProgress, IoUringError> {
        match self.lifecycle {
            RequestLifecycle::Open => self.lifecycle = RequestLifecycle::Closing,
            RequestLifecycle::Closing | RequestLifecycle::Draining | RequestLifecycle::Closed => {}
        }
        self.progress()
    }

    /// Enters explicit discard mode after every executor/terminal owner ended.
    pub fn begin_draining(&mut self) -> Result<RequestProgress, IoUringError> {
        if self.lifecycle == RequestLifecycle::Draining {
            return self.progress();
        }
        if self.lifecycle != RequestLifecycle::Closing {
            return Err(IoUringError::InvalidLifecycleTransition);
        }
        if self.slots.iter().any(|slot| {
            slot.entry
                .is_some_and(|entry| !matches!(entry.state, EntryState::CompletionPending(_)))
        }) {
            return Err(IoUringError::Busy);
        }
        self.lifecycle = RequestLifecycle::Draining;
        self.progress()
    }

    /// Discards one unpublished terminal CQE after userspace lost access.
    pub fn discard_completion(&mut self, token: CompletionToken) -> Result<(), IoUringError> {
        if self.lifecycle != RequestLifecycle::Draining {
            return Err(IoUringError::InvalidLifecycleTransition);
        }
        self.require_state(token.id, RequestState::CompletionPending)?;
        self.clear_slot(token.id)?;
        self.refund_credits(1)
    }

    /// Discards all published but unconsumed CQEs after mappings are quiescent.
    pub fn discard_published(&mut self) -> Result<u32, IoUringError> {
        if self.lifecycle != RequestLifecycle::Draining {
            return Err(IoUringError::InvalidLifecycleTransition);
        }
        if self.publication_in_flight.is_some() {
            return Err(IoUringError::PublicationInFlight);
        }
        let published = self.published_count()?;
        self.cq_head = self.cq_tail;
        self.refund_credits(published)?;
        Ok(published)
    }

    /// Finishes close only after every request and terminal credit is gone.
    pub fn finish_close(&mut self) -> Result<(), IoUringError> {
        match self.lifecycle {
            RequestLifecycle::Open => return Err(IoUringError::InvalidLifecycleTransition),
            RequestLifecycle::Closed => return Ok(()),
            RequestLifecycle::Closing | RequestLifecycle::Draining => {}
        }
        if self.publication_in_flight.is_some()
            || self.slots.iter().any(|slot| slot.entry.is_some())
            || self.terminal_credits != 0
        {
            return Err(IoUringError::Busy);
        }
        self.lifecycle = RequestLifecycle::Closed;
        Ok(())
    }

    /// Returns a finite snapshot without exposing internal storage.
    pub fn progress(&self) -> Result<RequestProgress, IoUringError> {
        let mut progress = RequestProgress {
            lifecycle: self.lifecycle,
            reserved: 0,
            prepared: 0,
            issued: 0,
            uncancellable_issued: 0,
            terminal_claimed: 0,
            completion_pending: 0,
            publishing: 0,
            terminal_credits: self.terminal_credits,
            published: self.published_count()?,
        };
        for slot in &self.slots {
            match slot.entry.map(|entry| entry.state) {
                Some(EntryState::Reserved) => progress.reserved += 1,
                Some(EntryState::Prepared) => progress.prepared += 1,
                Some(EntryState::Issued(mode)) => {
                    progress.issued += 1;
                    if mode == CancellationMode::Uncancellable {
                        progress.uncancellable_issued += 1;
                    }
                }
                Some(EntryState::TerminalClaimed(_)) => progress.terminal_claimed += 1,
                Some(EntryState::CompletionPending(_)) => progress.completion_pending += 1,
                Some(EntryState::Publishing(_)) => progress.publishing += 1,
                None => {}
            }
        }
        Ok(progress)
    }

    fn entry(&self, id: RequestId) -> Result<&RequestEntry, IoUringError> {
        if id.ring != self.ring {
            return Err(IoUringError::UnknownRequest);
        }
        let slot = self
            .slots
            .get(usize::try_from(id.slot).map_err(|_| IoUringError::UnknownRequest)?)
            .ok_or(IoUringError::UnknownRequest)?;
        if slot.generation != Some(id.generation) {
            return Err(IoUringError::UnknownRequest);
        }
        slot.entry.as_ref().ok_or(IoUringError::UnknownRequest)
    }

    fn entry_mut(&mut self, id: RequestId) -> Result<&mut RequestEntry, IoUringError> {
        if id.ring != self.ring {
            return Err(IoUringError::UnknownRequest);
        }
        let slot = self
            .slots
            .get_mut(usize::try_from(id.slot).map_err(|_| IoUringError::UnknownRequest)?)
            .ok_or(IoUringError::UnknownRequest)?;
        if slot.generation != Some(id.generation) {
            return Err(IoUringError::UnknownRequest);
        }
        slot.entry.as_mut().ok_or(IoUringError::UnknownRequest)
    }

    fn require_state(&self, id: RequestId, state: RequestState) -> Result<(), IoUringError> {
        if self.entry(id)?.state.public() == state {
            Ok(())
        } else {
            Err(IoUringError::InvalidRequestState)
        }
    }

    fn clear_slot(&mut self, id: RequestId) -> Result<(), IoUringError> {
        if id.ring != self.ring {
            return Err(IoUringError::UnknownRequest);
        }
        let slot = self
            .slots
            .get_mut(usize::try_from(id.slot).map_err(|_| IoUringError::UnknownRequest)?)
            .ok_or(IoUringError::UnknownRequest)?;
        if slot.generation != Some(id.generation) || slot.entry.is_none() {
            return Err(IoUringError::UnknownRequest);
        }
        slot.entry = None;
        let next_generation = id.generation.get().checked_add(1).and_then(NonZeroU64::new);
        slot.generation = next_generation;
        if next_generation.is_some() {
            if self.free_slots.len() >= self.slots.len() {
                return Err(IoUringError::InvalidRequestState);
            }
            self.free_slots.push(id.slot);
        }
        Ok(())
    }

    fn published_count(&self) -> Result<u32, IoUringError> {
        let published = self.cq_tail.wrapping_sub(self.cq_head);
        if published <= self.cq_entries {
            Ok(published)
        } else {
            Err(IoUringError::InvalidQueueGeometry)
        }
    }

    fn refund_credits(&mut self, count: u32) -> Result<(), IoUringError> {
        self.terminal_credits = self
            .terminal_credits
            .checked_sub(count)
            .ok_or(IoUringError::InvalidCompletionConsumption)?;
        Ok(())
    }

    #[cfg(test)]
    fn force_empty_slot_generation(&mut self, slot: u32, generation: u64) {
        let slot = &mut self.slots[slot as usize];
        assert!(slot.entry.is_none());
        slot.generation = NonZeroU64::new(generation);
    }

    #[cfg(test)]
    fn force_next_sequence(&mut self, sequence: u64) {
        self.next_sequence = NonZeroU64::new(sequence);
    }

    #[cfg(test)]
    fn force_empty_cq_counters(&mut self, counter: u32) {
        assert_eq!(self.terminal_credits, 0);
        assert!(self.publication_in_flight.is_none());
        self.cq_head = counter;
        self.cq_tail = counter;
    }
}

impl CancelSelector {
    const fn matches(self, descriptor: RequestDescriptor) -> bool {
        match self {
            Self::UserData(user_data) => descriptor.user_data == user_data,
            Self::Request(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ring(raw: u64) -> RingId {
        RingId::new(raw).unwrap()
    }

    fn descriptor(user_data: u64) -> RequestDescriptor {
        RequestDescriptor::new(user_data, RequestOperation::Nop)
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct Published {
        completion: Completion,
        slot: u32,
        new_tail: u32,
    }

    fn complete(
        registry: &mut RequestRegistry,
        prepared: PreparedRequest,
        result: i32,
    ) -> Published {
        let permit = registry
            .claim_terminal(prepared.id(), TerminalCause::Completed)
            .unwrap();
        let token = registry.finish_terminal(permit, result, 0).unwrap();
        let publication = registry.publish(&token).unwrap();
        let published = Published {
            completion: publication.completion(),
            slot: publication.slot(),
            new_tail: publication.new_tail(),
        };
        registry.commit_publication(publication).unwrap();
        published
    }

    #[test]
    fn terminal_credit_is_reserved_before_commit_and_rollback_refunds_it() {
        let mut registry = RequestRegistry::new(ring(1), 2, 1).unwrap();
        let reservation = registry.reserve(descriptor(7)).unwrap();
        assert_eq!(registry.progress().unwrap().terminal_credits(), 1);
        assert!(matches!(
            registry.reserve(descriptor(8)),
            Err(IoUringError::CompletionQueueFull)
        ));
        registry.rollback(reservation).unwrap();
        assert_eq!(registry.progress().unwrap().terminal_credits(), 0);
        assert!(registry.reserve(descriptor(8)).is_ok());
    }

    #[test]
    fn request_capacity_is_bounded_by_the_pinned_linux_sq_limit() {
        assert!(matches!(
            RequestRegistry::new(ring(1), IORING_MAX_ENTRIES + 1, 1),
            Err(IoUringError::RequestCapacityExceeded)
        ));
        assert_eq!(RequestRegistry::new(ring(1), 3, 4).unwrap().capacity(), 3);
    }

    #[test]
    fn published_credit_is_refunded_only_by_valid_user_head() {
        let mut registry = RequestRegistry::new(ring(1), 2, 2).unwrap();
        let reservation = registry.reserve(descriptor(11)).unwrap();
        let prepared = registry.commit(reservation).unwrap();
        let publication = complete(&mut registry, prepared, 42);
        assert_eq!(publication.slot, 0);
        assert_eq!(publication.new_tail, 1);
        assert_eq!(publication.completion, Completion::new(11, 42, 0));
        assert_eq!(registry.progress().unwrap().terminal_credits(), 1);
        assert_eq!(
            registry.observe_completion_head(2),
            Err(IoUringError::CorruptCompletionHead)
        );
        assert_eq!(registry.progress().unwrap().terminal_credits(), 1);
        assert_eq!(registry.observe_completion_head(1).unwrap(), 1);
        assert_eq!(registry.progress().unwrap().terminal_credits(), 0);
    }

    #[test]
    fn request_slot_reuse_changes_generation_before_cq_reap() {
        let mut registry = RequestRegistry::new(ring(1), 1, 2).unwrap();
        let reservation = registry.reserve(descriptor(1)).unwrap();
        let first = registry.commit(reservation).unwrap();
        let first_id = first.id();
        complete(&mut registry, first, 0);

        let reservation = registry.reserve(descriptor(2)).unwrap();
        let second = registry.commit(reservation).unwrap();
        assert_eq!(first_id.slot(), second.id().slot());
        assert_ne!(first_id.generation(), second.id().generation());
        assert_eq!(
            registry.request(first_id),
            Err(IoUringError::UnknownRequest)
        );
    }

    #[test]
    fn generation_and_admission_sequence_never_wrap_into_aba() {
        let mut generation_registry = RequestRegistry::new(ring(1), 1, 1).unwrap();
        generation_registry.force_empty_slot_generation(0, u64::MAX);
        let reservation = generation_registry.reserve(descriptor(1)).unwrap();
        let prepared = generation_registry.commit(reservation).unwrap();
        complete(&mut generation_registry, prepared, 0);
        generation_registry.observe_completion_head(1).unwrap();
        assert!(matches!(
            generation_registry.reserve(descriptor(2)),
            Err(IoUringError::GenerationExhausted)
        ));

        let mut sequence_registry = RequestRegistry::new(ring(2), 1, 1).unwrap();
        sequence_registry.force_next_sequence(u64::MAX);
        let reservation = sequence_registry.reserve(descriptor(1)).unwrap();
        let prepared = sequence_registry.commit(reservation).unwrap();
        complete(&mut sequence_registry, prepared, 0);
        sequence_registry.observe_completion_head(1).unwrap();
        assert!(matches!(
            sequence_registry.reserve(descriptor(2)),
            Err(IoUringError::GenerationExhausted)
        ));
    }

    #[test]
    fn cq_counters_wrap_monotonically_without_refunding_early() {
        let mut registry = RequestRegistry::new(ring(1), 1, 2).unwrap();
        registry.force_empty_cq_counters(u32::MAX);
        let reservation = registry.reserve(descriptor(1)).unwrap();
        let prepared = registry.commit(reservation).unwrap();
        let publication = complete(&mut registry, prepared, 0);
        assert_eq!(publication.new_tail, 0);
        assert_eq!(publication.slot, 1);
        assert_eq!(registry.observe_completion_head(0), Ok(1));
        assert_eq!(registry.progress().unwrap().terminal_credits(), 0);
    }

    #[test]
    fn terminal_race_has_exactly_one_owner() {
        let mut registry = RequestRegistry::new(ring(1), 1, 2).unwrap();
        let reservation = registry.reserve(descriptor(1)).unwrap();
        let prepared = registry.commit(reservation).unwrap();
        let issued = registry.issue(prepared).unwrap();
        let permit = registry
            .claim_terminal(issued.id(), TerminalCause::Completed)
            .unwrap();
        assert!(matches!(
            registry.claim_terminal(issued.id(), TerminalCause::Cancelled),
            Err(IoUringError::TerminalAlreadyClaimed)
        ));
        assert!(registry.finish_terminal(permit, 0, 0).is_ok());
    }

    #[test]
    fn publication_is_serialized_until_tail_commit_or_rollback() {
        let mut registry = RequestRegistry::new(ring(1), 2, 2).unwrap();
        let first_reservation = registry.reserve(descriptor(1)).unwrap();
        let first = registry.commit(first_reservation).unwrap();
        let first_permit = registry
            .claim_terminal(first.id(), TerminalCause::Completed)
            .unwrap();
        let first_token = registry.finish_terminal(first_permit, 10, 0).unwrap();

        let second_reservation = registry.reserve(descriptor(2)).unwrap();
        let second = registry.commit(second_reservation).unwrap();
        let second_permit = registry
            .claim_terminal(second.id(), TerminalCause::Completed)
            .unwrap();
        let second_token = registry.finish_terminal(second_permit, 20, 0).unwrap();

        let first_publication = registry.publish(&first_token).unwrap();
        assert_eq!(registry.progress().unwrap().publishing(), 1);
        assert!(matches!(
            registry.publish(&second_token),
            Err(IoUringError::PublicationInFlight)
        ));
        assert_eq!(
            registry.observe_completion_head(0),
            Err(IoUringError::PublicationInFlight)
        );
        let first_token = registry.rollback_publication(first_publication).unwrap();
        assert_eq!(registry.progress().unwrap().publishing(), 0);

        let first_publication = registry.publish(&first_token).unwrap();
        registry.commit_publication(first_publication).unwrap();
        let second_publication = registry.publish(&second_token).unwrap();
        assert_eq!(second_publication.slot(), 1);
        assert_eq!(second_publication.new_tail(), 2);
        registry.commit_publication(second_publication).unwrap();
    }

    #[test]
    fn duplicate_user_data_cancellation_selects_oldest_live_request() {
        let mut registry = RequestRegistry::new(ring(1), 3, 4).unwrap();
        let reservation = registry.reserve(descriptor(9)).unwrap();
        let first = registry.commit(reservation).unwrap();
        let reservation = registry.reserve(descriptor(9)).unwrap();
        let second = registry.commit(reservation).unwrap();
        let permit = registry
            .claim_cancel(CancelSelector::UserData(9), None)
            .unwrap();
        assert_eq!(permit.id(), first.id());
        assert_eq!(
            registry.request(second.id()).unwrap().1,
            RequestState::Prepared
        );
    }

    #[test]
    fn cancellation_exclusion_prevents_self_match() {
        let mut registry = RequestRegistry::new(ring(1), 1, 1).unwrap();
        let reservation = registry
            .reserve(RequestDescriptor::new(9, RequestOperation::AsyncCancel))
            .unwrap();
        let cancel = registry.commit(reservation).unwrap();
        assert!(matches!(
            registry.claim_cancel(CancelSelector::UserData(9), Some(cancel.id())),
            Err(IoUringError::CancellationTargetNotFound)
        ));
    }

    #[test]
    fn repeated_cancel_observes_no_cancellable_target() {
        let mut registry = RequestRegistry::new(ring(1), 1, 1).unwrap();
        let reservation = registry.reserve(descriptor(9)).unwrap();
        let target = registry.commit(reservation).unwrap();
        let permit = registry
            .claim_cancel(CancelSelector::UserData(9), None)
            .unwrap();
        assert_eq!(permit.id(), target.id());
        assert!(matches!(
            registry.claim_cancel(CancelSelector::UserData(9), None),
            Err(IoUringError::CancellationTargetNotFound)
        ));
    }

    #[test]
    fn irreversible_rw_handoff_blocks_cancel_and_forced_close_completion() {
        let mut registry = RequestRegistry::new(ring(1), 1, 1).unwrap();
        let reservation = registry
            .reserve(RequestDescriptor::new(9, RequestOperation::Write))
            .unwrap();
        let prepared = registry.commit(reservation).unwrap();
        let issued = registry.issue(prepared).unwrap();
        assert_eq!(issued.cancellation_mode(), CancellationMode::Uncancellable);
        assert!(matches!(
            registry.claim_cancel(CancelSelector::UserData(9), None),
            Err(IoUringError::CancellationTargetNotFound)
        ));
        assert_eq!(registry.progress().unwrap().uncancellable_issued(), 1);
        assert!(matches!(
            registry.claim_terminal(issued.id(), TerminalCause::Closing),
            Err(IoUringError::RequestUncancellable)
        ));
        let completion = registry
            .claim_terminal(issued.id(), TerminalCause::Completed)
            .unwrap();
        let completion = registry.finish_terminal(completion, 0, 0).unwrap();
        registry.begin_close().unwrap();
        registry.begin_draining().unwrap();
        registry.discard_completion(completion).unwrap();
        registry.finish_close().unwrap();
    }

    #[test]
    fn poll_handoff_remains_cancellable_and_issue_race_returns_proof() {
        let mut registry = RequestRegistry::new(ring(1), 2, 2).unwrap();
        let reservation = registry
            .reserve(RequestDescriptor::new(7, RequestOperation::PollAdd))
            .unwrap();
        let poll = registry.commit(reservation).unwrap();
        let issued = registry.issue(poll).unwrap();
        assert_eq!(issued.cancellation_mode(), CancellationMode::Cancellable);
        let first_cancel = registry
            .claim_cancel(CancelSelector::UserData(7), None)
            .unwrap();
        let first_completion = registry.finish_terminal(first_cancel, -1, 0).unwrap();

        let reservation = registry
            .reserve(RequestDescriptor::new(8, RequestOperation::PollAdd))
            .unwrap();
        let prepared = registry.commit(reservation).unwrap();
        let id = prepared.id();
        let second_cancel = registry
            .claim_cancel(CancelSelector::UserData(8), None)
            .unwrap();
        let issue_error = registry
            .issue(prepared)
            .expect_err("cancel must win before external hand-off");
        assert_eq!(issue_error.error(), IoUringError::TerminalAlreadyClaimed);
        assert_eq!(issue_error.prepared().id(), id);
        let second_completion = registry.finish_terminal(second_cancel, -1, 0).unwrap();
        registry.begin_close().unwrap();
        registry.begin_draining().unwrap();
        registry.discard_completion(first_completion).unwrap();
        registry.discard_completion(second_completion).unwrap();
        registry.finish_close().unwrap();
    }

    #[test]
    fn cross_ring_request_identity_is_rejected() {
        let mut first = RequestRegistry::new(ring(1), 1, 1).unwrap();
        let second = RequestRegistry::new(ring(2), 1, 1).unwrap();
        let reservation = first.reserve(descriptor(1)).unwrap();
        let prepared = first.commit(reservation).unwrap();
        assert_eq!(
            second.request(prepared.id()),
            Err(IoUringError::UnknownRequest)
        );
    }

    #[test]
    fn close_preserves_terminal_credit_until_reap() {
        let mut registry = RequestRegistry::new(ring(1), 1, 1).unwrap();
        let reservation = registry.reserve(descriptor(1)).unwrap();
        let prepared = registry.commit(reservation).unwrap();
        registry.begin_close().unwrap();
        assert!(matches!(
            registry.reserve(descriptor(2)),
            Err(IoUringError::Closing)
        ));
        complete(&mut registry, prepared, 0);
        assert_eq!(registry.finish_close(), Err(IoUringError::Busy));
        registry.observe_completion_head(1).unwrap();
        registry.finish_close().unwrap();
        registry.begin_close().unwrap();
        registry.finish_close().unwrap();
        assert_eq!(
            registry.progress().unwrap().lifecycle(),
            RequestLifecycle::Closed
        );
    }

    #[test]
    fn draining_requires_quiescent_execution_and_explicitly_refunds() {
        let mut registry = RequestRegistry::new(ring(1), 2, 2).unwrap();
        let reservation = registry.reserve(descriptor(1)).unwrap();
        let first = registry.commit(reservation).unwrap();
        let reservation = registry.reserve(descriptor(2)).unwrap();
        let second = registry.commit(reservation).unwrap();
        let first_token = {
            let permit = registry
                .claim_terminal(first.id(), TerminalCause::Closing)
                .unwrap();
            registry.finish_terminal(permit, -1, 0).unwrap()
        };
        registry.begin_close().unwrap();
        assert_eq!(registry.begin_draining(), Err(IoUringError::Busy));
        let second_token = {
            let permit = registry
                .claim_terminal(second.id(), TerminalCause::Closing)
                .unwrap();
            registry.finish_terminal(permit, -1, 0).unwrap()
        };
        registry.begin_draining().unwrap();
        registry.discard_completion(first_token).unwrap();
        registry.discard_completion(second_token).unwrap();
        registry.finish_close().unwrap();
    }
}
