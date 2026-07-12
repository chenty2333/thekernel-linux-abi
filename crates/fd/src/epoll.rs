use alloc::vec::Vec;

use crate::{EpollId, FdNumber, InterestMask, InterestMode, OfdId, ReadyMask};

/// Linux epoll interest identity: the shared OFD plus descriptor used by ADD.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EpollKey {
    /// Stable open-file-description identity.
    pub ofd: OfdId,
    /// Numeric descriptor supplied to `EPOLL_CTL_ADD`.
    pub fd: FdNumber,
}

/// One fully armed interest ready for atomic epoll publication.
pub struct EpollInterest<U, S> {
    key: EpollKey,
    interest: InterestMask,
    mode: InterestMode,
    user_data: U,
    subscription: S,
}

impl<U, S> EpollInterest<U, S> {
    /// Creates an interest after the aggregate source subscription is armed.
    pub const fn new(
        key: EpollKey,
        interest: InterestMask,
        mode: InterestMode,
        user_data: U,
        subscription: S,
    ) -> Self {
        Self {
            key,
            interest,
            mode,
            user_data,
            subscription,
        }
    }

    /// Returns the Linux `(OFD, fd)` identity.
    pub const fn key(&self) -> EpollKey {
        self.key
    }

    /// Returns the normal readiness interest mask.
    pub const fn interest(&self) -> InterestMask {
        self.interest
    }

    /// Returns trigger behavior.
    pub const fn mode(&self) -> InterestMode {
        self.mode
    }

    /// Returns user-provided event data.
    pub const fn user_data(&self) -> &U {
        &self.user_data
    }

    /// Returns the retained aggregate source subscription.
    pub const fn subscription(&self) -> &S {
        &self.subscription
    }

    /// Decomposes ownership for lock-external cancellation/destruction.
    pub fn into_parts(self) -> (EpollKey, InterestMask, InterestMode, U, S) {
        (
            self.key,
            self.interest,
            self.mode,
            self.user_data,
            self.subscription,
        )
    }
}

/// Generation-tagged callback/ctl identity for one epoll interest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EpollToken {
    epoll: EpollId,
    slot: usize,
    generation: u64,
}

impl EpollToken {
    /// Returns the owning epoll instance.
    pub const fn epoll(self) -> EpollId {
        self.epoll
    }

    /// Returns the private slot index for adapter indexes.
    pub const fn slot(self) -> usize {
        self.slot
    }

    /// Returns the opaque generation.
    pub const fn generation(self) -> u64 {
        self.generation
    }
}

/// In-flight ready event retained across lock-free userspace copyout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeliveryToken {
    interest: EpollToken,
    serial: u64,
    events: ReadyMask,
}

/// Ready event snapshot returned without retaining an epoll-core borrow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadyEvent<U> {
    /// Token required to finish copied or faulted delivery.
    pub delivery: DeliveryToken,
    /// Coalesced Linux readiness bits.
    pub events: ReadyMask,
    /// User data captured from the interest generation.
    pub user_data: U,
}

/// Result of userspace copyout and the post-copy level recheck.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryOutcome {
    /// The event was copied. Level-triggered callers provide readiness after
    /// copy; edge-triggered callers normally pass `ReadyMask::EMPTY`.
    Copied {
        /// Readiness observed by the adapter's post-copy level check.
        still_ready: ReadyMask,
    },
    /// Copyout faulted; the same event must remain deliverable.
    Fault,
}

/// Wake callback publication result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifyOutcome {
    /// A new ready-queue item was published.
    Enqueued,
    /// Bits were coalesced into an already queued or in-flight item.
    Coalesced,
    /// The interest is disabled or no requested/unconditional bit is ready.
    Ignored,
}

/// Epoll-core operation failure before errno mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EpollError {
    /// Fallible fixed-capacity storage could not be reserved.
    NoMemory,
    /// Interest or ready capacity is exhausted.
    Capacity,
    /// The `(OFD, fd)` interest already exists.
    Duplicate,
    /// The requested interest does not exist.
    NotFound,
    /// A callback, ctl, or delivery token is stale or foreign.
    StaleToken,
    /// Trigger flags form an unsupported combination.
    UnsupportedMode,
    /// No future unique generation/serial can be allocated.
    GenerationExhausted,
    /// Ready storage violated its admitted one-item-per-interest invariant.
    ReadyQueueFull,
    /// A bounded rescan was requested after an unexpected queue overflow.
    RescanRequired,
}

/// Progress from one explicitly bounded epoll readiness rescan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RescanProgress {
    /// Entry slots examined by this call.
    pub scanned: usize,
    /// Previously unqueued ready interests published by this call.
    pub enqueued: usize,
    /// Whether every entry was examined and the rescan request was cleared.
    pub complete: bool,
}

/// Failed ADD/MOD which returns the never-published replacement ownership.
pub struct EpollPublishError<U, S> {
    /// Typed epoll error.
    pub error: EpollError,
    /// Interest and retained subscription not published by the operation.
    pub interest: EpollInterest<U, S>,
}

impl<U, S> core::fmt::Debug for EpollPublishError<U, S> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("EpollPublishError")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

struct Entry<U, S> {
    generation: u64,
    interest: EpollInterest<U, S>,
    enabled: bool,
    queued: bool,
    in_delivery: Option<u64>,
    ready: ReadyMask,
    during_delivery: ReadyMask,
}

struct ReadyQueue {
    items: Vec<EpollToken>,
    head: usize,
    len: usize,
}

impl ReadyQueue {
    fn try_new(capacity: usize, filler: EpollToken) -> Result<Self, EpollError> {
        let mut items = Vec::new();
        items
            .try_reserve_exact(capacity)
            .map_err(|_| EpollError::NoMemory)?;
        items.resize(capacity, filler);
        Ok(Self {
            items,
            head: 0,
            len: 0,
        })
    }

    fn capacity(&self) -> usize {
        self.items.len()
    }

    fn push(&mut self, token: EpollToken) -> Result<(), EpollError> {
        if self.len == self.capacity() {
            return Err(EpollError::ReadyQueueFull);
        }
        let index = (self.head + self.len) % self.capacity();
        self.items[index] = token;
        self.len += 1;
        Ok(())
    }

    fn pop(&mut self) -> Option<EpollToken> {
        if self.len == 0 {
            return None;
        }
        let token = self.items[self.head];
        self.head = (self.head + 1) % self.capacity();
        self.len -= 1;
        Some(token)
    }

    fn peek(&self) -> Option<EpollToken> {
        (self.len != 0).then(|| self.items[self.head])
    }

    fn remove(&mut self, token: EpollToken) {
        if self.len == 0 {
            return;
        }
        let capacity = self.capacity();
        let mut retained = 0;
        for read in 0..self.len {
            let item = self.items[(self.head + read) % capacity];
            if item != token {
                let write = (self.head + retained) % capacity;
                self.items[write] = item;
                retained += 1;
            }
        }
        self.len = retained;
    }
}

/// Bounded allocation-free-after-construction epoll interest/ready core.
///
/// The consumer protects it with its chosen short IRQ-safe lock. Methods never
/// call source registrations, wakers, destructors, or usercopy; removed and
/// replaced interests are returned for lock-external teardown.
pub struct EpollCore<U, S> {
    id: EpollId,
    entries: Vec<Option<Entry<U, S>>>,
    ready: ReadyQueue,
    next_generation: u64,
    next_delivery: u64,
    rescan_required: bool,
    rescan_cursor: usize,
}

impl<U, S> EpollCore<U, S> {
    /// Fallibly reserves all interest and ready storage up front.
    pub fn try_new(id: EpollId, capacity: usize) -> Result<Self, EpollError> {
        if capacity == usize::MAX {
            return Err(EpollError::Capacity);
        }
        let filler = EpollToken {
            epoll: id,
            slot: 0,
            generation: 0,
        };
        let ready = ReadyQueue::try_new(capacity, filler)?;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(capacity)
            .map_err(|_| EpollError::NoMemory)?;
        entries.resize_with(capacity, || None);
        Ok(Self {
            id,
            entries,
            ready,
            next_generation: 1,
            next_delivery: 1,
            rescan_required: false,
            rescan_cursor: 0,
        })
    }

    /// Returns the instance identity.
    pub const fn id(&self) -> EpollId {
        self.id
    }

    /// Returns admitted interest capacity.
    pub fn capacity(&self) -> usize {
        self.entries.len()
    }

    /// Returns the number of published interests.
    pub fn len(&self) -> usize {
        self.entries.iter().filter(|entry| entry.is_some()).count()
    }

    /// Returns whether no interest is published.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns whether an unexpected ready-queue overflow requested a bounded
    /// adapter-driven rescan.
    pub const fn needs_rescan(&self) -> bool {
        self.rescan_required
    }

    fn allocate_generation(&mut self) -> Result<u64, EpollError> {
        let generation = self.next_generation;
        self.next_generation = generation
            .checked_add(1)
            .ok_or(EpollError::GenerationExhausted)?;
        Ok(generation)
    }

    fn allocate_delivery(&mut self) -> Result<u64, EpollError> {
        let serial = self.next_delivery;
        self.next_delivery = serial
            .checked_add(1)
            .ok_or(EpollError::GenerationExhausted)?;
        Ok(serial)
    }

    fn validate_mode(mode: InterestMode) -> Result<(), EpollError> {
        // Exclusive selection requires coordination across multiple epoll
        // instances at the source registry. This single-instance core cannot
        // honestly provide it until that lower-layer contract is supplied.
        if mode.exclusive {
            Err(EpollError::UnsupportedMode)
        } else {
            Ok(())
        }
    }

    fn entry(&self, token: EpollToken) -> Result<&Entry<U, S>, EpollError> {
        if token.epoll != self.id {
            return Err(EpollError::StaleToken);
        }
        match self.entries.get(token.slot).and_then(Option::as_ref) {
            Some(entry) if entry.generation == token.generation => Ok(entry),
            _ => Err(EpollError::StaleToken),
        }
    }

    fn entry_mut(&mut self, token: EpollToken) -> Result<&mut Entry<U, S>, EpollError> {
        if token.epoll != self.id {
            return Err(EpollError::StaleToken);
        }
        match self.entries.get_mut(token.slot).and_then(Option::as_mut) {
            Some(entry) if entry.generation == token.generation => Ok(entry),
            _ => Err(EpollError::StaleToken),
        }
    }

    /// Atomically publishes an already armed interest.
    pub fn add(
        &mut self,
        interest: EpollInterest<U, S>,
    ) -> Result<EpollToken, EpollPublishError<U, S>> {
        if let Err(error) = Self::validate_mode(interest.mode) {
            return Err(EpollPublishError { error, interest });
        }
        if self
            .entries
            .iter()
            .flatten()
            .any(|entry| entry.interest.key == interest.key)
        {
            return Err(EpollPublishError {
                error: EpollError::Duplicate,
                interest,
            });
        }
        let Some(slot) = self.entries.iter().position(Option::is_none) else {
            return Err(EpollPublishError {
                error: EpollError::Capacity,
                interest,
            });
        };
        let generation = match self.allocate_generation() {
            Ok(generation) => generation,
            Err(error) => return Err(EpollPublishError { error, interest }),
        };
        self.entries[slot] = Some(Entry {
            generation,
            interest,
            enabled: true,
            queued: false,
            in_delivery: None,
            ready: ReadyMask::EMPTY,
            during_delivery: ReadyMask::EMPTY,
        });
        Ok(EpollToken {
            epoll: self.id,
            slot,
            generation,
        })
    }

    /// Replaces one exact interest generation and returns the old subscription
    /// owner for lock-external cancellation.
    pub fn modify(
        &mut self,
        token: EpollToken,
        replacement: EpollInterest<U, S>,
    ) -> Result<(EpollToken, EpollInterest<U, S>), EpollPublishError<U, S>> {
        if let Err(error) = Self::validate_mode(replacement.mode) {
            return Err(EpollPublishError {
                error,
                interest: replacement,
            });
        }
        let slot = token.slot;
        let key_matches = self
            .entry(token)
            .is_ok_and(|entry| entry.interest.key == replacement.key);
        if !key_matches {
            return Err(EpollPublishError {
                error: EpollError::StaleToken,
                interest: replacement,
            });
        }
        let generation = match self.allocate_generation() {
            Ok(generation) => generation,
            Err(error) => {
                return Err(EpollPublishError {
                    error,
                    interest: replacement,
                });
            }
        };
        self.ready.remove(token);
        let Some(old) = self.entries[slot].take() else {
            return Err(EpollPublishError {
                error: EpollError::StaleToken,
                interest: replacement,
            });
        };
        self.entries[slot] = Some(Entry {
            generation,
            interest: replacement,
            enabled: true,
            queued: false,
            in_delivery: None,
            ready: ReadyMask::EMPTY,
            during_delivery: ReadyMask::EMPTY,
        });
        Ok((
            EpollToken {
                epoll: self.id,
                slot,
                generation,
            },
            old.interest,
        ))
    }

    /// Deletes one exact interest and returns retained ownership.
    pub fn remove(&mut self, token: EpollToken) -> Result<EpollInterest<U, S>, EpollError> {
        self.entry(token)?;
        self.ready.remove(token);
        self.entries[token.slot]
            .take()
            .map(|entry| entry.interest)
            .ok_or(EpollError::StaleToken)
    }

    /// Publishes bounded readiness from a source callback.
    pub fn notify(
        &mut self,
        token: EpollToken,
        ready: ReadyMask,
    ) -> Result<NotifyOutcome, EpollError> {
        let entry = self.entry_mut(token)?;
        if !entry.enabled {
            return Ok(NotifyOutcome::Ignored);
        }
        let deliverable = ready.deliverable(entry.interest.interest);
        if deliverable.is_empty() {
            return Ok(NotifyOutcome::Ignored);
        }
        if entry.in_delivery.is_some() {
            entry.during_delivery |= deliverable;
            return Ok(NotifyOutcome::Coalesced);
        }
        entry.ready |= deliverable;
        if entry.queued {
            return Ok(NotifyOutcome::Coalesced);
        }
        if let Err(error) = self.ready.push(token) {
            self.rescan_required = true;
            return Err(error);
        }
        self.entry_mut(token)?.queued = true;
        Ok(NotifyOutcome::Enqueued)
    }

    /// Starts one copyout transaction, skipping stale queue records defensively.
    pub fn begin_delivery(&mut self) -> Result<Option<ReadyEvent<U>>, EpollError>
    where
        U: Clone,
    {
        while let Some(token) = self.ready.peek() {
            let valid = self.entry(token).is_ok_and(|entry| entry.queued);
            if !valid {
                self.ready.pop();
                continue;
            }
            let serial = self.allocate_delivery()?;
            self.ready.pop();
            let entry = self.entry_mut(token)?;
            entry.queued = false;
            entry.in_delivery = Some(serial);
            let events = entry.ready;
            entry.ready = ReadyMask::EMPTY;
            return Ok(Some(ReadyEvent {
                delivery: DeliveryToken {
                    interest: token,
                    serial,
                    events,
                },
                events,
                user_data: entry.interest.user_data.clone(),
            }));
        }
        if self.rescan_required {
            Err(EpollError::RescanRequired)
        } else {
            Ok(None)
        }
    }

    /// Completes copyout, preserving faulted events and wakeups racing copy.
    pub fn finish_delivery(
        &mut self,
        delivery: DeliveryToken,
        outcome: DeliveryOutcome,
    ) -> Result<(), EpollError> {
        let token = delivery.interest;
        let should_enqueue = {
            let entry = self.entry_mut(token)?;
            if entry.in_delivery != Some(delivery.serial) {
                return Err(EpollError::StaleToken);
            }
            entry.in_delivery = None;
            match outcome {
                DeliveryOutcome::Fault => {
                    entry.ready |= delivery.events | entry.during_delivery;
                }
                DeliveryOutcome::Copied { still_ready } => {
                    entry.ready |= entry.during_delivery;
                    if !entry.interest.mode.edge {
                        entry.ready |= still_ready.deliverable(entry.interest.interest);
                    }
                    if entry.interest.mode.one_shot {
                        entry.enabled = false;
                    }
                }
            }
            entry.during_delivery = ReadyMask::EMPTY;
            entry.enabled && !entry.ready.is_empty() && !entry.queued
        };
        if should_enqueue {
            if let Err(error) = self.ready.push(token) {
                self.rescan_required = true;
                return Err(error);
            }
            self.entry_mut(token)?.queued = true;
        }
        Ok(())
    }

    /// Examines at most `max_entries` slots after an unexpected queue overflow.
    ///
    /// Normal operation admits one ready item per interest, so this is a
    /// defensive recovery seam rather than a periodic scan path. A zero budget
    /// performs no work and never clears a pending request.
    pub fn rescan_ready(&mut self, max_entries: usize) -> Result<RescanProgress, EpollError> {
        if !self.rescan_required {
            return Ok(RescanProgress {
                scanned: 0,
                enqueued: 0,
                complete: true,
            });
        }
        if self.entries.is_empty() || max_entries == 0 {
            let complete = self.entries.is_empty();
            if complete {
                self.rescan_required = false;
            }
            return Ok(RescanProgress {
                scanned: 0,
                enqueued: 0,
                complete,
            });
        }

        let target = max_entries.min(self.entries.len());
        let mut scanned = 0usize;
        let mut enqueued = 0usize;
        while scanned < target {
            let slot = self.rescan_cursor;
            self.rescan_cursor = (self.rescan_cursor + 1) % self.entries.len();
            scanned += 1;

            let Some(entry) = self.entries[slot].as_ref() else {
                continue;
            };
            if !entry.enabled
                || entry.ready.is_empty()
                || entry.queued
                || entry.in_delivery.is_some()
            {
                continue;
            }
            let token = EpollToken {
                epoll: self.id,
                slot,
                generation: entry.generation,
            };
            if let Err(error) = self.ready.push(token) {
                self.rescan_required = true;
                return Err(error);
            }
            self.entry_mut(token)?.queued = true;
            enqueued += 1;
        }

        let complete = scanned == self.entries.len();
        self.rescan_required = !complete;
        Ok(RescanProgress {
            scanned,
            enqueued,
            complete,
        })
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    struct Subscription(Arc<AtomicUsize>);

    impl Drop for Subscription {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn id(raw: u64) -> EpollId {
        EpollId::new(raw).unwrap()
    }

    fn ofd(raw: u64) -> OfdId {
        OfdId::new(raw).unwrap()
    }

    fn interest(
        key: EpollKey,
        mode: InterestMode,
        drops: &Arc<AtomicUsize>,
    ) -> EpollInterest<u64, Subscription> {
        EpollInterest::new(key, InterestMask::IN, mode, 99, Subscription(drops.clone()))
    }

    #[test]
    fn duplicate_and_capacity_failures_return_subscription_ownership() {
        let drops = Arc::new(AtomicUsize::new(0));
        let key = EpollKey {
            ofd: ofd(1),
            fd: FdNumber::new(3),
        };
        let mut core = EpollCore::try_new(id(1), 1).unwrap();
        core.add(interest(key, InterestMode::default(), &drops))
            .unwrap();
        let duplicate = core
            .add(interest(key, InterestMode::default(), &drops))
            .unwrap_err();
        assert_eq!(duplicate.error, EpollError::Duplicate);
        drop(duplicate.interest);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn exclusive_mode_is_rejected_until_a_cross_epoll_selector_is_supplied() {
        let drops = Arc::new(AtomicUsize::new(0));
        let key = EpollKey {
            ofd: ofd(1),
            fd: FdNumber::new(3),
        };
        let mut core = EpollCore::try_new(id(1), 1).unwrap();
        let error = core
            .add(interest(
                key,
                InterestMode {
                    exclusive: true,
                    ..InterestMode::default()
                },
                &drops,
            ))
            .unwrap_err();
        assert_eq!(error.error, EpollError::UnsupportedMode);
        drop(error.interest);
        assert!(core.is_empty());
    }

    #[test]
    fn level_delivery_requeues_only_after_post_copy_recheck() {
        let drops = Arc::new(AtomicUsize::new(0));
        let key = EpollKey {
            ofd: ofd(1),
            fd: FdNumber::new(3),
        };
        let mut core = EpollCore::try_new(id(1), 1).unwrap();
        let token = core
            .add(interest(key, InterestMode::default(), &drops))
            .unwrap();
        assert_eq!(
            core.notify(token, ReadyMask::IN),
            Ok(NotifyOutcome::Enqueued)
        );
        let event = core.begin_delivery().unwrap().unwrap();
        assert_eq!(event.events, ReadyMask::IN);
        core.finish_delivery(
            event.delivery,
            DeliveryOutcome::Copied {
                still_ready: ReadyMask::IN,
            },
        )
        .unwrap();
        assert!(core.begin_delivery().unwrap().is_some());
    }

    #[test]
    fn wake_during_edge_copyout_is_not_lost() {
        let drops = Arc::new(AtomicUsize::new(0));
        let key = EpollKey {
            ofd: ofd(1),
            fd: FdNumber::new(3),
        };
        let mut core = EpollCore::try_new(id(1), 1).unwrap();
        let token = core
            .add(interest(
                key,
                InterestMode {
                    edge: true,
                    ..InterestMode::default()
                },
                &drops,
            ))
            .unwrap();
        core.notify(token, ReadyMask::IN).unwrap();
        let event = core.begin_delivery().unwrap().unwrap();
        assert_eq!(
            core.notify(token, ReadyMask::IN),
            Ok(NotifyOutcome::Coalesced)
        );
        core.finish_delivery(
            event.delivery,
            DeliveryOutcome::Copied {
                still_ready: ReadyMask::EMPTY,
            },
        )
        .unwrap();
        assert!(core.begin_delivery().unwrap().is_some());
    }

    #[test]
    fn copyout_fault_requeues_the_same_event() {
        let drops = Arc::new(AtomicUsize::new(0));
        let key = EpollKey {
            ofd: ofd(1),
            fd: FdNumber::new(3),
        };
        let mut core = EpollCore::try_new(id(1), 1).unwrap();
        let token = core
            .add(interest(key, InterestMode::default(), &drops))
            .unwrap();

        core.notify(token, ReadyMask::IN).unwrap();
        let event = core.begin_delivery().unwrap().unwrap();
        assert_eq!(event.events, ReadyMask::IN);
        core.finish_delivery(event.delivery, DeliveryOutcome::Fault)
            .unwrap();

        let retried = core.begin_delivery().unwrap().unwrap();
        assert_eq!(retried.events, ReadyMask::IN);
    }

    #[test]
    fn copyout_fault_merges_a_concurrent_wake() {
        let drops = Arc::new(AtomicUsize::new(0));
        let key = EpollKey {
            ofd: ofd(1),
            fd: FdNumber::new(3),
        };
        let mut core = EpollCore::try_new(id(1), 1).unwrap();
        let token = core
            .add(EpollInterest::new(
                key,
                InterestMask::IN | InterestMask::OUT,
                InterestMode::default(),
                99,
                Subscription(drops.clone()),
            ))
            .unwrap();

        core.notify(token, ReadyMask::IN).unwrap();
        let event = core.begin_delivery().unwrap().unwrap();
        assert_eq!(
            core.notify(token, ReadyMask::OUT),
            Ok(NotifyOutcome::Coalesced)
        );
        core.finish_delivery(event.delivery, DeliveryOutcome::Fault)
            .unwrap();

        let retried = core.begin_delivery().unwrap().unwrap();
        assert_eq!(retried.events, ReadyMask::IN | ReadyMask::OUT);
    }

    #[test]
    fn remove_and_modify_invalidate_in_flight_delivery_tokens() {
        let drops = Arc::new(AtomicUsize::new(0));
        let key = EpollKey {
            ofd: ofd(1),
            fd: FdNumber::new(3),
        };
        let mut removed = EpollCore::try_new(id(1), 1).unwrap();
        let removed_token = removed
            .add(interest(key, InterestMode::default(), &drops))
            .unwrap();
        removed.notify(removed_token, ReadyMask::IN).unwrap();
        let old_delivery = removed.begin_delivery().unwrap().unwrap().delivery;
        drop(removed.remove(removed_token).unwrap());
        assert_eq!(
            removed.finish_delivery(old_delivery, DeliveryOutcome::Fault),
            Err(EpollError::StaleToken)
        );

        let mut modified = EpollCore::try_new(id(2), 1).unwrap();
        let modified_token = modified
            .add(interest(key, InterestMode::default(), &drops))
            .unwrap();
        modified.notify(modified_token, ReadyMask::IN).unwrap();
        let old_delivery = modified.begin_delivery().unwrap().unwrap().delivery;
        let (_new_token, old) = modified
            .modify(
                modified_token,
                interest(key, InterestMode::default(), &drops),
            )
            .unwrap();
        drop(old);
        assert_eq!(
            modified.finish_delivery(old_delivery, DeliveryOutcome::Fault),
            Err(EpollError::StaleToken)
        );
    }

    #[test]
    fn ready_queue_holds_at_most_one_item_per_interest() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mut core = EpollCore::try_new(id(1), 2).unwrap();
        let first = core
            .add(interest(
                EpollKey {
                    ofd: ofd(1),
                    fd: FdNumber::new(3),
                },
                InterestMode::default(),
                &drops,
            ))
            .unwrap();
        let second = core
            .add(interest(
                EpollKey {
                    ofd: ofd(2),
                    fd: FdNumber::new(4),
                },
                InterestMode::default(),
                &drops,
            ))
            .unwrap();

        assert_eq!(
            core.notify(first, ReadyMask::IN),
            Ok(NotifyOutcome::Enqueued)
        );
        assert_eq!(
            core.notify(first, ReadyMask::IN),
            Ok(NotifyOutcome::Coalesced)
        );
        assert_eq!(
            core.notify(second, ReadyMask::IN),
            Ok(NotifyOutcome::Enqueued)
        );
        assert_eq!(core.ready.len, 2);
    }

    #[test]
    fn zero_capacity_is_finite_and_rejects_publication() {
        let drops = Arc::new(AtomicUsize::new(0));
        let key = EpollKey {
            ofd: ofd(1),
            fd: FdNumber::new(3),
        };
        let mut core = EpollCore::try_new(id(1), 0).unwrap();
        assert_eq!(core.capacity(), 0);
        let error = core
            .add(interest(key, InterestMode::default(), &drops))
            .unwrap_err();
        assert_eq!(error.error, EpollError::Capacity);
        drop(error.interest);
    }

    #[test]
    fn delivery_generation_exhaustion_leaves_the_ready_item_queued() {
        let drops = Arc::new(AtomicUsize::new(0));
        let key = EpollKey {
            ofd: ofd(1),
            fd: FdNumber::new(3),
        };
        let mut core = EpollCore::try_new(id(1), 1).unwrap();
        let token = core
            .add(interest(key, InterestMode::default(), &drops))
            .unwrap();
        core.notify(token, ReadyMask::IN).unwrap();
        core.next_delivery = u64::MAX;

        assert_eq!(core.begin_delivery(), Err(EpollError::GenerationExhausted));
        assert_eq!(core.ready.len, 1);
        assert!(core.entry(token).unwrap().queued);
    }

    #[test]
    fn unexpected_queue_overflow_requests_only_an_explicit_bounded_rescan() {
        let drops = Arc::new(AtomicUsize::new(0));
        let key = EpollKey {
            ofd: ofd(1),
            fd: FdNumber::new(3),
        };
        let mut core = EpollCore::try_new(id(1), 1).unwrap();
        let token = core
            .add(interest(key, InterestMode::default(), &drops))
            .unwrap();
        let stale = EpollToken {
            epoll: id(99),
            slot: 0,
            generation: 1,
        };
        core.ready.push(stale).unwrap();

        assert_eq!(
            core.notify(token, ReadyMask::IN),
            Err(EpollError::ReadyQueueFull)
        );
        assert!(core.needs_rescan());
        assert_eq!(core.begin_delivery(), Err(EpollError::RescanRequired));
        assert_eq!(
            core.rescan_ready(0).unwrap(),
            RescanProgress {
                scanned: 0,
                enqueued: 0,
                complete: false,
            }
        );
        assert_eq!(
            core.rescan_ready(1).unwrap(),
            RescanProgress {
                scanned: 1,
                enqueued: 1,
                complete: true,
            }
        );
        assert_eq!(
            core.begin_delivery().unwrap().unwrap().events,
            ReadyMask::IN
        );
    }

    #[test]
    fn one_shot_disables_until_modify_and_old_tokens_go_stale() {
        let drops = Arc::new(AtomicUsize::new(0));
        let key = EpollKey {
            ofd: ofd(1),
            fd: FdNumber::new(3),
        };
        let mut core = EpollCore::try_new(id(1), 1).unwrap();
        let token = core
            .add(interest(
                key,
                InterestMode {
                    one_shot: true,
                    ..InterestMode::default()
                },
                &drops,
            ))
            .unwrap();
        core.notify(token, ReadyMask::IN).unwrap();
        let event = core.begin_delivery().unwrap().unwrap();
        core.finish_delivery(
            event.delivery,
            DeliveryOutcome::Copied {
                still_ready: ReadyMask::IN,
            },
        )
        .unwrap();
        assert_eq!(
            core.notify(token, ReadyMask::IN),
            Ok(NotifyOutcome::Ignored)
        );

        let (rearmed, old) = core
            .modify(token, interest(key, InterestMode::default(), &drops))
            .unwrap();
        drop(old);
        assert_eq!(
            core.notify(token, ReadyMask::IN),
            Err(EpollError::StaleToken)
        );
        assert_eq!(
            core.notify(rearmed, ReadyMask::IN),
            Ok(NotifyOutcome::Enqueued)
        );
    }
}
