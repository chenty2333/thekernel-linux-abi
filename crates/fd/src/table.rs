#[cfg(not(feature = "alloc"))]
use core::array;

use crate::{DescriptorFlags, FdNumber, FdTableId};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Opaque generation-tagged identity for one published descriptor slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DescriptorToken {
    table: FdTableId,
    fd: FdNumber,
    generation: u64,
}

impl DescriptorToken {
    /// Returns the owning table identity.
    pub const fn table(self) -> FdTableId {
        self.table
    }

    /// Returns the numeric descriptor.
    pub const fn fd(self) -> FdNumber {
        self.fd
    }

    /// Returns the opaque generation for diagnostics and adapter indexes.
    pub const fn generation(self) -> u64 {
        self.generation
    }
}

/// Opaque unpublished reservation for one numeric descriptor.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "a descriptor reservation must be published or explicitly cancelled"]
pub struct ReservationToken {
    table: FdTableId,
    fd: FdNumber,
    generation: u64,
}

impl ReservationToken {
    /// Returns the reserved number, which remains invisible to lookup.
    pub const fn fd(&self) -> FdNumber {
        self.fd
    }

    /// Returns the owning table identity.
    pub const fn table(&self) -> FdTableId {
        self.table
    }
}

/// One descriptor-local entry pointing at a shared OFD handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescriptorEntry<D> {
    description: D,
    flags: DescriptorFlags,
}

impl<D> DescriptorEntry<D> {
    /// Creates descriptor-local state around a shared OFD handle.
    pub const fn new(description: D, flags: DescriptorFlags) -> Self {
        Self { description, flags }
    }

    /// Returns the shared OFD handle.
    pub const fn description(&self) -> &D {
        &self.description
    }

    /// Returns descriptor-local flags.
    pub const fn flags(&self) -> DescriptorFlags {
        self.flags
    }

    /// Mutates descriptor-local flags without changing OFD state.
    pub fn set_flags(&mut self, flags: DescriptorFlags) {
        self.flags = flags;
    }

    /// Decomposes the entry for lock-external destruction or handoff.
    pub fn into_parts(self) -> (D, DescriptorFlags) {
        (self.description, self.flags)
    }
}

enum Slot<D> {
    Vacant,
    Reserved {
        generation: u64,
        flags: DescriptorFlags,
    },
    Occupied {
        generation: u64,
        entry: DescriptorEntry<D>,
    },
}

/// Bounded caller-owned Linux files-table state.
///
/// The consumer supplies external synchronization and chooses `N`. Every
/// user-visible mutation uses `&mut self`; callbacks, destructors, and
/// allocation therefore never run under a crate-owned hidden lock.
pub struct FdTable<D, const N: usize> {
    id: FdTableId,
    next_generation: u64,
    #[cfg(not(feature = "alloc"))]
    slots: [Slot<D>; N],
    #[cfg(feature = "alloc")]
    slots: Vec<Slot<D>>,
}

/// Descriptor-table operation failure before errno mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FdTableError {
    /// The numeric descriptor is absent or outside this table.
    BadDescriptor,
    /// No slot exists in the requested bounded range.
    TableFull,
    /// A dup/replace target is reserved by another publication transaction.
    Busy,
    /// The token belongs to another table or an older slot generation.
    StaleToken,
    /// No future unique generation can be allocated.
    GenerationExhausted,
    /// Caller-provided close storage cannot hold the whole transaction.
    InsufficientCloseStorage,
    /// Fallible owned storage could not be reserved.
    NoMemory,
    /// The requested capacity was effectively unbounded or could not be
    /// represented by the crate's Linux descriptor-number type.
    Unbounded,
}

/// Publication failure which returns ownership of the unpublished OFD handle.
#[derive(Debug)]
pub struct PublishError<D> {
    /// Typed table error.
    pub error: FdTableError,
    /// Description handle that was never published.
    pub description: D,
}

impl<D, const N: usize> FdTable<D, N> {
    /// Fallibly creates an empty table with an explicit stable identity.
    ///
    /// With the `alloc` feature, the complete slot array is reserved and
    /// initialized directly in heap-backed storage. The table value itself
    /// therefore stays small even for a kernel-sized descriptor ceiling, and
    /// moving it into an `Arc` or returning it from `fork_copy` does not create
    /// an `N * size_of::<Slot<D>>()` stack temporary. No later table mutation
    /// grows this storage.
    ///
    /// Without `alloc`, the caller deliberately selects inline fixed storage;
    /// construction remains fallible in the public contract so consumers do
    /// not need a feature-dependent call site.
    pub fn try_new(id: FdTableId) -> Result<Self, FdTableError> {
        if N == usize::MAX
            || u64::try_from(N)
                .ok()
                .is_none_or(|capacity| capacity > u64::from(u32::MAX) + 1)
        {
            return Err(FdTableError::Unbounded);
        }
        #[cfg(feature = "alloc")]
        let slots = {
            let mut slots = Vec::new();
            slots
                .try_reserve_exact(N)
                .map_err(|_| FdTableError::NoMemory)?;
            slots.resize_with(N, || Slot::Vacant);
            slots
        };
        #[cfg(not(feature = "alloc"))]
        let slots = array::from_fn(|_| Slot::Vacant);

        Ok(Self {
            id,
            next_generation: 1,
            slots,
        })
    }

    /// Returns the table identity used in every token.
    pub const fn id(&self) -> FdTableId {
        self.id
    }

    /// Returns the compile-time descriptor ceiling.
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Returns the number of visible published descriptors.
    pub fn len(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| matches!(slot, Slot::Occupied { .. }))
            .count()
    }

    /// Returns whether no descriptor is visible.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterates visible descriptors in ascending numeric order.
    ///
    /// Reserved slots remain unpublished and are intentionally skipped. The
    /// iterator borrows the table, so the embedding kernel retains its chosen
    /// external read lock for the duration without exposing crate-owned
    /// synchronization.
    pub fn iter(&self) -> impl Iterator<Item = (FdNumber, &DescriptorEntry<D>)> {
        self.slots.iter().enumerate().filter_map(|(fd, slot)| {
            let Slot::Occupied { entry, .. } = slot else {
                return None;
            };
            let fd = u32::try_from(fd).ok()?;
            Some((FdNumber::new(fd), entry))
        })
    }

    fn allocate_generation(&mut self) -> Result<u64, FdTableError> {
        let generation = self.next_generation;
        self.next_generation = generation
            .checked_add(1)
            .ok_or(FdTableError::GenerationExhausted)?;
        Ok(generation)
    }

    fn bounded_range(minimum: usize, limit: usize) -> core::ops::Range<usize> {
        minimum.min(N)..limit.min(N)
    }

    /// Reserves the lowest free number in `[minimum, limit)`.
    ///
    /// Reserved slots are excluded from concurrent allocation but invisible to
    /// lookup. The caller must publish or cancel the returned token on every
    /// path; adapters normally wrap it in an RAII rollback owner.
    pub fn reserve(
        &mut self,
        minimum: usize,
        limit: usize,
        flags: DescriptorFlags,
    ) -> Result<ReservationToken, FdTableError> {
        let fd = Self::bounded_range(minimum, limit)
            .find(|&fd| matches!(self.slots[fd], Slot::Vacant))
            .ok_or(FdTableError::TableFull)?;
        let generation = self.allocate_generation()?;
        self.slots[fd] = Slot::Reserved { generation, flags };
        Ok(ReservationToken {
            table: self.id,
            fd: FdNumber::new(fd as u32),
            generation,
        })
    }

    /// Cancels the exact unpublished reservation.
    pub fn cancel_reservation(
        &mut self,
        reservation: ReservationToken,
    ) -> Result<(), FdTableError> {
        let fd = self.validate_reservation(&reservation)?;
        self.slots[fd] = Slot::Vacant;
        Ok(())
    }

    fn validate_reservation(&self, reservation: &ReservationToken) -> Result<usize, FdTableError> {
        if reservation.table != self.id || reservation.fd.index() >= N {
            return Err(FdTableError::StaleToken);
        }
        let fd = reservation.fd.index();
        if matches!(
            self.slots[fd],
            Slot::Reserved { generation, .. } if generation == reservation.generation
        ) {
            Ok(fd)
        } else {
            Err(FdTableError::StaleToken)
        }
    }

    /// Publishes a completely constructed OFD handle into its reserved slot.
    pub fn publish(
        &mut self,
        reservation: ReservationToken,
        description: D,
    ) -> Result<DescriptorToken, PublishError<D>> {
        let fd = match self.validate_reservation(&reservation) {
            Ok(fd) => fd,
            Err(error) => return Err(PublishError { error, description }),
        };
        let flags = match self.slots[fd] {
            Slot::Reserved { flags, .. } => flags,
            _ => {
                return Err(PublishError {
                    error: FdTableError::StaleToken,
                    description,
                });
            }
        };
        let token = DescriptorToken {
            table: self.id,
            fd: reservation.fd,
            generation: reservation.generation,
        };
        self.slots[fd] = Slot::Occupied {
            generation: reservation.generation,
            entry: DescriptorEntry::new(description, flags),
        };
        Ok(token)
    }

    /// Looks up a visible descriptor by number.
    pub fn get(&self, fd: FdNumber) -> Result<&DescriptorEntry<D>, FdTableError> {
        match self.slots.get(fd.index()) {
            Some(Slot::Occupied { entry, .. }) => Ok(entry),
            _ => Err(FdTableError::BadDescriptor),
        }
    }

    /// Mutably looks up descriptor-local state.
    pub fn get_mut(&mut self, fd: FdNumber) -> Result<&mut DescriptorEntry<D>, FdTableError> {
        match self.slots.get_mut(fd.index()) {
            Some(Slot::Occupied { entry, .. }) => Ok(entry),
            _ => Err(FdTableError::BadDescriptor),
        }
    }

    /// Returns a generation token for the currently visible descriptor.
    pub fn token(&self, fd: FdNumber) -> Result<DescriptorToken, FdTableError> {
        match self.slots.get(fd.index()) {
            Some(Slot::Occupied { generation, .. }) => Ok(DescriptorToken {
                table: self.id,
                fd,
                generation: *generation,
            }),
            _ => Err(FdTableError::BadDescriptor),
        }
    }

    /// Revalidates a previously observed descriptor without returning a newer
    /// object that reused the same number.
    pub fn get_token(&self, token: DescriptorToken) -> Result<&DescriptorEntry<D>, FdTableError> {
        if token.table != self.id || token.fd.index() >= N {
            return Err(FdTableError::StaleToken);
        }
        match &self.slots[token.fd.index()] {
            Slot::Occupied { generation, entry } if *generation == token.generation => Ok(entry),
            _ => Err(FdTableError::StaleToken),
        }
    }

    /// Removes a visible descriptor and returns it for lock-external cleanup.
    pub fn close(&mut self, fd: FdNumber) -> Result<DescriptorEntry<D>, FdTableError> {
        let slot = self
            .slots
            .get_mut(fd.index())
            .ok_or(FdTableError::BadDescriptor)?;
        match core::mem::replace(slot, Slot::Vacant) {
            Slot::Occupied { entry, .. } => Ok(entry),
            other => {
                *slot = other;
                Err(FdTableError::BadDescriptor)
            }
        }
    }

    /// Closes only the exact generation previously observed.
    pub fn close_token(
        &mut self,
        token: DescriptorToken,
    ) -> Result<DescriptorEntry<D>, FdTableError> {
        self.get_token(token)?;
        self.close(token.fd)
    }

    /// Sets descriptor-local close-on-exec state.
    pub fn set_close_on_exec(&mut self, fd: FdNumber, enabled: bool) -> Result<(), FdTableError> {
        self.get_mut(fd)?
            .flags
            .set(DescriptorFlags::CLOSE_ON_EXEC, enabled);
        Ok(())
    }

    /// Marks every visible descriptor in an inclusive range close-on-exec.
    pub fn mark_close_on_exec_range(&mut self, first: FdNumber, last: FdNumber) {
        if N == 0 || last < first || first.index() >= N {
            return;
        }
        let end = last.index().min(N.saturating_sub(1));
        for fd in first.index().min(N)..=end {
            if let Slot::Occupied { entry, .. } = &mut self.slots[fd] {
                entry.flags.set(DescriptorFlags::CLOSE_ON_EXEC, true);
            }
        }
    }
}

impl<D: Clone, const N: usize> FdTable<D, N> {
    /// Duplicates a descriptor into the lowest free number in a bounded range.
    pub fn duplicate(
        &mut self,
        source: FdNumber,
        minimum: usize,
        limit: usize,
        flags: DescriptorFlags,
    ) -> Result<DescriptorToken, FdTableError> {
        let description = self.get(source)?.description.clone();
        let reservation = self.reserve(minimum, limit, flags)?;
        self.publish(reservation, description)
            .map_err(|error| error.error)
    }

    /// Atomically implements the table part of `dup2`/`dup3` replacement.
    ///
    /// The adapter handles the `old == new` difference between the two
    /// syscalls. A reserved target reports `Busy` and is never stolen.
    pub fn duplicate_replace(
        &mut self,
        source: FdNumber,
        target: FdNumber,
        flags: DescriptorFlags,
    ) -> Result<(DescriptorToken, Option<DescriptorEntry<D>>), FdTableError> {
        if source == target {
            return Ok((self.token(source)?, None));
        }
        if target.index() >= N {
            return Err(FdTableError::BadDescriptor);
        }
        if matches!(self.slots[target.index()], Slot::Reserved { .. }) {
            return Err(FdTableError::Busy);
        }
        let description = self.get(source)?.description.clone();
        let generation = self.allocate_generation()?;
        let replacement = Slot::Occupied {
            generation,
            entry: DescriptorEntry::new(description, flags),
        };
        let previous = core::mem::replace(&mut self.slots[target.index()], replacement);
        let removed = match previous {
            Slot::Vacant => None,
            Slot::Occupied { entry, .. } => Some(entry),
            Slot::Reserved { .. } => return Err(FdTableError::Busy),
        };
        Ok((
            DescriptorToken {
                table: self.id,
                fd: target,
                generation,
            },
            removed,
        ))
    }

    /// Copies visible descriptor entries for fork while sharing every OFD
    /// handle. Unpublished reservations are intentionally not inherited.
    pub fn fork_copy(&self, new_id: FdTableId) -> Result<Self, FdTableError> {
        let mut copy = Self::try_new(new_id)?;
        for (fd, slot) in self.slots.iter().enumerate() {
            if let Slot::Occupied { entry, .. } = slot {
                let generation = copy.allocate_generation()?;
                copy.slots[fd] = Slot::Occupied {
                    generation,
                    entry: entry.clone(),
                };
            }
        }
        Ok(copy)
    }
}

/// Preallocated owner for descriptors detached by one range/exec transaction.
#[cfg(feature = "alloc")]
pub struct CloseBatch<D> {
    entries: Vec<DescriptorEntry<D>>,
    limit: usize,
}

#[cfg(feature = "alloc")]
impl<D> CloseBatch<D> {
    /// Fallibly reserves exact transaction storage before table mutation.
    pub fn try_with_capacity(capacity: usize) -> Result<Self, FdTableError> {
        if capacity == usize::MAX {
            return Err(FdTableError::Unbounded);
        }
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(capacity)
            .map_err(|_| FdTableError::NoMemory)?;
        Ok(Self {
            entries,
            limit: capacity,
        })
    }

    /// Returns detached descriptors for cleanup after releasing table locks.
    pub fn entries(&self) -> &[DescriptorEntry<D>] {
        &self.entries
    }

    /// Consumes the batch and returns all detached ownership.
    pub fn into_entries(self) -> Vec<DescriptorEntry<D>> {
        self.entries
    }

    fn remaining(&self) -> usize {
        self.limit.saturating_sub(self.entries.len())
    }

    fn push(&mut self, entry: DescriptorEntry<D>) {
        debug_assert!(self.entries.len() < self.limit);
        self.entries.push(entry);
    }
}

#[cfg(feature = "alloc")]
impl<D, const N: usize> FdTable<D, N> {
    fn count_matching(
        &self,
        mut predicate: impl FnMut(usize, &DescriptorEntry<D>) -> bool,
    ) -> usize {
        self.slots
            .iter()
            .enumerate()
            .filter(|(fd, slot)| match slot {
                Slot::Occupied { entry, .. } => predicate(*fd, entry),
                _ => false,
            })
            .count()
    }

    fn detach_matching(
        &mut self,
        batch: &mut CloseBatch<D>,
        mut predicate: impl FnMut(usize, &DescriptorEntry<D>) -> bool,
    ) -> Result<(), FdTableError> {
        let count = self.count_matching(|fd, entry| predicate(fd, entry));
        if count > batch.remaining() {
            return Err(FdTableError::InsufficientCloseStorage);
        }
        for fd in 0..N {
            let should_remove = match &self.slots[fd] {
                Slot::Occupied { entry, .. } => predicate(fd, entry),
                _ => false,
            };
            if should_remove {
                let previous = core::mem::replace(&mut self.slots[fd], Slot::Vacant);
                if let Slot::Occupied { entry, .. } = previous {
                    batch.push(entry);
                }
            }
        }
        Ok(())
    }

    /// Detaches an inclusive numeric range after proving batch capacity.
    pub fn close_range(
        &mut self,
        first: FdNumber,
        last: FdNumber,
        batch: &mut CloseBatch<D>,
    ) -> Result<(), FdTableError> {
        if last < first {
            return Err(FdTableError::BadDescriptor);
        }
        self.detach_matching(batch, |fd, _| fd >= first.index() && fd <= last.index())
    }

    /// Transactionally detaches every close-on-exec descriptor.
    pub fn close_on_exec(&mut self, batch: &mut CloseBatch<D>) -> Result<(), FdTableError> {
        self.detach_matching(batch, |_, entry| {
            entry.flags.contains(DescriptorFlags::CLOSE_ON_EXEC)
        })
    }

    /// Transactionally detaches every visible descriptor.
    pub fn close_all(&mut self, batch: &mut CloseBatch<D>) -> Result<(), FdTableError> {
        self.detach_matching(batch, |_, _| true)
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use super::*;

    fn table_id(raw: u64) -> FdTableId {
        FdTableId::new(raw).unwrap()
    }

    #[test]
    fn reservation_is_invisible_and_publish_is_generation_tagged() {
        let mut table = FdTable::<Arc<u32>, 4>::try_new(table_id(1)).unwrap();
        let reservation = table.reserve(0, 4, DescriptorFlags::EMPTY).unwrap();
        assert_eq!(reservation.fd(), FdNumber::new(0));
        assert_eq!(
            table.get(FdNumber::new(0)),
            Err(FdTableError::BadDescriptor)
        );
        let token = table.publish(reservation, Arc::new(7)).unwrap();
        assert_eq!(**table.get_token(token).unwrap().description(), 7);
    }

    #[test]
    fn alloc_table_handle_stays_small_for_a_kernel_sized_ceiling() {
        assert!(core::mem::size_of::<FdTable<Arc<u32>, 1024>>() <= 64);
        let table = FdTable::<Arc<u32>, 1024>::try_new(table_id(1)).unwrap();
        assert_eq!(table.capacity(), 1024);
    }

    #[test]
    fn iterator_is_ordered_and_skips_unpublished_reservations() {
        let mut table = FdTable::<Arc<u32>, 8>::try_new(table_id(1)).unwrap();
        let unpublished = table.reserve(0, 8, DescriptorFlags::EMPTY).unwrap();
        let high = table.reserve(7, 8, DescriptorFlags::EMPTY).unwrap();
        table.publish(high, Arc::new(7)).unwrap();
        let middle = table.reserve(3, 7, DescriptorFlags::EMPTY).unwrap();
        table.publish(middle, Arc::new(3)).unwrap();

        let visible = table
            .iter()
            .map(|(fd, entry)| (fd.get(), **entry.description()))
            .collect::<alloc::vec::Vec<_>>();
        assert_eq!(visible, alloc::vec![(3, 3), (7, 7)]);
        table.cancel_reservation(unpublished).unwrap();
    }

    #[test]
    fn effectively_unbounded_table_is_rejected_before_allocation() {
        assert!(matches!(
            FdTable::<Arc<u32>, { usize::MAX }>::try_new(table_id(1)),
            Err(FdTableError::Unbounded)
        ));
    }

    #[test]
    fn foreign_publication_returns_unpublished_ownership() {
        let mut one = FdTable::<Arc<u32>, 2>::try_new(table_id(1)).unwrap();
        let mut two = FdTable::<Arc<u32>, 2>::try_new(table_id(2)).unwrap();
        let reservation = one.reserve(0, 2, DescriptorFlags::EMPTY).unwrap();
        let description = Arc::new(9);
        let error = two.publish(reservation, description.clone()).unwrap_err();
        assert_eq!(error.error, FdTableError::StaleToken);
        assert!(Arc::ptr_eq(&error.description, &description));
    }

    #[test]
    fn stale_token_cannot_close_a_reused_number() {
        let mut table = FdTable::<Arc<u32>, 1>::try_new(table_id(1)).unwrap();
        let first = table.reserve(0, 1, DescriptorFlags::EMPTY).unwrap();
        let first = table.publish(first, Arc::new(1)).unwrap();
        drop(table.close_token(first).unwrap());
        let second = table.reserve(0, 1, DescriptorFlags::EMPTY).unwrap();
        let second = table.publish(second, Arc::new(2)).unwrap();
        assert_eq!(table.close_token(first), Err(FdTableError::StaleToken));
        assert_eq!(**table.get_token(second).unwrap().description(), 2);
    }

    #[test]
    fn dup_and_fork_share_ofd_handle_but_copy_descriptor_flags() {
        let mut table = FdTable::<Arc<u32>, 4>::try_new(table_id(1)).unwrap();
        let source = table.reserve(0, 4, DescriptorFlags::EMPTY).unwrap();
        let source = table.publish(source, Arc::new(3)).unwrap();
        let duplicate = table
            .duplicate(source.fd(), 0, 4, DescriptorFlags::CLOSE_ON_EXEC)
            .unwrap();
        assert!(Arc::ptr_eq(
            table.get_token(source).unwrap().description(),
            table.get_token(duplicate).unwrap().description(),
        ));
        assert_ne!(
            table.get_token(source).unwrap().flags(),
            table.get_token(duplicate).unwrap().flags(),
        );

        let fork = table.fork_copy(table_id(2)).unwrap();
        assert_eq!(fork.iter().count(), 2);
        assert!(Arc::ptr_eq(
            table.get(source.fd()).unwrap().description(),
            fork.get(source.fd()).unwrap().description(),
        ));
    }

    #[test]
    fn close_batch_capacity_failure_is_atomic() {
        let mut table = FdTable::<Arc<u32>, 4>::try_new(table_id(1)).unwrap();
        for _ in 0..2 {
            let reservation = table.reserve(0, 4, DescriptorFlags::CLOSE_ON_EXEC).unwrap();
            table.publish(reservation, Arc::new(1)).unwrap();
        }
        let mut too_small = CloseBatch::try_with_capacity(1).unwrap();
        assert_eq!(
            table.close_on_exec(&mut too_small),
            Err(FdTableError::InsufficientCloseStorage)
        );
        assert_eq!(table.len(), 2);

        let mut exact = CloseBatch::try_with_capacity(2).unwrap();
        table.close_on_exec(&mut exact).unwrap();
        assert_eq!(exact.entries().len(), 2);
        assert!(table.is_empty());
    }

    #[test]
    fn close_batch_rejects_an_effectively_unbounded_request() {
        assert!(matches!(
            CloseBatch::<Arc<u32>>::try_with_capacity(usize::MAX),
            Err(FdTableError::Unbounded)
        ));
    }

    #[test]
    fn dup_replace_never_steals_a_reserved_target() {
        let mut table = FdTable::<Arc<u32>, 2>::try_new(table_id(1)).unwrap();
        let source = table.reserve(0, 1, DescriptorFlags::EMPTY).unwrap();
        let source = table.publish(source, Arc::new(1)).unwrap();
        let target = table.reserve(1, 2, DescriptorFlags::EMPTY).unwrap();
        assert_eq!(
            table.duplicate_replace(source.fd(), target.fd(), DescriptorFlags::EMPTY),
            Err(FdTableError::Busy)
        );
        table.cancel_reservation(target).unwrap();
    }
}
