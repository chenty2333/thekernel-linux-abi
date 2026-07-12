use crate::OfdId;

/// Shared open-file-description state which must be protected by the
/// consumer's sleepable OFD lock while an offset-dependent I/O is in flight.
///
/// Keeping this type separate from [`DescriptorEntry`](crate::DescriptorEntry)
/// makes `dup`/fork sharing and descriptor-local close-on-exec state explicit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenFileDescriptionState<A = ()> {
    id: OfdId,
    status_flags: u32,
    offset: u64,
    async_owner: A,
}

impl<A> OpenFileDescriptionState<A> {
    /// Creates unpublished OFD state with a caller-allocated identity.
    pub const fn new(id: OfdId, status_flags: u32, offset: u64, async_owner: A) -> Self {
        Self {
            id,
            status_flags,
            offset,
            async_owner,
        }
    }

    /// Returns the stable OFD identity.
    pub const fn id(&self) -> OfdId {
        self.id
    }

    /// Returns file status flags shared by all duplicated descriptors.
    pub const fn status_flags(&self) -> u32 {
        self.status_flags
    }

    /// Replaces status flags after the file adapter has accepted every change.
    pub fn commit_status_flags(&mut self, status_flags: u32) {
        self.status_flags = status_flags;
    }

    /// Returns the current shared file offset.
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    /// Moves the offset for an explicit seek after adapter validation.
    pub fn commit_seek(&mut self, offset: u64) {
        self.offset = offset;
    }

    /// Commits a short or complete sequential I/O result.
    ///
    /// `start` must be the offset retained while the consumer held its
    /// sleepable OFD lock across the underlying operation. A mismatch is an
    /// adapter serialization bug and is reported rather than silently
    /// overwriting a newer offset.
    pub fn commit_io(&mut self, start: u64, transferred: usize) -> Result<u64, OfdOffsetError> {
        if self.offset != start {
            return Err(OfdOffsetError::StaleStart {
                expected: self.offset,
                supplied: start,
            });
        }
        let transferred = u64::try_from(transferred).map_err(|_| OfdOffsetError::Overflow)?;
        let next = start
            .checked_add(transferred)
            .ok_or(OfdOffsetError::Overflow)?;
        self.offset = next;
        Ok(next)
    }

    /// Returns the async-owner state retained by the OFD.
    pub const fn async_owner(&self) -> &A {
        &self.async_owner
    }

    /// Mutates async-owner state while the consumer holds its OFD state lock.
    pub fn async_owner_mut(&mut self) -> &mut A {
        &mut self.async_owner
    }
}

/// Invalid shared-offset publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OfdOffsetError {
    /// The resulting offset would overflow `u64`.
    Overflow,
    /// The adapter did not retain serialization across an offset-based I/O.
    StaleStart {
        /// Offset currently stored by the OFD.
        expected: u64,
        /// Start offset supplied by the completing operation.
        supplied: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_io_advances_only_by_transferred_bytes() {
        let id = OfdId::new(1).unwrap();
        let mut state = OpenFileDescriptionState::new(id, 0, 10, ());
        assert_eq!(state.commit_io(10, 3), Ok(13));
        assert_eq!(state.offset(), 13);
    }

    #[test]
    fn stale_or_overflowing_completion_does_not_mutate_offset() {
        let id = OfdId::new(1).unwrap();
        let mut state = OpenFileDescriptionState::new(id, 0, u64::MAX, ());
        assert_eq!(
            state.commit_io(7, 1),
            Err(OfdOffsetError::StaleStart {
                expected: u64::MAX,
                supplied: 7,
            })
        );
        assert_eq!(state.commit_io(u64::MAX, 1), Err(OfdOffsetError::Overflow));
        assert_eq!(state.offset(), u64::MAX);
    }
}
