use core::num::NonZeroU64;

use crate::{MappingSnapshot, MmError};

/// Typed memory access that caused a page fault.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FaultAccess {
    /// Data read.
    Read,
    /// Data write.
    Write,
    /// Instruction fetch.
    Execute,
}

/// Page offset relative to the mapping's first page.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PageOffset(u64);

impl PageOffset {
    /// Builds an offset. Zero is the first page and is valid.
    pub const fn new(pages: u64) -> Self {
        Self(pages)
    }

    /// Relative page count.
    pub const fn get(self) -> u64 {
        self.0
    }
}

macro_rules! nonzero_fault_id {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(NonZeroU64);

        impl $name {
            /// Builds an identity, rejecting zero.
            pub const fn new(raw: u64) -> Result<Self, MmError> {
                match NonZeroU64::new(raw) {
                    Some(raw) => Ok(Self(raw)),
                    None => Err(MmError::InvalidIdentity),
                }
            }

            /// Integer identity.
            pub const fn get(self) -> u64 {
                self.0.get()
            }
        }
    };
}

nonzero_fault_id!(
    FaultHandlerId,
    "Consumer-owned identity of a fault handler port."
);
nonzero_fault_id!(
    FaultRequestId,
    "Consumer-owned identity of a queued fault request."
);

/// Stable mapping-generation key for one delegated fault page.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FaultKey {
    address_space: crate::AddressSpaceId,
    mapping: crate::MappingId,
    generation: crate::MappingGeneration,
    page: PageOffset,
    access: FaultAccess,
}

impl FaultKey {
    /// Builds a key from typed mapping facts.
    pub const fn new(
        address_space: crate::AddressSpaceId,
        mapping: crate::MappingId,
        generation: crate::MappingGeneration,
        page: PageOffset,
        access: FaultAccess,
    ) -> Self {
        Self {
            address_space,
            mapping,
            generation,
            page,
            access,
        }
    }

    /// Builds a key for a fault address contained by `snapshot`.
    pub fn from_address(
        snapshot: MappingSnapshot,
        address: usize,
        access: FaultAccess,
    ) -> Result<Self, MmError> {
        if !snapshot.range().user_range().contains_address(address) {
            return Err(MmError::RangeNotMapped);
        }
        Self::check_access(snapshot, access)?;
        let byte_offset = address
            .checked_sub(snapshot.range().start())
            .ok_or(MmError::Overflow)?;
        let page = byte_offset / snapshot.range().page_size().bytes();
        Ok(Self::new(
            snapshot.address_space(),
            snapshot.mapping(),
            snapshot.generation(),
            PageOffset::new(u64::try_from(page).map_err(|_| MmError::Overflow)?),
            access,
        ))
    }

    /// Address-space identity.
    pub const fn address_space(self) -> crate::AddressSpaceId {
        self.address_space
    }

    /// Mapping identity.
    pub const fn mapping(self) -> crate::MappingId {
        self.mapping
    }

    /// Mapping generation frozen at fault admission.
    pub const fn generation(self) -> crate::MappingGeneration {
        self.generation
    }

    /// Relative page offset.
    pub const fn page(self) -> PageOffset {
        self.page
    }

    /// Fault access.
    pub const fn access(self) -> FaultAccess {
        self.access
    }

    /// Revalidates identity, generation, page coverage, and access.
    pub fn revalidate(self, current: MappingSnapshot) -> Result<(), MmError> {
        if self.address_space != current.address_space()
            || self.mapping != current.mapping()
            || self.generation != current.generation()
        {
            return Err(MmError::StaleGeneration);
        }
        if self.page.get()
            >= u64::try_from(current.range().page_count()).map_err(|_| MmError::Overflow)?
        {
            return Err(MmError::RangeNotMapped);
        }
        Self::check_access(current, self.access)
    }

    fn check_access(snapshot: MappingSnapshot, access: FaultAccess) -> Result<(), MmError> {
        let allowed = match access {
            FaultAccess::Read => snapshot.access().readable(),
            FaultAccess::Write => snapshot.access().writable(),
            FaultAccess::Execute => snapshot.access().executable(),
        };
        if !allowed {
            return Err(MmError::AccessDenied);
        }
        Ok(())
    }
}

/// Linux-visible fault classification before a lower mechanism resolves it.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum FaultType {
    /// Missing anonymous/file page.
    Missing,
    /// Minor fault with backing already resident elsewhere.
    Minor,
    /// Write-protect event.
    WriteProtect,
    /// Private COW break.
    Cow,
    /// File-backed fault not delegated to userspace.
    File,
}

/// Immutable request passed to a consumer-owned bounded broker mechanism.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultRequest {
    key: FaultKey,
    handler: FaultHandlerId,
    fault_type: FaultType,
}

impl FaultRequest {
    /// Builds a typed fault request.
    pub const fn new(key: FaultKey, handler: FaultHandlerId, fault_type: FaultType) -> Self {
        Self {
            key,
            handler,
            fault_type,
        }
    }

    /// Stable generation key.
    pub const fn key(self) -> FaultKey {
        self.key
    }

    /// Target lower handler identity.
    pub const fn handler(self) -> FaultHandlerId {
        self.handler
    }

    /// Fault class.
    pub const fn fault_type(self) -> FaultType {
        self.fault_type
    }
}

/// Stable typed failure disposition.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum FaultFailure {
    /// Linux-visible protection/address failure, normally mapped to SIGSEGV.
    Segmentation,
    /// Backing-object failure, normally mapped to SIGBUS.
    Bus,
    /// Memory pressure prevented resolution.
    OutOfMemory,
    /// Backing I/O failed.
    Io,
    /// Mapping changed and the caller may retry within a finite budget.
    Retry,
}

/// Typed resolver result; it does not contain a frame or page-table object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FaultDisposition {
    /// Consumer supplies an initialized mechanism-owned page.
    Supply,
    /// Consumer requests a zero-filled page.
    ZeroFill,
    /// Existing backing may continue without supplying a new page.
    Continue,
    /// Consumer requests a write-protection state change.
    WriteProtect,
    /// Typed failure.
    Failure(FaultFailure),
    /// Request was cancelled by its waiter or mapping lifecycle.
    Cancelled,
    /// Handler detached or closed.
    HandlerDetached,
}

/// Explicit finite queue limits consumed by admission policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultCapacity {
    per_address_space: u32,
    per_handler: u32,
    global: u32,
}

impl FaultCapacity {
    /// Builds nonzero finite limits.
    pub const fn new(
        per_address_space: u32,
        per_handler: u32,
        global: u32,
    ) -> Result<Self, MmError> {
        if per_address_space == 0 || per_handler == 0 || global == 0 {
            return Err(MmError::ZeroLength);
        }
        if per_address_space == u32::MAX || per_handler == u32::MAX || global == u32::MAX {
            return Err(MmError::UnboundedLimit);
        }
        Ok(Self {
            per_address_space,
            per_handler,
            global,
        })
    }

    /// Per-address-space request limit.
    pub const fn per_address_space(self) -> u32 {
        self.per_address_space
    }

    /// Per-handler request limit.
    pub const fn per_handler(self) -> u32 {
        self.per_handler
    }

    /// Global request limit.
    pub const fn global(self) -> u32 {
        self.global
    }
}

/// Consumer-supplied current queue load before admitting one request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultLoad {
    address_space: u32,
    handler: u32,
    global: u32,
}

impl FaultLoad {
    /// Builds exact current counts.
    pub const fn new(address_space: u32, handler: u32, global: u32) -> Self {
        Self {
            address_space,
            handler,
            global,
        }
    }

    /// Current address-space count.
    pub const fn address_space(self) -> u32 {
        self.address_space
    }

    /// Current handler count.
    pub const fn handler(self) -> u32 {
        self.handler
    }

    /// Current global count.
    pub const fn global(self) -> u32 {
        self.global
    }
}

/// Consumer-owned broker lifecycle observed by policy admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultLifecycleState {
    /// Requests may be admitted.
    Open,
    /// Existing requests drain, but new requests are rejected.
    Closing,
    /// Handler has detached and requests must fail/wake.
    Detached,
    /// Broker/port is fully closed.
    Closed,
}

/// Stateless admission policy for a typed fault request.
pub struct FaultAdmission;

impl FaultAdmission {
    /// Revalidates the mapping, then checks lifecycle and all three finite
    /// counts before a task can sleep.
    pub fn check(
        request: FaultRequest,
        current: MappingSnapshot,
        capacity: FaultCapacity,
        load: FaultLoad,
        lifecycle: FaultLifecycleState,
    ) -> Result<FaultAdmissionPermit, MmError> {
        match lifecycle {
            FaultLifecycleState::Open => {}
            FaultLifecycleState::Closing => return Err(MmError::Closing),
            FaultLifecycleState::Detached => return Err(MmError::TearingDown),
            FaultLifecycleState::Closed => return Err(MmError::Closed),
        }
        request.key.revalidate(current)?;
        if load.address_space >= capacity.per_address_space
            || load.handler >= capacity.per_handler
            || load.global >= capacity.global
        {
            return Err(MmError::QuotaExceeded);
        }
        Ok(FaultAdmissionPermit { request })
    }
}

/// Opaque proof that lifecycle and finite queue limits admitted a request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use = "an admitted fault must be submitted or cancelled by the adapter"]
pub struct FaultAdmissionPermit {
    request: FaultRequest,
}

impl FaultAdmissionPermit {
    /// Admitted request.
    pub const fn request(self) -> FaultRequest {
        self.request
    }
}

/// Opaque proof that a reply still targets the exact mapping generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use = "a revalidated fault completion must be committed through the lower port"]
pub struct FaultCompletionPermit {
    request: FaultRequest,
    disposition: FaultDisposition,
}

impl FaultCompletionPermit {
    /// Revalidated request.
    pub const fn request(self) -> FaultRequest {
        self.request
    }

    /// Typed resolver disposition.
    pub const fn disposition(self) -> FaultDisposition {
        self.disposition
    }
}

/// Rejects a late reply to a replaced mapping before mechanism publication.
pub fn validate_fault_completion(
    request: FaultRequest,
    current: MappingSnapshot,
    disposition: FaultDisposition,
) -> Result<FaultCompletionPermit, MmError> {
    request.key.revalidate(current)?;
    Ok(FaultCompletionPermit {
        request,
        disposition,
    })
}

/// Port implemented by a lower generic bounded fault broker.
///
/// The trait deliberately leaves storage, locks, waiter ownership, readiness,
/// coalescing, cancellation, and wakeup mechanics to Layer 1. Linux MM policy
/// passes only typed admission/completion values across this seam.
pub trait FaultPort {
    /// Lower broker ticket/handle type.
    type Ticket;
    /// Lower mechanism error type.
    type Error;

    /// Publishes one previously admitted request.
    fn submit(&mut self, permit: FaultAdmissionPermit) -> Result<Self::Ticket, Self::Error>;

    /// Completes one lower ticket after generation revalidation.
    fn complete(
        &mut self,
        ticket: Self::Ticket,
        permit: FaultCompletionPermit,
    ) -> Result<(), Self::Error>;

    /// Cancels one independently owned waiter/request ticket.
    fn cancel(&mut self, ticket: Self::Ticket) -> Result<(), Self::Error>;

    /// Detaches one handler and makes lower storage wake/cancel its requests.
    fn detach(&mut self, handler: FaultHandlerId) -> Result<(), Self::Error>;
}
