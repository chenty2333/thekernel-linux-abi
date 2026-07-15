#![no_std]
#![forbid(unsafe_code)]

//! Pure Linux-visible memory-management policy contracts.
//!
//! This crate owns checked address ranges, mapping generations, bounded pin
//! and fault lifecycles, and arithmetic-only mapping planners. It deliberately
//! does not own page tables, frames, files, tasks, locks, raw user memory, or
//! architecture-specific addresses. Consumers freeze those mechanism facts,
//! call this crate, and execute the resulting plan in their own transaction.

mod error;
mod fault;
mod identity;
mod mapping;
mod pin;
mod plan;
mod range;

pub use error::MmError;
pub use fault::{
    FaultAccess, FaultAdmission, FaultAdmissionPermit, FaultCapacity, FaultCompletionPermit,
    FaultDisposition, FaultFailure, FaultHandlerId, FaultKey, FaultLifecycleState, FaultLoad,
    FaultPort, FaultRequest, FaultRequestId, FaultType, PageOffset, validate_fault_completion,
};
pub use identity::{AddressSpaceId, MappingGeneration, MappingId, PinOwner};
pub use mapping::{
    ExpectedMapping, InvalidationRange, InvalidationReason, MappingAccess, MappingKind,
    MappingSnapshot,
};
pub use pin::{
    LifecycleProgress, MutationBlocker, PinAccess, PinAccounting, PinDuration, PinLeaseView,
    PinQuota, PinRegistry, PinRegistryState, PinRequest, PinReservation, PinSnapshot, PinToken,
    PinUse, TeardownReport,
};
pub use plan::{
    AffineRelocation, MemlockLimit, MemlockPlan, PageCoveringPlan, RemapGeometry,
    RemapSegmentGeometry, relocate_affine_origin,
};
pub use range::{PageRange, PageSize, UserRange};

#[cfg(test)]
mod tests;
