//! Linux-visible pathname, discretionary-access, and setattr policy over a
//! generic VFS.
//!
//! This crate owns no filesystem tree and never selects a current task. A
//! kernel supplies stable location handles, one immutable credential snapshot,
//! and a generic walker. The types here describe the observable Linux policy
//! that the walker and mutation backend must enforce during that operation.

#![no_std]
#![warn(missing_docs)]

mod context;
mod dac;
mod path;
mod setattr;
mod transaction;

pub use context::{PathContext, PathContextError};
pub use dac::{
    Access, CreateAttributes, DacCapability, DacCredentials, DacError, HardlinkCredentials,
    NodeKind, NodeMetadata, check_dac, check_directory_mutation, check_hardlink_source,
    check_sticky_mutation, initial_create_attributes,
};
pub use path::{
    LimitKind, Openat2Policy, PathLimitError, PathLimits, ResolveFlags, ResolveFlagsError,
    TopologyEvent, TraversalAction, WalkBudget, WalkError,
};
pub use setattr::{
    ChmodRequest, ChmodSetattrPlan, ChownRequest, ChownSetattrPlan, PreparedSetattr, SetattrError,
    plan_chmod, plan_chown,
};
pub use transaction::{MutationBackend, MutationTransaction};
