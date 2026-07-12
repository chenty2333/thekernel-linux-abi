//! Linux-visible pathname and discretionary-access policy over a generic VFS.
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
mod transaction;

pub use context::{PathContext, PathContextError};
pub use dac::{
    Access, CreateAttributes, DacCapability, DacCredentials, DacError, NodeKind, NodeMetadata,
    check_dac, check_directory_mutation, check_sticky_mutation, initial_create_attributes,
};
pub use path::{
    LimitKind, Openat2Policy, PathLimitError, PathLimits, ResolveFlags, ResolveFlagsError,
    TopologyEvent, TraversalAction, WalkBudget, WalkError,
};
pub use transaction::{MutationBackend, MutationTransaction};
