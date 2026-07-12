//! Explicit-domain process, thread-group, session, and zombie lifecycle state.
//!
//! This crate never selects a process registry or init process globally. A
//! kernel owns a [`ProcessDomain`] and passes its [`ProcessRegistry`] to
//! topology queries. The durable zombie payload is a caller-chosen type, so
//! Linux wait status, credentials, and accounting remain adapter policy.

#![no_std]
#![feature(allocator_api)]
#![warn(missing_docs)]

extern crate alloc;

mod process;
mod process_group;
mod session;

/// A process ID, also used as session ID, process group ID, and thread ID.
pub type Pid = u32;

pub use process::{
    CreatedSession, ExitOutcome, PROCESS_MEMBERSHIP_LIMIT, Process, ProcessAdmission,
    ProcessDomain, ProcessError, ProcessRegistry, Processes, ThreadAdmission, ThreadExitOutcome,
    ThreadIds,
};
pub use process_group::ProcessGroup;
pub use session::Session;
