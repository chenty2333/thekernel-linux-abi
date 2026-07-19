//! Bounded Linux seccomp policy and classic-BPF execution contracts.
//!
//! This crate owns immutable verified programs, allocation-free evaluation,
//! filter stacking, Linux action precedence, and explicit task-state
//! transitions. It deliberately does not dereference userspace, own task
//! locks, deliver signals, implement ptrace stops, allocate listener file
//! descriptors, or perform audit logging. Kernel adapters prepare copied
//! programs outside their publication gates and execute the returned plans.

#![no_std]
#![feature(allocator_api)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

mod action;
mod bpf;
mod chain;
mod state;
mod uapi;

pub use action::{Action, ActionClass, MAX_ERRNO};
pub use bpf::{ClassicBpfInstruction, ProgramError, SeccompData, VerifiedProgram};
pub use chain::{FilterChain, FilterDecision, FilterInstallError, FilterMetadata};
pub use state::{SeccompMode, SeccompState, StateTransitionError, SyncEligibility};
pub use uapi::*;
