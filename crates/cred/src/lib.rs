//! Allocation-aware credential values for Linux ABI kernels.
//!
//! This crate contains no syscall glue and owns no process, signal, VFS,
//! file-descriptor, memory-management, or usercopy state. Kernel adapters map
//! [`CredError`] into their local errno type and explicitly own all namespace
//! publication policy.

#![no_std]
#![feature(allocator_api)]
#![warn(missing_docs)]

extern crate alloc;

mod credential;
mod error;
mod idmap;

pub use credential::{
    CAPABILITY_VALID_MASK, CAPABILITY_WORDS, CapabilitySets, Credential, CredentialIds,
    CredentialTransitionMode, FsCredentialSnapshot, GroupInfo, SECBIT_KEEP_CAPS,
    SECBIT_KEEP_CAPS_LOCKED, SECBIT_NO_CAP_AMBIENT_RAISE, SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED,
    SECBIT_NO_SETUID_FIXUP, SECBIT_NO_SETUID_FIXUP_LOCKED, SECBIT_NOROOT, SECBIT_NOROOT_LOCKED,
    SECURE_ALL_BITS, SECURE_ALL_LOCKS, UserNamespaceView, credential_cap_is_subset, ns_capable,
};
pub use error::CredError;
pub use idmap::{
    ID_MAP_MAX_EXTENTS, IdMap, IdMapInputExtent, Kgid, Kuid, UserGid, UserUid,
    validate_id_map_input,
};
