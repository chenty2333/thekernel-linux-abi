//! Explicit-context utilities for accessing userspace memory.
//!
//! This crate never selects an address space implicitly and never dereferences
//! a userspace pointer. The kernel adapter supplies a [`UserMemory`]
//! implementation and creates a [`UserMemoryContext`] for each operation.

#![no_std]
#![warn(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

use core::{fmt, mem::MaybeUninit, slice};

use bytemuck::NoUninit;

/// Errors produced before an operating-system adapter maps them to errno.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum UserCopyError {
    /// The address is invalid, outside userspace, or overflows.
    BadAddress,
    /// The requested access is not permitted by the selected address space.
    AccessDenied,
    /// A bounded NUL-terminated read reached its maximum length.
    #[cfg(feature = "alloc")]
    TooLong,
    /// An owned snapshot could not reserve its required storage.
    #[cfg(feature = "alloc")]
    NoMemory,
}

impl fmt::Display for UserCopyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadAddress => f.write_str("invalid userspace address"),
            Self::AccessDenied => f.write_str("userspace access denied"),
            #[cfg(feature = "alloc")]
            Self::TooLong => f.write_str("bounded userspace value is too long"),
            #[cfg(feature = "alloc")]
            Self::NoMemory => f.write_str("usercopy snapshot allocation failed"),
        }
    }
}

/// Compatibility error alias retained for source migrations from `starry-vm`.
pub type VmError = UserCopyError;

/// A user-memory operation result.
pub type VmResult<T = ()> = Result<T, UserCopyError>;

/// An address-space provider used by one explicit usercopy operation.
///
/// # Safety
///
/// Implementations must not directly dereference `start` as a kernel pointer.
/// They must validate the full userspace range and access permissions. On
/// successful [`read`](UserMemory::read), every destination byte must have
/// been initialized. Returning an error may leave destination bytes partially
/// initialized because callers never observe them as initialized after an
/// error.
pub unsafe trait UserMemory {
    /// Reads exactly `dst.len()` bytes from `start`.
    fn read(&mut self, start: usize, dst: &mut [MaybeUninit<u8>]) -> VmResult;

    /// Writes exactly `src.len()` bytes to `start`.
    fn write(&mut self, start: usize, src: &[u8]) -> VmResult;
}

// SAFETY: delegating through an exclusive reference preserves the underlying
// provider's safety contract and does not add another access path.
unsafe impl<M: UserMemory + ?Sized> UserMemory for &mut M {
    fn read(&mut self, start: usize, dst: &mut [MaybeUninit<u8>]) -> VmResult {
        (**self).read(start, dst)
    }

    fn write(&mut self, start: usize, src: &[u8]) -> VmResult {
        (**self).write(start, src)
    }
}

/// Explicit operation context binding usercopy helpers to one provider.
///
/// Holding an exclusive provider reference makes accidental address-space
/// switching inside a multi-step copy impossible without constructing a new
/// context.
pub struct UserMemoryContext<'a, M: ?Sized> {
    memory: &'a mut M,
}

impl<'a, M: UserMemory + ?Sized> UserMemoryContext<'a, M> {
    /// Binds an operation context to `memory`.
    pub const fn new(memory: &'a mut M) -> Self {
        Self { memory }
    }

    /// Returns the provider for a lower-level adapter operation.
    pub fn memory_mut(&mut self) -> &mut M {
        self.memory
    }

    /// Reads a byte range after checked address arithmetic.
    pub fn read_bytes(&mut self, start: usize, dst: &mut [MaybeUninit<u8>]) -> VmResult {
        if dst.is_empty() {
            return Ok(());
        }
        checked_end(start, dst.len())?;
        self.memory.read(start, dst)
    }

    /// Writes a byte range after checked address arithmetic.
    pub fn write_bytes(&mut self, start: usize, src: &[u8]) -> VmResult {
        if src.is_empty() {
            return Ok(());
        }
        checked_end(start, src.len())?;
        self.memory.write(start, src)
    }

    /// Reads a typed slice without assuming that its bit patterns are valid.
    ///
    /// The userspace address need not satisfy `T`'s Rust alignment. Linux
    /// usercopy treats it as a byte address; only the kernel-owned destination
    /// is dereferenced as `T` after the provider initialized every byte.
    pub fn read_slice<T>(&mut self, ptr: *const T, dst: &mut [MaybeUninit<T>]) -> VmResult {
        let byte_len = core::mem::size_of_val(dst);
        if byte_len == 0 {
            return Ok(());
        }
        let start = ptr as usize;
        // SAFETY: `MaybeUninit<T>` may hold any byte pattern. The byte slice
        // covers exactly the same initialized-or-uninitialized storage.
        let bytes = unsafe {
            slice::from_raw_parts_mut(dst.as_mut_ptr().cast::<MaybeUninit<u8>>(), byte_len)
        };
        self.read_bytes(start, bytes)
    }

    /// Writes a typed slice whose type has no uninitialized padding.
    #[allow(clippy::not_unsafe_ptr_arg_deref)] // Pointer is an opaque user address, never dereferenced.
    pub fn write_slice<T: NoUninit>(&mut self, ptr: *mut T, src: &[T]) -> VmResult {
        // SAFETY: `NoUninit` guarantees that every byte of each value,
        // including padding, is initialized and safe to copy.
        unsafe { self.write_slice_unchecked(ptr, src) }
    }

    /// Writes the complete object representation of a typed slice.
    ///
    /// # Safety
    ///
    /// Every byte in each source value, including padding, must be initialized.
    /// Prefer [`write_slice`](Self::write_slice) with `T: NoUninit`.
    pub unsafe fn write_slice_unchecked<T>(&mut self, ptr: *mut T, src: &[T]) -> VmResult {
        let byte_len = core::mem::size_of_val(src);
        if byte_len == 0 {
            return Ok(());
        }
        // The pointer is an opaque Linux userspace byte address. The source
        // slice is kernel-owned and aligned; this function never dereferences
        // `ptr` as `T`.
        let start = ptr as usize;
        // SAFETY: the caller guarantees that all bytes, including padding,
        // are initialized; the resulting slice has the exact object extent.
        let bytes = unsafe { slice::from_raw_parts(src.as_ptr().cast::<u8>(), byte_len) };
        self.write_bytes(start, bytes)
    }
}

fn checked_end(start: usize, len: usize) -> VmResult<usize> {
    start.checked_add(len).ok_or(UserCopyError::BadAddress)
}

/// Reads a typed slice using an explicit operation context.
pub fn vm_read_slice<M: UserMemory + ?Sized, T>(
    memory: &mut UserMemoryContext<'_, M>,
    ptr: *const T,
    dst: &mut [MaybeUninit<T>],
) -> VmResult {
    memory.read_slice(ptr, dst)
}

/// Writes a typed slice using an explicit operation context.
pub fn vm_write_slice<M: UserMemory + ?Sized, T: NoUninit>(
    memory: &mut UserMemoryContext<'_, M>,
    ptr: *mut T,
    src: &[T],
) -> VmResult {
    memory.write_slice(ptr, src)
}

/// Writes typed bytes whose complete object representation is initialized.
///
/// # Safety
///
/// Every source byte, including padding, must be initialized.
pub unsafe fn vm_write_slice_unchecked<M: UserMemory + ?Sized, T>(
    memory: &mut UserMemoryContext<'_, M>,
    ptr: *mut T,
    src: &[T],
) -> VmResult {
    // SAFETY: forwarded from this function's caller.
    unsafe { memory.write_slice_unchecked(ptr, src) }
}

mod thin;
pub use thin::{VmMutPtr, VmPtr};

#[cfg(feature = "alloc")]
#[path = "alloc.rs"]
mod owned;
#[cfg(feature = "alloc")]
pub use owned::{
    MAX_NUL_SEARCH_BYTES, vm_load, vm_load_any, vm_load_any_until_nul, vm_load_until_nul,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_range_rejects_overflow_but_allows_empty_top_address() {
        assert_eq!(checked_end(usize::MAX, 1), Err(UserCopyError::BadAddress));
        assert_eq!(checked_end(usize::MAX, 0), Ok(usize::MAX));
    }
}
