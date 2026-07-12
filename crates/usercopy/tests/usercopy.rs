use core::{mem::MaybeUninit, ops::Range};

use bytemuck::{Pod, Zeroable};
use thekernel_linux_usercopy::{
    MAX_NUL_SEARCH_BYTES, UserCopyError, UserMemory, UserMemoryContext, VmMutPtr, VmPtr, VmResult,
    vm_load, vm_load_any_until_nul, vm_load_until_nul, vm_read_slice, vm_write_slice,
};

struct TestMemory {
    bytes: Vec<u8>,
    writable_from: usize,
    reads: usize,
}

impl TestMemory {
    fn new(size: usize) -> Self {
        Self {
            bytes: vec![0; size],
            writable_from: 0x1000,
            reads: 0,
        }
    }

    fn range(&self, start: usize, len: usize) -> VmResult<Range<usize>> {
        let end = start.checked_add(len).ok_or(UserCopyError::BadAddress)?;
        if end > self.bytes.len() {
            return Err(UserCopyError::BadAddress);
        }
        Ok(start..end)
    }
}

// SAFETY: TestMemory treats addresses as checked offsets, never dereferences
// them, and initializes every destination byte before returning success.
unsafe impl UserMemory for TestMemory {
    fn read(&mut self, start: usize, dst: &mut [MaybeUninit<u8>]) -> VmResult {
        let range = self.range(start, dst.len())?;
        self.reads += 1;
        for (output, input) in dst.iter_mut().zip(&self.bytes[range]) {
            output.write(*input);
        }
        Ok(())
    }

    fn write(&mut self, start: usize, src: &[u8]) -> VmResult {
        if start < self.writable_from {
            return Err(UserCopyError::AccessDenied);
        }
        let range = self.range(start, src.len())?;
        self.bytes[range].copy_from_slice(src);
        Ok(())
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Pod, Zeroable)]
struct Pair {
    first: u64,
    second: u64,
}

#[test]
fn typed_slice_and_pointer_round_trip_use_one_explicit_context() {
    let mut provider = TestMemory::new(0x8000);
    let mut memory = UserMemoryContext::new(&mut provider);
    let values = [
        Pair {
            first: 1,
            second: 2,
        },
        Pair {
            first: 3,
            second: 4,
        },
    ];
    let ptr = 0x2000usize as *mut Pair;

    vm_write_slice(&mut memory, ptr, &values).unwrap();
    let mut output = [MaybeUninit::<Pair>::uninit(); 2];
    vm_read_slice(&mut memory, ptr, &mut output).unwrap();
    // SAFETY: the successful read initialized both values and Pair is Pod.
    let output = unsafe { core::mem::transmute::<[MaybeUninit<Pair>; 2], [Pair; 2]>(output) };
    assert_eq!(output, values);

    assert_eq!(ptr.vm_read(&mut memory), Ok(values[0]));
    ptr.wrapping_add(1)
        .vm_write(
            &mut memory,
            Pair {
                first: 5,
                second: 6,
            },
        )
        .unwrap();
    assert_eq!(
        ptr.wrapping_add(1).vm_read(&mut memory),
        Ok(Pair {
            first: 5,
            second: 6
        })
    );
}

#[test]
fn independent_contexts_never_share_an_implicit_provider() {
    let mut first = TestMemory::new(0x4000);
    let mut second = TestMemory::new(0x4000);
    let ptr = 0x1000usize as *mut u32;

    {
        let mut memory = UserMemoryContext::new(&mut first);
        ptr.vm_write(&mut memory, 11).unwrap();
    }
    {
        let mut memory = UserMemoryContext::new(&mut second);
        ptr.vm_write(&mut memory, 22).unwrap();
    }

    let mut first_memory = UserMemoryContext::new(&mut first);
    let mut second_memory = UserMemoryContext::new(&mut second);
    assert_eq!(ptr.vm_read(&mut first_memory), Ok(11));
    assert_eq!(ptr.vm_read(&mut second_memory), Ok(22));
}

#[test]
fn provider_errors_and_address_checks_remain_distinct() {
    let mut provider = TestMemory::new(0x4000);
    let mut memory = UserMemoryContext::new(&mut provider);

    // Linux-style zero-length usercopy performs no provider access and does
    // not validate the otherwise unusable address.
    memory.write_bytes(usize::MAX, &[]).unwrap();
    let reads_before = memory.memory_mut().reads;
    memory.read_bytes(0x200, &mut []).unwrap();
    assert_eq!(memory.memory_mut().reads, reads_before);
    assert_eq!(
        memory.write_bytes(0x100, &[1]),
        Err(UserCopyError::AccessDenied)
    );
    assert_eq!(
        memory.read_slice(0x1001usize as *const u64, &mut [MaybeUninit::uninit()]),
        Err(UserCopyError::BadAddress)
    );
    assert_eq!(
        memory.read_bytes(usize::MAX, &mut [MaybeUninit::uninit(); 2]),
        Err(UserCopyError::BadAddress)
    );
}

#[test]
fn owned_load_is_fallible_and_preserves_values() {
    let mut provider = TestMemory::new(0x8000);
    let mut memory = UserMemoryContext::new(&mut provider);
    let ptr = 0x3000usize as *mut u8;
    let value = b"a quick brown fox";

    vm_write_slice(&mut memory, ptr, value).unwrap();
    assert_eq!(vm_load(&mut memory, ptr, value.len()).unwrap(), value);
    assert_eq!(
        memory.load::<u64>(0x1000usize as *const u64, usize::MAX),
        Err(UserCopyError::NoMemory)
    );
}

#[test]
fn nul_load_stops_at_zero_and_enforces_the_byte_bound() {
    let base = 0x1000usize;
    let mut provider = TestMemory::new(base + MAX_NUL_SEARCH_BYTES + 64);
    provider.bytes[base..base + 6].copy_from_slice(b"abc\0de");
    {
        let mut memory = UserMemoryContext::new(&mut provider);
        assert_eq!(
            vm_load_until_nul(&mut memory, base as *const u8).unwrap(),
            b"abc"
        );
    }

    provider.bytes[base..base + MAX_NUL_SEARCH_BYTES].fill(1);
    let mut memory = UserMemoryContext::new(&mut provider);
    assert_eq!(
        vm_load_until_nul(&mut memory, base as *const u8),
        Err(UserCopyError::TooLong)
    );
}

#[test]
fn unsafe_nul_loader_supports_raw_pointer_arrays_without_pointer_pod() {
    let base = 0x2000usize;
    let mut provider = TestMemory::new(0x8000);
    let raw = [0x4000usize, 0x5000usize, 0usize];
    provider.bytes[base..base + core::mem::size_of_val(&raw)]
        .copy_from_slice(bytemuck::cast_slice(&raw));
    let mut memory = UserMemoryContext::new(&mut provider);

    // SAFETY: every loaded word is converted into a raw pointer, for which
    // these exposed address representations and the null sentinel are valid.
    let pointers = unsafe { vm_load_any_until_nul(&mut memory, base as *const *const u8) }.unwrap();
    assert_eq!(
        pointers,
        [0x4000usize as *const u8, 0x5000usize as *const u8]
    );
}
