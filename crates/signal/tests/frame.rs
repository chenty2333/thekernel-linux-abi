use std::mem::{MaybeUninit, align_of, offset_of, size_of};

use axcpu::uspace::UserContext;
use linux_raw_sys::general::SS_ONSTACK;
use thekernel_linux_signal::{
    SignalInfo, SignalSet, SignalStack, SignalStackRestoreError, Signo,
    api::{
        FpRestore, FpStateRestoreError, PreparedSignalFrame, SIGNAL_FPSTATE_SIZE, SIGNAL_RED_ZONE,
        SignalFrame, SignalFrameLayout, SignalFramePublishError, SignalFrameRestoreError,
        SignalFrameStack, copyin_and_prepare_restore, prepare_signal_frame,
        prepare_signal_frame_with_fp_bytes, prepare_signal_restore,
    },
    arch::{
        LegacyFpState64, MContext, SignalContextError, UC_SIGCONTEXT_SS, UC_STRICT_RESTORE_SS,
        UContext,
    },
};
use thekernel_linux_usercopy::{UserCopyError, UserMemory, UserMemoryContext, VmResult};

mod common;
use common::{Vm, initial_sp, memory_provider};

unsafe extern "C" fn test_handler(_: i32) {}

fn frame_info() -> SignalInfo {
    SignalInfo::new_user(Signo::SIGUSR1, 1, 7, 0)
}

fn normal_context() -> UserContext {
    UserContext::new(0x1000, initial_sp().into(), 0)
}

fn publish_normal(
    context: &UserContext,
    mask: SignalSet,
) -> (
    PreparedSignalFrame,
    thekernel_linux_signal::api::SignalFrameLayout,
) {
    let prepared = prepare_signal_frame(
        context,
        mask,
        SignalStack::default(),
        SignalFrameStack::Normal,
        frame_info(),
        test_handler as *const () as usize,
        0xfeed,
    )
    .unwrap();
    let layout = prepared.layout();
    (prepared, layout)
}

#[test]
fn layout_is_x86_64_aligned_and_reserves_the_red_zone() {
    assert_eq!(align_of::<LegacyFpState64>(), 16);
    assert_eq!(size_of::<LegacyFpState64>(), SIGNAL_FPSTATE_SIZE);
    assert_eq!(align_of::<MContext>(), 8);
    assert_eq!(size_of::<MContext>(), 256);
    assert_eq!(offset_of!(UContext, mcontext), 40);
    assert_eq!(offset_of!(UContext, sigmask), 296);
    assert_eq!(size_of::<UContext>(), 304);
    assert_eq!(align_of::<SignalFrame>(), 16);
    assert_eq!(layout_ucontext_offset(), 0);

    let context = normal_context();
    let layout = SignalFrameLayout::new(
        context.sp(),
        &SignalStack::default(),
        SignalFrameStack::Normal,
    )
    .unwrap();
    assert_eq!(layout.frame_start() % 16, 0);
    assert_eq!(layout.fpstate() % 16, 0);
    assert_eq!(layout.fpstate() + SIGNAL_FPSTATE_SIZE, layout.payload_end());
    assert_eq!(layout.fpstate(), layout.fixed_frame_end());
    assert_eq!(layout.published_sp() % 16, 8);
    assert!(layout.frame_start() <= context.sp() - SIGNAL_RED_ZONE);
    assert_eq!(
        layout.siginfo(),
        layout.frame_start() + size_of::<UContext>()
    );
    assert_eq!(
        layout.ucontext(),
        layout.frame_start() + layout_ucontext_offset()
    );
}

#[test]
fn legacy_fp_delivery_publishes_metadata_and_owned_snapshot() {
    let context = normal_context();
    let mut mask = SignalSet::default();
    mask.add(Signo::SIGUSR2);
    let bytes = [0x5a; LegacyFpState64::SIZE];
    let prepared = prepare_signal_frame_with_fp_bytes(
        &context,
        mask,
        SignalStack::default(),
        SignalFrameStack::Normal,
        frame_info(),
        test_handler as *const () as usize,
        0xfeed,
        || bytes,
    )
    .unwrap();
    assert_eq!(prepared.fpstate().as_bytes(), &bytes);
    let layout = prepared.layout();

    let mut provider = memory_provider();
    let mut memory = UserMemoryContext::new(&mut provider);
    let published = prepared.publish(&mut memory).unwrap();
    let frame =
        SignalFrame::read_from_user(&mut memory, layout.frame_start() as *const SignalFrame)
            .unwrap();
    assert_eq!(
        frame.ucontext().flags,
        UC_SIGCONTEXT_SS | UC_STRICT_RESTORE_SS
    );
    assert_eq!(frame.ucontext().mcontext.fpstate(), layout.fpstate());
    assert_eq!(frame.ucontext().mcontext.stack_segment(), context.ss as u16);
    assert_eq!(frame.ucontext().mcontext.old_mask(), mask.bits() as usize);

    let mut observed = [MaybeUninit::uninit(); LegacyFpState64::SIZE];
    memory.read_bytes(layout.fpstate(), &mut observed).unwrap();
    let observed = observed.map(|byte| {
        // SAFETY: the provider initializes every byte on a successful read.
        unsafe { byte.assume_init() }
    });
    assert_eq!(observed, bytes);
    let mut installed = context;
    published.install(&mut installed);
}

#[test]
fn fp_restore_reads_owned_image_and_distinguishes_reset_and_misalignment() {
    let context = normal_context();
    let bytes = [0xa7; LegacyFpState64::SIZE];
    let prepared = prepare_signal_frame_with_fp_bytes(
        &context,
        SignalSet::default(),
        SignalStack::default(),
        SignalFrameStack::Normal,
        frame_info(),
        test_handler as *const () as usize,
        0xfeed,
        || bytes,
    )
    .unwrap();
    let layout = prepared.layout();
    let mut provider = memory_provider();
    let mut memory = UserMemoryContext::new(&mut provider);
    let _ = prepared.publish(&mut memory).unwrap();

    let mut current = context;
    let restored = copyin_and_prepare_restore(
        &mut memory,
        layout.frame_start() as *const SignalFrame,
        &current,
        |_| true,
        |_| true,
        SignalStack::default(),
        |_, _, _| Ok(()),
    )
    .unwrap();
    assert_eq!(restored.fp_restore().as_image().unwrap().as_bytes(), &bytes);
    let token = restored.commit_context(&mut current);
    assert!(matches!(token, FpRestore::Image(_)));

    let mut reset_frame =
        SignalFrame::read_from_user(&mut memory, layout.frame_start() as *const SignalFrame)
            .unwrap();
    reset_frame.ucontext_mut().mcontext.set_fpstate(0);
    reset_frame
        .write_to_user(&mut memory, layout.frame_start() as *mut SignalFrame)
        .unwrap();
    let reset = copyin_and_prepare_restore(
        &mut memory,
        layout.frame_start() as *const SignalFrame,
        &current,
        |_| true,
        |_| true,
        SignalStack::default(),
        |_, _, _| Ok(()),
    )
    .unwrap();
    assert!(matches!(reset.fp_restore(), FpRestore::Reset));

    reset_frame
        .ucontext_mut()
        .mcontext
        .set_fpstate(layout.fpstate() + 1);
    reset_frame
        .write_to_user(&mut memory, layout.frame_start() as *mut SignalFrame)
        .unwrap();
    assert!(matches!(
        copyin_and_prepare_restore(
            &mut memory,
            layout.frame_start() as *const SignalFrame,
            &current,
            |_| true,
            |_| true,
            SignalStack::default(),
            |_, _, _| Ok(()),
        ),
        Err(SignalFrameRestoreError::Fpstate(
            FpStateRestoreError::Misaligned
        ))
    ));
}

const fn layout_ucontext_offset() -> usize {
    0
}

#[test]
fn normal_delivery_leaves_red_zone_canary_and_publishes_once() {
    let context = normal_context();
    let mut provider = memory_provider();
    let mut memory = UserMemoryContext::new(&mut provider);
    let red_zone_start = context.sp() - SIGNAL_RED_ZONE;
    let canary = [0xa5; SIGNAL_RED_ZONE];
    memory.write_bytes(red_zone_start, &canary).unwrap();

    let (prepared, layout) = publish_normal(&context, SignalSet::default());
    let published = prepared.publish(&mut memory).unwrap();
    let mut installed = context;
    published.install(&mut installed);
    assert_eq!(installed.sp() % 16, 8);
    assert_eq!(installed.ip(), test_handler as *const () as usize);

    let mut observed = [MaybeUninit::uninit(); SIGNAL_RED_ZONE];
    memory.read_bytes(red_zone_start, &mut observed).unwrap();
    let observed = observed.map(|byte| {
        // SAFETY: the provider initializes every byte on a successful read.
        unsafe { byte.assume_init() }
    });
    assert_eq!(observed, canary);
    assert_eq!(layout.frame_start() % 16, 0);
}

#[test]
fn fresh_and_nested_altstack_placements_have_distinct_origins() {
    let top = initial_sp();
    let configured = SignalStack::new(top - 0x4000, 0, 0x4000);
    let ordinary = UserContext::new(0x1000, initial_sp().into(), 0);

    let fresh = prepare_signal_frame(
        &ordinary,
        SignalSet::default(),
        configured,
        SignalFrameStack::FreshAltStack,
        frame_info(),
        test_handler as *const () as usize,
        0xfeed,
    )
    .unwrap();
    let fresh_layout = fresh.layout();
    assert!(fresh_layout.frame_start() >= configured.sp);
    assert!(fresh_layout.published_sp() >= configured.sp);
    assert!(
        fresh_layout.frame_start() >= top - size_of::<SignalFrame>() - SIGNAL_FPSTATE_SIZE - 16
    );

    let mut provider = memory_provider();
    let mut memory = UserMemoryContext::new(&mut provider);
    let fresh_published = fresh.publish(&mut memory).unwrap();
    let mut nested_context = ordinary;
    fresh_published.install(&mut nested_context);
    let nested = prepare_signal_frame(
        &nested_context,
        SignalSet::default(),
        configured,
        SignalFrameStack::NestedAltStack,
        frame_info(),
        test_handler as *const () as usize,
        0xfeed,
    )
    .unwrap();
    let nested_layout = nested.layout();
    assert!(nested_layout.frame_start() <= nested_context.sp() - SIGNAL_RED_ZONE);
    assert!(nested_layout.frame_start() < fresh_layout.frame_start());

    let nested_published = nested.publish(&mut memory).unwrap();
    let mut nested_handler_context = nested_context;
    nested_published.install(&mut nested_handler_context);
    let frame = SignalFrame::read_from_user(
        &mut memory,
        (nested_handler_context.sp() + size_of::<usize>()) as *const SignalFrame,
    )
    .unwrap();
    assert_eq!(frame.ucontext().stack.flags, SS_ONSTACK);
}

struct RejectWrite {
    inner: Vm,
    address: usize,
}

struct RejectRead {
    inner: Vm,
    address: usize,
}

// SAFETY: all non-rejected accesses delegate to the range-checking test VM.
unsafe impl UserMemory for RejectRead {
    fn read(&mut self, start: usize, dst: &mut [MaybeUninit<u8>]) -> VmResult {
        let end = start
            .checked_add(dst.len())
            .ok_or(UserCopyError::BadAddress)?;
        if start <= self.address && self.address < end {
            return Err(UserCopyError::AccessDenied);
        }
        self.inner.read(start, dst)
    }

    fn write(&mut self, start: usize, src: &[u8]) -> VmResult {
        self.inner.write(start, src)
    }
}

// SAFETY: all non-rejected accesses delegate to the range-checking test VM.
unsafe impl UserMemory for RejectWrite {
    fn read(&mut self, start: usize, dst: &mut [MaybeUninit<u8>]) -> VmResult {
        self.inner.read(start, dst)
    }

    fn write(&mut self, start: usize, src: &[u8]) -> VmResult {
        let end = start
            .checked_add(src.len())
            .ok_or(UserCopyError::BadAddress)?;
        if start <= self.address && self.address < end {
            return Err(UserCopyError::AccessDenied);
        }
        self.inner.write(start, src)
    }
}

#[test]
fn restorer_fault_does_not_install_published_context() {
    let context = normal_context();
    let original_sp = context.sp();
    let (prepared, layout) = publish_normal(&context, SignalSet::default());

    let mut provider = RejectWrite {
        inner: memory_provider(),
        address: layout.published_sp(),
    };
    let mut memory = UserMemoryContext::new(&mut provider);
    assert!(matches!(
        prepared.publish(&mut memory),
        Err(SignalFramePublishError::Restorer(
            UserCopyError::AccessDenied
        ))
    ));
    assert_eq!(context.ip(), 0x1000);
    assert_eq!(context.sp(), original_sp);
}

#[test]
fn fpstate_fault_does_not_prepare_a_restore_token() {
    let context = normal_context();
    let prepared = prepare_signal_frame(
        &context,
        SignalSet::default(),
        SignalStack::default(),
        SignalFrameStack::Normal,
        frame_info(),
        test_handler as *const () as usize,
        0xfeed,
    )
    .unwrap();
    let layout = prepared.layout();
    let mut provider = memory_provider();
    let mut memory = UserMemoryContext::new(&mut provider);
    let _ = prepared.publish(&mut memory).unwrap();

    let mut reject = RejectRead {
        inner: memory_provider(),
        address: layout.fpstate(),
    };
    let mut rejected_memory = UserMemoryContext::new(&mut reject);
    assert!(matches!(
        copyin_and_prepare_restore(
            &mut rejected_memory,
            layout.frame_start() as *const SignalFrame,
            &context,
            |_| true,
            |_| true,
            SignalStack::default(),
            |_, _, _| Ok(()),
        ),
        Err(SignalFrameRestoreError::Fpstate(
            FpStateRestoreError::Copyin(UserCopyError::AccessDenied)
        ))
    ));
}

#[test]
fn deliver_copyin_restore_filters_mask_and_squashes_altstack_errors() {
    let original = normal_context();
    let mut mask = SignalSet::default();
    mask.add(Signo::SIGKILL);
    mask.add(Signo::SIGSTOP);
    mask.add(Signo::SIGUSR2);

    let mut provider = memory_provider();
    let mut memory = UserMemoryContext::new(&mut provider);
    let (prepared, layout) = publish_normal(&original, mask);
    let published = prepared.publish(&mut memory).unwrap();
    let mut handler_context = original;
    published.install(&mut handler_context);
    let frame =
        SignalFrame::read_from_user(&mut memory, (layout.frame_start()) as *const SignalFrame)
            .unwrap();

    let prepared_restore = prepare_signal_restore(
        &handler_context,
        frame.clone(),
        |_| true,
        |_| true,
        SignalStack::default(),
        |_, _, _| Ok(()),
    )
    .unwrap();
    assert!(prepared_restore.blocked().has(Signo::SIGUSR2));
    assert!(!prepared_restore.blocked().has(Signo::SIGKILL));
    assert!(!prepared_restore.blocked().has(Signo::SIGSTOP));
    assert_eq!(prepared_restore.context().ip(), original.ip());

    let mut invalid = frame;
    invalid.ucontext_mut().mcontext.set_code_segment(0);
    assert!(matches!(
        prepare_signal_restore(
            &handler_context,
            invalid,
            |_| true,
            |_| true,
            SignalStack::default(),
            |_, _, _| Ok(()),
        ),
        Err(SignalContextError::InvalidProcessorState)
    ));

    let mut bad_stack =
        SignalFrame::read_from_user(&mut memory, layout.frame_start() as *const SignalFrame)
            .unwrap();
    bad_stack.ucontext_mut().stack = SignalStack::new(0x8000, 0x40, 0x1000);
    let prepared_bad_stack = prepare_signal_restore(
        &handler_context,
        bad_stack,
        |_| true,
        |_| true,
        SignalStack::default(),
        |_, _, _| Ok(()),
    )
    .unwrap();
    assert_eq!(prepared_bad_stack.stack(), None);
    assert_eq!(
        prepared_bad_stack.stack_error(),
        Some(SignalStackRestoreError::InvalidFlags)
    );
}

struct PartialRead;

// SAFETY: this provider initializes one byte and reports a fault, so callers
// must discard the partially initialized destination on error.
unsafe impl UserMemory for PartialRead {
    fn read(&mut self, _start: usize, dst: &mut [MaybeUninit<u8>]) -> VmResult {
        if let Some(first) = dst.first_mut() {
            first.write(0);
        }
        Err(UserCopyError::AccessDenied)
    }

    fn write(&mut self, _start: usize, _src: &[u8]) -> VmResult {
        Err(UserCopyError::AccessDenied)
    }
}

#[test]
fn unaligned_copyin_is_allowed_but_partial_copyin_is_rejected() {
    let original = normal_context();
    let mut provider = memory_provider();
    let mut memory = UserMemoryContext::new(&mut provider);
    let (prepared, layout) = publish_normal(&original, SignalSet::default());
    let _ = prepared.publish(&mut memory).unwrap();
    assert!(
        SignalFrame::read_from_user(
            &mut memory,
            (layout.frame_start() + 1) as *const SignalFrame,
        )
        .is_ok()
    );

    let mut partial = PartialRead;
    let mut partial_memory = UserMemoryContext::new(&mut partial);
    assert!(
        SignalFrame::read_from_user(
            &mut partial_memory,
            layout.frame_start() as *const SignalFrame,
        )
        .is_err()
    );
}
