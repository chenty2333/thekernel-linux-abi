use std::mem::MaybeUninit;

use axcpu::uspace::UserContext;
use linux_raw_sys::general::{SS_DISABLE, SS_ONSTACK};
use thekernel_linux_signal::{
    SignalAction, SignalActionFlags, SignalDisposition, SignalInfo, SignalOSAction, SignalSet,
    SignalStack, SignalStackRestoreError, Signo,
    api::{ProcessSignalManager, SignalFrame},
    arch::SignalContextError,
};
use thekernel_linux_usercopy::{UserCopyError, UserMemory, UserMemoryContext, VmResult};

mod common;
use common::*;

fn replace_action(proc: &ProcessSignalManager, signo: Signo, action: SignalAction) {
    proc.try_replace_action(signo, action).unwrap();
}

fn handler_action(handler: usize, flags: SignalActionFlags) -> SignalAction {
    SignalAction {
        disposition: SignalDisposition::Handler(handler),
        flags,
        ..SignalAction::default()
    }
}

struct PartialReadFailure;

// SAFETY: this provider never dereferences the user address. It deliberately
// initializes one byte and returns an error to exercise the partial-fault
// contract; callers must discard the destination on error.
unsafe impl UserMemory for PartialReadFailure {
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

#[cfg(target_arch = "x86_64")]
struct RejectWriteAt {
    inner: Vm,
    address: usize,
}

#[cfg(target_arch = "x86_64")]
// SAFETY: all non-rejected accesses delegate to the fully validating test VM.
// A rejected write performs no access and reports a provider fault.
unsafe impl UserMemory for RejectWriteAt {
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

fn copy_signal_frame(memory: &mut UserMemoryContext<'_, Vm>, uctx: &UserContext) -> SignalFrame {
    SignalFrame::read_from_user(memory, uctx.sp() as *const SignalFrame)
        .expect("signal frame must be readable from the test VM")
}

fn point_at_signal_frame(uctx: &mut UserContext) {
    #[cfg(target_arch = "x86_64")]
    {
        let frame = uctx.sp() + core::mem::size_of::<usize>();
        uctx.set_sp(frame);
    }
}

#[test]
fn dequeue_signal() {
    let (proc, thr) = new_test_env();

    let sig1 = SignalInfo::new_user(Signo::SIGINT, 9, 9);
    assert!(thr.send_unqueued_signal(sig1));

    let sig2 = SignalInfo::new_user(Signo::SIGTERM, 9, 9);
    assert_eq!(proc.send_unqueued_signal(sig2), Some(TID));

    let mask = !SignalSet::default();
    assert_eq!(thr.dequeue_signal(&mask).unwrap().signo(), Signo::SIGINT);
    assert_eq!(thr.dequeue_signal(&mask).unwrap().signo(), Signo::SIGTERM);
    assert!(thr.dequeue_signal(&mask).is_none());
}

#[test]
fn handle_signal() {
    let (proc, thr) = new_test_env();

    let signo = Signo::SIGTERM;
    let sig = SignalInfo::new_user(signo, 9, 9);

    unsafe extern "C" fn test_handler(_: i32) {}
    replace_action(
        &proc,
        signo,
        handler_action(test_handler as usize, SignalActionFlags::empty()),
    );

    let initial = UserContext::new(0, initial_sp().into(), 0);

    let mut uctx = initial;
    let mut provider = memory_provider();
    let mut memory = UserMemoryContext::new(&mut provider);
    let restore_blocked = thr.blocked();
    let action = proc.action(signo);
    let result = thr.handle_signal(&mut memory, &mut uctx, restore_blocked, &sig, &action);

    assert_eq!(result, Some(SignalOSAction::Handler));
    assert_eq!(uctx.ip(), test_handler as *const () as usize);
    assert!(uctx.sp() < initial.sp());
    assert_eq!(uctx.arg0(), signo as usize);
}

#[test]
fn alternate_stack_status_and_bounds_are_overflow_safe() {
    let disabled = SignalStack::default();
    assert_eq!(disabled.flags_at(0x2000), SS_DISABLE);
    assert!(!disabled.contains_sp(0x2000));

    let stack = SignalStack::new(0x1000, 0, 0x1000);
    assert_eq!(stack.checked_top(), Some(0x2000));
    assert!(!stack.contains_sp(0x1000));
    assert!(stack.contains_sp(0x1001));
    assert!(stack.contains_sp(0x2000));
    assert!(!stack.contains_sp(0x2001));
    assert_eq!(stack.flags_at(0x1800), SS_ONSTACK);
    assert_eq!(stack.flags_at(0x2001), 0);
    assert!(stack.contains_range(0x1001, 0xfff));
    assert!(stack.contains_range(0x1000, 0x1000));

    let overflowing = SignalStack::new(usize::MAX - 8, 0, 16);
    assert_eq!(overflowing.checked_top(), None);
    assert!(!overflowing.contains_range(usize::MAX - 4, 8));
}

#[test]
fn nested_onstack_signal_uses_remaining_stack_instead_of_reusing_top() {
    let (proc, thr) = new_test_env();
    let signo = Signo::SIGTERM;
    let sig = SignalInfo::new_user(signo, 9, 9);

    unsafe extern "C" fn test_handler(_: i32) {}
    replace_action(
        &proc,
        signo,
        handler_action(test_handler as usize, SignalActionFlags::ONSTACK),
    );

    let alt_top = initial_sp();
    let alt_size = 0x8000;
    let alt_stack = SignalStack::new(alt_top - alt_size, 0, alt_size);
    thr.set_stack(alt_stack.clone());

    let mut uctx = UserContext::new(0, initial_sp().into(), 0);
    let mut provider = memory_provider();
    let mut memory = UserMemoryContext::new(&mut provider);
    let action = proc.action(signo);
    assert_eq!(
        thr.handle_signal(&mut memory, &mut uctx, thr.blocked(), &sig, &action),
        Some(SignalOSAction::Handler)
    );
    let outer_sp = uctx.sp();
    assert!(alt_stack.contains_sp(outer_sp));
    let mut outer_frame_context = uctx;
    point_at_signal_frame(&mut outer_frame_context);
    let outer_frame = copy_signal_frame(&mut memory, &outer_frame_context);
    assert_eq!(
        outer_frame.ucontext().stack,
        SignalStack::new(alt_top - alt_size, 0, alt_size)
    );

    assert_eq!(
        thr.handle_signal(&mut memory, &mut uctx, thr.blocked(), &sig, &action),
        Some(SignalOSAction::Handler)
    );
    assert!(uctx.sp() < outer_sp);
    assert!(alt_stack.contains_sp(uctx.sp()));
    let mut inner_frame_context = uctx;
    point_at_signal_frame(&mut inner_frame_context);
    let inner_frame = copy_signal_frame(&mut memory, &inner_frame_context);
    assert_eq!(
        inner_frame.ucontext().stack,
        SignalStack::new(alt_top - alt_size, SS_ONSTACK, alt_size)
    );
}

#[test]
fn overflowing_alternate_stack_fails_without_publishing_handler_context() {
    let (proc, thr) = new_test_env();
    let signo = Signo::SIGTERM;
    let sig = SignalInfo::new_user(signo, 9, 9);

    unsafe extern "C" fn test_handler(_: i32) {}
    replace_action(
        &proc,
        signo,
        handler_action(test_handler as usize, SignalActionFlags::ONSTACK),
    );
    thr.set_stack(SignalStack::new(usize::MAX - 8, 0, 16));

    let initial = UserContext::new(0x1234, initial_sp().into(), 0);
    let mut uctx = initial;
    let mut provider = memory_provider();
    let mut memory = UserMemoryContext::new(&mut provider);
    let action = proc.action(signo);
    assert_eq!(
        thr.handle_signal(&mut memory, &mut uctx, thr.blocked(), &sig, &action),
        Some(SignalOSAction::CoreDump)
    );
    assert_eq!(uctx.ip(), initial.ip());
    assert_eq!(uctx.sp(), initial.sp());
}

#[test]
fn block_ignore_send_signal() {
    let (proc, thr) = new_test_env();

    let signo = Signo::SIGINT;
    let sig = SignalInfo::new_user(signo, 0, 1);
    assert!(thr.send_unqueued_signal(sig.clone()));
    assert_eq!(
        thr.dequeue_signal(&!SignalSet::default()).unwrap().signo(),
        sig.signo()
    );

    replace_action(
        &proc,
        signo,
        SignalAction {
            disposition: SignalDisposition::Ignore,
            ..SignalAction::default()
        },
    );
    assert!(!thr.send_unqueued_signal(sig.clone()));
    assert!(!thr.pending().has(signo));

    let mut set = SignalSet::default();
    set.add(signo);
    thr.set_blocked(set);
    assert!(thr.signal_blocked(signo));
    assert!(!thr.send_unqueued_signal(sig.clone()));
    assert!(thr.pending().has(signo));

    replace_action(&proc, signo, SignalAction::default());
    assert!(!thr.send_unqueued_signal(sig.clone()));
    assert!(thr.pending().has(signo));

    let empty = SignalSet::default();
    thr.set_blocked(empty);
    assert!(!thr.signal_blocked(signo));
}

#[test]
fn check_signals() {
    let (proc, thr) = new_test_env();

    let mut uctx = UserContext::new(0, 0.into(), 0);
    let mut provider = memory_provider();
    let mut memory = UserMemoryContext::new(&mut provider);

    let signo = Signo::SIGTERM;
    let sig = SignalInfo::new_user(signo, 0, 1);

    assert_eq!(proc.send_unqueued_signal(sig.clone()), Some(TID));
    let delivered = thr.check_signals(&mut memory, &mut uctx, None).unwrap();
    assert_eq!(delivered.info.signo(), signo);

    assert!(thr.send_unqueued_signal(sig.clone()));
    let delivered = thr.check_signals(&mut memory, &mut uctx, None).unwrap();
    assert_eq!(delivered.info.signo(), signo);
}

#[test]
fn check_signals_preserves_restartability_for_reset_hand() {
    let (proc, thr) = new_test_env();
    let mut uctx = UserContext::new(0, initial_sp().into(), 0);
    let mut provider = memory_provider();
    let mut memory = UserMemoryContext::new(&mut provider);

    unsafe extern "C" fn test_handler(_: i32) {}

    let signo = Signo::SIGTERM;
    replace_action(
        &proc,
        signo,
        handler_action(
            test_handler as usize,
            SignalActionFlags::RESTART | SignalActionFlags::RESETHAND,
        ),
    );

    assert_eq!(
        proc.send_unqueued_signal(SignalInfo::new_user(signo, 0, 1)),
        Some(TID)
    );
    let delivered = thr.check_signals(&mut memory, &mut uctx, None).unwrap();
    assert_eq!(delivered.os_action, SignalOSAction::Handler);
    assert!(delivered.restartable_handler);
    assert!(matches!(
        proc.action(signo).disposition,
        SignalDisposition::Default
    ));
}

#[test]
fn reset_hand_copyout_fault_rolls_back_the_one_shot_claim() {
    let (proc, thr) = new_test_env();
    let signo = Signo::SIGTERM;
    replace_action(
        &proc,
        signo,
        handler_action(0x4000, SignalActionFlags::RESETHAND),
    );

    assert!(thr.send_unqueued_signal(SignalInfo::new_user(signo, 1, 1)));
    let mut denied = PartialReadFailure;
    let mut denied_memory = UserMemoryContext::new(&mut denied);
    let mut context = UserContext::new(0x1000, initial_sp().into(), 0);
    let delivered = thr
        .check_signals(&mut denied_memory, &mut context, None)
        .unwrap();
    assert_eq!(delivered.os_action, SignalOSAction::CoreDump);
    assert!(matches!(
        proc.action(signo).disposition,
        SignalDisposition::Handler(0x4000)
    ));

    assert!(thr.send_unqueued_signal(SignalInfo::new_user(signo, 1, 1)));
    let mut provider = memory_provider();
    let mut memory = UserMemoryContext::new(&mut provider);
    let mut context = UserContext::new(0x1000, initial_sp().into(), 0);
    let delivered = thr.check_signals(&mut memory, &mut context, None).unwrap();
    assert_eq!(delivered.os_action, SignalOSAction::Handler);
    assert!(matches!(
        proc.action(signo).disposition,
        SignalDisposition::Default
    ));
}

#[test]
fn restore() {
    let (proc, thr) = new_test_env();

    let signo = Signo::SIGTERM;
    let sig = SignalInfo::new_user(signo, 0, 1);

    unsafe extern "C" fn test_handler(_: i32) {}
    replace_action(
        &proc,
        signo,
        handler_action(test_handler as usize, SignalActionFlags::empty()),
    );

    let initial = UserContext::new(0x219, initial_sp().into(), 0);

    let mut uctx = initial;
    let mut provider = memory_provider();
    let mut memory = UserMemoryContext::new(&mut provider);
    let restore_blocked = thr.blocked();
    let action = proc.action(sig.signo());
    thr.handle_signal(&mut memory, &mut uctx, restore_blocked, &sig, &action);

    let new_sp = uctx.sp() + 8;
    uctx.set_sp(new_sp);
    let frame = copy_signal_frame(&mut memory, &uctx);
    let prepared = thr
        .prepare_restore(&uctx, frame, |_| true, |_| true, |_, _, _| Ok(()))
        .unwrap();
    thr.commit_restore(&mut uctx, prepared);

    assert_eq!(uctx.ip(), initial.ip());
    assert_eq!(uctx.sp(), initial.sp());
}

#[test]
fn restore_rejects_bad_context_without_partial_commit() {
    let (proc, thr) = new_test_env();
    let signo = Signo::SIGTERM;
    let sig = SignalInfo::new_user(signo, 0, 1);

    unsafe extern "C" fn test_handler(_: i32) {}
    replace_action(
        &proc,
        signo,
        handler_action(test_handler as usize, SignalActionFlags::empty()),
    );

    let initial = UserContext::new(0x4000, initial_sp().into(), 0);
    let mut current = initial;
    let mut provider = memory_provider();
    let mut memory = UserMemoryContext::new(&mut provider);
    let action = proc.action(signo);
    thr.handle_signal(&mut memory, &mut current, thr.blocked(), &sig, &action);
    let frame_sp = current.sp() + 8;
    current.set_sp(frame_sp);

    let frame = copy_signal_frame(&mut memory, &current);
    let handler_ip = current.ip();
    let handler_sp = current.sp();
    let blocked_before = thr.blocked();
    let result = thr.prepare_restore(&current, frame, |_| false, |_| true, |_, _, _| Ok(()));

    assert!(matches!(
        result,
        Err(SignalContextError::InvalidProgramCounter)
    ));
    assert_eq!(current.ip(), handler_ip);
    assert_eq!(current.sp(), handler_sp);
    assert_eq!(
        format!("{:?}", thr.blocked()),
        format!("{blocked_before:?}")
    );
}

#[test]
fn restore_never_blocks_sigkill_or_sigstop() {
    let (proc, thr) = new_test_env();
    let signo = Signo::SIGTERM;
    let sig = SignalInfo::new_user(signo, 0, 1);

    unsafe extern "C" fn test_handler(_: i32) {}
    replace_action(
        &proc,
        signo,
        handler_action(test_handler as usize, SignalActionFlags::empty()),
    );

    let mut current = UserContext::new(0x4000, initial_sp().into(), 0);
    let mut provider = memory_provider();
    let mut memory = UserMemoryContext::new(&mut provider);
    let action = proc.action(signo);
    thr.handle_signal(&mut memory, &mut current, thr.blocked(), &sig, &action);
    let frame_sp = current.sp() + 8;
    current.set_sp(frame_sp);

    let mut frame = copy_signal_frame(&mut memory, &current);
    frame.ucontext_mut().sigmask.add(Signo::SIGKILL);
    frame.ucontext_mut().sigmask.add(Signo::SIGSTOP);
    let prepared = thr
        .prepare_restore(&current, frame, |_| true, |_| true, |_, _, _| Ok(()))
        .unwrap();
    thr.commit_restore(&mut current, prepared);

    assert!(!thr.blocked().has(Signo::SIGKILL));
    assert!(!thr.blocked().has(Signo::SIGSTOP));
}

#[test]
fn sigreturn_validates_and_commits_altstack_with_context_and_mask() {
    let (proc, thr) = new_test_env();
    let signo = Signo::SIGTERM;
    let sig = SignalInfo::new_user(signo, 0, 1);
    replace_action(
        &proc,
        signo,
        handler_action(0x4000, SignalActionFlags::empty()),
    );

    let initial = UserContext::new(0x2000, initial_sp().into(), 0);
    let mut current = initial;
    let mut provider = memory_provider();
    let mut memory = UserMemoryContext::new(&mut provider);
    let action = proc.action(signo);
    assert_eq!(
        thr.handle_signal(&mut memory, &mut current, thr.blocked(), &sig, &action),
        Some(SignalOSAction::Handler)
    );
    point_at_signal_frame(&mut current);

    let mut frame = copy_signal_frame(&mut memory, &current);
    let candidate = SignalStack::new(initial_sp() - 0x4000, 0, 0x2000);
    frame.ucontext_mut().stack = candidate.clone();
    let prepared = thr
        .prepare_restore(
            &current,
            frame,
            |_| true,
            |_| true,
            |configured, syscall_sp, proposed| {
                assert!(configured.disabled());
                assert_eq!(syscall_sp, current.sp());
                assert_eq!(proposed, &candidate);
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(prepared.stack(), Some(&candidate));
    assert_eq!(prepared.stack_error(), None);

    thr.commit_restore(&mut current, prepared);
    assert_eq!(current.ip(), initial.ip());
    assert_eq!(current.sp(), initial.sp());
    assert_eq!(thr.stack(), candidate);
}

#[test]
fn sigreturn_squashes_bad_altstack_update_without_partial_state() {
    let (proc, thr) = new_test_env();
    let signo = Signo::SIGTERM;
    let sig = SignalInfo::new_user(signo, 0, 1);
    replace_action(
        &proc,
        signo,
        handler_action(0x4000, SignalActionFlags::empty()),
    );
    let configured = SignalStack::new(initial_sp() - 0x4000, 0, 0x2000);
    thr.set_stack(configured.clone());

    let initial = UserContext::new(0x2000, initial_sp().into(), 0);
    let mut current = initial;
    let mut provider = memory_provider();
    let mut memory = UserMemoryContext::new(&mut provider);
    let action = proc.action(signo);
    assert_eq!(
        thr.handle_signal(&mut memory, &mut current, thr.blocked(), &sig, &action),
        Some(SignalOSAction::Handler)
    );
    point_at_signal_frame(&mut current);

    let mut frame = copy_signal_frame(&mut memory, &current);
    frame.ucontext_mut().stack = SignalStack::new(0x8000, 0x40, 0x2000);
    let prepared = thr
        .prepare_restore(
            &current,
            frame,
            |_| true,
            |_| true,
            |_, _, _| panic!("structurally invalid stack must not reach policy"),
        )
        .unwrap();
    assert!(prepared.stack().is_none());
    assert_eq!(
        prepared.stack_error(),
        Some(SignalStackRestoreError::InvalidFlags)
    );

    thr.commit_restore(&mut current, prepared);
    assert_eq!(current.ip(), initial.ip());
    assert_eq!(current.sp(), initial.sp());
    assert_eq!(thr.stack(), configured);
}

#[test]
fn sigreturn_squashes_consumer_altstack_policy_error() {
    let (proc, thr) = new_test_env();
    let signo = Signo::SIGTERM;
    let sig = SignalInfo::new_user(signo, 0, 1);
    replace_action(
        &proc,
        signo,
        handler_action(0x4000, SignalActionFlags::empty()),
    );
    let configured = SignalStack::new(initial_sp() - 0x4000, 0, 0x2000);
    thr.set_stack(configured.clone());

    let mut current = UserContext::new(0x2000, initial_sp().into(), 0);
    let mut provider = memory_provider();
    let mut memory = UserMemoryContext::new(&mut provider);
    assert_eq!(
        thr.handle_signal(
            &mut memory,
            &mut current,
            thr.blocked(),
            &sig,
            &proc.action(signo),
        ),
        Some(SignalOSAction::Handler)
    );
    point_at_signal_frame(&mut current);
    let mut frame = copy_signal_frame(&mut memory, &current);
    frame.ucontext_mut().stack = SignalStack::new(0x8000, 0, 0x2000);

    let prepared = thr
        .prepare_restore(
            &current,
            frame,
            |_| true,
            |_| true,
            |_, _, _| Err(SignalStackRestoreError::ActiveStack),
        )
        .unwrap();
    assert_eq!(
        prepared.stack_error(),
        Some(SignalStackRestoreError::ActiveStack)
    );
    thr.commit_restore(&mut current, prepared);
    assert_eq!(thr.stack(), configured);
}

#[cfg(target_arch = "x86_64")]
#[test]
fn restore_sanitizes_x86_privileged_flags_and_rejects_bad_cs() {
    let (proc, thr) = new_test_env();
    let signo = Signo::SIGTERM;
    let sig = SignalInfo::new_user(signo, 0, 1);

    unsafe extern "C" fn test_handler(_: i32) {}
    replace_action(
        &proc,
        signo,
        handler_action(test_handler as usize, SignalActionFlags::empty()),
    );

    let mut current = UserContext::new(0x4000, initial_sp().into(), 0);
    let mut provider = memory_provider();
    let mut memory = UserMemoryContext::new(&mut provider);
    let action = proc.action(signo);
    thr.handle_signal(&mut memory, &mut current, thr.blocked(), &sig, &action);
    let frame_sp = current.sp() + 8;
    current.set_sp(frame_sp);

    let mut frame = copy_signal_frame(&mut memory, &current);
    let trusted_flags = current.rflags;
    frame
        .ucontext_mut()
        .mcontext
        .set_processor_flags(trusted_flags as usize | (0b11 << 12));
    let prepared = thr
        .prepare_restore(
            &current,
            frame.clone(),
            |_| true,
            |_| true,
            |_, _, _| Ok(()),
        )
        .unwrap();
    assert_eq!(prepared.context().rflags & (0b11 << 12), 0);
    assert_eq!(
        prepared.context().rflags & (1 << 9),
        trusted_flags & (1 << 9)
    );

    frame.ucontext_mut().mcontext.set_code_segment(0);
    assert!(matches!(
        thr.prepare_restore(&current, frame, |_| true, |_| true, |_, _, _| Ok(()),),
        Err(SignalContextError::InvalidProcessorState)
    ));
}

#[test]
fn signal_frame_copy_rejects_unmapped_and_unaligned_addresses() {
    let mut provider = memory_provider();
    let mut memory = UserMemoryContext::new(&mut provider);
    assert!(SignalFrame::read_from_user(&mut memory, std::ptr::dangling::<SignalFrame>()).is_err());

    let unaligned = initial_sp() - 1;
    assert!(SignalFrame::read_from_user(&mut memory, unaligned as *const SignalFrame).is_err());

    let mut partial = PartialReadFailure;
    let mut partial_memory = UserMemoryContext::new(&mut partial);
    assert!(
        SignalFrame::read_from_user(&mut partial_memory, 0x1000 as *const SignalFrame).is_err()
    );
}

#[cfg(target_arch = "x86_64")]
#[test]
fn restorer_copyout_fault_never_publishes_partial_handler_state() {
    let (proc, thr) = new_test_env();
    let signo = Signo::SIGTERM;
    let sig = SignalInfo::new_user(signo, 7, 9);
    replace_action(
        &proc,
        signo,
        SignalAction {
            disposition: SignalDisposition::Handler(0x4000),
            restorer: Some(0x5000),
            flags: SignalActionFlags::RESETHAND,
            ..SignalAction::default()
        },
    );

    let top = initial_sp();
    let layout = std::alloc::Layout::new::<SignalFrame>();
    let frame_start = top.checked_sub(layout.size()).unwrap() & !(layout.align() - 1);
    let published_sp = frame_start - core::mem::size_of::<usize>();
    let mut provider = RejectWriteAt {
        inner: memory_provider(),
        address: published_sp,
    };
    let mut memory = UserMemoryContext::new(&mut provider);
    let initial = UserContext::new(0x1000, top.into(), 0);
    let mut context = initial;
    let blocked = thr.blocked();
    let action = proc.action(signo);

    assert_eq!(
        thr.handle_signal(&mut memory, &mut context, blocked, &sig, &action),
        Some(SignalOSAction::CoreDump)
    );
    assert_eq!(context.ip(), initial.ip());
    assert_eq!(context.sp(), initial.sp());
    assert_eq!(format!("{:?}", thr.blocked()), format!("{blocked:?}"));
    assert!(matches!(
        proc.action(signo).disposition,
        SignalDisposition::Handler(_)
    ));
}

#[cfg(target_arch = "x86_64")]
#[test]
fn signal_frame_write_initializes_every_explicit_abi_padding_byte() {
    let (proc, thr) = new_test_env();
    let signo = Signo::SIGTERM;
    let sig = SignalInfo::new_user(signo, 7, 9);
    replace_action(
        &proc,
        signo,
        handler_action(0x4000, SignalActionFlags::empty()),
    );

    let top = initial_sp();
    let layout = std::alloc::Layout::new::<SignalFrame>();
    let frame_start = top.checked_sub(layout.size()).unwrap() & !(layout.align() - 1);
    let poison = vec![0xa5; layout.size()];
    let mut provider = memory_provider();
    let mut memory = UserMemoryContext::new(&mut provider);
    memory.write_bytes(frame_start, &poison).unwrap();

    let mut context = UserContext::new(0x1000, top.into(), 0);
    let action = proc.action(signo);
    assert_eq!(
        thr.handle_signal(&mut memory, &mut context, thr.blocked(), &sig, &action),
        Some(SignalOSAction::Handler)
    );

    let mut byte_at = |offset: usize| {
        let mut byte = [MaybeUninit::uninit()];
        memory.read_bytes(frame_start + offset, &mut byte).unwrap();
        // SAFETY: the test UserMemory provider initializes the byte on success.
        unsafe { byte[0].assume_init() }
    };
    let stack_padding = core::mem::offset_of!(thekernel_linux_signal::arch::UContext, stack)
        + core::mem::offset_of!(SignalStack, flags)
        + core::mem::size_of::<u32>();
    for offset in stack_padding..stack_padding + 4 {
        assert_eq!(byte_at(offset), 0);
    }

    let mcontext = core::mem::offset_of!(thekernel_linux_signal::arch::UContext, mcontext);
    for offset in mcontext - 8..mcontext {
        assert_eq!(byte_at(offset), 0);
    }
    for offset in core::mem::size_of::<thekernel_linux_signal::arch::UContext>() - 8
        ..core::mem::size_of::<thekernel_linux_signal::arch::UContext>()
    {
        assert_eq!(byte_at(offset), 0);
    }
}
