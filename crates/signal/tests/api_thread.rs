use std::{
    cell::Cell,
    mem::{MaybeUninit, align_of, offset_of, size_of},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use axcpu::uspace::UserContext;
use linux_raw_sys::general::{SS_DISABLE, SS_ONSTACK};
use thekernel_linux_signal::{
    PreparedSignal, SignalAction, SignalActionFlags, SignalDisposition, SignalInfo, SignalOSAction,
    SignalQueueAccount, SignalSet, SignalStack, SignalStackRestoreError, Signo,
    api::{
        ProcessSignalManager, SIGNAL_RED_ZONE, SignalDeliveryPreflight, SignalDeliveryResult,
        SignalFrame, SignalPreHandlerError, SignalWaitObservation,
    },
    arch::{LegacyFpState64, MContext, SignalContextError, UContext},
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

struct CountingWrites {
    inner: Vm,
    writes: Arc<AtomicUsize>,
}

// SAFETY: all accesses delegate to the range-checking test VM. The counter is
// independent of the provider's memory safety contract and only observes
// complete write attempts.
unsafe impl UserMemory for CountingWrites {
    fn read(&mut self, start: usize, dst: &mut [MaybeUninit<u8>]) -> VmResult {
        self.inner.read(start, dst)
    }

    fn write(&mut self, start: usize, src: &[u8]) -> VmResult {
        self.writes.fetch_add(1, Ordering::Relaxed);
        self.inner.write(start, src)
    }
}

struct RejectWriteAt {
    inner: Vm,
    address: usize,
}

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
    let frame = uctx.sp() + core::mem::size_of::<usize>();
    uctx.set_sp(frame);
}

#[test]
fn x86_64_signal_context_matches_linux_layout() {
    assert_eq!(align_of::<MContext>(), 8);
    assert_eq!(size_of::<MContext>(), 256);
    assert_eq!(offset_of!(UContext, mcontext), 40);
    assert_eq!(offset_of!(UContext, sigmask), 296);
    assert_eq!(size_of::<UContext>(), 304);
}

#[test]
fn dequeue_signal() {
    let (proc, thr) = new_test_env();

    let sig1 = SignalInfo::new_user(Signo::SIGINT, 9, 9, 0);
    assert!(thr.send_unqueued_signal(sig1));

    let sig2 = SignalInfo::new_user(Signo::SIGTERM, 9, 9, 0);
    assert_eq!(proc.send_unqueued_signal(sig2), Some(TID));

    let mask = !SignalSet::default();
    assert_eq!(thr.dequeue_signal(&mask).unwrap().signo(), Signo::SIGINT);
    assert_eq!(thr.dequeue_signal(&mask).unwrap().signo(), Signo::SIGTERM);
    assert!(thr.dequeue_signal(&mask).is_none());
}

#[test]
fn signalfd_selection_requires_fd_mask_and_current_blocked_mask() {
    let (proc, thr) = new_test_env();

    let mut fd_mask = SignalSet::default();
    fd_mask.add(Signo::SIGUSR1);
    fd_mask.add(Signo::SIGUSR2);

    let mut blocked = SignalSet::default();
    blocked.add(Signo::SIGUSR1);
    thr.set_blocked(blocked);

    let _ = thr.send_unqueued_signal(SignalInfo::new_user(Signo::SIGUSR1, 0, 1, 0));
    assert!(thr.pending().has(Signo::SIGUSR1));
    assert_eq!(
        proc.send_unqueued_signal(SignalInfo::new_user(Signo::SIGUSR2, 0, 2, 0)),
        Some(TID)
    );

    assert!(thr.has_pending_signal_for_signalfd(&fd_mask));
    assert_eq!(
        thr.dequeue_signal_for_signalfd(&fd_mask)
            .expect("blocked fd signal must be readable")
            .signo(),
        Signo::SIGUSR1
    );
    assert!(thr.pending().has(Signo::SIGUSR2));

    // The same fd mask must not consume a signal which is currently
    // unblocked. Changing the thread mask makes the pending process signal
    // visible to the canonical selection path.
    assert!(!thr.has_pending_signal_for_signalfd(&fd_mask));
    blocked.remove(Signo::SIGUSR1);
    blocked.add(Signo::SIGUSR2);
    thr.set_blocked(blocked);
    assert!(thr.has_pending_signal_for_signalfd(&fd_mask));
    assert_eq!(
        thr.dequeue_signal_for_signalfd(&fd_mask)
            .expect("newly blocked fd signal must be readable")
            .signo(),
        Signo::SIGUSR2
    );
    assert!(thr.dequeue_signal_for_signalfd(&fd_mask).is_none());
}

#[test]
fn signalfd_fd_mask_changes_do_not_consume_pending_signals() {
    let (_proc, thr) = new_test_env();
    let signo = Signo::SIGUSR1;

    let mut blocked = SignalSet::default();
    blocked.add(signo);
    thr.set_blocked(blocked);
    let _ = thr.send_unqueued_signal(SignalInfo::new_user(signo, 0, 1, 0));
    assert!(thr.pending().has(signo));

    let mut empty_mask = SignalSet::default();
    assert!(!thr.has_pending_signal_for_signalfd(&empty_mask));
    assert!(thr.dequeue_signal_for_signalfd(&empty_mask).is_none());
    assert!(thr.pending().has(signo));

    empty_mask.add(signo);
    assert!(thr.has_pending_signal_for_signalfd(&empty_mask));
    assert_eq!(
        thr.dequeue_signal_for_signalfd(&empty_mask)
            .expect("updated fd mask must expose the pending signal")
            .signo(),
        signo
    );
}

#[test]
fn handle_signal() {
    let (proc, thr) = new_test_env();

    let signo = Signo::SIGTERM;
    let sig = SignalInfo::new_user(signo, 9, 9, 0);

    unsafe extern "C" fn test_handler(_: i32) {}
    replace_action(
        &proc,
        signo,
        handler_action(
            test_handler as *const () as usize,
            SignalActionFlags::empty(),
        ),
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
    let sig = SignalInfo::new_user(signo, 9, 9, 0);

    unsafe extern "C" fn test_handler(_: i32) {}
    replace_action(
        &proc,
        signo,
        handler_action(
            test_handler as *const () as usize,
            SignalActionFlags::ONSTACK,
        ),
    );

    let alt_top = initial_sp();
    let alt_size = 0x8000;
    let alt_stack = SignalStack::new(alt_top - alt_size, 0, alt_size);
    thr.set_stack(alt_stack);

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
    let sig = SignalInfo::new_user(signo, 9, 9, 0);

    unsafe extern "C" fn test_handler(_: i32) {}
    replace_action(
        &proc,
        signo,
        handler_action(
            test_handler as *const () as usize,
            SignalActionFlags::ONSTACK,
        ),
    );
    thr.set_stack(SignalStack::new(usize::MAX - 8, 0, 16));

    let initial = UserContext::new(0x1234, initial_sp().into(), 0);
    let mut uctx = initial;
    let mut provider = memory_provider();
    let mut memory = UserMemoryContext::new(&mut provider);
    let action = proc.action(signo);
    assert_eq!(
        thr.handle_signal_with_pre_handler(
            &mut memory,
            &mut uctx,
            thr.blocked(),
            &sig,
            &action,
            |_, context| {
                context.set_ip(0xdead_beef);
                context.set_sp(0xfeed_cafe);
                Ok::<(), ()>(())
            },
        )
        .unwrap(),
        Some(SignalOSAction::CoreDump)
    );
    assert_eq!(uctx.ip(), initial.ip());
    assert_eq!(uctx.sp(), initial.sp());
}

#[test]
fn block_ignore_send_signal() {
    let (proc, thr) = new_test_env();

    let signo = Signo::SIGINT;
    let sig = SignalInfo::new_user(signo, 0, 1, 0);
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
fn thread_prepared_send_defers_ignored_record_release() {
    let (proc, thread) = new_test_env();
    replace_action(
        &proc,
        Signo::SIGRTMIN,
        SignalAction {
            disposition: SignalDisposition::Ignore,
            ..SignalAction::default()
        },
    );
    let endpoint = thread.try_prepare_signal_send().unwrap();
    let per_user = SignalQueueAccount::try_new(4).unwrap();
    let global = SignalQueueAccount::try_new(4).unwrap();
    let prepared = PreparedSignal::try_accounted(
        SignalInfo::new_user(Signo::SIGRTMIN, -1, 100, 0),
        &per_user,
        4,
        &global,
    )
    .unwrap();

    let deferred = endpoint.publish(prepared);
    assert!(!deferred.outcome().published);
    assert!(!deferred.outcome().wake);
    assert_eq!(per_user.queued(), 1);
    assert_eq!(global.queued(), 1);

    let (_, unused) = deferred.finish();
    assert!(unused.is_some());
    assert_eq!(per_user.queued(), 1);
    drop(unused);
    assert_eq!(per_user.queued(), 0);
    assert_eq!(global.queued(), 0);
}

#[test]
fn thread_prepared_send_rechecks_endpoint_cancellation() {
    let (_proc, thread) = new_test_env();
    let endpoint = thread.try_prepare_signal_send().unwrap();
    assert!(thread.cancel_registration());

    let per_user = SignalQueueAccount::try_new(4).unwrap();
    let global = SignalQueueAccount::try_new(4).unwrap();
    let prepared = PreparedSignal::try_accounted(
        SignalInfo::new_user(Signo::SIGRTMIN, -1, 100, 0),
        &per_user,
        4,
        &global,
    )
    .unwrap();
    let deferred = endpoint.publish(prepared);
    assert!(!deferred.outcome().published);
    assert!(!deferred.outcome().wake);
    assert_eq!(per_user.queued(), 1);

    let (_, unused) = deferred.finish();
    assert!(unused.is_some());
    drop(unused);
    assert_eq!(per_user.queued(), 0);
    assert_eq!(global.queued(), 0);
}

#[test]
fn thread_prepared_send_cannot_cross_registration_reuse() {
    let (_proc, thread) = new_test_env();
    let stale = thread.try_prepare_signal_send().unwrap();
    assert!(thread.cancel_registration());
    thread.try_register(99).unwrap().commit().unwrap();

    let per_user = SignalQueueAccount::try_new(4).unwrap();
    let global = SignalQueueAccount::try_new(4).unwrap();
    let prepared = PreparedSignal::try_accounted(
        SignalInfo::new_user(Signo::SIGRTMIN, -1, 100, 0),
        &per_user,
        4,
        &global,
    )
    .unwrap();

    let deferred = stale.publish(prepared);
    assert!(!deferred.outcome().published);
    assert!(!deferred.outcome().wake);
    let (_, unused) = deferred.finish();
    assert!(unused.is_some());
    drop(unused);
    assert_eq!(per_user.queued(), 0);
    assert_eq!(global.queued(), 0);

    let current = thread.try_prepare_signal_send().unwrap();
    let outcome = current.publish(PreparedSignal::unqueued(SignalInfo::new_user(
        Signo::SIGTERM,
        -1,
        100,
        0,
    )));
    assert!(outcome.outcome().published);
    assert!(outcome.outcome().wake);
    let (_, unused) = outcome.finish();
    assert!(unused.is_none());
}

#[test]
fn check_signals() {
    let (proc, thr) = new_test_env();

    let mut uctx = UserContext::new(0, 0.into(), 0);
    let mut provider = memory_provider();
    let mut memory = UserMemoryContext::new(&mut provider);

    let signo = Signo::SIGTERM;
    let sig = SignalInfo::new_user(signo, 0, 1, 0);

    assert_eq!(proc.send_unqueued_signal(sig.clone()), Some(TID));
    let delivered = thr.check_signals(&mut memory, &mut uctx, None).unwrap();
    assert_eq!(delivered.info.signo(), signo);

    assert!(thr.send_unqueued_signal(sig.clone()));
    let delivered = thr.check_signals(&mut memory, &mut uctx, None).unwrap();
    assert_eq!(delivered.info.signo(), signo);
}

#[test]
fn prepared_and_direct_thread_publications_return_exact_generations() {
    let (_proc, thr) = new_test_env();
    let endpoint = thr.try_prepare_signal_send().unwrap();
    let per_user = SignalQueueAccount::try_new(4).unwrap();
    let global = SignalQueueAccount::try_new(4).unwrap();
    let prepared = PreparedSignal::try_accounted(
        SignalInfo::new_user(Signo::SIGRTMIN, 1, 7, 0),
        &per_user,
        4,
        &global,
    )
    .unwrap();
    let deferred = endpoint.publish(prepared);
    let prepared_outcome = deferred.outcome();
    assert!(prepared_outcome.published);
    assert!(prepared_outcome.generation.is_some());
    let (_, unused) = deferred.finish();
    assert!(unused.is_none());

    let direct = thr
        .try_send_signal_with(SignalInfo::new_user(Signo::SIGRTMIN, 2, 7, 0), |info| {
            PreparedSignal::try_accounted(info, &per_user, 4, &global)
        })
        .unwrap();
    assert!(direct.published);
    assert!(direct.generation.is_some());
    assert_ne!(direct.generation, prepared_outcome.generation);
}

#[test]
fn fallback_and_coalesced_thread_publications_have_no_generation() {
    let (proc, thr) = new_test_env();
    let signo = Signo::SIGTERM;
    let first = thr
        .try_send_signal_with(SignalInfo::new_user(signo, 1, 1, 0), |info| {
            Ok::<_, core::convert::Infallible>(PreparedSignal::unqueued(info))
        })
        .unwrap();
    assert!(first.published);
    assert!(first.generation.is_some());
    let duplicate = thr
        .try_send_signal_with(SignalInfo::new_user(signo, 2, 2, 0), |info| {
            Ok::<_, core::convert::Infallible>(PreparedSignal::unqueued(info))
        })
        .unwrap();
    assert!(!duplicate.published);
    assert!(duplicate.generation.is_none());

    let rt = Signo::SIGRTMIN;
    replace_action(
        &proc,
        rt,
        SignalAction {
            disposition: SignalDisposition::Handler(0x4000),
            ..SignalAction::default()
        },
    );
    let fallback = thr
        .try_send_signal_with(SignalInfo::new_user(rt, 3, 3, 0), |info| {
            Ok::<_, core::convert::Infallible>(PreparedSignal::unqueued(info))
        })
        .unwrap();
    assert!(fallback.published);
    assert!(fallback.generation.is_none());
}

#[test]
fn prepared_thread_job_control_send_flushes_live_and_retained_queues() {
    let (proc, active) = new_test_env();
    let retained = thekernel_linux_signal::api::ThreadSignalManager::try_new(proc.clone()).unwrap();
    retained.try_register(TID + 1).unwrap().commit().unwrap();

    assert!(active.send_unqueued_signal(SignalInfo::new_kernel(Signo::SIGSTOP)));
    assert!(retained.send_unqueued_signal(SignalInfo::new_kernel(Signo::SIGTSTP)));
    assert_eq!(
        proc.send_unqueued_signal(SignalInfo::new_kernel(Signo::SIGTTIN)),
        Some(TID)
    );
    retained.retire_registration(TID + 1, true);

    let endpoint = active.try_prepare_signal_send().unwrap();
    let deferred = endpoint.publish(PreparedSignal::unqueued(SignalInfo::new_kernel(
        Signo::SIGCONT,
    )));
    assert!(deferred.outcome().published);
    assert!(deferred.outcome().wake);
    assert!(deferred.finish().1.is_none());

    assert!(!active.pending().has(Signo::SIGSTOP));
    assert!(!retained.pending().has(Signo::SIGTSTP));
    assert!(!proc.pending().has(Signo::SIGTTIN));
    assert!(active.pending().has(Signo::SIGCONT));
}

#[test]
fn prepared_thread_send_rejects_retained_identity_and_reap_refunds_charge() {
    let (_proc, thread) = new_test_env();
    let stale = thread.try_prepare_signal_send().unwrap();
    let stale_again = thread.try_prepare_signal_send().unwrap();
    thread.retire_registration(TID, true);

    let per_user = SignalQueueAccount::try_new(1).unwrap();
    let global = SignalQueueAccount::try_new(1).unwrap();
    let prepared = PreparedSignal::try_accounted(
        SignalInfo::new_user(Signo::SIGRTMIN, 1, 1, 0),
        &per_user,
        1,
        &global,
    )
    .unwrap();
    let deferred = stale.publish(prepared);
    assert!(!deferred.outcome().published);
    let (_, unused) = deferred.finish();
    assert!(unused.is_some());
    drop(unused);
    assert_eq!(per_user.queued(), 0);
    assert_eq!(global.queued(), 0);

    thread.retire_registration(TID, false);
    let called = std::cell::Cell::new(false);
    let late = thread
        .try_send_retained_signal_with(SignalInfo::new_user(Signo::SIGTERM, 2, 2, 0), |info| {
            called.set(true);
            Ok::<_, core::convert::Infallible>(PreparedSignal::unqueued(info))
        })
        .unwrap();
    assert!(!late.published);
    assert!(!called.get());

    thread.try_register(TID + 2).unwrap().commit().unwrap();
    let stale_again = stale_again.publish(PreparedSignal::unqueued(SignalInfo::new_user(
        Signo::SIGTERM,
        3,
        3,
        0,
    )));
    assert!(!stale_again.outcome().published);
    assert!(stale_again.finish().1.is_some());
}

#[test]
fn dropping_a_retained_pending_registration_reclaims_private_records() {
    let (_proc, thread, admission) = new_unregistered_test_env();
    thread.retire_registration(TID, true);

    let per_user = SignalQueueAccount::try_new(1).unwrap();
    let global = SignalQueueAccount::try_new(1).unwrap();
    let outcome = thread
        .try_send_retained_signal_with(SignalInfo::new_user(Signo::SIGRTMIN, 9, 9, 0), |info| {
            PreparedSignal::try_accounted(info, &per_user, 1, &global)
        })
        .unwrap();
    assert!(outcome.published);
    assert_eq!(per_user.queued(), 1);
    assert_eq!(global.queued(), 1);

    // The admission never committed.  Its rollback must invalidate the
    // retained identity and drain the exact private queue before returning.
    drop(admission);
    assert!(!thread.is_registered());
    assert!(!thread.pending().has(Signo::SIGRTMIN));
    assert_eq!(per_user.queued(), 0);
    assert_eq!(global.queued(), 0);
}

#[test]
fn retry_requeues_exact_rt_node_and_preserves_fifo_siginfo_and_accounting() {
    let (proc, thr) = new_test_env();
    let user = SignalQueueAccount::try_new(4).unwrap();
    let global = SignalQueueAccount::try_new(4).unwrap();
    let signo = Signo::SIGRTMIN;
    replace_action(
        &proc,
        signo,
        handler_action(0x4000, SignalActionFlags::NODEFER),
    );
    for code in [11, 22] {
        thr.try_send_signal_with(SignalInfo::new_user(signo, code, 7, 0), |info| {
            PreparedSignal::try_accounted(info, &user, 4, &global)
        })
        .unwrap();
    }
    assert_eq!(user.queued(), 2);
    assert_eq!(global.queued(), 2);

    let mut provider = memory_provider();
    let mut memory = UserMemoryContext::new(&mut provider);
    let mut context = UserContext::new(0, initial_sp().into(), 0);
    let result = thr.check_signals_with_pre_delivery(&mut memory, &mut context, None, |_, _, _| {
        SignalDeliveryPreflight::Retry
    });
    assert!(matches!(result, SignalDeliveryResult::Retry));
    assert_eq!(user.queued(), 2);
    assert_eq!(global.queued(), 2);

    let waited = SignalSet::default();
    let result = thr.observe_signal_wait_with_pre_delivery(
        &mut memory,
        &mut context,
        &waited,
        SignalSet::default(),
        |_, _, _| SignalDeliveryPreflight::Proceed,
    );
    assert!(matches!(
        result,
        SignalWaitObservation::Delivered(delivered) if delivered.info.code() == 11
    ));
    assert_eq!(user.queued(), 1);
    assert_eq!(global.queued(), 1);

    let result = thr.check_signals_with_pre_delivery(&mut memory, &mut context, None, |_, _, _| {
        SignalDeliveryPreflight::Proceed
    });
    assert!(matches!(
        result,
        SignalDeliveryResult::Delivered(delivered) if delivered.info.code() == 22
    ));
    assert_eq!(user.queued(), 0);
    assert_eq!(global.queued(), 0);
}

#[test]
fn retry_requeues_process_rt_record_with_its_source_accounting() {
    let (proc, thr) = new_test_env();
    let user = SignalQueueAccount::try_new(2).unwrap();
    let global = SignalQueueAccount::try_new(2).unwrap();
    let signo = Signo::SIGRTMIN;
    replace_action(
        &proc,
        signo,
        handler_action(0x4000, SignalActionFlags::NODEFER),
    );
    let outcome = proc
        .try_send_signal_with(SignalInfo::new_user(signo, 31, 8, 0), |info| {
            PreparedSignal::try_accounted(info, &user, 2, &global)
        })
        .unwrap();
    assert!(outcome.published);
    assert_eq!(user.queued(), 1);
    assert_eq!(global.queued(), 1);

    let mut provider = memory_provider();
    let mut memory = UserMemoryContext::new(&mut provider);
    let mut context = UserContext::new(0, initial_sp().into(), 0);
    let result = thr.check_signals_with_pre_delivery(&mut memory, &mut context, None, |_, _, _| {
        SignalDeliveryPreflight::Fault
    });
    assert!(matches!(result, SignalDeliveryResult::Fault));
    assert_eq!(user.queued(), 1);
    assert_eq!(global.queued(), 1);

    let result = thr.check_signals_with_pre_delivery(&mut memory, &mut context, None, |_, _, _| {
        SignalDeliveryPreflight::Proceed
    });
    assert!(matches!(
        result,
        SignalDeliveryResult::Delivered(delivered)
            if delivered.info.code() == 31
    ));
    assert_eq!(user.queued(), 0);
    assert_eq!(global.queued(), 0);
}

#[test]
fn retry_drops_selected_process_record_if_process_retires() {
    let (proc, thr) = new_test_env();
    let user = SignalQueueAccount::try_new(1).unwrap();
    let global = SignalQueueAccount::try_new(1).unwrap();
    let signo = Signo::SIGRTMIN;
    replace_action(
        &proc,
        signo,
        handler_action(0x4000, SignalActionFlags::NODEFER),
    );
    let outcome = proc
        .try_send_signal_with(SignalInfo::new_user(signo, 41, 9, 0), |info| {
            PreparedSignal::try_accounted(info, &user, 1, &global)
        })
        .unwrap();
    assert!(outcome.published);
    assert_eq!(user.queued(), 1);
    assert_eq!(global.queued(), 1);

    let mut provider = memory_provider();
    let mut memory = UserMemoryContext::new(&mut provider);
    let mut context = UserContext::new(0, initial_sp().into(), 0);
    let result = thr.check_signals_with_pre_delivery(&mut memory, &mut context, None, |_, _, _| {
        proc.retire_pending();
        SignalDeliveryPreflight::Retry
    });
    assert!(matches!(result, SignalDeliveryResult::Retry));
    assert!(!proc.pending().has(signo));
    assert_eq!(user.queued(), 0);
    assert_eq!(global.queued(), 0);
}

#[test]
fn pre_delivery_skips_default_actions_and_runs_for_handler_frames() {
    let (proc, thr) = new_test_env();
    let mut provider = memory_provider();
    let mut memory = UserMemoryContext::new(&mut provider);
    let mut context = UserContext::new(0, initial_sp().into(), 0);
    let callbacks = Cell::new(0);

    assert!(thr.send_unqueued_signal(SignalInfo::new_kernel(Signo::SIGKILL)));
    let result = thr.check_signals_with_pre_delivery(&mut memory, &mut context, None, |_, _, _| {
        callbacks.set(callbacks.get() + 1);
        SignalDeliveryPreflight::Fault
    });
    assert!(matches!(
        result,
        SignalDeliveryResult::Delivered(delivered)
            if delivered.os_action == SignalOSAction::Terminate
    ));
    assert_eq!(callbacks.get(), 0);

    let signo = Signo::SIGUSR1;
    replace_action(
        &proc,
        signo,
        handler_action(0x4000, SignalActionFlags::empty()),
    );
    assert!(thr.send_unqueued_signal(SignalInfo::new_user(signo, 0, 1, 0)));
    let result = thr.check_signals_with_pre_delivery(&mut memory, &mut context, None, |_, _, _| {
        callbacks.set(callbacks.get() + 1);
        SignalDeliveryPreflight::Proceed
    });
    assert!(matches!(
        result,
        SignalDeliveryResult::Delivered(delivered)
            if delivered.os_action == SignalOSAction::Handler
    ));
    assert_eq!(callbacks.get(), 1);
}

#[test]
fn pre_delivery_retry_rolls_back_reset_hand_claim_and_user_context() {
    let (proc, thr) = new_test_env();
    let signo = Signo::SIGTERM;
    replace_action(
        &proc,
        signo,
        handler_action(0x4000, SignalActionFlags::RESETHAND),
    );
    assert!(thr.send_unqueued_signal(SignalInfo::new_user(signo, 1, 1, 0)));

    let mut provider = memory_provider();
    let mut memory = UserMemoryContext::new(&mut provider);
    let initial = UserContext::new(0x1000, initial_sp().into(), 0);
    let mut context = initial;
    let result =
        thr.check_signals_with_pre_delivery(&mut memory, &mut context, None, |uctx, _, _| {
            uctx.set_ip(0xdead_beef);
            SignalDeliveryPreflight::Retry
        });
    assert!(matches!(result, SignalDeliveryResult::Retry));
    assert_eq!(context.ip(), initial.ip());
    assert!(matches!(
        proc.action(signo).disposition,
        SignalDisposition::Handler(0x4000)
    ));
    assert!(thr.pending().has(signo));

    let result = thr.check_signals_with_pre_delivery(&mut memory, &mut context, None, |_, _, _| {
        SignalDeliveryPreflight::Proceed
    });
    assert!(matches!(
        result,
        SignalDeliveryResult::Delivered(delivered)
            if delivered.os_action == SignalOSAction::Handler
    ));
    assert!(matches!(
        proc.action(signo).disposition,
        SignalDisposition::Default
    ));
}

#[test]
fn exact_bypass_matches_signo_and_generation_once() {
    let (proc, thr) = new_test_env();
    let signo = Signo::SIGSEGV;
    let lower = Signo::SIGUSR1;
    replace_action(
        &proc,
        signo,
        handler_action(0x4000, SignalActionFlags::empty()),
    );
    replace_action(
        &proc,
        lower,
        handler_action(0x4000, SignalActionFlags::empty()),
    );
    assert!(thr.send_unqueued_signal(SignalInfo::new_kernel(lower)));
    let outcome = thr
        .try_send_signal_with(SignalInfo::new_kernel(signo), |info| {
            Ok::<_, core::convert::Infallible>(PreparedSignal::unqueued(info))
        })
        .unwrap();
    let generation = outcome.generation.expect("forced signal must publish");
    thr.arm_signal_delivery_bypass(signo, generation);

    let mut provider = memory_provider();
    let mut memory = UserMemoryContext::new(&mut provider);
    let mut context = UserContext::new(0, initial_sp().into(), 0);
    let result =
        thr.check_signals_with_pre_delivery(&mut memory, &mut context, None, |_, sig, _| {
            assert_eq!(sig.signo(), signo);
            assert!(thr.take_signal_delivery_bypass(signo));
            SignalDeliveryPreflight::Proceed
        });
    assert!(matches!(
        result,
        SignalDeliveryResult::Delivered(delivered)
            if delivered.info.signo() == signo
    ));
    let result = thr.check_signals_with_pre_delivery(&mut memory, &mut context, None, |_, _, _| {
        SignalDeliveryPreflight::Proceed
    });
    assert!(matches!(
        result,
        SignalDeliveryResult::Delivered(delivered) if delivered.info.signo() == lower
    ));
    assert!(!thr.take_signal_delivery_bypass(signo));
}

#[test]
fn stale_or_coalesced_bypass_cannot_consume_a_record() {
    let (proc, thr) = new_test_env();
    let signo = Signo::SIGSEGV;
    replace_action(
        &proc,
        signo,
        handler_action(0x4000, SignalActionFlags::empty()),
    );

    let old = thr
        .try_send_signal_with(SignalInfo::new_kernel(signo), |info| {
            Ok::<_, core::convert::Infallible>(PreparedSignal::unqueued(info))
        })
        .unwrap()
        .generation
        .expect("first record must publish");
    let duplicate = thr
        .try_send_signal_with(SignalInfo::new_kernel(signo), |info| {
            Ok::<_, core::convert::Infallible>(PreparedSignal::unqueued(info))
        })
        .unwrap();
    assert!(!duplicate.published);
    assert!(duplicate.generation.is_none());
    thr.flush_signal(signo);

    let fresh = thr
        .try_send_signal_with(SignalInfo::new_kernel(signo), |info| {
            Ok::<_, core::convert::Infallible>(PreparedSignal::unqueued(info))
        })
        .unwrap()
        .generation
        .expect("replacement record must publish");
    assert_ne!(fresh, old);
    thr.arm_signal_delivery_bypass(signo, old);

    let mut provider = memory_provider();
    let mut memory = UserMemoryContext::new(&mut provider);
    let mut context = UserContext::new(0, initial_sp().into(), 0);
    let result = thr.check_signals_with_pre_delivery(&mut memory, &mut context, None, |_, _, _| {
        assert!(!thr.take_signal_delivery_bypass(signo));
        SignalDeliveryPreflight::Fault
    });
    assert!(matches!(result, SignalDeliveryResult::Fault));
    assert!(thr.pending().has(signo));
}

#[test]
fn rseq_fault_coalescing_consumes_origin_or_fails_closed() {
    let (proc, thr) = new_test_env();
    let faulting = Signo::SIGUSR1;
    let segv = Signo::SIGSEGV;
    replace_action(
        &proc,
        faulting,
        handler_action(0x4000, SignalActionFlags::empty()),
    );
    replace_action(
        &proc,
        segv,
        handler_action(0x5000, SignalActionFlags::NODEFER),
    );

    // An existing standard SIGSEGV makes the origin-bound replacement
    // coalesce. The selected handler record must be consumed and the caller
    // must take the fatal path; requeueing it would select the same record
    // forever because SIGUSR1 sorts before SIGSEGV.
    let existing = thr
        .try_send_signal_with(SignalInfo::new_kernel(segv), |info| {
            Ok::<_, core::convert::Infallible>(PreparedSignal::unqueued(info))
        })
        .unwrap();
    assert!(existing.published);
    assert!(existing.generation.is_some());
    assert!(thr.send_unqueued_signal(SignalInfo::new_kernel(faulting)));

    let mut provider = memory_provider();
    let mut memory = UserMemoryContext::new(&mut provider);
    let mut context = UserContext::new(0, initial_sp().into(), 0);
    let result =
        thr.check_signals_with_pre_delivery(&mut memory, &mut context, None, |_, sig, _| {
            assert_eq!(sig.signo(), faulting);
            let coalesced = thr
                .try_send_signal_with(SignalInfo::new_kernel(segv), |info| {
                    Ok::<_, core::convert::Infallible>(PreparedSignal::unqueued(info))
                })
                .unwrap();
            assert!(!coalesced.published);
            assert!(coalesced.generation.is_none());
            SignalDeliveryPreflight::Fatal
        });
    assert!(matches!(result, SignalDeliveryResult::Fatal));
    assert!(!thr.pending().has(faulting));
    assert!(thr.pending().has(segv));

    // The kernel's fatal fallback changes SIGSEGV to its default action before
    // consuming the already-pending record. It must be deliverable now, with
    // no faulting handler record left to retry.
    replace_action(&proc, segv, SignalAction::default());
    let result = thr.check_signals_with_pre_delivery(&mut memory, &mut context, None, |_, _, _| {
        panic!("default SIGSEGV must not invoke the pre-delivery hook")
    });
    assert!(matches!(
        result,
        SignalDeliveryResult::Delivered(delivered)
            if delivered.info.signo() == segv
                && delivered.os_action == SignalOSAction::CoreDump
    ));
    assert!(!thr.pending().has(segv));
}

#[test]
fn rseq_replacement_bypass_uses_only_its_origin_generation() {
    let (proc, thr) = new_test_env();
    let faulting = Signo::SIGUSR1;
    let segv = Signo::SIGSEGV;
    replace_action(
        &proc,
        faulting,
        handler_action(0x4000, SignalActionFlags::empty()),
    );
    replace_action(
        &proc,
        segv,
        handler_action(0x5000, SignalActionFlags::NODEFER),
    );
    assert!(thr.send_unqueued_signal(SignalInfo::new_kernel(faulting)));

    let mut provider = memory_provider();
    let mut memory = UserMemoryContext::new(&mut provider);
    let mut context = UserContext::new(0, initial_sp().into(), 0);
    let result =
        thr.check_signals_with_pre_delivery(&mut memory, &mut context, None, |_, sig, _| {
            assert_eq!(sig.signo(), faulting);
            let forced = thr
                .try_send_signal_with(SignalInfo::new_kernel(segv), |info| {
                    Ok::<_, core::convert::Infallible>(PreparedSignal::unqueued(info))
                })
                .unwrap();
            let generation = forced
                .generation
                .expect("replacement must be uniquely published");
            thr.arm_signal_delivery_bypass(segv, generation);
            SignalDeliveryPreflight::Replaced
        });
    assert!(matches!(result, SignalDeliveryResult::Replaced));
    assert!(!thr.pending().has(faulting));

    // A later process-directed SIGSEGV is a different queue record and must
    // not steal the thread-private bypass.
    assert_eq!(
        proc.send_unqueued_signal(SignalInfo::new_kernel(segv)),
        Some(TID)
    );
    let result =
        thr.check_signals_with_pre_delivery(&mut memory, &mut context, None, |_, sig, _| {
            assert_eq!(sig.signo(), segv);
            assert!(thr.take_signal_delivery_bypass(segv));
            SignalDeliveryPreflight::Proceed
        });
    assert!(matches!(
        result,
        SignalDeliveryResult::Delivered(delivered) if delivered.info.signo() == segv
    ));

    let result =
        thr.check_signals_with_pre_delivery(&mut memory, &mut context, None, |_, sig, _| {
            assert_eq!(sig.signo(), segv);
            assert!(!thr.take_signal_delivery_bypass(segv));
            SignalDeliveryPreflight::Proceed
        });
    assert!(matches!(
        result,
        SignalDeliveryResult::Delivered(delivered) if delivered.info.signo() == segv
    ));
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
            test_handler as *const () as usize,
            SignalActionFlags::RESTART | SignalActionFlags::RESETHAND,
        ),
    );

    assert_eq!(
        proc.send_unqueued_signal(SignalInfo::new_user(signo, 0, 1, 0)),
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
fn fp_snapshot_runs_only_for_handler_after_preflight_and_layout() {
    let (proc, thr) = new_test_env();
    let signo = Signo::SIGUSR1;
    replace_action(
        &proc,
        signo,
        handler_action(0x4000, SignalActionFlags::empty()),
    );
    assert!(thr.send_unqueued_signal(SignalInfo::new_kernel(signo)));

    let mut provider = memory_provider();
    let mut memory = UserMemoryContext::new(&mut provider);
    let mut context = UserContext::new(0, initial_sp().into(), 0);
    let calls = Cell::new(0);
    let result = thr.check_signals_with_pre_delivery_and_fp_snapshot(
        &mut memory,
        &mut context,
        None,
        |_, _, _| SignalDeliveryPreflight::Proceed,
        || {
            calls.set(calls.get() + 1);
            LegacyFpState64::from_bytes([0x5a; LegacyFpState64::SIZE])
        },
    );
    assert!(matches!(
        result,
        SignalDeliveryResult::Delivered(delivered)
            if delivered.os_action == SignalOSAction::Handler
    ));
    assert_eq!(calls.get(), 1);

    for preflight in [
        SignalDeliveryPreflight::Retry,
        SignalDeliveryPreflight::Fault,
        SignalDeliveryPreflight::Replaced,
    ] {
        let (proc, thr) = new_test_env();
        replace_action(
            &proc,
            signo,
            handler_action(0x4000, SignalActionFlags::empty()),
        );
        assert!(thr.send_unqueued_signal(SignalInfo::new_kernel(signo)));
        let mut provider = memory_provider();
        let mut memory = UserMemoryContext::new(&mut provider);
        let mut context = UserContext::new(0, initial_sp().into(), 0);
        let calls = Cell::new(0);
        let result = thr.check_signals_with_pre_delivery_and_fp_snapshot(
            &mut memory,
            &mut context,
            None,
            |_, _, _| preflight,
            || {
                calls.set(calls.get() + 1);
                LegacyFpState64::default()
            },
        );
        assert!(matches!(
            (preflight, result),
            (SignalDeliveryPreflight::Retry, SignalDeliveryResult::Retry)
                | (SignalDeliveryPreflight::Fault, SignalDeliveryResult::Fault)
                | (
                    SignalDeliveryPreflight::Replaced,
                    SignalDeliveryResult::Replaced
                )
        ));
        assert_eq!(calls.get(), 0);
    }

    let (_proc, thr) = new_test_env();
    assert!(thr.send_unqueued_signal(SignalInfo::new_kernel(Signo::SIGKILL)));
    let mut provider = memory_provider();
    let mut memory = UserMemoryContext::new(&mut provider);
    let mut context = UserContext::new(0, initial_sp().into(), 0);
    let calls = Cell::new(0);
    let result = thr.check_signals_with_pre_delivery_and_fp_snapshot(
        &mut memory,
        &mut context,
        None,
        |_, _, _| panic!("default signal must not enter preflight"),
        || {
            calls.set(calls.get() + 1);
            LegacyFpState64::default()
        },
    );
    assert!(matches!(
        result,
        SignalDeliveryResult::Delivered(delivered)
            if delivered.os_action == SignalOSAction::Terminate
    ));
    assert_eq!(calls.get(), 0);

    let (proc, thr) = new_test_env();
    replace_action(
        &proc,
        signo,
        handler_action(0x4000, SignalActionFlags::empty()),
    );
    assert!(thr.send_unqueued_signal(SignalInfo::new_kernel(signo)));
    replace_action(
        &proc,
        signo,
        SignalAction {
            disposition: SignalDisposition::Ignore,
            ..SignalAction::default()
        },
    );
    let mut provider = memory_provider();
    let mut memory = UserMemoryContext::new(&mut provider);
    let mut context = UserContext::new(0, initial_sp().into(), 0);
    let calls = Cell::new(0);
    let result = thr.check_signals_with_pre_delivery_and_fp_snapshot(
        &mut memory,
        &mut context,
        None,
        |_, _, _| panic!("ignored signal must not enter preflight"),
        || {
            calls.set(calls.get() + 1);
            LegacyFpState64::default()
        },
    );
    assert!(matches!(result, SignalDeliveryResult::None));
    assert_eq!(calls.get(), 0);

    let (proc, thr) = new_test_env();
    replace_action(
        &proc,
        signo,
        handler_action(0x4000, SignalActionFlags::ONSTACK),
    );
    thr.set_stack(SignalStack::new(usize::MAX - 8, 0, 16));
    assert!(thr.send_unqueued_signal(SignalInfo::new_kernel(signo)));
    let mut provider = memory_provider();
    let mut memory = UserMemoryContext::new(&mut provider);
    let mut context = UserContext::new(0, initial_sp().into(), 0);
    let calls = Cell::new(0);
    let result = thr.check_signals_with_pre_delivery_and_fp_snapshot(
        &mut memory,
        &mut context,
        None,
        |_, _, _| SignalDeliveryPreflight::Proceed,
        || {
            calls.set(calls.get() + 1);
            LegacyFpState64::default()
        },
    );
    assert!(matches!(
        result,
        SignalDeliveryResult::Delivered(delivered)
            if delivered.os_action == SignalOSAction::CoreDump
    ));
    assert_eq!(calls.get(), 0);
}

#[test]
fn async_signal_wait_uses_pre_delivery_fp_snapshot() {
    let (proc, thr) = new_test_env();
    let signo = Signo::SIGUSR1;
    replace_action(
        &proc,
        signo,
        handler_action(0x4000, SignalActionFlags::empty()),
    );
    assert!(thr.send_unqueued_signal(SignalInfo::new_kernel(signo)));

    let waited = SignalSet::default();
    let mut provider = memory_provider();
    let mut memory = UserMemoryContext::new(&mut provider);
    let mut context = UserContext::new(0, initial_sp().into(), 0);
    let calls = Cell::new(0);
    let result = thr.observe_signal_wait_with_pre_delivery_and_fp_snapshot(
        &mut memory,
        &mut context,
        &waited,
        SignalSet::default(),
        |_, _, _| SignalDeliveryPreflight::Proceed,
        || {
            calls.set(calls.get() + 1);
            LegacyFpState64::from_bytes([0xa5; LegacyFpState64::SIZE])
        },
    );
    assert!(matches!(
        result,
        SignalWaitObservation::Delivered(delivered)
            if delivered.info.signo() == signo
                && delivered.os_action == SignalOSAction::Handler
    ));
    assert_eq!(calls.get(), 1);
}

#[test]
fn pre_handler_runs_once_before_signal_frame_snapshot() {
    let (proc, thr) = new_test_env();
    let signo = Signo::SIGTERM;
    unsafe extern "C" fn test_handler(_: i32) {}
    replace_action(
        &proc,
        signo,
        handler_action(
            test_handler as *const () as usize,
            SignalActionFlags::empty(),
        ),
    );
    assert!(thr.send_unqueued_signal(SignalInfo::new_user(signo, 1, 1, 0)));

    let initial = UserContext::new(0x1000, initial_sp().into(), 0);
    let mut context = initial;
    let mut provider = memory_provider();
    let mut memory = UserMemoryContext::new(&mut provider);
    let calls = std::cell::Cell::new(0);
    let snapshot_ip = 0xfeed_beef;

    let delivered = thr
        .check_signals_with_pre_handler(&mut memory, &mut context, None, |_, uctx| {
            calls.set(calls.get() + 1);
            assert_eq!(uctx.ip(), initial.ip());
            uctx.set_ip(snapshot_ip);
            Ok::<_, ()>(())
        })
        .unwrap()
        .unwrap();
    assert_eq!(calls.get(), 1);
    assert_eq!(delivered.os_action, SignalOSAction::Handler);
    assert_eq!(context.ip(), test_handler as *const () as usize);

    let mut frame_context = context;
    point_at_signal_frame(&mut frame_context);
    let frame = copy_signal_frame(&mut memory, &frame_context);
    let prepared = thr
        .prepare_restore(&context, frame, |_| true, |_| true, |_, _, _| Ok(()))
        .unwrap();
    assert_eq!(prepared.context().ip(), snapshot_ip);
}

#[test]
fn pre_handler_skips_ignored_default_and_blocked_signals() {
    let (proc, thr) = new_test_env();
    let mut context = UserContext::new(0x1000, initial_sp().into(), 0);
    let mut provider = memory_provider();
    let mut memory = UserMemoryContext::new(&mut provider);
    let calls = std::cell::Cell::new(0);

    let ignored_action = SignalAction {
        disposition: SignalDisposition::Ignore,
        ..SignalAction::default()
    };
    let ignored = thr.handle_signal_with_pre_handler(
        &mut memory,
        &mut context,
        SignalSet::default(),
        &SignalInfo::new_user(Signo::SIGUSR1, 1, 1, 0),
        &ignored_action,
        |_, _| {
            calls.set(calls.get() + 1);
            Ok::<_, ()>(())
        },
    );
    assert!(matches!(ignored, Ok(None)));

    let default = thr.handle_signal_with_pre_handler(
        &mut memory,
        &mut context,
        SignalSet::default(),
        &SignalInfo::new_user(Signo::SIGCHLD, 1, 1, 0),
        &SignalAction::default(),
        |_, _| {
            calls.set(calls.get() + 1);
            Ok::<_, ()>(())
        },
    );
    assert!(matches!(default, Ok(None)));

    let blocked_signo = Signo::SIGUSR2;
    replace_action(
        &proc,
        blocked_signo,
        handler_action(0x4000, SignalActionFlags::empty()),
    );
    let mut blocked = SignalSet::default();
    blocked.add(blocked_signo);
    thr.set_blocked(blocked);
    assert!(!thr.send_unqueued_signal(SignalInfo::new_user(blocked_signo, 1, 1, 0,)));
    let blocked_result =
        thr.check_signals_with_pre_handler(&mut memory, &mut context, None, |_, _| {
            calls.set(calls.get() + 1);
            Ok::<_, ()>(())
        });
    assert!(matches!(blocked_result, Ok(None)));
    assert!(thr.pending().has(blocked_signo));
    assert_eq!(calls.get(), 0);
}

#[test]
fn pre_handler_failure_writes_no_frame_and_rolls_back_reset_hand_claim() {
    let (proc, thr) = new_test_env();
    let signo = Signo::SIGTERM;
    replace_action(
        &proc,
        signo,
        handler_action(0x4000, SignalActionFlags::RESETHAND),
    );
    assert!(thr.send_unqueued_signal(SignalInfo::new_user(signo, 1, 1, 0)));

    let writes = Arc::new(AtomicUsize::new(0));
    let mut provider = CountingWrites {
        inner: memory_provider(),
        writes: Arc::clone(&writes),
    };
    let mut memory = UserMemoryContext::new(&mut provider);
    let initial = UserContext::new(0x1000, initial_sp().into(), 0);
    let mut context = initial;
    let result = thr.check_signals_with_pre_handler(&mut memory, &mut context, None, |_, uctx| {
        uctx.set_ip(0xdead);
        Err::<(), _>(7u8)
    });

    assert!(matches!(result, Err(SignalPreHandlerError::Hook(7u8))));
    assert_eq!(writes.load(Ordering::Relaxed), 0);
    assert_eq!(context.ip(), initial.ip());
    assert_eq!(context.sp(), initial.sp());
    assert!(matches!(
        proc.action(signo).disposition,
        SignalDisposition::Handler(0x4000)
    ));

    assert!(thr.send_unqueued_signal(SignalInfo::new_user(signo, 1, 1, 0)));
    let delivered = thr.check_signals(&mut memory, &mut context, None).unwrap();
    assert_eq!(delivered.os_action, SignalOSAction::Handler);
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

    assert!(thr.send_unqueued_signal(SignalInfo::new_user(signo, 1, 1, 0)));
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

    assert!(thr.send_unqueued_signal(SignalInfo::new_user(signo, 1, 1, 0)));
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
    let sig = SignalInfo::new_user(signo, 0, 1, 0);

    unsafe extern "C" fn test_handler(_: i32) {}
    replace_action(
        &proc,
        signo,
        handler_action(
            test_handler as *const () as usize,
            SignalActionFlags::empty(),
        ),
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
    let sig = SignalInfo::new_user(signo, 0, 1, 0);

    unsafe extern "C" fn test_handler(_: i32) {}
    replace_action(
        &proc,
        signo,
        handler_action(
            test_handler as *const () as usize,
            SignalActionFlags::empty(),
        ),
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
    let sig = SignalInfo::new_user(signo, 0, 1, 0);

    unsafe extern "C" fn test_handler(_: i32) {}
    replace_action(
        &proc,
        signo,
        handler_action(
            test_handler as *const () as usize,
            SignalActionFlags::empty(),
        ),
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
    let sig = SignalInfo::new_user(signo, 0, 1, 0);
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
    frame.ucontext_mut().stack = candidate;
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
    let sig = SignalInfo::new_user(signo, 0, 1, 0);
    replace_action(
        &proc,
        signo,
        handler_action(0x4000, SignalActionFlags::empty()),
    );
    let configured = SignalStack::new(initial_sp() - 0x4000, 0, 0x2000);
    thr.set_stack(configured);

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
    let sig = SignalInfo::new_user(signo, 0, 1, 0);
    replace_action(
        &proc,
        signo,
        handler_action(0x4000, SignalActionFlags::empty()),
    );
    let configured = SignalStack::new(initial_sp() - 0x4000, 0, 0x2000);
    thr.set_stack(configured);

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

#[test]
fn restore_sanitizes_x86_privileged_flags_and_rejects_bad_cs() {
    let (proc, thr) = new_test_env();
    let signo = Signo::SIGTERM;
    let sig = SignalInfo::new_user(signo, 0, 1, 0);

    unsafe extern "C" fn test_handler(_: i32) {}
    replace_action(
        &proc,
        signo,
        handler_action(
            test_handler as *const () as usize,
            SignalActionFlags::empty(),
        ),
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
fn signal_frame_copy_accepts_unaligned_but_rejects_unmapped_or_partial_reads() {
    let mut provider = memory_provider();
    let mut memory = UserMemoryContext::new(&mut provider);
    assert!(SignalFrame::read_from_user(&mut memory, std::ptr::dangling::<SignalFrame>()).is_err());

    let unaligned = initial_sp() - 1;
    assert!(SignalFrame::read_from_user(&mut memory, unaligned as *const SignalFrame).is_ok());

    let mut partial = PartialReadFailure;
    let mut partial_memory = UserMemoryContext::new(&mut partial);
    assert!(
        SignalFrame::read_from_user(&mut partial_memory, 0x1000 as *const SignalFrame).is_err()
    );
}

#[test]
fn restorer_copyout_fault_never_publishes_partial_handler_state() {
    let (proc, thr) = new_test_env();
    let signo = Signo::SIGTERM;
    let sig = SignalInfo::new_user(signo, 7, 9, 0);
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
    let frame_start = top
        .checked_sub(SIGNAL_RED_ZONE)
        .and_then(|sp| sp.checked_sub(layout.size()))
        .unwrap()
        & !(layout.align() - 1);
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
        thr.handle_signal_with_pre_handler(
            &mut memory,
            &mut context,
            blocked,
            &sig,
            &action,
            |_, context| {
                context.set_ip(0xdead_beef);
                context.set_sp(0xfeed_cafe);
                Ok::<(), ()>(())
            },
        )
        .unwrap(),
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

#[test]
fn signal_frame_write_initializes_every_explicit_abi_padding_byte() {
    let (proc, thr) = new_test_env();
    let signo = Signo::SIGTERM;
    let sig = SignalInfo::new_user(signo, 7, 9, 0);
    replace_action(
        &proc,
        signo,
        handler_action(0x4000, SignalActionFlags::empty()),
    );

    let top = initial_sp();
    let layout = std::alloc::Layout::new::<SignalFrame>();
    let frame_start = top
        .checked_sub(SIGNAL_RED_ZONE)
        .and_then(|sp| sp.checked_sub(layout.size()))
        .unwrap()
        & !(layout.align() - 1);
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
