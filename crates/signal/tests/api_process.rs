use std::sync::Arc;

use thekernel_linux_signal::{
    PreparedSignal, SignalAction, SignalActionFlags, SignalDisposition, SignalInfo,
    SignalQueueAccount, Signo,
    api::{ProcessSignalManager, SignalActions, ThreadSignalManager},
};

struct TestEnv {
    proc: Arc<ProcessSignalManager>,
}

impl TestEnv {
    fn new() -> Self {
        let proc = Arc::new(ProcessSignalManager::new(SignalActions::default(), 0));
        TestEnv { proc }
    }
}

#[test]
fn send_wakes_sets_pending() {
    let env = TestEnv::new();
    let thr = ThreadSignalManager::try_new(env.proc.clone()).unwrap();
    thr.try_register(9).unwrap().commit().unwrap();
    let sig = SignalInfo::new_user(Signo::SIGTERM, 0, 100);

    assert_eq!(env.proc.send_unqueued_signal(sig.clone()), Some(9));
    assert!(env.proc.pending().has(Signo::SIGTERM));
}

#[test]
fn rolled_back_registration_is_never_selected_for_wakeup() {
    let env = TestEnv::new();
    let rolled_back = ThreadSignalManager::try_new(env.proc.clone()).unwrap();
    drop(rolled_back.try_register(8).unwrap());

    let live = ThreadSignalManager::try_new(env.proc.clone()).unwrap();
    live.try_register(9).unwrap().commit().unwrap();

    let sig = SignalInfo::new_user(Signo::SIGTERM, 0, 100);
    assert_eq!(env.proc.send_unqueued_signal(sig), Some(9));
}

#[test]
fn signal_ignore() {
    let env = TestEnv::new();
    env.proc
        .try_replace_action(
            Signo::SIGTERM,
            SignalAction {
                disposition: SignalDisposition::Ignore,
                ..SignalAction::default()
            },
        )
        .unwrap();
    let sig = SignalInfo::new_user(Signo::SIGTERM, 0, 100);

    assert_eq!(env.proc.send_unqueued_signal(sig), None);
    assert!(!env.proc.pending().has(Signo::SIGTERM));
}

#[test]
fn prepared_send_defers_unused_queue_ownership_until_finish() {
    let env = TestEnv::new();
    let thread = ThreadSignalManager::try_new(env.proc.clone()).unwrap();
    thread.try_register(9).unwrap().commit().unwrap();
    env.proc
        .try_replace_action(
            Signo::SIGRTMIN,
            SignalAction {
                disposition: SignalDisposition::Ignore,
                ..SignalAction::default()
            },
        )
        .unwrap();

    let route = env.proc.try_prepare_signal_send().unwrap();
    let per_user = SignalQueueAccount::try_new(4).unwrap();
    let global = SignalQueueAccount::try_new(4).unwrap();
    let prepared = PreparedSignal::try_accounted(
        SignalInfo::new_user(Signo::SIGRTMIN, -1, 100),
        &per_user,
        4,
        &global,
    )
    .unwrap();

    let deferred = route.publish(prepared);
    assert!(!deferred.outcome().published);
    assert_eq!(deferred.outcome().wake_tid, None);
    assert_eq!(per_user.queued(), 1);
    assert_eq!(global.queued(), 1);

    let (outcome, unused) = deferred.finish();
    assert!(!outcome.published);
    assert!(unused.is_some());
    assert_eq!(per_user.queued(), 1);
    drop(unused);
    assert_eq!(per_user.queued(), 0);
    assert_eq!(global.queued(), 0);
}

#[test]
fn prepared_route_rejects_cancelled_registration_identity_after_tid_reuse() {
    let env = TestEnv::new();
    let thread = ThreadSignalManager::try_new(env.proc.clone()).unwrap();
    thread.try_register(41).unwrap().commit().unwrap();
    let stale_route = env.proc.try_prepare_signal_send().unwrap();

    assert!(thread.cancel_registration());
    thread.try_register(42).unwrap().commit().unwrap();
    let stale = stale_route.publish(PreparedSignal::unqueued(SignalInfo::new_user(
        Signo::SIGTERM,
        1,
        100,
    )));
    assert!(stale.outcome().published);
    assert_eq!(stale.outcome().wake_tid, None);
    assert!(stale.finish().1.is_none());

    let current_route = env.proc.try_prepare_signal_send().unwrap();
    let current = current_route.publish(PreparedSignal::unqueued(SignalInfo::new_user(
        Signo::SIGTERM,
        2,
        100,
    )));
    assert!(!current.outcome().published);
    assert_eq!(current.outcome().wake_tid, Some(42));
    let (_, unused) = current.finish();
    assert!(unused.is_some());
    drop(unused);
    env.proc.flush_pending();
}

#[test]
fn can_restart() {
    let env = TestEnv::new();
    assert!(!env.proc.can_restart(Signo::SIGTERM));

    let mut action = SignalAction::default();
    action.flags.insert(SignalActionFlags::RESTART);
    env.proc.try_replace_action(Signo::SIGTERM, action).unwrap();
    assert!(env.proc.can_restart(Signo::SIGTERM));
}

#[test]
fn registration_identity_is_explicit_unique_and_reusable_after_cancel() {
    use thekernel_linux_signal::api::ThreadRegistrationError;

    let env = TestEnv::new();
    let first = ThreadSignalManager::try_new(env.proc.clone()).unwrap();
    first.try_register(41).unwrap().commit().unwrap();
    assert!(first.is_registered());
    assert!(matches!(
        first.try_register(42),
        Err(ThreadRegistrationError::AlreadyRegistered)
    ));

    let replacement = ThreadSignalManager::try_new(env.proc.clone()).unwrap();
    assert!(matches!(
        replacement.try_register(41),
        Err(ThreadRegistrationError::TidInUse)
    ));

    assert!(first.cancel_registration());
    assert!(!first.is_registered());
    assert!(!first.cancel_registration());
    replacement.try_register(41).unwrap().commit().unwrap();
    assert!(replacement.is_registered());
}

#[test]
fn thread_registry_limit_is_finite_refunded_and_configurable() {
    use thekernel_linux_signal::api::{SignalManagerConfigError, ThreadRegistrationError};

    assert!(matches!(
        ProcessSignalManager::try_with_thread_limit(SignalActions::default(), 0, usize::MAX),
        Err(SignalManagerConfigError::UnboundedThreadRegistry)
    ));
    let process = Arc::new(
        ProcessSignalManager::try_with_thread_limit(SignalActions::default(), 0, 1).unwrap(),
    );
    assert_eq!(process.thread_limit(), 1);
    let first = ThreadSignalManager::try_new(process.clone()).unwrap();
    first.try_register(1).unwrap().commit().unwrap();
    let second = ThreadSignalManager::try_new(process.clone()).unwrap();
    assert!(matches!(
        second.try_register(2),
        Err(ThreadRegistrationError::Capacity)
    ));

    assert!(first.cancel_registration());
    second.try_register(2).unwrap().commit().unwrap();
}

#[test]
fn cancelled_admission_token_cannot_resurrect_a_stale_endpoint() {
    use thekernel_linux_signal::api::ThreadRegistrationError;

    let env = TestEnv::new();
    let thread = ThreadSignalManager::try_new(env.proc.clone()).unwrap();
    let admission = thread.try_register(51).unwrap();
    assert!(thread.cancel_registration());
    assert!(matches!(
        admission.commit(),
        Err(ThreadRegistrationError::Cancelled)
    ));
    assert!(!thread.is_registered());

    assert_eq!(
        env.proc
            .send_unqueued_signal(SignalInfo::new_user(Signo::SIGTERM, 0, 100)),
        None
    );
    thread.try_register(51).unwrap().commit().unwrap();
    assert!(thread.is_registered());
}
