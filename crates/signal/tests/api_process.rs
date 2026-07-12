use std::sync::Arc;

use thekernel_linux_signal::{
    SignalAction, SignalActionFlags, SignalDisposition, SignalInfo, Signo,
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
