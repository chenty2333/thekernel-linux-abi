use std::sync::Arc;

use thekernel_linux_signal::{
    PreparedSignal, PreparedSignalPublicationOutcome, SignalAction, SignalDisposition, SignalInfo,
    SignalQueueAccount, Signo,
    api::{ProcessSignalManager, SignalActions, ThreadSignalManager},
};

fn process_and_thread() -> (Arc<ProcessSignalManager>, Arc<ThreadSignalManager>) {
    let process = Arc::new(ProcessSignalManager::new(SignalActions::default(), 0));
    let thread = ThreadSignalManager::try_new(process.clone()).unwrap();
    thread.try_register(7).unwrap().commit().unwrap();
    (process, thread)
}

fn accounted(signo: Signo) -> (PreparedSignal, Arc<SignalQueueAccount>) {
    let user = SignalQueueAccount::try_new(4).unwrap();
    let global = SignalQueueAccount::try_new(4).unwrap();
    let prepared =
        PreparedSignal::try_accounted(SignalInfo::new_user(signo, 1, 1), &user, 4, &global)
            .unwrap();
    (prepared, user)
}

#[test]
fn process_publication_defers_unused_record_and_route_destruction() {
    let (process, thread) = process_and_thread();
    process
        .try_replace_action(
            Signo::SIGRTMIN,
            SignalAction {
                disposition: SignalDisposition::Ignore,
                ..SignalAction::default()
            },
        )
        .unwrap();

    let route = process.try_prepare_signal_send(Signo::SIGRTMIN).unwrap();
    let weak_thread = Arc::downgrade(&thread);
    assert!(thread.cancel_registration());
    drop(thread);
    assert!(weak_thread.upgrade().is_some());

    let (prepared, user) = accounted(Signo::SIGRTMIN);
    let deferred = route.publish(prepared);
    assert_eq!(user.queued(), 1);
    assert!(weak_thread.upgrade().is_some());

    let outcome = match deferred.finish() {
        PreparedSignalPublicationOutcome::Applied(outcome) => outcome,
        PreparedSignalPublicationOutcome::SignoMismatch => {
            panic!("matching route rejected its prepared record")
        }
    };
    assert!(!outcome.published);
    assert_eq!(outcome.wake_tid, None);
    assert_eq!(user.queued(), 0);
    assert!(weak_thread.upgrade().is_none());
}

#[test]
fn cancelled_route_cannot_be_selected_but_process_signal_stays_pending() {
    let (process, thread) = process_and_thread();
    let route = process.try_prepare_signal_send(Signo::SIGTERM).unwrap();
    assert!(thread.cancel_registration());

    let prepared = PreparedSignal::unqueued(SignalInfo::new_user(Signo::SIGTERM, 1, 1));
    let deferred = route.publish(prepared);
    let outcome = match deferred.finish() {
        PreparedSignalPublicationOutcome::Applied(outcome) => outcome,
        PreparedSignalPublicationOutcome::SignoMismatch => {
            panic!("matching route rejected its prepared record")
        }
    };
    assert!(outcome.published);
    assert_eq!(outcome.wake_tid, None);
    assert!(process.pending().has(Signo::SIGTERM));
}

#[test]
fn thread_publication_rechecks_cancellation_and_returns_queue_ownership() {
    let (_process, thread) = process_and_thread();
    let send = thread.prepare_signal_send(Signo::SIGRTMIN);
    assert!(thread.cancel_registration());

    let (prepared, user) = accounted(Signo::SIGRTMIN);
    let deferred = send.publish(prepared);
    assert_eq!(user.queued(), 1);
    let outcome = match deferred.finish() {
        PreparedSignalPublicationOutcome::Applied(outcome) => outcome,
        PreparedSignalPublicationOutcome::SignoMismatch => {
            panic!("matching endpoint rejected its prepared record")
        }
    };
    assert!(!outcome.published);
    assert!(!outcome.wake);
    assert_eq!(user.queued(), 0);
}

#[test]
fn signo_mismatch_returns_both_unpublished_owners() {
    let (process, _thread) = process_and_thread();
    let route = process.try_prepare_signal_send(Signo::SIGTERM).unwrap();
    let (prepared, user) = accounted(Signo::SIGRTMIN);

    let deferred = route.publish(prepared);
    assert_eq!(user.queued(), 1);
    let (outcome, route, prepared) = deferred.into_parts();
    assert_eq!(outcome, PreparedSignalPublicationOutcome::SignoMismatch);
    let prepared = prepared.expect("mismatched record must remain unpublished");
    assert_eq!(route.signo(), Signo::SIGTERM);
    assert_eq!(prepared.signo(), Signo::SIGRTMIN);
    drop(route);
    drop(prepared);
    assert_eq!(user.queued(), 0);
}
