use std::sync::Arc;

use thekernel_linux_process::{ExitOutcome, ProcessDomain, ProcessError, ThreadExitOutcome};

mod common;
use common::{Zombie, child, domain, exit_and_reap, init, zombie};

#[test]
fn domains_isolate_pid_identity_and_registry_queries() {
    let left = domain();
    let right = domain();
    let left_init = init(&left);
    let right_init = init(&right);

    assert_eq!(left_init.pid(), right_init.pid());
    assert!(!Arc::ptr_eq(&left_init, &right_init));
    assert!(Arc::ptr_eq(&left.registry().get(1).unwrap(), &left_init));
    assert!(Arc::ptr_eq(&right.registry().get(1).unwrap(), &right_init));
    assert_eq!(
        left_init.try_children(right.registry()).err(),
        Some(ProcessError::WrongDomain)
    );
    assert_eq!(
        left.prepare_fork(&right_init, 2, None).err(),
        Some(ProcessError::WrongDomain)
    );
}

#[test]
fn process_admission_is_invisible_until_commit_and_rolls_back() {
    let domain = ProcessDomain::<Zombie>::try_with_membership_limit(2).unwrap();
    let init = init(&domain);

    let admission = domain.prepare_fork(&init, 2, None).unwrap();
    let unpublished = admission.process().clone();
    assert!(domain.registry().get(2).is_none());
    assert!(init.try_children(domain.registry()).unwrap().is_empty());
    assert_eq!(domain.registry().membership_count(), 2);
    assert_eq!(
        domain.prepare_fork(&init, 3, None).err(),
        Some(ProcessError::Capacity)
    );
    drop(admission);
    assert_eq!(domain.registry().membership_count(), 1);
    assert_eq!(
        domain.exit(&unpublished, zombie(2), drop),
        Err(ProcessError::NotPublished)
    );

    let committed = child(&domain, &init, 2);
    assert!(Arc::ptr_eq(&domain.registry().get(2).unwrap(), &committed));
    assert_eq!(init.try_children(domain.registry()).unwrap().len(), 1);
    exit_and_reap(&domain, &committed);
}

#[test]
fn typed_zombie_payload_is_once_only_and_survives_runtime_exit() {
    let domain = domain();
    let init = init(&domain);
    let child = child(&domain, &init, 2);
    let payload = Zombie {
        wait_status: 9,
        uid: 1000,
        user_ns_cookie: 0xabc,
    };

    assert_eq!(
        domain.exit(&child, payload, drop),
        Ok(ExitOutcome::BecameZombie)
    );
    assert_eq!(
        domain.exit(&child, zombie(99), drop),
        Ok(ExitOutcome::AlreadyZombie)
    );
    assert_eq!(
        domain.prepare_fork(&child, 3, None).err(),
        Some(ProcessError::NotLive)
    );
    assert_eq!(child.zombie_payload(), Some(payload));
    assert!(domain.reap(&child).unwrap());
    assert!(!domain.reap(&child).unwrap());
}

#[test]
fn nearest_live_subreaper_inherits_children_and_zombie_notification() {
    let domain = domain();
    let init = init(&domain);
    let subreaper = child(&domain, &init, 2);
    subreaper.set_child_subreaper(true);
    let parent = child(&domain, &subreaper, 3);
    let child = child(&domain, &parent, 4);

    assert_eq!(
        domain.exit(&child, zombie(4), drop),
        Ok(ExitOutcome::BecameZombie)
    );
    let mut inherited = Vec::new();
    assert_eq!(
        domain.exit(&parent, zombie(3), |process| inherited.push(process.pid())),
        Ok(ExitOutcome::BecameZombie)
    );
    assert_eq!(inherited, [4]);
    assert!(Arc::ptr_eq(&child.parent().unwrap(), &subreaper));

    assert!(domain.reap(&child).unwrap());
    assert!(domain.reap(&parent).unwrap());
    exit_and_reap(&domain, &subreaper);
}

#[test]
fn thread_admissions_are_bounded_ordered_and_rollback_safe() {
    let domain = ProcessDomain::<Zombie>::try_with_membership_limit(3).unwrap();
    let init = init(&domain);

    init.prepare_thread(30).unwrap().commit();
    init.prepare_thread(10).unwrap().commit();
    let pending = init.prepare_thread(20).unwrap();
    assert_eq!(init.try_threads().unwrap(), [10, 30]);
    assert_eq!(init.prepare_thread(40).err(), Some(ProcessError::Capacity));
    drop(pending);
    init.prepare_thread(20).unwrap().commit();
    assert_eq!(init.thread_ids().collect::<Vec<_>>(), [10, 20, 30]);

    assert_eq!(init.exit_thread(999, 55), ThreadExitOutcome::NotFound);
    assert_eq!(init.exit_code(), 0);
    assert_eq!(
        init.exit_thread(10, 7),
        ThreadExitOutcome::LiveThreadsRemain
    );
    assert!(init.group_exit(42));
    assert!(!init.group_exit(99));
    assert_eq!(
        init.exit_thread(20, 3),
        ThreadExitOutcome::LiveThreadsRemain
    );
    assert_eq!(init.exit_thread(30, 3), ThreadExitOutcome::FinalThread);
    assert_eq!(init.exit_code(), 42);
    assert_eq!(domain.registry().thread_membership_count(), 0);
}

#[test]
fn init_is_unique_and_cannot_be_exited() {
    let domain = domain();
    let init = init(&domain);
    assert_eq!(
        domain.try_new_init(2, None).unwrap_err(),
        ProcessError::AlreadyExists
    );
    assert_eq!(
        domain.exit(&init, zombie(1), drop),
        Ok(ExitOutcome::InitProcess)
    );
    assert!(!init.is_zombie());
}

#[test]
fn domain_thread_limit_is_shared_across_processes() {
    let domain = ProcessDomain::<Zombie>::try_with_membership_limit(2).unwrap();
    let init = init(&domain);
    let child = child(&domain, &init, 2);

    init.prepare_thread(10).unwrap().commit();
    child.prepare_thread(20).unwrap().commit();
    assert_eq!(domain.registry().thread_membership_count(), 2);
    assert_eq!(init.prepare_thread(30).err(), Some(ProcessError::Capacity));
    assert!(child.remove_thread(20));
    init.prepare_thread(30).unwrap().commit();
    assert_eq!(domain.registry().thread_membership_count(), 2);
    assert!(init.remove_thread(10));
    assert!(init.remove_thread(30));
    exit_and_reap(&domain, &child);
}
