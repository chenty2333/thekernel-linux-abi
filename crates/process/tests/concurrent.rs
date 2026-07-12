use std::sync::{Arc, Barrier};

mod common;
use common::{child, domain, exit_and_reap, init, zombie};

#[test]
fn concurrent_fork_admission_exit_and_reap_preserve_registry_counts() {
    const WORKERS: usize = 16;
    let domain = Arc::new(domain());
    let init = init(&domain);
    let start = Arc::new(Barrier::new(WORKERS));

    std::thread::scope(|scope| {
        for worker in 0..WORKERS {
            let worker_domain = domain.clone();
            let init = init.clone();
            let start = start.clone();
            scope.spawn(move || {
                let pid = worker as u32 + 2;
                start.wait();
                let process = child(&worker_domain, &init, pid);
                worker_domain.exit(&process, zombie(pid), drop).unwrap();
                assert!(worker_domain.reap(&process).unwrap());
            });
        }
    });

    assert_eq!(domain.registry().membership_count(), 1);
    assert_eq!(domain.registry().process_group_count(), 1);
    assert_eq!(init.group().membership_count(), 1);
}

#[test]
fn concurrent_thread_admission_and_removal_refund_domain_credits() {
    const WORKERS: usize = 32;
    let domain = Arc::new(domain());
    let init = init(&domain);
    let admitted = Arc::new(Barrier::new(WORKERS));

    std::thread::scope(|scope| {
        for worker in 0..WORKERS {
            let init = init.clone();
            let admitted = admitted.clone();
            scope.spawn(move || {
                let tid = worker as u32 + 100;
                init.prepare_thread(tid).unwrap().commit();
                admitted.wait();
                assert!(init.remove_thread(tid));
            });
        }
    });

    assert_eq!(init.thread_count(), 0);
    assert_eq!(domain.registry().thread_membership_count(), 0);
}

#[test]
fn concurrent_nested_exit_keeps_leaf_on_the_nearest_subreaper() {
    for _ in 0..32 {
        let domain = Arc::new(domain());
        let init = init(&domain);
        let subreaper = child(&domain, &init, 2);
        subreaper.set_child_subreaper(true);
        let ancestor = child(&domain, &subreaper, 3);
        let parent = child(&domain, &ancestor, 4);
        let leaf = child(&domain, &parent, 5);
        let start = Arc::new(Barrier::new(3));

        std::thread::scope(|scope| {
            let ancestor_domain = domain.clone();
            let ancestor = ancestor.clone();
            let start_ancestor = start.clone();
            scope.spawn(move || {
                start_ancestor.wait();
                ancestor_domain.exit(&ancestor, zombie(3), drop).unwrap();
            });

            let parent_domain = domain.clone();
            let parent = parent.clone();
            let start_parent = start.clone();
            scope.spawn(move || {
                start_parent.wait();
                parent_domain.exit(&parent, zombie(4), drop).unwrap();
            });

            start.wait();
        });

        assert!(Arc::ptr_eq(&leaf.parent().unwrap(), &subreaper));
        exit_and_reap(&domain, &leaf);
        assert!(domain.reap(&parent).unwrap());
        assert!(domain.reap(&ancestor).unwrap());
        exit_and_reap(&domain, &subreaper);
    }
}
