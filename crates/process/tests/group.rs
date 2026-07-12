use std::sync::Arc;

use thekernel_linux_process::ProcessError;

mod common;
use common::{child, domain, exit_and_reap, init};

#[test]
fn group_membership_uses_an_explicit_registry() {
    let process_domain = domain();
    let other_domain = domain();
    let init_process = init(&process_domain);
    let other_init = init(&other_domain);
    let group = init_process.group();
    let child = child(&process_domain, &init_process, 2);

    let processes = group.try_processes(process_domain.registry()).unwrap();
    assert_eq!(processes.len(), 2);
    assert!(
        processes
            .iter()
            .any(|process| Arc::ptr_eq(process, &init_process))
    );
    assert!(processes.iter().any(|process| Arc::ptr_eq(process, &child)));
    assert_eq!(
        group.try_processes(other_domain.registry()).err(),
        Some(ProcessError::WrongDomain)
    );
    assert!(
        other_init
            .group()
            .try_processes(other_domain.registry())
            .is_ok()
    );

    let mut visited = Vec::new();
    group
        .for_each_process(process_domain.registry(), |process| {
            visited.push(process.pid())
        })
        .unwrap();
    assert_eq!(visited, [1, 2]);
    assert!(
        group
            .any_process(process_domain.registry(), |process| process.pid() == 2)
            .unwrap()
    );
    exit_and_reap(&process_domain, &child);
}

#[test]
fn create_and_move_group_preserve_session_identity() {
    let process_domain = domain();
    let init_process = init(&process_domain);
    let first = child(&process_domain, &init_process, 2);
    let first_group = first.try_create_group().unwrap().unwrap();
    let second = child(&process_domain, &init_process, 3);
    let second_group = second.try_create_group().unwrap().unwrap();

    assert!(second.move_to_group(&first_group));
    assert!(Arc::ptr_eq(&second.group(), &first_group));
    assert_eq!(
        first_group
            .try_processes(process_domain.registry())
            .unwrap()
            .len(),
        2
    );
    assert!(
        second_group
            .try_processes(process_domain.registry())
            .unwrap()
            .is_empty()
    );

    let (new_session, new_group) = first.try_create_session().unwrap().unwrap();
    assert!(Arc::ptr_eq(&new_group.session(), &new_session));
    assert!(!second.move_to_group(&new_group));

    exit_and_reap(&process_domain, &second);
    exit_and_reap(&process_domain, &first);
}
