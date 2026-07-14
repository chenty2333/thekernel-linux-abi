use std::{string::String, sync::Arc};

use thekernel_linux_cred::{
    CAPABILITY_WORDS, CredError, Credential, ExecCredentialInput, ExecDumpability, ExecFileOwner,
    ExecImageReadability, ExecMountPrivilege, ExecTraceState, ExecUserNamespaceView,
    FileOpenAccess, FileOpenContext, FileOpenOperation, FsCredentialSnapshot, IdMap,
    InodePermissionAccess, InodePermissionContext, Kgid, Kuid, PtraceAccessContext,
    PtraceAccessKind, PtraceCredentialKind, PtraceTracemeContext, SECURITY_CAPABILITY_XATTR_NAME,
    SchedulerSecurityContext, SchedulerSecurityOperation, SignalCoreAuthorizationReason,
    SignalDeliveryScope, SignalNumber, SignalSecurityContext, SignalSecurityOperation,
    SignalSecuritySource, UserNamespaceDomain, UserNamespaceMapState, UserNamespaceView,
    authorize_signal_core, commoncap_exec_transition, commoncap_ptrace_access,
    commoncap_ptrace_traceme, commoncap_scheduler, derive_exec_credential, parse_file_capabilities,
};

struct TestNamespace {
    label: &'static str,
    parent: Option<Arc<Self>>,
    level: u32,
    owner: Kuid,
    root: Option<Kuid>,
    uid_map: Arc<IdMap>,
    gid_map: Arc<IdMap>,
}

impl TestNamespace {
    fn initial(label: &'static str) -> Arc<Self> {
        let identity = IdMap::try_identity().unwrap();
        Arc::new(Self {
            label,
            parent: None,
            level: 0,
            owner: Kuid::INITIAL_ROOT,
            root: Some(Kuid::INITIAL_ROOT),
            uid_map: identity.clone(),
            gid_map: identity,
        })
    }

    fn child(parent: &Arc<Self>, label: &'static str, owner: Kuid) -> Arc<Self> {
        Arc::new(Self {
            label,
            parent: Some(parent.clone()),
            level: parent.level + 1,
            owner,
            root: Some(Kuid::INITIAL_ROOT),
            uid_map: parent.uid_map.clone(),
            gid_map: parent.gid_map.clone(),
        })
    }
}

impl UserNamespaceView for TestNamespace {
    fn parent(self: &Arc<Self>) -> Option<Arc<Self>> {
        self.parent.clone()
    }

    fn level(&self) -> u32 {
        self.level
    }

    fn owner_kuid(&self) -> Kuid {
        self.owner
    }

    fn root_kuid(&self) -> Option<Kuid> {
        self.root
    }

    fn is_initial(&self) -> bool {
        self.parent.is_none()
    }
}

impl ExecUserNamespaceView for TestNamespace {
    fn exec_id_map_snapshot(&self) -> (Arc<IdMap>, Arc<IdMap>) {
        (self.uid_map.clone(), self.gid_map.clone())
    }
}

struct NonCopyObject {
    identity: String,
}

fn overridden_dac_credential(
    actor: &Credential<TestNamespace>,
    raw_id: u32,
) -> FsCredentialSnapshot {
    FsCredentialSnapshot::new(
        Kuid::from_raw(raw_id).unwrap(),
        Kgid::from_raw(raw_id).unwrap(),
        actor.groups().clone(),
        [0; CAPABILITY_WORDS],
        false,
    )
}

fn parsed_file_capabilities() -> thekernel_linux_cred::FileCapabilities {
    // Linux VFS_CAP_REVISION_2 | VFS_CAP_FLAGS_EFFECTIVE, with CAP_CHOWN in
    // the permitted low word and every other capability word empty.
    let record = [
        0x01, 0x00, 0x00, 0x02, // magic_etc
        0x01, 0x00, 0x00, 0x00, // permitted[0]
        0x00, 0x00, 0x00, 0x00, // inheritable[0]
        0x00, 0x00, 0x00, 0x00, // permitted[1]
        0x00, 0x00, 0x00, 0x00, // inheritable[1]
    ];
    parse_file_capabilities(&record).unwrap()
}

#[test]
fn canonical_namespace_and_credential_construction_is_public() {
    let namespace = TestNamespace::initial("initial");
    let domain = UserNamespaceDomain::<TestNamespace>::initial();
    let map_state = UserNamespaceMapState::try_initial().unwrap();

    assert!(domain.is_initial());
    assert_eq!(domain.level(), 0);
    assert_eq!(domain.owner_kuid(), Kuid::INITIAL_ROOT);
    assert!(map_state.uid_map_written());
    assert!(map_state.gid_map_written());
    assert_eq!(
        map_state
            .uid_map()
            .kernel_uid_to_user(Kuid::INITIAL_ROOT)
            .unwrap()
            .into_raw(),
        0
    );

    let root = Credential::try_root(namespace.clone()).unwrap();
    let child_domain = UserNamespaceDomain::try_child(
        &namespace,
        namespace.uid_map.as_ref(),
        namespace.gid_map.as_ref(),
        root.ids().euid,
        root.ids().egid,
        true,
    )
    .unwrap();
    assert_eq!(child_domain.level(), 1);
    assert!(Arc::ptr_eq(
        child_domain.parent().as_ref().unwrap(),
        &namespace
    ));

    let child_namespace = TestNamespace::child(&namespace, "child", root.ids().euid);
    let entered =
        Credential::try_with_user_namespace(root.as_ref(), child_namespace.clone()).unwrap();
    assert!(Arc::ptr_eq(entered.user_ns(), &child_namespace));
    assert_eq!(entered.ids(), root.ids());
    assert_eq!(entered.fs_credential_snapshot().uid(), entered.ids().fsuid);
    assert!(entered.capabilities().has_effective(0));
}

#[test]
fn ordinary_transition_proposal_is_bound_to_the_exact_old_arc() {
    let namespace = TestNamespace::initial("ordinary-transition");
    let old = Credential::try_root(namespace.clone()).unwrap();
    let equal_looking_but_distinct = Credential::try_root(namespace).unwrap();

    let rejected = Credential::try_prepare_transition(
        &old,
        old.ids(),
        old.groups().clone(),
        old.capabilities(),
        true,
    )
    .unwrap();
    assert!(std::ptr::eq(rejected.old(), old.as_ref()));
    assert!(rejected.proposed().no_new_privs());
    assert_eq!(
        rejected
            .try_into_proposed(&equal_looking_but_distinct)
            .err(),
        Some(CredError::NotPermitted)
    );

    let accepted = Credential::try_prepare_transition(
        &old,
        old.ids(),
        old.groups().clone(),
        old.capabilities(),
        true,
    )
    .unwrap();
    assert!(!accepted.effects().requires_dumpability_drop());
    assert!(!accepted.effects().clear_pdeath_signal());
    let proposed = accepted.try_into_proposed(&old).unwrap();
    assert!(proposed.no_new_privs());
    assert!(Arc::ptr_eq(proposed.user_ns(), old.user_ns()));
}

#[test]
fn file_capability_parser_and_exec_proposal_are_publicly_composable() {
    assert_eq!(SECURITY_CAPABILITY_XATTR_NAME, "security.capability");
    let file_capabilities = parsed_file_capabilities();
    assert_eq!(file_capabilities.permitted()[0], 1);
    assert_eq!(file_capabilities.inheritable(), [0; CAPABILITY_WORDS]);
    assert!(file_capabilities.effective());
    assert_eq!(file_capabilities.rootid(), Kuid::INITIAL_ROOT);

    let namespace = TestNamespace::initial("exec");
    let old = Credential::try_root(namespace).unwrap();
    let input = ExecCredentialInput::new(
        0o755,
        Some(ExecFileOwner::new(Kuid::INITIAL_ROOT, Kgid::INITIAL_ROOT)),
        ExecMountPrivilege::Honor,
        ExecTraceState::NotSuppressingPrivilege,
        ExecImageReadability::Readable,
        Some(file_capabilities),
    );
    let proposal = derive_exec_credential(&old, input).unwrap();

    assert!(std::ptr::eq(proposal.old(), old.as_ref()));
    assert_eq!(proposal.input(), input);
    assert_eq!(
        proposal.effects().dumpability(),
        ExecDumpability::UserDumpable
    );
    assert!(!proposal.effects().secure_exec());
    assert!(!proposal.revalidation().privilege_sensitive());
    commoncap_exec_transition(&proposal).unwrap();

    let proposed = proposal.try_into_proposed(&old).unwrap();
    assert!(Arc::ptr_eq(proposed.user_ns(), old.user_ns()));
}

#[test]
fn ptrace_scheduler_and_signal_contexts_compile_from_root_exports() {
    let namespace = TestNamespace::initial("security-contexts");
    let actor = Credential::try_root(namespace.clone()).unwrap();
    let target = Credential::try_root(namespace.clone()).unwrap();
    let object = NonCopyObject {
        identity: String::from("exact-security-target"),
    };

    let ptrace = PtraceAccessContext::new(
        &actor,
        &target,
        &namespace,
        &object,
        PtraceAccessKind::Read,
        PtraceCredentialKind::Real,
    );
    commoncap_ptrace_access(&ptrace).unwrap();
    assert!(std::ptr::eq(ptrace.actor(), actor.as_ref()));
    assert!(std::ptr::eq(ptrace.target(), target.as_ref()));
    assert!(Arc::ptr_eq(ptrace.target_image_owner_user_ns(), &namespace));
    assert_eq!(ptrace.target_object().identity, "exact-security-target");

    let traceme = PtraceTracemeContext::new(&actor, &target, &namespace, &object);
    commoncap_ptrace_traceme(&traceme).unwrap();
    assert!(std::ptr::eq(traceme.parent_actor(), actor.as_ref()));
    assert!(std::ptr::eq(traceme.child_target(), target.as_ref()));

    let scheduler =
        SchedulerSecurityContext::new(&actor, &target, SchedulerSecurityOperation::SetAffinity);
    commoncap_scheduler(&scheduler).unwrap();
    assert!(scheduler.owner_match());
    assert_eq!(
        scheduler.operation(),
        SchedulerSecurityOperation::SetAffinity
    );

    let signal_operation = SignalSecurityOperation::send(
        SignalNumber::try_new(15).unwrap(),
        SignalSecuritySource::Kill,
        SignalDeliveryScope::ThreadGroup,
    );
    let authorization =
        authorize_signal_core(&actor, &target, signal_operation, false, false).unwrap();
    assert_eq!(
        authorization.reason(),
        SignalCoreAuthorizationReason::CredentialMatch
    );
    let signal = SignalSecurityContext::new(authorization, &object);
    assert!(std::ptr::eq(signal.actor(), actor.as_ref()));
    assert!(std::ptr::eq(signal.target(), target.as_ref()));
    assert!(Arc::ptr_eq(signal.target_owner_user_ns(), &namespace));
    assert_eq!(signal.target_object().identity, "exact-security-target");
    assert_eq!(signal.operation(), signal_operation);
}

#[test]
fn inode_permission_public_contract_binds_distinct_frozen_inputs() {
    let actor_namespace = TestNamespace::initial("actor");
    let target_owner_namespace = TestNamespace::initial("target-owner");
    let actor = Credential::try_root(actor_namespace.clone()).unwrap();
    let dac_credential = overridden_dac_credential(&actor, 1000);
    let object = NonCopyObject {
        identity: String::from("exact-inode-location"),
    };
    let access =
        InodePermissionAccess::READ | InodePermissionAccess::WRITE | InodePermissionAccess::EXECUTE;
    let context = InodePermissionContext::new(
        &actor,
        &dac_credential,
        &target_owner_namespace,
        &object,
        access,
    );

    assert!(std::ptr::eq(context.actor(), actor.as_ref()));
    assert!(std::ptr::eq(context.dac_credential(), &dac_credential));
    assert_ne!(context.dac_credential().uid(), actor.ids().fsuid);
    assert!(Arc::ptr_eq(
        context.target_owner_user_ns(),
        &target_owner_namespace
    ));
    assert!(!Arc::ptr_eq(
        context.target_owner_user_ns(),
        actor.user_ns()
    ));
    assert_eq!(context.target_owner_user_ns().label, "target-owner");
    assert!(std::ptr::eq(context.target_object(), &object));
    assert_eq!(context.target_object().identity, "exact-inode-location");
    assert_eq!(context.access(), InodePermissionAccess::ALL);
    assert!(context.access().contains(InodePermissionAccess::WRITE));
    assert_eq!(InodePermissionAccess::try_from_bits(0), None);
    assert_eq!(
        InodePermissionAccess::try_from_bits(InodePermissionAccess::ALL.bits() | (1 << 7)),
        None
    );
}

#[test]
fn file_open_public_contract_normalizes_flags_without_raw_fd_values() {
    let actor_namespace = TestNamespace::initial("actor");
    let target_owner_namespace = TestNamespace::initial("open-owner");
    let actor = Credential::try_root(actor_namespace).unwrap();
    let dac_credential = overridden_dac_credential(&actor, 2000);
    let object = NonCopyObject {
        identity: String::from("exact-open-location"),
    };
    let operation =
        FileOpenOperation::new(FileOpenAccess::ReadWrite, true, true, true, false).unwrap();
    let context = FileOpenContext::new(
        &actor,
        &dac_credential,
        &target_owner_namespace,
        &object,
        operation,
    );

    assert!(std::ptr::eq(context.actor(), actor.as_ref()));
    assert!(std::ptr::eq(context.dac_credential(), &dac_credential));
    assert_ne!(context.dac_credential().uid(), actor.ids().fsuid);
    assert!(Arc::ptr_eq(
        context.target_owner_user_ns(),
        &target_owner_namespace
    ));
    assert!(std::ptr::eq(context.target_object(), &object));
    assert_eq!(context.target_object().identity, "exact-open-location");
    assert_eq!(context.operation(), operation);
    assert_eq!(operation.access(), FileOpenAccess::ReadWrite);
    assert!(operation.access().reads());
    assert!(operation.access().writes());
    assert!(operation.append());
    assert!(operation.truncate());
    assert!(operation.created());
    assert!(!operation.unnamed());

    let unnamed = FileOpenOperation::new(FileOpenAccess::Write, false, false, true, true)
        .expect("O_TMPFILE is created, unnamed, and writable");
    assert!(unnamed.created());
    assert!(unnamed.unnamed());
    assert_eq!(
        FileOpenOperation::new(FileOpenAccess::Write, false, false, false, true),
        None
    );

    let read_truncate = FileOpenOperation::new(FileOpenAccess::Read, false, true, false, false)
        .expect("Linux O_RDONLY|O_TRUNC remains a representable normalized request");
    assert_eq!(read_truncate.access(), FileOpenAccess::Read);
    assert!(read_truncate.truncate());

    let no_data = FileOpenOperation::new(FileOpenAccess::NoData, false, true, true, false)
        .expect("Linux access mode 3 may retain open-time truncate/create facts");
    assert_eq!(no_data.access(), FileOpenAccess::NoData);
    assert!(!no_data.access().reads());
    assert!(!no_data.access().writes());
    assert!(no_data.truncate());
    assert!(no_data.created());
    assert_eq!(
        FileOpenOperation::new(FileOpenAccess::NoData, true, false, false, false),
        None
    );
    let no_data_unnamed = FileOpenOperation::new(FileOpenAccess::NoData, false, false, true, true)
        .expect("mode-3 MAY_WRITE admission permits O_TMPFILE creation");
    assert!(!no_data_unnamed.access().writes());
    assert!(no_data_unnamed.created());
    assert!(no_data_unnamed.unnamed());
    assert_eq!(
        FileOpenOperation::new(FileOpenAccess::NoData, false, false, false, true),
        None
    );
}
