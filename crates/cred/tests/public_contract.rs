use std::{string::String, sync::Arc};

use thekernel_linux_cred::{
    CAPABILITY_WORDS, CredError, Credential, ExecCredentialInput, ExecDumpability, ExecFileOwner,
    ExecImageReadability, ExecMountPrivilege, ExecTraceState, ExecUserNamespaceView,
    FileOpenAccess, FileOpenContext, FileOpenOperation, FsCredentialSnapshot, IdMap,
    InodeChmodIntent, InodeChownIntent, InodeCreateContext, InodeCreateMode, InodeLinkContext,
    InodeMkdirContext, InodeMknodContext, InodeMknodKind, InodeMknodOperation,
    InodePermissionAccess, InodePermissionContext, InodePostSetattrContext, InodeRenameContext,
    InodeRmdirContext, InodeSetattrContext, InodeSetattrIntent, InodeSetattrMode,
    InodeSetattrPrivilegeCleanup, InodeSetattrProposal, InodeSymlinkContext, InodeUnlinkContext,
    InodeXattrContext, InodeXattrOperation, Kgid, Kuid, PtraceAccessContext, PtraceAccessKind,
    PtraceCredentialKind, PtraceTracemeContext, SECURITY_CAPABILITY_XATTR_NAME,
    SchedulerSecurityContext, SchedulerSecurityOperation, SignalCoreAuthorizationReason,
    SignalDeliveryScope, SignalNumber, SignalSecurityContext, SignalSecurityOperation,
    SignalSecuritySource, UserNamespaceDomain, UserNamespaceMapState, UserNamespaceView,
    XATTR_NAME_MAX, XattrSetFlags, XattrValueClass, authorize_signal_core,
    commoncap_exec_transition, commoncap_ptrace_access, commoncap_ptrace_traceme,
    commoncap_scheduler, derive_exec_credential, parse_file_capabilities,
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
    assert_eq!(SECURITY_CAPABILITY_XATTR_NAME, b"security.capability");
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
fn inode_setattr_public_contract_preserves_omission_and_hook_point_effects() {
    let actor_namespace = TestNamespace::initial("setattr-actor");
    let target_owner_namespace = TestNamespace::initial("setattr-owner");
    let actor = Credential::try_root(actor_namespace).unwrap();
    let dac_credential = overridden_dac_credential(&actor, 2400);
    let old_object = NonCopyObject {
        identity: String::from("exact-old-setattr-inode"),
    };
    let committed_object = NonCopyObject {
        identity: String::from("exact-committed-setattr-inode"),
    };

    assert_eq!(InodeSetattrMode::try_from_bits(0).unwrap().bits(), 0);
    assert_eq!(
        InodeSetattrMode::try_from_bits(0o7777).unwrap().bits(),
        0o7777
    );
    assert_eq!(InodeSetattrMode::try_from_bits(0o100000 | 0o644), None);

    let chmod_intent = InodeChmodIntent::new(InodeSetattrMode::try_from_bits(0o2750).unwrap());
    let chmod = InodeSetattrProposal::chmod(chmod_intent);
    assert_eq!(chmod.intent(), InodeSetattrIntent::Chmod(chmod_intent));
    assert_eq!(chmod.mode(), Some(chmod_intent.mode()));
    assert_eq!(chmod.user(), None);
    assert_eq!(chmod.group(), None);
    assert_eq!(
        chmod.privilege_cleanup(),
        InodeSetattrPrivilegeCleanup::Preserve
    );

    let omitted = InodeChownIntent::new(None, None);
    let omitted_proposal = InodeSetattrProposal::chown(
        omitted,
        Some(InodeSetattrMode::try_from_bits(0o755).unwrap()),
        InodeSetattrPrivilegeCleanup::Kill,
    );
    assert_eq!(
        omitted_proposal.intent(),
        InodeSetattrIntent::Chown(omitted)
    );
    assert_eq!(omitted_proposal.user(), None);
    assert_eq!(omitted_proposal.group(), None);
    assert_eq!(
        omitted_proposal.privilege_cleanup(),
        InodeSetattrPrivilegeCleanup::Kill
    );

    let requested_user = Kuid::from_raw(2401).unwrap();
    let requested_group = Kgid::from_raw(2402).unwrap();
    let explicit = InodeChownIntent::new(Some(requested_user), Some(requested_group));
    let explicit_proposal =
        InodeSetattrProposal::chown(explicit, None, InodeSetattrPrivilegeCleanup::Preserve);
    assert_ne!(explicit, omitted);
    assert_eq!(explicit.user(), Some(requested_user));
    assert_eq!(explicit.group(), Some(requested_group));
    assert_eq!(explicit_proposal.user(), Some(requested_user));
    assert_eq!(explicit_proposal.group(), Some(requested_group));

    let pre = InodeSetattrContext::new(
        &actor,
        &dac_credential,
        &target_owner_namespace,
        &old_object,
        omitted_proposal,
    );
    assert!(std::ptr::eq(pre.actor(), actor.as_ref()));
    assert!(std::ptr::eq(pre.dac_credential(), &dac_credential));
    assert_ne!(pre.dac_credential().uid(), actor.ids().fsuid);
    assert!(Arc::ptr_eq(
        pre.target_owner_user_ns(),
        &target_owner_namespace
    ));
    assert!(std::ptr::eq(pre.target_object(), &old_object));
    assert_eq!(pre.target_object().identity, "exact-old-setattr-inode");
    assert_eq!(pre.proposal(), omitted_proposal);
    assert_eq!(pre.intent(), InodeSetattrIntent::Chown(omitted));

    let post = InodePostSetattrContext::new(
        &actor,
        &dac_credential,
        &target_owner_namespace,
        &committed_object,
        omitted_proposal,
    );
    assert!(std::ptr::eq(post.actor(), actor.as_ref()));
    assert!(std::ptr::eq(post.dac_credential(), &dac_credential));
    assert!(Arc::ptr_eq(
        post.target_owner_user_ns(),
        &target_owner_namespace
    ));
    assert!(std::ptr::eq(post.committed_object(), &committed_object));
    assert_eq!(
        post.committed_object().identity,
        "exact-committed-setattr-inode"
    );
    assert_eq!(post.proposal(), omitted_proposal);
    assert_eq!(post.intent(), InodeSetattrIntent::Chown(omitted));
}

#[test]
fn named_inode_creation_public_contract_preserves_linux_hook_roles() {
    let actor_namespace = TestNamespace::initial("actor");
    let target_owner_namespace = TestNamespace::initial("named-create-owner");
    let actor = Credential::try_root(actor_namespace).unwrap();
    let dac_credential = overridden_dac_credential(&actor, 3000);
    let parent = NonCopyObject {
        identity: String::from("exact-parent-directory"),
    };
    let new_entry = NonCopyObject {
        identity: String::from("exact-prospective-named-entry"),
    };

    assert_eq!(InodeCreateMode::try_from_bits(0).unwrap().bits(), 0);
    assert_eq!(
        InodeCreateMode::try_from_bits(0o7777).unwrap().bits(),
        0o7777
    );
    assert_eq!(InodeCreateMode::try_from_bits(0o100000 | 0o644), None);

    let file_mode = InodeCreateMode::try_from_bits(0o640).unwrap();
    let create = InodeCreateContext::new(
        &actor,
        &dac_credential,
        &target_owner_namespace,
        &parent,
        &new_entry,
        file_mode,
    );
    assert!(std::ptr::eq(create.actor(), actor.as_ref()));
    assert!(std::ptr::eq(create.dac_credential(), &dac_credential));
    assert!(Arc::ptr_eq(
        create.target_owner_user_ns(),
        &target_owner_namespace
    ));
    assert!(std::ptr::eq(create.parent_object(), &parent));
    assert!(std::ptr::eq(create.new_entry_object(), &new_entry));
    assert_eq!(create.parent_object().identity, "exact-parent-directory");
    assert_eq!(
        create.new_entry_object().identity,
        "exact-prospective-named-entry"
    );
    assert_eq!(create.mode(), file_mode);

    let directory_mode = InodeCreateMode::try_from_bits(0o2750).unwrap();
    let mkdir = InodeMkdirContext::new(
        &actor,
        &dac_credential,
        &target_owner_namespace,
        &parent,
        &new_entry,
        directory_mode,
    );
    assert!(std::ptr::eq(mkdir.parent_object(), &parent));
    assert!(std::ptr::eq(mkdir.new_entry_object(), &new_entry));
    assert_eq!(mkdir.mode(), directory_mode);

    let special_mode = InodeCreateMode::try_from_bits(0o620).unwrap();
    assert_eq!(
        InodeMknodOperation::new(InodeMknodKind::Fifo, special_mode, Some(1)),
        None
    );
    assert_eq!(
        InodeMknodOperation::new(InodeMknodKind::CharacterDevice, special_mode, None),
        None
    );
    let operation =
        InodeMknodOperation::new(InodeMknodKind::CharacterDevice, special_mode, Some(0x0501))
            .unwrap();
    let mknod = InodeMknodContext::new(
        &actor,
        &dac_credential,
        &target_owner_namespace,
        &parent,
        &new_entry,
        operation,
    );
    assert!(std::ptr::eq(mknod.parent_object(), &parent));
    assert!(std::ptr::eq(mknod.new_entry_object(), &new_entry));
    assert_eq!(mknod.operation().kind(), InodeMknodKind::CharacterDevice);
    assert_eq!(mknod.operation().mode(), special_mode);
    assert_eq!(mknod.operation().rdev(), Some(0x0501));

    assert!(InodeMknodOperation::new(InodeMknodKind::Fifo, special_mode, None).is_some());
    assert!(InodeMknodOperation::new(InodeMknodKind::Socket, special_mode, None).is_some());
    assert!(InodeMknodOperation::new(InodeMknodKind::BlockDevice, special_mode, Some(0)).is_some());

    let target = vec![0xff, b'/', b't', b'a', b'r', b'g', b'e', b't'];
    let symlink = InodeSymlinkContext::new(
        &actor,
        &dac_credential,
        &target_owner_namespace,
        &parent,
        &new_entry,
        target.as_slice(),
    );
    assert!(std::ptr::eq(symlink.actor(), actor.as_ref()));
    assert!(std::ptr::eq(symlink.dac_credential(), &dac_credential));
    assert!(Arc::ptr_eq(
        symlink.target_owner_user_ns(),
        &target_owner_namespace
    ));
    assert!(std::ptr::eq(symlink.parent_object(), &parent));
    assert!(std::ptr::eq(symlink.new_entry_object(), &new_entry));
    assert!(std::ptr::eq(symlink.symlink_target(), target.as_slice()));
    assert_eq!(symlink.symlink_target(), target.as_slice());
}

#[test]
fn inode_link_public_contract_preserves_source_and_destination_roles() {
    let actor_namespace = TestNamespace::initial("actor");
    let target_owner_namespace = TestNamespace::initial("hard-link-owner");
    let actor = Credential::try_root(actor_namespace).unwrap();
    let dac_credential = overridden_dac_credential(&actor, 3100);
    let source = NonCopyObject {
        identity: String::from("exact-source-inode"),
    };
    let parent = NonCopyObject {
        identity: String::from("exact-destination-parent"),
    };
    let new_entry = NonCopyObject {
        identity: String::from("exact-prospective-hard-link-entry"),
    };
    let context = InodeLinkContext::new(
        &actor,
        &dac_credential,
        &target_owner_namespace,
        &source,
        &parent,
        &new_entry,
    );

    assert!(std::ptr::eq(context.actor(), actor.as_ref()));
    assert!(std::ptr::eq(context.dac_credential(), &dac_credential));
    assert_ne!(context.dac_credential().uid(), actor.ids().fsuid);
    assert!(Arc::ptr_eq(
        context.target_owner_user_ns(),
        &target_owner_namespace
    ));
    assert!(std::ptr::eq(context.source_object(), &source));
    assert!(std::ptr::eq(context.parent_object(), &parent));
    assert!(std::ptr::eq(context.new_entry_object(), &new_entry));
    assert_eq!(context.source_object().identity, "exact-source-inode");
    assert_eq!(context.parent_object().identity, "exact-destination-parent");
    assert_eq!(
        context.new_entry_object().identity,
        "exact-prospective-hard-link-entry"
    );
}

#[test]
fn inode_removal_public_contracts_preserve_parent_and_existing_entry_roles() {
    let actor_namespace = TestNamespace::initial("actor");
    let target_owner_namespace = TestNamespace::initial("removal-owner");
    let actor = Credential::try_root(actor_namespace).unwrap();
    let dac_credential = overridden_dac_credential(&actor, 3200);
    let parent = NonCopyObject {
        identity: String::from("exact-removal-parent"),
    };
    let target_entry = NonCopyObject {
        identity: String::from("exact-existing-victim-entry"),
    };

    let unlink = InodeUnlinkContext::new(
        &actor,
        &dac_credential,
        &target_owner_namespace,
        &parent,
        &target_entry,
    );
    assert!(std::ptr::eq(unlink.actor(), actor.as_ref()));
    assert!(std::ptr::eq(unlink.dac_credential(), &dac_credential));
    assert_ne!(unlink.dac_credential().uid(), actor.ids().fsuid);
    assert!(Arc::ptr_eq(
        unlink.target_owner_user_ns(),
        &target_owner_namespace
    ));
    assert!(std::ptr::eq(unlink.parent_object(), &parent));
    assert!(std::ptr::eq(unlink.target_entry_object(), &target_entry));

    let rmdir = InodeRmdirContext::new(
        &actor,
        &dac_credential,
        &target_owner_namespace,
        &parent,
        &target_entry,
    );
    assert!(std::ptr::eq(rmdir.actor(), actor.as_ref()));
    assert!(std::ptr::eq(rmdir.dac_credential(), &dac_credential));
    assert!(Arc::ptr_eq(
        rmdir.target_owner_user_ns(),
        &target_owner_namespace
    ));
    assert!(std::ptr::eq(rmdir.parent_object(), &parent));
    assert!(std::ptr::eq(rmdir.target_entry_object(), &target_entry));
    assert_eq!(
        rmdir.target_entry_object().identity,
        "exact-existing-victim-entry"
    );
}

#[test]
fn inode_rename_public_contract_preserves_four_ordered_object_roles() {
    let actor_namespace = TestNamespace::initial("actor");
    let target_owner_namespace = TestNamespace::initial("rename-owner");
    let actor = Credential::try_root(actor_namespace).unwrap();
    let dac_credential = overridden_dac_credential(&actor, 3300);
    let old_parent = NonCopyObject {
        identity: String::from("exact-old-parent"),
    };
    let old_entry = NonCopyObject {
        identity: String::from("exact-old-entry-and-source"),
    };
    let new_parent = NonCopyObject {
        identity: String::from("exact-new-parent"),
    };
    let new_entry = NonCopyObject {
        identity: String::from("exact-new-entry-and-target-state"),
    };

    let forward = InodeRenameContext::new(
        &actor,
        &dac_credential,
        &target_owner_namespace,
        &old_parent,
        &old_entry,
        &new_parent,
        &new_entry,
    );
    assert!(std::ptr::eq(forward.actor(), actor.as_ref()));
    assert!(std::ptr::eq(forward.dac_credential(), &dac_credential));
    assert_ne!(forward.dac_credential().uid(), actor.ids().fsuid);
    assert!(Arc::ptr_eq(
        forward.target_owner_user_ns(),
        &target_owner_namespace
    ));
    assert!(std::ptr::eq(forward.old_parent_object(), &old_parent));
    assert!(std::ptr::eq(forward.old_entry_object(), &old_entry));
    assert!(std::ptr::eq(forward.new_parent_object(), &new_parent));
    assert!(std::ptr::eq(forward.new_entry_object(), &new_entry));
    assert_eq!(forward.old_parent_object().identity, "exact-old-parent");
    assert_eq!(
        forward.old_entry_object().identity,
        "exact-old-entry-and-source"
    );
    assert_eq!(forward.new_parent_object().identity, "exact-new-parent");
    assert_eq!(
        forward.new_entry_object().identity,
        "exact-new-entry-and-target-state"
    );

    // An exchange adapter constructs and dispatches this reverse direction
    // before dispatching `forward`; the leaf payload itself has no flags.
    let reverse = InodeRenameContext::new(
        &actor,
        &dac_credential,
        &target_owner_namespace,
        &new_parent,
        &new_entry,
        &old_parent,
        &old_entry,
    );
    assert!(std::ptr::eq(reverse.old_parent_object(), &new_parent));
    assert!(std::ptr::eq(reverse.old_entry_object(), &new_entry));
    assert!(std::ptr::eq(reverse.new_parent_object(), &old_parent));
    assert!(std::ptr::eq(reverse.new_entry_object(), &old_entry));
}

#[test]
fn inode_xattr_public_contract_validates_operations_and_preserves_roles() {
    assert_eq!(XattrSetFlags::try_from_bits(0), Some(XattrSetFlags::NONE));
    assert_eq!(
        XattrSetFlags::try_from_bits(0x1),
        Some(XattrSetFlags::CREATE)
    );
    assert_eq!(
        XattrSetFlags::try_from_bits(0x2),
        Some(XattrSetFlags::REPLACE)
    );
    assert_eq!(
        XattrSetFlags::CREATE.bits() | XattrSetFlags::REPLACE.bits(),
        0x3
    );
    assert_eq!(XattrSetFlags::try_from_bits(0x3), None);
    assert_eq!(XattrSetFlags::try_from_bits(0x4), None);
    assert_eq!(XattrSetFlags::try_from_bits(u32::MAX), None);

    assert_eq!(XATTR_NAME_MAX, 255);
    assert_eq!(InodeXattrOperation::get(b""), None);
    assert_eq!(
        InodeXattrOperation::set(b"", b"value", XattrSetFlags::NONE),
        None
    );
    assert_eq!(InodeXattrOperation::remove(b""), None);
    assert_eq!(InodeXattrOperation::get(b"user.\0hidden"), None);
    assert_eq!(
        InodeXattrOperation::set(b"user.\0hidden", b"value", XattrSetFlags::NONE),
        None
    );
    assert_eq!(InodeXattrOperation::remove(b"user.\0hidden"), None);

    let maximum_name = [0xff; XATTR_NAME_MAX];
    let get = InodeXattrOperation::get(maximum_name.as_slice()).unwrap();
    assert!(std::ptr::eq(get.name().unwrap(), maximum_name.as_slice()));
    assert!(
        InodeXattrOperation::set(maximum_name.as_slice(), b"value", XattrSetFlags::NONE).is_some()
    );
    assert!(InodeXattrOperation::remove(maximum_name.as_slice()).is_some());

    let oversized_name = [b'x'; XATTR_NAME_MAX + 1];
    assert_eq!(InodeXattrOperation::get(oversized_name.as_slice()), None);
    assert_eq!(
        InodeXattrOperation::set(oversized_name.as_slice(), b"value", XattrSetFlags::NONE),
        None
    );
    assert_eq!(InodeXattrOperation::remove(oversized_name.as_slice()), None);

    let get = InodeXattrOperation::get(b"user.example").unwrap();
    assert!(matches!(
        get,
        InodeXattrOperation::Get { name, .. } if name == b"user.example"
    ));
    assert_eq!(get.name(), Some(b"user.example".as_slice()));
    assert_eq!(get.value(), None);
    assert_eq!(get.set_flags(), None);
    assert_eq!(get.value_class(), None);

    let list = InodeXattrOperation::list();
    assert!(matches!(list, InodeXattrOperation::List));
    assert_eq!(list.name(), None);
    assert_eq!(list.value(), None);

    let remove = InodeXattrOperation::remove(b"trusted.example").unwrap();
    assert!(matches!(
        remove,
        InodeXattrOperation::Remove { name, .. } if name == b"trusted.example"
    ));
    assert_eq!(remove.name(), Some(b"trusted.example".as_slice()));
    assert_eq!(remove.value(), None);

    let ordinary_value = [0xff, 0x00];
    let mut non_utf8_name = b"user.".to_vec();
    non_utf8_name.push(0xff);
    assert!(std::str::from_utf8(non_utf8_name.as_slice()).is_err());
    let ordinary = InodeXattrOperation::set(
        non_utf8_name.as_slice(),
        ordinary_value.as_slice(),
        XattrSetFlags::CREATE,
    )
    .unwrap();
    assert!(std::ptr::eq(
        ordinary.name().unwrap(),
        non_utf8_name.as_slice()
    ));
    assert_eq!(ordinary.value_class(), Some(XattrValueClass::Opaque));

    let near_capability = b"security.capability\xff";
    let ordinary = InodeXattrOperation::set(near_capability, &[], XattrSetFlags::NONE).unwrap();
    assert_eq!(ordinary.value_class(), Some(XattrValueClass::Opaque));

    let actor_namespace = TestNamespace::initial("xattr-actor");
    let target_owner_namespace = TestNamespace::initial("xattr-owner");
    let actor = Credential::try_root(actor_namespace).unwrap();
    let dac_credential = overridden_dac_credential(&actor, 3400);
    let target = NonCopyObject {
        identity: String::from("exact-xattr-target"),
    };
    let name = SECURITY_CAPABILITY_XATTR_NAME.to_vec();
    let value = vec![0x01, 0x00, 0x00, 0x02];
    let operation =
        InodeXattrOperation::set(name.as_slice(), value.as_slice(), XattrSetFlags::REPLACE)
            .unwrap();
    assert!(matches!(
        operation,
        InodeXattrOperation::Set {
            flags: XattrSetFlags::REPLACE,
            value_class: XattrValueClass::SecurityCapability,
            ..
        }
    ));

    let context = InodeXattrContext::new(
        &actor,
        &dac_credential,
        &target_owner_namespace,
        &target,
        operation,
    );
    assert!(std::ptr::eq(context.actor(), actor.as_ref()));
    assert!(std::ptr::eq(context.dac_credential(), &dac_credential));
    assert_ne!(context.dac_credential().uid(), actor.ids().fsuid);
    assert!(Arc::ptr_eq(
        context.target_owner_user_ns(),
        &target_owner_namespace
    ));
    assert!(std::ptr::eq(context.target_object(), &target));
    assert_eq!(context.target_object().identity, "exact-xattr-target");
    assert!(std::ptr::eq(
        context.operation().name().unwrap(),
        name.as_slice()
    ));
    assert!(std::ptr::eq(
        context.operation().value().unwrap(),
        value.as_slice()
    ));
    assert_eq!(
        context.operation().set_flags(),
        Some(XattrSetFlags::REPLACE)
    );
    assert_eq!(
        context.operation().value_class(),
        Some(XattrValueClass::SecurityCapability)
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
