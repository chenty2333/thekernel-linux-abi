//! Policy-neutral typed security contexts and Linux commoncap decisions.
//!
//! Contexts borrow immutable credentials, namespace ownership, and opaque
//! object payloads supplied by an embedding kernel. This module owns no task
//! lookup, `current()` access, process or address-space type, hook registry,
//! lock, publication mechanism, or errno mapping.

use alloc::sync::Arc;
use core::fmt;

use linux_raw_sys::general::{CAP_SYS_NICE, CAP_SYS_PTRACE};

use crate::{CAPABILITY_WORDS, Credential, UserNamespaceView, ns_capable};

/// Policy-neutral authorization failures returned by commoncap helpers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AuthorizationError {
    /// The actor lacks authority over the target or requested operation.
    NotPermitted,
    /// Access is denied by an operation-specific discretionary limit.
    AccessDenied,
}

impl fmt::Display for AuthorizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotPermitted => formatter.write_str("security operation not permitted"),
            Self::AccessDenied => formatter.write_str("security access denied"),
        }
    }
}

/// Ptrace operation class presented to security policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PtraceAccessKind {
    /// Observe target state without establishing a controlling attachment.
    Read,
    /// Attach to or otherwise control the target.
    Attach,
}

/// Actor capability view selected by a ptrace-style operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PtraceCredentialKind {
    /// Use the actor's permitted capabilities, matching a real-credential check.
    Real,
    /// Use the actor's effective capabilities, matching a filesystem check.
    Fs,
}

/// Complete immutable input to one ptrace access hook or commoncap decision.
///
/// `O` is an embedding-defined identity for the exact pinned target object,
/// such as an image-generation token. No trait or ownership assumption is
/// imposed on it; the context only borrows the payload.
pub struct PtraceAccessContext<'a, N: UserNamespaceView, O: ?Sized> {
    actor: &'a Credential<N>,
    target: &'a Credential<N>,
    target_image_owner_user_ns: &'a Arc<N>,
    target_object: &'a O,
    access_kind: PtraceAccessKind,
    credential_kind: PtraceCredentialKind,
}

impl<'a, N: UserNamespaceView, O: ?Sized> PtraceAccessContext<'a, N, O> {
    /// Constructs a context from already-frozen actor, target, image-owner, and
    /// object facts.
    pub const fn new(
        actor: &'a Credential<N>,
        target: &'a Credential<N>,
        target_image_owner_user_ns: &'a Arc<N>,
        target_object: &'a O,
        access_kind: PtraceAccessKind,
        credential_kind: PtraceCredentialKind,
    ) -> Self {
        Self {
            actor,
            target,
            target_image_owner_user_ns,
            target_object,
            access_kind,
            credential_kind,
        }
    }

    /// Borrows the exact immutable actor credential.
    pub const fn actor(&self) -> &'a Credential<N> {
        self.actor
    }

    /// Borrows the exact immutable target credential.
    pub const fn target(&self) -> &'a Credential<N> {
        self.target
    }

    /// Borrows the user namespace which owns the pinned target image.
    pub const fn target_image_owner_user_ns(&self) -> &'a Arc<N> {
        self.target_image_owner_user_ns
    }

    /// Borrows the embedding-defined exact target object payload.
    pub const fn target_object(&self) -> &'a O {
        self.target_object
    }

    /// Returns the requested ptrace operation class.
    pub const fn access_kind(&self) -> PtraceAccessKind {
        self.access_kind
    }

    /// Returns the actor capability view selected by the caller's ABI rule.
    pub const fn credential_kind(&self) -> PtraceCredentialKind {
        self.credential_kind
    }
}

/// Complete immutable input to one `PTRACE_TRACEME` decision.
///
/// The prospective parent tracer is explicitly the actor and the calling child
/// is explicitly the target, preventing the easy-to-miss direction reversal.
pub struct PtraceTracemeContext<'a, N: UserNamespaceView, O: ?Sized> {
    parent_actor: &'a Credential<N>,
    child_target: &'a Credential<N>,
    child_image_owner_user_ns: &'a Arc<N>,
    child_object: &'a O,
}

impl<'a, N: UserNamespaceView, O: ?Sized> PtraceTracemeContext<'a, N, O> {
    /// Constructs a traceme context from an already-frozen parent/child pair and
    /// exact child object.
    pub const fn new(
        parent_actor: &'a Credential<N>,
        child_target: &'a Credential<N>,
        child_image_owner_user_ns: &'a Arc<N>,
        child_object: &'a O,
    ) -> Self {
        Self {
            parent_actor,
            child_target,
            child_image_owner_user_ns,
            child_object,
        }
    }

    /// Borrows the prospective parent tracer credential.
    pub const fn parent_actor(&self) -> &'a Credential<N> {
        self.parent_actor
    }

    /// Borrows the calling child target credential.
    pub const fn child_target(&self) -> &'a Credential<N> {
        self.child_target
    }

    /// Borrows the user namespace which owns the pinned child image.
    pub const fn child_image_owner_user_ns(&self) -> &'a Arc<N> {
        self.child_image_owner_user_ns
    }

    /// Borrows the embedding-defined exact child object payload.
    pub const fn child_object(&self) -> &'a O {
        self.child_object
    }
}

/// One Linux-visible scheduler mutation presented to security policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchedulerSecurityOperation {
    /// Change scheduling policy; real-time classes require `CAP_SYS_NICE`.
    SetPolicy {
        /// Whether the requested policy is a real-time class.
        realtime: bool,
    },
    /// Change parameters of the target's current scheduling policy.
    SetParam {
        /// Whether the target policy is a real-time class.
        realtime: bool,
    },
    /// Change the target CPU-affinity mask.
    SetAffinity,
    /// Change the target nice value against one frozen `RLIMIT_NICE` value.
    SetNice {
        /// Current nice value.
        current_nice: i8,
        /// Requested nice value.
        requested_nice: i8,
        /// Frozen soft `RLIMIT_NICE` value.
        rlimit_nice: u64,
    },
}

/// Complete immutable input to one scheduler authorization decision.
///
/// Ownership is computed internally from the frozen credentials; callers
/// cannot provide or forge an `owner_match` fact.
pub struct SchedulerSecurityContext<'a, N: UserNamespaceView> {
    actor: &'a Credential<N>,
    target: &'a Credential<N>,
    operation: SchedulerSecurityOperation,
    owner_match: bool,
}

impl<'a, N: UserNamespaceView> SchedulerSecurityContext<'a, N> {
    /// Constructs one context and derives the Linux scheduler ownership relation.
    pub fn new(
        actor: &'a Credential<N>,
        target: &'a Credential<N>,
        operation: SchedulerSecurityOperation,
    ) -> Self {
        Self {
            actor,
            target,
            operation,
            owner_match: scheduler_owner_matches(actor, target),
        }
    }

    /// Borrows the exact immutable actor credential.
    pub const fn actor(&self) -> &'a Credential<N> {
        self.actor
    }

    /// Borrows the exact immutable target credential.
    pub const fn target(&self) -> &'a Credential<N> {
        self.target
    }

    /// Returns the frozen scheduler operation.
    pub const fn operation(&self) -> SchedulerSecurityOperation {
        self.operation
    }

    /// Returns the internally derived Linux ownership relation.
    pub const fn owner_match(&self) -> bool {
        self.owner_match
    }
}

fn scheduler_owner_matches<N: UserNamespaceView>(
    actor: &Credential<N>,
    target: &Credential<N>,
) -> bool {
    let actor_euid = actor.ids().euid;
    let target_ids = target.ids();
    actor_euid == target_ids.ruid || actor_euid == target_ids.euid
}

fn selected_actor_capabilities<N: UserNamespaceView>(
    actor: &Credential<N>,
    credential_kind: PtraceCredentialKind,
) -> [u32; CAPABILITY_WORDS] {
    let capabilities = actor.capabilities();
    match credential_kind {
        PtraceCredentialKind::Real => capabilities.permitted(),
        PtraceCredentialKind::Fs => capabilities.effective(),
    }
}

fn commoncap_ptrace_allows<N: UserNamespaceView>(
    actor: &Credential<N>,
    target: &Credential<N>,
    credential_kind: PtraceCredentialKind,
) -> bool {
    let selected_actor = selected_actor_capabilities(actor, credential_kind);
    let target_permitted = target.capabilities().permitted();
    (Arc::ptr_eq(actor.user_ns(), target.user_ns())
        && target_permitted
            .iter()
            .zip(selected_actor.iter())
            .all(|(target, actor)| target & !actor == 0))
        || ns_capable(actor, target.user_ns(), CAP_SYS_PTRACE)
}

/// Applies Linux commoncap's ptrace rule to one frozen access context.
///
/// # Errors
///
/// Returns [`AuthorizationError::NotPermitted`] when the selected actor
/// capability view neither contains the target permitted set in the same
/// namespace nor holds `CAP_SYS_PTRACE` over the target namespace.
pub fn commoncap_ptrace_access<N: UserNamespaceView, O: ?Sized>(
    context: &PtraceAccessContext<'_, N, O>,
) -> Result<(), AuthorizationError> {
    if commoncap_ptrace_allows(context.actor, context.target, context.credential_kind) {
        Ok(())
    } else {
        Err(AuthorizationError::NotPermitted)
    }
}

/// Applies Linux commoncap's `PTRACE_TRACEME` rule.
///
/// The parent actor always uses its permitted capability view.
///
/// # Errors
///
/// Returns [`AuthorizationError::NotPermitted`] when the prospective parent
/// tracer lacks authority over the calling child.
pub fn commoncap_ptrace_traceme<N: UserNamespaceView, O: ?Sized>(
    context: &PtraceTracemeContext<'_, N, O>,
) -> Result<(), AuthorizationError> {
    if commoncap_ptrace_allows(
        context.parent_actor,
        context.child_target,
        PtraceCredentialKind::Real,
    ) {
        Ok(())
    } else {
        Err(AuthorizationError::NotPermitted)
    }
}

fn valid_rlimit_nice(rlimit_nice: u64) -> Option<u64> {
    (rlimit_nice <= 40).then_some(rlimit_nice)
}

fn nice_to_rlimit(nice: i8) -> Option<u64> {
    (-20..=19)
        .contains(&nice)
        .then_some((20_i32 - nice as i32) as u64)
}

fn rlimit_allows_nice(rlimit_nice: u64, requested_nice: i8) -> bool {
    let Some(rlimit_nice) = valid_rlimit_nice(rlimit_nice) else {
        return false;
    };
    nice_to_rlimit(requested_nice).is_some_and(|required| required <= rlimit_nice)
}

/// Applies Linux commoncap's scheduler authority and `RLIMIT_NICE` rules.
///
/// # Errors
///
/// Returns [`AuthorizationError::NotPermitted`] for an ownership/capability or
/// real-time authority failure. Returns [`AuthorizationError::AccessDenied`]
/// when an owner without `CAP_SYS_NICE` requests a nicer value not admitted by
/// the frozen `RLIMIT_NICE` value.
pub fn commoncap_scheduler<N: UserNamespaceView>(
    context: &SchedulerSecurityContext<'_, N>,
) -> Result<(), AuthorizationError> {
    let capable = ns_capable(context.actor, context.target.user_ns(), CAP_SYS_NICE);
    if !context.owner_match && !capable {
        return Err(AuthorizationError::NotPermitted);
    }

    match context.operation {
        SchedulerSecurityOperation::SetPolicy { realtime }
        | SchedulerSecurityOperation::SetParam { realtime }
            if realtime && !capable =>
        {
            Err(AuthorizationError::NotPermitted)
        }
        SchedulerSecurityOperation::SetNice {
            current_nice,
            requested_nice,
            rlimit_nice,
        } if requested_nice < current_nice
            && !capable
            && !rlimit_allows_nice(rlimit_nice, requested_nice) =>
        {
            Err(AuthorizationError::AccessDenied)
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use alloc::{string::ToString, sync::Arc, vec};

    use linux_raw_sys::general::{CAP_CHOWN, CAP_SYS_NICE, CAP_SYS_PTRACE};

    use super::*;
    use crate::{
        CAPABILITY_VALID_MASK, CapabilitySets, CredentialIds, CredentialTransitionMode, GroupInfo,
        Kgid, Kuid,
    };

    struct MockNamespace {
        level: u32,
        parent: Option<Arc<Self>>,
        owner: Kuid,
        root: Option<Kuid>,
    }

    impl MockNamespace {
        fn root() -> Arc<Self> {
            Arc::new(Self {
                level: 0,
                parent: None,
                owner: Kuid::INITIAL_ROOT,
                root: Some(Kuid::INITIAL_ROOT),
            })
        }

        fn child(parent: &Arc<Self>, owner: Kuid, root: Option<Kuid>) -> Arc<Self> {
            Arc::new(Self {
                level: parent.level + 1,
                parent: Some(parent.clone()),
                owner,
                root,
            })
        }
    }

    impl UserNamespaceView for MockNamespace {
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

    fn kuid(raw: u32) -> Kuid {
        Kuid::from_raw(raw).unwrap()
    }

    fn kgid(raw: u32) -> Kgid {
        Kgid::from_raw(raw).unwrap()
    }

    fn capability_set(capabilities: &[u32]) -> [u32; CAPABILITY_WORDS] {
        let mut result = [0; CAPABILITY_WORDS];
        for capability in capabilities {
            let (word, mask) = CapabilitySets::cap_mask(*capability).unwrap();
            result[word] |= mask;
        }
        result
    }

    fn root_credential(namespace: Arc<MockNamespace>) -> Arc<Credential<MockNamespace>> {
        Credential::try_root(namespace).unwrap()
    }

    fn credential_with_identity_and_caps(
        base: &Arc<Credential<MockNamespace>>,
        uid: u32,
        permitted: &[u32],
        effective: &[u32],
    ) -> Arc<Credential<MockNamespace>> {
        let uid = kuid(uid);
        let gid = kgid(uid.into_raw());
        let ids = CredentialIds {
            ruid: uid,
            euid: uid,
            suid: uid,
            fsuid: uid,
            rgid: gid,
            egid: gid,
            sgid: gid,
            fsgid: gid,
        };
        let caps = CapabilitySets::try_new(
            capability_set(effective),
            capability_set(permitted),
            [0; CAPABILITY_WORDS],
            CAPABILITY_VALID_MASK,
            [0; CAPABILITY_WORDS],
            base.capabilities().securebits(),
        )
        .unwrap();
        Credential::try_from_transition(
            base,
            ids,
            GroupInfo::try_new(vec![gid]).unwrap(),
            caps,
            base.no_new_privs(),
            base.user_ns().clone(),
            CredentialTransitionMode::Normal,
        )
        .unwrap()
    }

    fn credential_with_caps(
        base: &Arc<Credential<MockNamespace>>,
        permitted: &[u32],
        effective: &[u32],
    ) -> Arc<Credential<MockNamespace>> {
        let caps = CapabilitySets::try_new(
            capability_set(effective),
            capability_set(permitted),
            [0; CAPABILITY_WORDS],
            CAPABILITY_VALID_MASK,
            [0; CAPABILITY_WORDS],
            base.capabilities().securebits(),
        )
        .unwrap();
        Credential::try_from_transition(
            base,
            base.ids(),
            base.groups().clone(),
            caps,
            base.no_new_privs(),
            base.user_ns().clone(),
            CredentialTransitionMode::Normal,
        )
        .unwrap()
    }

    struct DummyImage {
        generation: u64,
    }

    struct DummyHandle {
        cookie: &'static str,
    }

    #[test]
    fn ptrace_real_uses_permitted_and_fs_uses_effective() {
        let namespace = MockNamespace::root();
        let root = root_credential(namespace.clone());
        let actor = credential_with_caps(&root, &[CAP_CHOWN], &[]);
        let target = credential_with_caps(&root, &[CAP_CHOWN], &[]);
        let image = DummyImage { generation: 1 };

        commoncap_ptrace_access(&PtraceAccessContext::new(
            &actor,
            &target,
            &namespace,
            &image,
            PtraceAccessKind::Read,
            PtraceCredentialKind::Real,
        ))
        .unwrap();
        assert_eq!(
            commoncap_ptrace_access(&PtraceAccessContext::new(
                &actor,
                &target,
                &namespace,
                &image,
                PtraceAccessKind::Read,
                PtraceCredentialKind::Fs,
            )),
            Err(AuthorizationError::NotPermitted)
        );
    }

    #[test]
    fn ptrace_same_namespace_subset_and_effective_cap_override_are_independent() {
        let namespace = MockNamespace::root();
        let root = root_credential(namespace.clone());
        let empty_actor = credential_with_caps(&root, &[], &[]);
        let empty_target = credential_with_caps(&root, &[], &[]);
        let image = DummyImage { generation: 2 };

        commoncap_ptrace_access(&PtraceAccessContext::new(
            &empty_actor,
            &empty_target,
            &namespace,
            &image,
            PtraceAccessKind::Attach,
            PtraceCredentialKind::Fs,
        ))
        .unwrap();

        let capable = credential_with_caps(&root, &[CAP_SYS_PTRACE], &[CAP_SYS_PTRACE]);
        commoncap_ptrace_access(&PtraceAccessContext::new(
            &capable,
            &root,
            &namespace,
            &image,
            PtraceAccessKind::Attach,
            PtraceCredentialKind::Fs,
        ))
        .unwrap();

        let permitted_only = credential_with_caps(&root, &[CAP_SYS_PTRACE], &[]);
        assert_eq!(
            commoncap_ptrace_access(&PtraceAccessContext::new(
                &permitted_only,
                &root,
                &namespace,
                &image,
                PtraceAccessKind::Attach,
                PtraceCredentialKind::Fs,
            )),
            Err(AuthorizationError::NotPermitted)
        );
    }

    #[test]
    fn ptrace_capability_follows_namespace_direction() {
        let root_namespace = MockNamespace::root();
        let root = root_credential(root_namespace.clone());
        let child_namespace =
            MockNamespace::child(&root_namespace, Kuid::INITIAL_ROOT, Some(kuid(1000)));
        let child_root =
            Credential::try_with_user_namespace(&root, child_namespace.clone()).unwrap();
        let target = credential_with_identity_and_caps(&child_root, 1000, &[], &[]);
        let actor = credential_with_caps(&root, &[CAP_SYS_PTRACE], &[CAP_SYS_PTRACE]);
        let image = DummyImage { generation: 3 };

        commoncap_ptrace_access(&PtraceAccessContext::new(
            &actor,
            &target,
            &child_namespace,
            &image,
            PtraceAccessKind::Attach,
            PtraceCredentialKind::Real,
        ))
        .unwrap();

        let child_actor = credential_with_identity_and_caps(
            &child_root,
            1000,
            &[CAP_SYS_PTRACE],
            &[CAP_SYS_PTRACE],
        );
        assert_eq!(
            commoncap_ptrace_access(&PtraceAccessContext::new(
                &child_actor,
                &root,
                &root_namespace,
                &image,
                PtraceAccessKind::Attach,
                PtraceCredentialKind::Real,
            )),
            Err(AuthorizationError::NotPermitted)
        );
    }

    #[test]
    fn traceme_keeps_parent_actor_and_child_target_direction() {
        let namespace = MockNamespace::root();
        let root = root_credential(namespace.clone());
        let parent = credential_with_caps(&root, &[], &[]);
        let child = credential_with_identity_and_caps(&root, 1000, &[CAP_CHOWN], &[]);
        let object = DummyImage { generation: 4 };
        let context = PtraceTracemeContext::new(&parent, &child, &namespace, &object);
        assert_eq!(
            commoncap_ptrace_traceme(&context),
            Err(AuthorizationError::NotPermitted)
        );
        assert_eq!(context.parent_actor().ids().euid, Kuid::INITIAL_ROOT);
        assert_eq!(context.child_target().ids().euid, kuid(1000));

        let parent = credential_with_caps(&root, &[CAP_CHOWN], &[]);
        commoncap_ptrace_traceme(&PtraceTracemeContext::new(
            &parent, &child, &namespace, &object,
        ))
        .unwrap();
    }

    #[test]
    fn contexts_borrow_distinct_noncopy_object_payloads_and_image_owner() {
        let root_namespace = MockNamespace::root();
        let root = root_credential(root_namespace.clone());
        let child_namespace =
            MockNamespace::child(&root_namespace, Kuid::INITIAL_ROOT, Some(kuid(1000)));
        let child = Credential::try_with_user_namespace(&root, child_namespace).unwrap();
        let image = DummyImage { generation: 41 };
        let handle = DummyHandle { cookie: "exact" };

        let access = PtraceAccessContext::new(
            &root,
            &child,
            &root_namespace,
            &image,
            PtraceAccessKind::Read,
            PtraceCredentialKind::Real,
        );
        let traceme = PtraceTracemeContext::new(&root, &child, &root_namespace, &handle);
        assert_eq!(access.target_object().generation, 41);
        assert_eq!(traceme.child_object().cookie, "exact");
        assert!(Arc::ptr_eq(
            access.target_image_owner_user_ns(),
            &root_namespace
        ));
        assert!(Arc::ptr_eq(
            traceme.child_image_owner_user_ns(),
            &root_namespace
        ));
        assert!(!Arc::ptr_eq(
            access.target_image_owner_user_ns(),
            child.user_ns()
        ));
        assert_eq!(access.access_kind(), PtraceAccessKind::Read);
    }

    #[test]
    fn scheduler_owner_relation_is_internal_and_controls_affinity() {
        let namespace = MockNamespace::root();
        let root = root_credential(namespace);
        let actor = credential_with_identity_and_caps(&root, 1000, &[], &[]);
        let owned = credential_with_identity_and_caps(&root, 1000, &[], &[]);
        let other = credential_with_identity_and_caps(&root, 2000, &[], &[]);

        let owned_context =
            SchedulerSecurityContext::new(&actor, &owned, SchedulerSecurityOperation::SetAffinity);
        assert!(owned_context.owner_match());
        commoncap_scheduler(&owned_context).unwrap();

        let other_context =
            SchedulerSecurityContext::new(&actor, &other, SchedulerSecurityOperation::SetAffinity);
        assert!(!other_context.owner_match());
        assert_eq!(
            commoncap_scheduler(&other_context),
            Err(AuthorizationError::NotPermitted)
        );
    }

    #[test]
    fn scheduler_realtime_requires_effective_capability_even_for_owner() {
        let namespace = MockNamespace::root();
        let root = root_credential(namespace);
        let actor = credential_with_identity_and_caps(&root, 1000, &[], &[]);
        let target = credential_with_identity_and_caps(&root, 1000, &[], &[]);
        assert_eq!(
            commoncap_scheduler(&SchedulerSecurityContext::new(
                &actor,
                &target,
                SchedulerSecurityOperation::SetPolicy { realtime: true },
            )),
            Err(AuthorizationError::NotPermitted)
        );
        commoncap_scheduler(&SchedulerSecurityContext::new(
            &actor,
            &target,
            SchedulerSecurityOperation::SetParam { realtime: false },
        ))
        .unwrap();

        let actor =
            credential_with_identity_and_caps(&root, 1000, &[CAP_SYS_NICE], &[CAP_SYS_NICE]);
        commoncap_scheduler(&SchedulerSecurityContext::new(
            &actor,
            &target,
            SchedulerSecurityOperation::SetParam { realtime: true },
        ))
        .unwrap();
    }

    #[test]
    fn scheduler_capability_follows_namespace_direction() {
        let root_namespace = MockNamespace::root();
        let root = root_credential(root_namespace.clone());
        let child_namespace =
            MockNamespace::child(&root_namespace, Kuid::INITIAL_ROOT, Some(kuid(1000)));
        let child_root = Credential::try_with_user_namespace(&root, child_namespace).unwrap();
        let child_target = credential_with_identity_and_caps(&child_root, 1000, &[], &[]);

        commoncap_scheduler(&SchedulerSecurityContext::new(
            &root,
            &child_target,
            SchedulerSecurityOperation::SetParam { realtime: true },
        ))
        .unwrap();

        let child_actor =
            credential_with_identity_and_caps(&child_root, 1000, &[CAP_SYS_NICE], &[CAP_SYS_NICE]);
        assert_eq!(
            commoncap_scheduler(&SchedulerSecurityContext::new(
                &child_actor,
                &root,
                SchedulerSecurityOperation::SetAffinity,
            )),
            Err(AuthorizationError::NotPermitted)
        );
    }

    #[test]
    fn scheduler_nonroot_capability_crosses_owner_boundary() {
        let namespace = MockNamespace::root();
        let root = root_credential(namespace);
        let actor =
            credential_with_identity_and_caps(&root, 1000, &[CAP_SYS_NICE], &[CAP_SYS_NICE]);
        let target = credential_with_identity_and_caps(&root, 2000, &[], &[]);
        commoncap_scheduler(&SchedulerSecurityContext::new(
            &actor,
            &target,
            SchedulerSecurityOperation::SetNice {
                current_nice: 0,
                requested_nice: -20,
                rlimit_nice: 0,
            },
        ))
        .unwrap();
    }

    #[test]
    fn scheduler_nice_uses_owner_and_exact_frozen_rlimit() {
        let namespace = MockNamespace::root();
        let root = root_credential(namespace);
        let actor = credential_with_identity_and_caps(&root, 1000, &[], &[]);
        let target = credential_with_identity_and_caps(&root, 1000, &[], &[]);

        commoncap_scheduler(&SchedulerSecurityContext::new(
            &actor,
            &target,
            SchedulerSecurityOperation::SetNice {
                current_nice: 0,
                requested_nice: -5,
                rlimit_nice: 25,
            },
        ))
        .unwrap();
        assert_eq!(
            commoncap_scheduler(&SchedulerSecurityContext::new(
                &actor,
                &target,
                SchedulerSecurityOperation::SetNice {
                    current_nice: 0,
                    requested_nice: -5,
                    rlimit_nice: 24,
                },
            )),
            Err(AuthorizationError::AccessDenied)
        );
        commoncap_scheduler(&SchedulerSecurityContext::new(
            &actor,
            &target,
            SchedulerSecurityOperation::SetNice {
                current_nice: 0,
                requested_nice: 5,
                rlimit_nice: 0,
            },
        ))
        .unwrap();
    }

    #[test]
    fn nice_to_rlimit_boundaries_are_exact_and_bounded() {
        assert_eq!(nice_to_rlimit(-20), Some(40));
        assert_eq!(nice_to_rlimit(19), Some(1));
        assert_eq!(nice_to_rlimit(-21), None);
        assert_eq!(nice_to_rlimit(20), None);
        assert!(!rlimit_allows_nice(0, 19));
        assert!(rlimit_allows_nice(1, 19));
        assert!(rlimit_allows_nice(40, -20));
        assert!(!rlimit_allows_nice(u64::MAX, 19));
    }

    #[test]
    fn authorization_errors_remain_policy_neutral() {
        assert_eq!(
            AuthorizationError::NotPermitted.to_string(),
            "security operation not permitted"
        );
        assert_eq!(
            AuthorizationError::AccessDenied.to_string(),
            "security access denied"
        );
    }
}
