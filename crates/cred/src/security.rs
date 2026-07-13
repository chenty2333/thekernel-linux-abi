//! Policy-neutral typed security contexts and Linux commoncap decisions.
//!
//! Contexts borrow immutable credentials, namespace ownership, and opaque
//! object payloads supplied by an embedding kernel. This module owns no task
//! lookup, `current()` access, process or address-space type, hook registry,
//! lock, publication mechanism, or errno mapping.

use alloc::sync::Arc;
use core::{fmt, num::NonZeroU32};

use linux_raw_sys::general::{CAP_KILL, CAP_SYS_NICE, CAP_SYS_PTRACE, SIGCONT};

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

/// Origin class for one userspace-requested signal authorization.
///
/// This is intentionally narrower than a raw `siginfo_t`: the embedding ABI
/// adapter validates and resolves userspace records first, then preserves only
/// the source facts a policy module can safely consume without retaining a
/// userspace pointer or repeating usercopy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignalSecuritySource {
    /// `kill(2)` and its process-group or broadcast forms.
    Kill,
    /// `tkill(2)` or `tgkill(2)`.
    Thread,
    /// `rt_sigqueueinfo(2)` or `rt_tgsigqueueinfo(2)` with its validated code.
    Queued {
        /// Frozen `si_code` copied from the mandatory userspace record.
        code: i32,
    },
    /// `pidfd_send_signal(2)` with its validated optional `siginfo_t` code.
    PidFd {
        /// Frozen supplied or kernel-synthesized `si_code`.
        code: i32,
    },
}

/// Publication scope after an exact target task passes authorization.
///
/// Linux can authorize a named non-leader task while publishing to that
/// task's shared thread-group pending queue, so this is deliberately separate
/// from source and object identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignalDeliveryScope {
    /// Publish to the target task's thread group/shared pending queue.
    ThreadGroup,
    /// Publish only to the exact target task's private pending queue.
    Thread,
}

/// Valid Linux signal number accepted by the typed security contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SignalNumber(NonZeroU32);

impl SignalNumber {
    /// Highest signal number in the Linux 64-signal ABI set.
    pub const MAX: u32 = 64;

    /// Validates a raw Linux signal number.
    pub const fn try_new(raw: u32) -> Option<Self> {
        if raw > Self::MAX {
            return None;
        }
        match NonZeroU32::new(raw) {
            Some(raw) => Some(Self(raw)),
            None => None,
        }
    }

    /// Returns the validated raw Linux signal number.
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

/// One already-validated userspace signal request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignalSecurityOperation {
    signal: Option<SignalNumber>,
    source: SignalSecuritySource,
    delivery_scope: SignalDeliveryScope,
}

impl SignalSecurityOperation {
    /// Constructs a signal-zero existence/permission probe.
    pub const fn probe(source: SignalSecuritySource, delivery_scope: SignalDeliveryScope) -> Self {
        Self {
            signal: None,
            source,
            delivery_scope,
        }
    }

    /// Constructs a request to send one already-validated nonzero signal.
    pub const fn send(
        signal: SignalNumber,
        source: SignalSecuritySource,
        delivery_scope: SignalDeliveryScope,
    ) -> Self {
        Self {
            signal: Some(signal),
            source,
            delivery_scope,
        }
    }

    /// Constructs the corresponding probe or send operation.
    pub const fn from_optional_signal(
        signal: Option<SignalNumber>,
        source: SignalSecuritySource,
        delivery_scope: SignalDeliveryScope,
    ) -> Self {
        match signal {
            Some(signal) => Self::send(signal, source, delivery_scope),
            None => Self::probe(source, delivery_scope),
        }
    }

    /// Returns the requested signal, or `None` for a signal-zero probe.
    pub const fn signal(self) -> Option<SignalNumber> {
        self.signal
    }

    /// Fallibly constructs a send operation from an untrusted raw number.
    /// Embedding adapters which already parsed a signal should prefer
    /// [`Self::send`] and carry [`SignalNumber`] directly.
    pub const fn try_send(
        signal: u32,
        source: SignalSecuritySource,
        delivery_scope: SignalDeliveryScope,
    ) -> Option<Self> {
        match SignalNumber::try_new(signal) {
            Some(signal) => Some(Self::send(signal, source, delivery_scope)),
            None => None,
        }
    }

    /// Returns the frozen userspace request source.
    pub const fn source(self) -> SignalSecuritySource {
        self.source
    }

    /// Returns the frozen publication scope.
    pub const fn delivery_scope(self) -> SignalDeliveryScope {
        self.delivery_scope
    }
}

/// Linux core rule which admitted a signal request before policy hooks run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignalCoreAuthorizationReason {
    /// Actor and target belong to the same Linux thread group.
    SameThreadGroup,
    /// A real/effective actor UID matches the target real/saved UID.
    CredentialMatch,
    /// The actor holds `CAP_KILL` over the target credential namespace.
    Capability,
    /// A `SIGCONT` request crosses credentials within the same session.
    SigcontSameSession,
}

/// Opaque proof that Linux's non-LSM signal permission rule admitted one exact
/// immutable actor/target pair.
///
/// The token borrows both credentials and carries the normalized operation, so
/// it cannot be rebound to a later credential snapshot before construction of
/// [`SignalSecurityContext`].
pub struct SignalCoreAuthorization<'a, N: UserNamespaceView> {
    actor: &'a Credential<N>,
    target: &'a Credential<N>,
    operation: SignalSecurityOperation,
    reason: SignalCoreAuthorizationReason,
    same_thread_group: bool,
    sigcont_same_session: bool,
}

impl<'a, N: UserNamespaceView> SignalCoreAuthorization<'a, N> {
    /// Borrows the exact immutable actor credential admitted by the core rule.
    pub const fn actor(&self) -> &'a Credential<N> {
        self.actor
    }

    /// Borrows the exact immutable target credential admitted by the core rule.
    pub const fn target(&self) -> &'a Credential<N> {
        self.target
    }

    /// Returns the frozen signal operation.
    pub const fn operation(&self) -> SignalSecurityOperation {
        self.operation
    }

    /// Returns the core rule which admitted this request.
    pub const fn reason(&self) -> SignalCoreAuthorizationReason {
        self.reason
    }

    /// Returns the already-resolved same-thread-group fact.
    pub const fn same_thread_group(&self) -> bool {
        self.same_thread_group
    }

    /// Returns whether the request is `SIGCONT` and both processes share one
    /// already-resolved session identity.
    pub const fn sigcont_same_session(&self) -> bool {
        self.sigcont_same_session
    }
}

/// Applies Linux's core signal permission rule before stacked policy hooks.
///
/// Same-thread-group admission is checked first. Otherwise the actor's real or
/// effective UID must match the target's real or saved UID, the actor must hold
/// `CAP_KILL` over the target namespace, or `SIGCONT` must target the same
/// already-resolved session. The session fact is ignored for every other
/// signal and for a signal-zero probe.
///
/// # Errors
///
/// Returns [`AuthorizationError::NotPermitted`] when none of the core rules
/// admits the exact immutable credential pair.
pub fn authorize_signal_core<'a, N: UserNamespaceView>(
    actor: &'a Credential<N>,
    target: &'a Credential<N>,
    operation: SignalSecurityOperation,
    same_thread_group: bool,
    same_session: bool,
) -> Result<SignalCoreAuthorization<'a, N>, AuthorizationError> {
    let actor_ids = actor.ids();
    let target_ids = target.ids();
    let credential_match = [actor_ids.ruid, actor_ids.euid]
        .into_iter()
        .any(|uid| uid == target_ids.ruid || uid == target_ids.suid);
    let sigcont_same_session = operation
        .signal
        .is_some_and(|signal| signal.get() == SIGCONT)
        && same_session;
    let reason = if same_thread_group {
        SignalCoreAuthorizationReason::SameThreadGroup
    } else if credential_match {
        SignalCoreAuthorizationReason::CredentialMatch
    } else if ns_capable(actor, target.user_ns(), CAP_KILL) {
        SignalCoreAuthorizationReason::Capability
    } else if sigcont_same_session {
        SignalCoreAuthorizationReason::SigcontSameSession
    } else {
        return Err(AuthorizationError::NotPermitted);
    };
    Ok(SignalCoreAuthorization {
        actor,
        target,
        operation,
        reason,
        same_thread_group,
        sigcont_same_session,
    })
}

/// Complete immutable input to one stacked signal policy hook.
///
/// `O` is an embedding-owned identity for the exact live thread, process, or
/// durable zombie selected before dispatch. The context can only be built from
/// a successful [`authorize_signal_core`] token, preserving the Linux ordering
/// between core signal permission and policy-module authorization.
pub struct SignalSecurityContext<'a, N: UserNamespaceView, O: ?Sized> {
    authorization: SignalCoreAuthorization<'a, N>,
    target_object: &'a O,
}

impl<'a, N: UserNamespaceView, O: ?Sized> SignalSecurityContext<'a, N, O> {
    /// Binds a successful core authorization to one exact target object.
    pub const fn new(authorization: SignalCoreAuthorization<'a, N>, target_object: &'a O) -> Self {
        Self {
            authorization,
            target_object,
        }
    }

    /// Borrows the exact immutable actor credential.
    pub const fn actor(&self) -> &'a Credential<N> {
        self.authorization.actor
    }

    /// Borrows the exact immutable target credential.
    pub const fn target(&self) -> &'a Credential<N> {
        self.authorization.target
    }

    /// Borrows the target credential's owning user namespace.
    pub const fn target_owner_user_ns(&self) -> &'a Arc<N> {
        self.authorization.target.user_ns()
    }

    /// Borrows the embedding-defined exact target object identity.
    pub const fn target_object(&self) -> &'a O {
        self.target_object
    }

    /// Returns the frozen userspace signal operation.
    pub const fn operation(&self) -> SignalSecurityOperation {
        self.authorization.operation
    }

    /// Returns the Linux core rule which admitted the request.
    pub const fn core_reason(&self) -> SignalCoreAuthorizationReason {
        self.authorization.reason
    }

    /// Returns the already-resolved same-thread-group fact.
    pub const fn same_thread_group(&self) -> bool {
        self.authorization.same_thread_group
    }

    /// Returns the already-resolved `SIGCONT` same-session fact.
    pub const fn sigcont_same_session(&self) -> bool {
        self.authorization.sigcont_same_session
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

    use linux_raw_sys::general::{CAP_CHOWN, CAP_KILL, CAP_SYS_NICE, CAP_SYS_PTRACE, SIGTERM};

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
    fn signal_core_authorization_covers_probe_identity_capability_and_group_rules() {
        let namespace = MockNamespace::root();
        let root = root_credential(namespace);
        let actor = credential_with_identity_and_caps(&root, 1000, &[], &[]);
        let unrelated = credential_with_identity_and_caps(&root, 2000, &[], &[]);
        let probe = SignalSecurityOperation::probe(
            SignalSecuritySource::Kill,
            SignalDeliveryScope::ThreadGroup,
        );

        assert_eq!(
            authorize_signal_core(&actor, &unrelated, probe, false, false).err(),
            Some(AuthorizationError::NotPermitted)
        );
        let same_group = authorize_signal_core(&actor, &unrelated, probe, true, false).unwrap();
        assert_eq!(
            same_group.reason(),
            SignalCoreAuthorizationReason::SameThreadGroup
        );
        assert!(same_group.same_thread_group());

        let mut saved_ids = unrelated.ids();
        saved_ids.suid = actor.ids().euid;
        let saved_match = Credential::try_from_transition(
            &unrelated,
            saved_ids,
            unrelated.groups().clone(),
            unrelated.capabilities(),
            unrelated.no_new_privs(),
            unrelated.user_ns().clone(),
            CredentialTransitionMode::Normal,
        )
        .unwrap();
        assert_eq!(
            authorize_signal_core(&actor, &saved_match, probe, false, false)
                .unwrap()
                .reason(),
            SignalCoreAuthorizationReason::CredentialMatch
        );

        let capable = credential_with_identity_and_caps(&root, 3000, &[CAP_KILL], &[CAP_KILL]);
        assert_eq!(
            authorize_signal_core(&capable, &unrelated, probe, false, false)
                .unwrap()
                .reason(),
            SignalCoreAuthorizationReason::Capability
        );
    }

    #[test]
    fn signal_core_uses_same_session_only_for_sigcont() {
        let namespace = MockNamespace::root();
        let root = root_credential(namespace);
        let actor = credential_with_identity_and_caps(&root, 1000, &[], &[]);
        let target = credential_with_identity_and_caps(&root, 2000, &[], &[]);

        let sigcont = SignalSecurityOperation::send(
            SignalNumber::try_new(SIGCONT).unwrap(),
            SignalSecuritySource::Queued { code: -1 },
            SignalDeliveryScope::ThreadGroup,
        );
        let authorization = authorize_signal_core(&actor, &target, sigcont, false, true).unwrap();
        assert_eq!(
            authorization.reason(),
            SignalCoreAuthorizationReason::SigcontSameSession
        );
        assert!(authorization.sigcont_same_session());

        let ordinary = SignalSecurityOperation::send(
            SignalNumber::try_new(SIGTERM).unwrap(),
            SignalSecuritySource::Kill,
            SignalDeliveryScope::ThreadGroup,
        );
        assert_eq!(
            authorize_signal_core(&actor, &target, ordinary, false, true).err(),
            Some(AuthorizationError::NotPermitted)
        );
        assert_eq!(
            authorize_signal_core(
                &actor,
                &target,
                SignalSecurityOperation::probe(
                    SignalSecuritySource::Kill,
                    SignalDeliveryScope::ThreadGroup,
                ),
                false,
                true,
            )
            .err(),
            Some(AuthorizationError::NotPermitted)
        );
    }

    #[test]
    fn signal_context_binds_exact_credentials_operation_owner_and_object() {
        let namespace = MockNamespace::root();
        let root = root_credential(namespace.clone());
        let actor = credential_with_identity_and_caps(&root, 1000, &[], &[]);
        let target = credential_with_identity_and_caps(&root, 2000, &[], &[]);
        let operation = SignalSecurityOperation::send(
            SignalNumber::try_new(SIGTERM).unwrap(),
            SignalSecuritySource::PidFd { code: -6 },
            SignalDeliveryScope::Thread,
        );
        let authorization = authorize_signal_core(&actor, &target, operation, true, false).unwrap();
        let object = DummyHandle {
            cookie: "pidfd-target",
        };
        let context = SignalSecurityContext::new(authorization, &object);

        assert!(core::ptr::eq(context.actor(), actor.as_ref()));
        assert!(core::ptr::eq(context.target(), target.as_ref()));
        assert!(Arc::ptr_eq(context.target_owner_user_ns(), &namespace));
        assert!(core::ptr::eq(context.target_object(), &object));
        assert_eq!(context.target_object().cookie, "pidfd-target");
        assert_eq!(context.operation(), operation);
        assert_eq!(
            context.core_reason(),
            SignalCoreAuthorizationReason::SameThreadGroup
        );
        assert!(context.same_thread_group());
        assert!(!context.sigcont_same_session());
    }

    #[test]
    fn signal_send_construction_rejects_zero_and_preserves_nonzero() {
        assert_eq!(
            SignalSecurityOperation::try_send(
                0,
                SignalSecuritySource::Thread,
                SignalDeliveryScope::Thread,
            ),
            None
        );
        let signal = SignalSecurityOperation::try_send(
            15,
            SignalSecuritySource::Thread,
            SignalDeliveryScope::Thread,
        )
        .unwrap();
        assert_eq!(signal.signal(), SignalNumber::try_new(15));
        assert_eq!(signal.source(), SignalSecuritySource::Thread);
        assert_eq!(signal.delivery_scope(), SignalDeliveryScope::Thread);
    }

    #[test]
    fn signal_number_bounds_are_exact() {
        assert_eq!(SignalNumber::try_new(0), None);
        assert_eq!(SignalNumber::try_new(1).unwrap().get(), 1);
        assert_eq!(SignalNumber::try_new(64).unwrap().get(), 64);
        assert_eq!(SignalNumber::try_new(65), None);
        assert_eq!(SignalNumber::try_new(u32::MAX), None);
        assert_eq!(
            SignalSecurityOperation::try_send(
                65,
                SignalSecuritySource::Kill,
                SignalDeliveryScope::ThreadGroup,
            ),
            None
        );
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
