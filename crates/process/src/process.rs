use alloc::{
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{
    fmt,
    sync::atomic::{AtomicBool, Ordering},
};

use intrusive_collections::{Bound, KeyAdapter, RBTree, RBTreeAtomicLink, intrusive_adapter};
use kspin::SpinNoIrq;

use crate::{Pid, ProcessGroup, Session};

/// Default maximum number of process or per-process thread membership records.
///
/// A [`ProcessDomain`] may choose a lower process-registry limit. Its processes
/// use that same lower limit for each thread group.
pub const PROCESS_MEMBERSHIP_LIMIT: usize = 65_536;

/// Failure returned by fallible process-lifecycle operations.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProcessError {
    /// Allocator capacity could not be reserved.
    NoMemory,
    /// The requested PID or TID is already live or reserved.
    AlreadyExists,
    /// The configured membership ceiling has been reached.
    Capacity,
    /// An object belongs to a different process registry.
    WrongDomain,
    /// The process is unpublished, reaped, or otherwise not in the registry.
    NotPublished,
    /// The process has already entered zombie state.
    NotLive,
    /// The domain does not yet have an init process.
    NotInitialized,
}

impl fmt::Display for ProcessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoMemory => f.write_str("process allocation failed"),
            Self::AlreadyExists => f.write_str("process identifier already exists"),
            Self::Capacity => f.write_str("process membership limit reached"),
            Self::WrongDomain => f.write_str("object belongs to another process domain"),
            Self::NotPublished => f.write_str("process is not published"),
            Self::NotLive => f.write_str("process is no longer live"),
            Self::NotInitialized => f.write_str("process domain has no init process"),
        }
    }
}

/// Result of asking a process domain to transition a process to zombie state.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ExitOutcome {
    /// Init processes remain live and were not changed.
    InitProcess,
    /// Another caller had already completed the zombie transition.
    AlreadyZombie,
    /// This call performed the zombie transition and child reparenting.
    BecameZombie,
}

/// A newly created session together with its initial process group.
pub type CreatedSession<Z> = (Arc<Session<Z>>, Arc<ProcessGroup<Z>>);

struct ThreadNode {
    link: RBTreeAtomicLink,
    tid: Pid,
    live: AtomicBool,
}

intrusive_adapter!(ThreadAdapter = Arc<ThreadNode>: ThreadNode { link: RBTreeAtomicLink });

impl<'a> KeyAdapter<'a> for ThreadAdapter {
    type Key = Pid;

    fn get_key(&self, thread: &'a ThreadNode) -> Self::Key {
        thread.tid
    }
}

struct ThreadGroup {
    threads: RBTree<ThreadAdapter>,
    memberships: usize,
    live_threads: usize,
    exit_code: i32,
    group_exited: bool,
}

impl ThreadGroup {
    fn new() -> Self {
        Self {
            threads: RBTree::new(ThreadAdapter::new()),
            memberships: 0,
            live_threads: 0,
            exit_code: 0,
            group_exited: false,
        }
    }
}

/// A process whose durable zombie state is supplied by the caller as `Z`.
pub struct Process<Z> {
    registry_link: RBTreeAtomicLink,
    registry: Weak<ProcessRegistry<Z>>,
    published: AtomicBool,
    pid: Pid,
    init: bool,
    is_zombie: AtomicBool,
    reaped: AtomicBool,
    tg: SpinNoIrq<ThreadGroup>,
    exit_signal: Option<u8>,
    zombie_payload: SpinNoIrq<Option<Z>>,
    child_subreaper: AtomicBool,
    parent: SpinNoIrq<Weak<Process<Z>>>,
    group: SpinNoIrq<Arc<ProcessGroup<Z>>>,
}

intrusive_adapter!(ProcessAdapter<Z> = Arc<Process<Z>>: Process<Z> {
    registry_link: RBTreeAtomicLink
});

impl<'a, Z> KeyAdapter<'a> for ProcessAdapter<Z> {
    type Key = Pid;

    fn get_key(&self, process: &'a Process<Z>) -> Self::Key {
        process.pid
    }
}

struct RegistryState<Z> {
    entries: RBTree<ProcessAdapter<Z>>,
    memberships: usize,
}

impl<Z> RegistryState<Z> {
    fn new() -> Self {
        Self {
            entries: RBTree::new(ProcessAdapter::new()),
            memberships: 0,
        }
    }
}

/// A bounded PID registry owned by exactly one [`ProcessDomain`].
///
/// The registry has no singleton instance. Read-only enumeration is explicit,
/// and mutation is mediated by the owning domain and admission tokens.
pub struct ProcessRegistry<Z> {
    state: SpinNoIrq<RegistryState<Z>>,
    membership_limit: usize,
}

impl<Z> ProcessRegistry<Z> {
    fn new(membership_limit: usize) -> Self {
        Self {
            state: SpinNoIrq::new(RegistryState::new()),
            membership_limit: membership_limit.min(PROCESS_MEMBERSHIP_LIMIT),
        }
    }

    /// Returns the configured process and per-process thread membership limit.
    pub fn membership_limit(&self) -> usize {
        self.membership_limit
    }

    /// Returns the number of live and reserved process membership records.
    pub fn membership_count(&self) -> usize {
        self.state.lock().memberships
    }

    /// Looks up one published process by PID.
    pub fn get(&self, pid: Pid) -> Option<Arc<Process<Z>>> {
        let state = self.state.lock();
        let process = state.entries.find(&pid).clone_pointer();
        drop(state);
        process.filter(|process| process.published.load(Ordering::Acquire))
    }

    /// Iterates published processes in PID order without allocating.
    pub fn processes(&self) -> Processes<'_, Z> {
        Processes {
            registry: self,
            last: None,
            after: None,
            remaining: self.membership_count(),
            finished: false,
        }
    }

    /// Fallibly snapshots every published process in PID order.
    pub fn try_processes(&self) -> Result<Vec<Arc<Process<Z>>>, ProcessError> {
        self.try_collect_process_values(|process| Some(process.clone()))
    }

    fn belongs(&self, process: &Process<Z>) -> bool {
        core::ptr::eq(process.registry.as_ptr(), self)
    }

    fn ensure_published(&self, process: &Process<Z>) -> Result<(), ProcessError> {
        if !self.belongs(process) {
            return Err(ProcessError::WrongDomain);
        }
        if !process.published.load(Ordering::Acquire) || !process.registry_link.is_linked() {
            return Err(ProcessError::NotPublished);
        }
        Ok(())
    }

    fn admit(
        self: &Arc<Self>,
        process: Arc<Process<Z>>,
    ) -> Result<ProcessAdmission<Z>, ProcessError> {
        if !self.belongs(&process) {
            return Err(ProcessError::WrongDomain);
        }
        let mut state = self.state.lock();
        if state.memberships >= self.membership_limit {
            return Err(ProcessError::Capacity);
        }
        if !state.entries.find(&process.pid).is_null() {
            return Err(ProcessError::AlreadyExists);
        }
        state.entries.insert(process.clone());
        state.memberships += 1;
        drop(state);
        Ok(ProcessAdmission {
            registry: self.clone(),
            process,
            committed: false,
        })
    }

    pub(crate) fn try_collect_process_values<T>(
        &self,
        mut map: impl FnMut(&Arc<Process<Z>>) -> Option<T>,
    ) -> Result<Vec<T>, ProcessError> {
        let mut snapshot = Vec::new();
        loop {
            snapshot.clear();
            let required = self.membership_count();
            if snapshot.capacity() < required {
                snapshot
                    .try_reserve_exact(required)
                    .map_err(|_| ProcessError::NoMemory)?;
            }

            let mut overflow = false;
            for process in self.processes() {
                let Some(value) = map(&process) else {
                    continue;
                };
                if snapshot.len() == snapshot.capacity() {
                    drop(value);
                    overflow = true;
                    break;
                }
                snapshot.push(value);
            }
            if !overflow {
                return Ok(snapshot);
            }

            let current = snapshot.capacity();
            if current >= self.membership_limit {
                return Err(ProcessError::Capacity);
            }
            let target = current.max(1).saturating_mul(2).min(self.membership_limit);
            snapshot.clear();
            snapshot
                .try_reserve_exact(target)
                .map_err(|_| ProcessError::NoMemory)?;
        }
    }
}

/// Explicit owner of one process registry and its unique init identity.
pub struct ProcessDomain<Z> {
    registry: Arc<ProcessRegistry<Z>>,
    init: SpinNoIrq<Option<Arc<Process<Z>>>>,
}

impl<Z> ProcessDomain<Z> {
    /// Fallibly creates a domain with the default bounded membership limit.
    pub fn try_new() -> Result<Self, ProcessError> {
        Self::try_with_membership_limit(PROCESS_MEMBERSHIP_LIMIT)
    }

    /// Fallibly creates a domain with a lower process/thread membership limit.
    pub fn try_with_membership_limit(limit: usize) -> Result<Self, ProcessError> {
        let registry =
            Arc::try_new(ProcessRegistry::new(limit)).map_err(|_| ProcessError::NoMemory)?;
        Ok(Self {
            registry,
            init: SpinNoIrq::new(None),
        })
    }

    /// Returns this domain's explicit registry.
    pub fn registry(&self) -> &ProcessRegistry<Z> {
        &self.registry
    }

    /// Returns the domain's init process after initialization.
    pub fn init_process(&self) -> Option<Arc<Process<Z>>> {
        self.init.lock().clone()
    }

    /// Fallibly creates, publishes, and records the domain's unique init process.
    pub fn try_new_init(
        &self,
        pid: Pid,
        exit_signal: Option<u8>,
    ) -> Result<Arc<Process<Z>>, ProcessError> {
        let session = Session::try_new(pid, &self.registry)?;
        let group = ProcessGroup::try_new(pid, &session)?;
        let process = Process::try_allocate(&self.registry, pid, true, None, group, exit_signal)?;
        let admission = self.registry.admit(process.clone())?;

        let mut init = self.init.lock();
        if init.is_some() {
            drop(init);
            drop(admission);
            return Err(ProcessError::AlreadyExists);
        }
        admission.commit();
        *init = Some(process.clone());
        Ok(process)
    }

    /// Reserves an unpublished child process and registry capacity credit.
    ///
    /// The adapter must serialize this admission and its final commit against
    /// [`exit`](Self::exit) for the same parent, as it already must serialize
    /// the runtime resources installed between prepare and commit.
    pub fn prepare_fork(
        &self,
        parent: &Arc<Process<Z>>,
        pid: Pid,
        exit_signal: Option<u8>,
    ) -> Result<ProcessAdmission<Z>, ProcessError> {
        self.registry.ensure_published(parent)?;
        if parent.is_zombie() {
            return Err(ProcessError::NotLive);
        }
        let process = Process::try_allocate(
            &self.registry,
            pid,
            false,
            Some(parent),
            parent.group(),
            exit_signal,
        )?;
        self.registry.admit(process)
    }

    fn reaper_for_exit(&self, process: &Arc<Process<Z>>) -> Result<Arc<Process<Z>>, ProcessError> {
        let init = self.init_process().ok_or(ProcessError::NotInitialized)?;
        let mut ancestor = process.parent();
        while let Some(candidate) = ancestor {
            if candidate.is_child_subreaper() && !candidate.is_zombie() {
                return Ok(candidate);
            }
            ancestor = candidate.parent();
        }
        Ok(init)
    }

    /// Marks a process zombie and reparents its children without allocation.
    ///
    /// `inherited_zombie` runs outside registry and parent-pointer locks for
    /// each already-zombie child moved to the new reaper.
    /// The adapter must serialize this operation against child admission for
    /// `process`; the crate deliberately does not hide a kernel lifecycle lock.
    pub fn exit(
        &self,
        process: &Arc<Process<Z>>,
        mut inherited_zombie: impl FnMut(Arc<Process<Z>>),
    ) -> Result<ExitOutcome, ProcessError> {
        self.registry.ensure_published(process)?;
        if process.is_init() {
            return Ok(ExitOutcome::InitProcess);
        }
        let reaper = self.reaper_for_exit(process)?;
        if process
            .is_zombie
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(ExitOutcome::AlreadyZombie);
        }

        let reaper_weak = Arc::downgrade(&reaper);
        for child in self.registry.processes().filter(|child| {
            child
                .parent()
                .is_some_and(|parent| Arc::ptr_eq(&parent, process))
        }) {
            let old_parent = core::mem::replace(&mut *child.parent.lock(), reaper_weak.clone());
            drop(old_parent);
            if child.is_zombie() {
                inherited_zombie(child);
            }
        }
        Ok(ExitOutcome::BecameZombie)
    }

    /// Reaps a zombie from this domain, returning false for invalid or duplicate reap.
    pub fn reap(&self, process: &Process<Z>) -> Result<bool, ProcessError> {
        if !self.registry.belongs(process) {
            return Err(ProcessError::WrongDomain);
        }
        if process.reaped.load(Ordering::Acquire) {
            return Ok(false);
        }
        self.registry.ensure_published(process)?;
        if !process.is_zombie()
            || process
                .reaped
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return Ok(false);
        }

        let removed = {
            let mut state = self.registry.state.lock();
            // SAFETY: registry identity was checked above, the linked bit is
            // true, and this registry exclusively owns the intrusive tree.
            let removed = unsafe {
                state
                    .entries
                    .cursor_mut_from_ptr(process as *const Process<Z>)
                    .remove()
            };
            if removed.is_some() {
                state.memberships -= 1;
            }
            removed
        };
        let existed = removed.is_some();
        drop(removed);
        Ok(existed)
    }
}

/// Allocation-free PID-ordered iterator over a [`ProcessRegistry`].
///
/// Each lock acquisition clones at most one intrusive node. The initial
/// membership count bounds the walk under concurrent fork and reap activity.
pub struct Processes<'a, Z> {
    registry: &'a ProcessRegistry<Z>,
    last: Option<Arc<Process<Z>>>,
    after: Option<Pid>,
    remaining: usize,
    finished: bool,
}

impl<Z> Iterator for Processes<'_, Z> {
    type Item = Arc<Process<Z>>;

    fn next(&mut self) -> Option<Self::Item> {
        while !self.finished && self.remaining != 0 {
            let state = self.registry.state.lock();
            let next = if let Some(last) = self
                .last
                .as_ref()
                .filter(|last| last.registry_link.is_linked())
            {
                // SAFETY: a linked node with matching registry identity is in
                // this tree; the state lock prevents concurrent removal.
                let mut cursor = unsafe { state.entries.cursor_from_ptr(Arc::as_ptr(last)) };
                cursor.move_next();
                cursor.clone_pointer()
            } else if let Some(after) = self.after.as_ref() {
                state
                    .entries
                    .lower_bound(Bound::Excluded(after))
                    .clone_pointer()
            } else {
                state.entries.front().clone_pointer()
            };
            drop(state);

            let Some(next) = next else {
                self.finished = true;
                break;
            };
            self.remaining -= 1;
            self.after = Some(next.pid);
            let last = self.last.replace(next.clone());
            drop(last);
            if next.published.load(Ordering::Acquire) {
                return Some(next);
            }
        }

        self.finished = true;
        let last = self.last.take();
        drop(last);
        None
    }
}

impl<Z> Process<Z> {
    fn try_allocate(
        registry: &Arc<ProcessRegistry<Z>>,
        pid: Pid,
        init: bool,
        parent: Option<&Arc<Process<Z>>>,
        group: Arc<ProcessGroup<Z>>,
        exit_signal: Option<u8>,
    ) -> Result<Arc<Self>, ProcessError> {
        Arc::try_new(Self {
            registry_link: RBTreeAtomicLink::new(),
            registry: Arc::downgrade(registry),
            published: AtomicBool::new(false),
            pid,
            init,
            is_zombie: AtomicBool::new(false),
            reaped: AtomicBool::new(false),
            tg: SpinNoIrq::new(ThreadGroup::new()),
            exit_signal,
            zombie_payload: SpinNoIrq::new(None),
            child_subreaper: AtomicBool::new(false),
            parent: SpinNoIrq::new(parent.map(Arc::downgrade).unwrap_or_default()),
            group: SpinNoIrq::new(group),
        })
        .map_err(|_| ProcessError::NoMemory)
    }

    /// The process ID.
    pub fn pid(&self) -> Pid {
        self.pid
    }

    /// Returns whether this is the unique init process of its domain.
    pub fn is_init(&self) -> bool {
        self.init
    }

    /// Returns the signal selected by the caller for parent notification.
    pub fn exit_signal(&self) -> Option<u8> {
        self.exit_signal
    }

    /// Publishes the caller-defined durable zombie payload exactly once.
    ///
    /// On duplicate publication, ownership of `payload` is returned unchanged.
    pub fn try_publish_zombie_payload(&self, payload: Z) -> Result<(), Z> {
        let mut slot = self.zombie_payload.lock();
        if slot.is_some() {
            return Err(payload);
        }
        *slot = Some(payload);
        Ok(())
    }

    /// Copies the caller-defined zombie payload, if it has been published.
    ///
    /// Requiring `Copy` keeps arbitrary clone or allocation code out of the
    /// non-sleeping payload lock. Callers needing a larger object may choose a
    /// small copyable handle as `Z` and own the object in their adapter layer.
    pub fn zombie_payload(&self) -> Option<Z>
    where
        Z: Copy,
    {
        *self.zombie_payload.lock()
    }

    /// Returns whether this process acts as a child subreaper.
    pub fn is_child_subreaper(&self) -> bool {
        self.child_subreaper.load(Ordering::Acquire)
    }

    /// Configures child-subreaper state.
    pub fn set_child_subreaper(&self, enabled: bool) {
        self.child_subreaper.store(enabled, Ordering::Release);
    }

    /// Returns the current parent, if it remains alive.
    pub fn parent(&self) -> Option<Arc<Process<Z>>> {
        self.parent.lock().upgrade()
    }

    /// Fallibly snapshots this process's published children in `registry`.
    pub fn try_children(
        self: &Arc<Self>,
        registry: &ProcessRegistry<Z>,
    ) -> Result<Vec<Arc<Process<Z>>>, ProcessError> {
        registry.ensure_published(self)?;
        registry.try_collect_process_values(|child| {
            child
                .parent()
                .is_some_and(|parent| Arc::ptr_eq(&parent, self))
                .then(|| child.clone())
        })
    }

    /// Returns this process's process group.
    pub fn group(&self) -> Arc<ProcessGroup<Z>> {
        self.group.lock().clone()
    }

    fn set_group(self: &Arc<Self>, group: &Arc<ProcessGroup<Z>>) {
        let old = core::mem::replace(&mut *self.group.lock(), group.clone());
        drop(old);
    }

    /// Fallibly creates a new session and group, then moves this process into it.
    pub fn try_create_session(self: &Arc<Self>) -> Result<Option<CreatedSession<Z>>, ProcessError> {
        if self.group().session.sid() == self.pid {
            return Ok(None);
        }
        let registry = self.registry.upgrade().ok_or(ProcessError::WrongDomain)?;
        let session = Session::try_new(self.pid, &registry)?;
        let group = ProcessGroup::try_new(self.pid, &session)?;
        self.set_group(&group);
        Ok(Some((session, group)))
    }

    /// Fallibly creates a new process group, then moves this process into it.
    pub fn try_create_group(
        self: &Arc<Self>,
    ) -> Result<Option<Arc<ProcessGroup<Z>>>, ProcessError> {
        let old_group = self.group();
        if old_group.pgid() == self.pid {
            return Ok(None);
        }
        let group = ProcessGroup::try_new(self.pid, &old_group.session)?;
        self.set_group(&group);
        Ok(Some(group))
    }

    /// Moves this process to a group in the same session and registry.
    pub fn move_to_group(self: &Arc<Self>, group: &Arc<ProcessGroup<Z>>) -> bool {
        let old_group = self.group();
        if Arc::ptr_eq(&old_group, group) {
            return true;
        }
        if !Arc::ptr_eq(&old_group.session, &group.session) {
            return false;
        }
        self.set_group(group);
        true
    }

    /// Reserves capacity for a thread without publishing its TID.
    pub fn prepare_thread(self: &Arc<Self>, tid: Pid) -> Result<ThreadAdmission<Z>, ProcessError> {
        let node = Arc::try_new(ThreadNode {
            link: RBTreeAtomicLink::new(),
            tid,
            live: AtomicBool::new(false),
        })
        .map_err(|_| ProcessError::NoMemory)?;
        let limit = self
            .registry
            .upgrade()
            .ok_or(ProcessError::WrongDomain)?
            .membership_limit;
        let mut tg = self.tg.lock();
        if tg.memberships >= limit {
            return Err(ProcessError::Capacity);
        }
        if !tg.threads.find(&tid).is_null() {
            return Err(ProcessError::AlreadyExists);
        }
        tg.threads.insert(node.clone());
        tg.memberships += 1;
        drop(tg);
        Ok(ThreadAdmission {
            process: self.clone(),
            node,
            committed: false,
        })
    }

    fn detach_thread_locked(
        tg: &mut ThreadGroup,
        node: *const ThreadNode,
    ) -> Option<Arc<ThreadNode>> {
        // SAFETY: callers obtain `node` from this tree while holding `tg`.
        let removed = unsafe { tg.threads.cursor_mut_from_ptr(node).remove() };
        if let Some(node) = removed.as_ref() {
            tg.memberships -= 1;
            if node.live.swap(false, Ordering::Relaxed) {
                tg.live_threads -= 1;
            }
        }
        removed
    }

    /// Removes a live thread without updating process exit state.
    pub fn remove_thread(&self, tid: Pid) {
        let removed = {
            let mut tg = self.tg.lock();
            let node = tg.threads.find(&tid).get().and_then(|thread| {
                thread
                    .live
                    .load(Ordering::Relaxed)
                    .then_some(thread as *const ThreadNode)
            });
            node.and_then(|node| Self::detach_thread_locked(&mut tg, node))
        };
        drop(removed);
    }

    /// Removes a thread and reports whether it was the final live thread.
    pub fn exit_thread(&self, tid: Pid, exit_code: i32) -> bool {
        let mut tg = self.tg.lock();
        if !tg.group_exited {
            tg.exit_code = exit_code;
        }
        let node = tg.threads.find(&tid).get().and_then(|thread| {
            thread
                .live
                .load(Ordering::Relaxed)
                .then_some(thread as *const ThreadNode)
        });
        let removed = node.and_then(|node| Self::detach_thread_locked(&mut tg, node));
        let empty = tg.live_threads == 0;
        drop(tg);
        drop(removed);
        empty
    }

    /// Returns the live thread count without allocating.
    pub fn thread_count(&self) -> usize {
        self.tg.lock().live_threads
    }

    /// Returns whether `tid` is the only live thread.
    pub fn has_only_thread(&self, tid: Pid) -> bool {
        let tg = self.tg.lock();
        tg.live_threads == 1
            && tg
                .threads
                .find(&tid)
                .get()
                .is_some_and(|thread| thread.live.load(Ordering::Relaxed))
    }

    /// Fallibly snapshots all live thread IDs.
    pub fn try_threads(self: &Arc<Self>) -> Result<Vec<Pid>, ProcessError> {
        let limit = self
            .registry
            .upgrade()
            .ok_or(ProcessError::WrongDomain)?
            .membership_limit;
        let mut snapshot = Vec::new();
        loop {
            snapshot.clear();
            let required = self.tg.lock().memberships;
            if snapshot.capacity() < required {
                snapshot
                    .try_reserve_exact(required)
                    .map_err(|_| ProcessError::NoMemory)?;
            }

            let mut overflow = false;
            for tid in self.thread_ids() {
                if snapshot.len() == snapshot.capacity() {
                    overflow = true;
                    break;
                }
                snapshot.push(tid);
            }
            if !overflow {
                return Ok(snapshot);
            }

            let current = snapshot.capacity();
            if current >= limit {
                return Err(ProcessError::Capacity);
            }
            let target = current.max(1).saturating_mul(2).min(limit);
            snapshot.clear();
            snapshot
                .try_reserve_exact(target)
                .map_err(|_| ProcessError::NoMemory)?;
        }
    }

    /// Iterates live thread IDs without allocating.
    pub fn thread_ids(self: &Arc<Self>) -> ThreadIds<Z> {
        ThreadIds {
            process: self.clone(),
            last: None,
            after: None,
            remaining: self.tg.lock().memberships,
            finished: false,
        }
    }

    /// Visits every live thread ID without allocating.
    pub fn for_each_thread(self: &Arc<Self>, mut visitor: impl FnMut(Pid)) {
        for tid in self.thread_ids() {
            visitor(tid);
        }
    }

    /// Returns whether this is a non-zombie process with a live thread.
    pub fn is_live(&self) -> bool {
        !self.is_zombie() && self.thread_count() != 0
    }

    /// Returns whether a group-wide exit has been requested.
    pub fn is_group_exited(&self) -> bool {
        self.tg.lock().group_exited
    }

    /// Marks this process as group-exited.
    pub fn group_exit(&self) {
        self.tg.lock().group_exited = true;
    }

    /// Returns the stored process exit code.
    pub fn exit_code(&self) -> i32 {
        self.tg.lock().exit_code
    }

    /// Returns whether this process has transitioned to zombie state.
    pub fn is_zombie(&self) -> bool {
        self.is_zombie.load(Ordering::Acquire)
    }
}

impl<Z> fmt::Debug for Process<Z> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut builder = f.debug_struct("Process");
        builder.field("pid", &self.pid);
        let tg = self.tg.lock();
        if tg.group_exited {
            builder.field("group_exited", &tg.group_exited);
        }
        if self.is_zombie() {
            builder.field("exit_code", &tg.exit_code);
        }
        if let Some(parent) = self.parent() {
            builder.field("parent", &parent.pid());
        }
        builder.field("group", &self.group());
        builder.finish()
    }
}

/// Reserved, fully allocated child process awaiting final publication.
pub struct ProcessAdmission<Z> {
    registry: Arc<ProcessRegistry<Z>>,
    process: Arc<Process<Z>>,
    committed: bool,
}

impl<Z> ProcessAdmission<Z> {
    /// Returns the unpublished process object.
    pub fn process(&self) -> &Arc<Process<Z>> {
        &self.process
    }

    /// Publishes the process against its reserved registry membership slot.
    pub fn commit(mut self) {
        self.process.published.store(true, Ordering::Release);
        self.committed = true;
    }
}

impl<Z> Drop for ProcessAdmission<Z> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let removed = {
            let mut state = self.registry.state.lock();
            if !self.process.registry_link.is_linked() {
                None
            } else {
                // SAFETY: the token owns a registry-matched process that was
                // inserted by `ProcessRegistry::admit` and is still linked.
                let removed = unsafe {
                    state
                        .entries
                        .cursor_mut_from_ptr(Arc::as_ptr(&self.process))
                        .remove()
                };
                if removed.is_some() {
                    state.memberships -= 1;
                }
                removed
            }
        };
        drop(removed);
    }
}

/// Reserved thread-group membership awaiting final publication.
pub struct ThreadAdmission<Z> {
    process: Arc<Process<Z>>,
    node: Arc<ThreadNode>,
    committed: bool,
}

impl<Z> ThreadAdmission<Z> {
    /// Marks this already-linked thread membership live without consuming the token.
    pub fn publish(&mut self) {
        let mut tg = self.process.tg.lock();
        if !self.node.live.swap(true, Ordering::Relaxed) {
            tg.live_threads += 1;
        }
        drop(tg);
        self.committed = true;
    }

    /// Publishes the TID against its reserved process membership capacity.
    pub fn commit(mut self) {
        self.publish();
    }
}

impl<Z> Drop for ThreadAdmission<Z> {
    fn drop(&mut self) {
        if !self.committed {
            let removed = {
                let mut tg = self.process.tg.lock();
                if !self.node.link.is_linked() {
                    None
                } else {
                    Process::<Z>::detach_thread_locked(&mut tg, Arc::as_ptr(&self.node))
                }
            };
            drop(removed);
        }
    }
}

/// Allocation-free PID-ordered iterator over a process's live thread IDs.
pub struct ThreadIds<Z> {
    process: Arc<Process<Z>>,
    last: Option<Arc<ThreadNode>>,
    after: Option<Pid>,
    remaining: usize,
    finished: bool,
}

impl<Z> Iterator for ThreadIds<Z> {
    type Item = Pid;

    fn next(&mut self) -> Option<Self::Item> {
        while !self.finished && self.remaining != 0 {
            let tg = self.process.tg.lock();
            let next = if let Some(last) = self.last.as_ref().filter(|last| last.link.is_linked()) {
                // SAFETY: `last` is linked in this process's thread tree and
                // the thread-group lock prevents concurrent removal.
                let mut cursor = unsafe { tg.threads.cursor_from_ptr(Arc::as_ptr(last)) };
                cursor.move_next();
                cursor.clone_pointer()
            } else if let Some(after) = self.after.as_ref() {
                tg.threads
                    .lower_bound(Bound::Excluded(after))
                    .clone_pointer()
            } else {
                tg.threads.front().clone_pointer()
            };
            drop(tg);

            let Some(next) = next else {
                self.finished = true;
                break;
            };
            self.remaining -= 1;
            self.after = Some(next.tid);
            let last = self.last.replace(next.clone());
            drop(last);
            if next.live.load(Ordering::Relaxed) {
                return Some(next.tid);
            }
        }

        self.finished = true;
        let last = self.last.take();
        drop(last);
        None
    }
}
