use alloc::{sync::Arc, vec::Vec};
use core::{any::Any, fmt};

use kspin::SpinNoIrq;

use crate::{Pid, ProcessError, ProcessGroup, ProcessRegistry};

/// A collection of process groups inside one explicit process registry.
pub struct Session<Z> {
    sid: Pid,
    registry: alloc::sync::Weak<ProcessRegistry<Z>>,
    terminal: SpinNoIrq<Option<Arc<dyn Any + Send + Sync>>>,
}

impl<Z> Session<Z> {
    pub(crate) fn try_new(
        sid: Pid,
        registry: &Arc<ProcessRegistry<Z>>,
    ) -> Result<Arc<Self>, ProcessError> {
        Arc::try_new(Self {
            sid,
            registry: Arc::downgrade(registry),
            terminal: SpinNoIrq::new(None),
        })
        .map_err(|_| ProcessError::NoMemory)
    }

    pub(crate) fn belongs_to(&self, registry: &ProcessRegistry<Z>) -> bool {
        core::ptr::eq(self.registry.as_ptr(), registry)
    }

    /// The session ID.
    pub fn sid(&self) -> Pid {
        self.sid
    }

    /// Fallibly snapshots the live process groups in this registry and session.
    pub fn try_process_groups(
        self: &Arc<Self>,
        registry: &ProcessRegistry<Z>,
    ) -> Result<Vec<Arc<ProcessGroup<Z>>>, ProcessError> {
        if !self.belongs_to(registry) {
            return Err(ProcessError::WrongDomain);
        }
        let mut groups = registry.try_collect_process_values(|process| {
            let group = process.group();
            Arc::ptr_eq(&group.session(), self).then_some(group)
        })?;
        groups.sort_unstable_by_key(|group| group.pgid());
        groups.dedup_by_key(|group| group.pgid());
        Ok(groups)
    }

    /// Installs a terminal if this session does not already own one.
    pub fn set_terminal_with(&self, terminal: impl FnOnce() -> Arc<dyn Any + Send + Sync>) -> bool {
        let terminal = terminal();
        let mut guard = self.terminal.lock();
        if guard.is_some() {
            return false;
        }
        *guard = Some(terminal);
        true
    }

    /// Removes the terminal only when it is the same allocation as `terminal`.
    pub fn unset_terminal(&self, terminal: &Arc<dyn Any + Send + Sync>) -> bool {
        let mut guard = self.terminal.lock();
        if guard
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, terminal))
        {
            let removed = guard.take();
            drop(guard);
            drop(removed);
            true
        } else {
            false
        }
    }

    /// Returns the session terminal, if one is installed.
    pub fn terminal(&self) -> Option<Arc<dyn Any + Send + Sync>> {
        self.terminal.lock().clone()
    }
}

impl<Z> fmt::Debug for Session<Z> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Session({})", self.sid)
    }
}
