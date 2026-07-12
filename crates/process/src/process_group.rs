use alloc::{sync::Arc, vec::Vec};
use core::fmt;

use crate::{Pid, Process, ProcessError, ProcessRegistry, Session};

/// A collection of processes inside one session and process registry.
pub struct ProcessGroup<Z> {
    pgid: Pid,
    pub(crate) session: Arc<Session<Z>>,
}

impl<Z> ProcessGroup<Z> {
    pub(crate) fn try_new(pgid: Pid, session: &Arc<Session<Z>>) -> Result<Arc<Self>, ProcessError> {
        Arc::try_new(Self {
            pgid,
            session: session.clone(),
        })
        .map_err(|_| ProcessError::NoMemory)
    }

    /// The process group ID.
    pub fn pgid(&self) -> Pid {
        self.pgid
    }

    /// The session containing this process group.
    pub fn session(&self) -> Arc<Session<Z>> {
        self.session.clone()
    }

    /// Fallibly snapshots the published processes in this group.
    pub fn try_processes(
        self: &Arc<Self>,
        registry: &ProcessRegistry<Z>,
    ) -> Result<Vec<Arc<Process<Z>>>, ProcessError> {
        if !self.session.belongs_to(registry) {
            return Err(ProcessError::WrongDomain);
        }
        registry.try_collect_process_values(|process| {
            Arc::ptr_eq(&process.group(), self).then(|| process.clone())
        })
    }

    /// Visits published group members without running caller code under the registry lock.
    pub fn for_each_process(
        self: &Arc<Self>,
        registry: &ProcessRegistry<Z>,
        mut visitor: impl FnMut(&Arc<Process<Z>>),
    ) -> Result<(), ProcessError> {
        if !self.session.belongs_to(registry) {
            return Err(ProcessError::WrongDomain);
        }
        for process in registry.processes() {
            if Arc::ptr_eq(&process.group(), self) {
                visitor(&process);
            }
        }
        Ok(())
    }

    /// Tests published group members without allocating.
    pub fn any_process(
        self: &Arc<Self>,
        registry: &ProcessRegistry<Z>,
        mut predicate: impl FnMut(&Arc<Process<Z>>) -> bool,
    ) -> Result<bool, ProcessError> {
        if !self.session.belongs_to(registry) {
            return Err(ProcessError::WrongDomain);
        }
        Ok(registry
            .processes()
            .any(|process| Arc::ptr_eq(&process.group(), self) && predicate(&process)))
    }
}

impl<Z> fmt::Debug for ProcessGroup<Z> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ProcessGroup({}, session={})",
            self.pgid,
            self.session.sid()
        )
    }
}
