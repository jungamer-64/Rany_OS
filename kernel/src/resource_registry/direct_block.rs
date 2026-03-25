use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::sync::PoisonLock;

#[derive(Debug, Clone, Copy)]
pub(crate) struct NvmeOpenEntry {
    pub(crate) device_id: u64,
    pub(crate) start_block: u64,
    pub(crate) block_count: u64,
    pub(crate) block_size: u32,
    pub(crate) owner: u64,
    pub(crate) token: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NvmeOpenError {
    InvalidHandle,
    PermissionDenied,
}

struct NvmeDirectRegistry {
    opens: PoisonLock<BTreeMap<u64, NvmeOpenEntry>>,
    next_id: AtomicU64,
}

impl NvmeDirectRegistry {
    const fn new() -> Self {
        Self {
            opens: PoisonLock::new(BTreeMap::new()),
            next_id: AtomicU64::new(1),
        }
    }

    fn register(
        &self,
        device_id: u64,
        start_block: u64,
        block_count: u64,
        block_size: u32,
        owner: u64,
        token: Option<u64>,
    ) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.opens.lock().unwrap_or_else(|e| e.into_inner()).insert(
            id,
            NvmeOpenEntry {
                device_id,
                start_block,
                block_count,
                block_size,
                owner,
                token,
            },
        );
        id
    }

    fn lookup_owned(&self, id: u64, caller: u64) -> Result<NvmeOpenEntry, NvmeOpenError> {
        let opens = self.opens.lock().unwrap_or_else(|e| e.into_inner());
        let Some(entry) = opens.get(&id).copied() else {
            return Err(NvmeOpenError::InvalidHandle);
        };
        if entry.owner != caller {
            return Err(NvmeOpenError::PermissionDenied);
        }
        Ok(entry)
    }

    fn unregister_if_owner_or_admin(
        &self,
        id: u64,
        caller: u64,
    ) -> Result<NvmeOpenEntry, NvmeOpenError> {
        let mgr = crate::security::capability::manager();
        let has_admin = mgr.has_capability(caller, crate::security::capability::CAP_SYS_ADMIN);
        let mut opens = self.opens.lock().unwrap_or_else(|e| e.into_inner());
        let Some(entry) = opens.get(&id).copied() else {
            return Err(NvmeOpenError::InvalidHandle);
        };
        if entry.owner != caller && !has_admin {
            return Err(NvmeOpenError::PermissionDenied);
        }
        opens.remove(&id).ok_or(NvmeOpenError::InvalidHandle)
    }
}

static NVME_DIRECT_REGISTRY: NvmeDirectRegistry = NvmeDirectRegistry::new();

pub(crate) fn register_open(
    device_id: u64,
    start_block: u64,
    block_count: u64,
    block_size: u32,
    owner: u64,
    token: Option<u64>,
) -> u64 {
    NVME_DIRECT_REGISTRY.register(
        device_id,
        start_block,
        block_count,
        block_size,
        owner,
        token,
    )
}

pub(crate) fn lookup_open_owned(id: u64, caller: u64) -> Result<NvmeOpenEntry, NvmeOpenError> {
    NVME_DIRECT_REGISTRY.lookup_owned(id, caller)
}

pub(crate) fn unregister_if_owner_or_admin(
    id: u64,
    caller: u64,
) -> Result<NvmeOpenEntry, NvmeOpenError> {
    NVME_DIRECT_REGISTRY.unregister_if_owner_or_admin(id, caller)
}

pub(crate) fn cleanup_owner(owner: u64) -> usize {
    let entries = {
        let mut opens = NVME_DIRECT_REGISTRY
            .opens
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let ids: alloc::vec::Vec<u64> = opens
            .iter()
            .filter_map(|(id, entry)| (entry.owner == owner).then_some(*id))
            .collect();
        let mut removed = alloc::vec::Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(entry) = opens.remove(&id) {
                removed.push(entry);
            }
        }
        removed
    };

    for entry in &entries {
        if let Some(token) = entry.token {
            let _ = crate::security::capability::manager().decrement_in_flight(token);
        }
    }

    entries.len()
}
