use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::sync::PoisonLock;

/// Open metadata is an observation. It does not carry close or grant authority.
#[derive(Debug, Clone, Copy)]
pub(crate) struct NvmeOpenView {
    pub(crate) device_id: u64,
    pub(crate) start_block: u64,
    pub(crate) block_count: u64,
    pub(crate) block_size: u32,
}

/// Registration retains the grant until close or owner cleanup removes it.
#[derive(Debug)]
pub(crate) struct NvmeOpenEntry<'a> {
    pub(crate) view: NvmeOpenView,
    pub(crate) owner: u64,
    pub(crate) _grant: Option<crate::security::capability::TokenUse<'a>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NvmeOpenError {
    InvalidHandle,
    PermissionDenied,
}

struct NvmeDirectRegistry<'a> {
    opens: PoisonLock<BTreeMap<u64, NvmeOpenEntry<'a>>>,
    next_id: AtomicU64,
}

impl<'a> NvmeDirectRegistry<'a> {
    const fn new() -> Self {
        Self {
            opens: PoisonLock::new(BTreeMap::new()),
            next_id: AtomicU64::new(1),
        }
    }

    fn register(&self, entry: NvmeOpenEntry<'a>) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.opens
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, entry);
        id
    }

    fn lookup_owned(&self, id: u64, caller: u64) -> Result<NvmeOpenView, NvmeOpenError> {
        let opens = self.opens.lock().unwrap_or_else(|e| e.into_inner());
        let Some(entry) = opens.get(&id) else {
            return Err(NvmeOpenError::InvalidHandle);
        };
        if entry.owner != caller {
            return Err(NvmeOpenError::PermissionDenied);
        }
        Ok(entry.view)
    }

    fn unregister(
        &self,
        id: u64,
        caller: u64,
        has_admin: bool,
    ) -> Result<NvmeOpenEntry<'a>, NvmeOpenError> {
        let mut opens = self.opens.lock().unwrap_or_else(|e| e.into_inner());
        let Some(entry) = opens.get(&id) else {
            return Err(NvmeOpenError::InvalidHandle);
        };
        if entry.owner != caller && !has_admin {
            return Err(NvmeOpenError::PermissionDenied);
        }
        opens.remove(&id).ok_or(NvmeOpenError::InvalidHandle)
    }
    fn cleanup_owner(&self, owner: u64) -> usize {
        let entries = {
            let mut opens = self.opens.lock().unwrap_or_else(|e| e.into_inner());
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

        let count = entries.len();
        // Grant destructors run after the registration lock is released.
        drop(entries);
        count
    }
}

static NVME_DIRECT_REGISTRY: NvmeDirectRegistry<'static> = NvmeDirectRegistry::new();

pub(crate) fn register_open(entry: NvmeOpenEntry<'static>) -> u64 {
    NVME_DIRECT_REGISTRY.register(entry)
}

pub(crate) fn lookup_open_owned(id: u64, caller: u64) -> Result<NvmeOpenView, NvmeOpenError> {
    NVME_DIRECT_REGISTRY.lookup_owned(id, caller)
}

pub(crate) fn unregister_if_owner_or_admin(
    id: u64,
    caller: u64,
) -> Result<NvmeOpenEntry<'static>, NvmeOpenError> {
    let has_admin = crate::security::capability::manager()
        .has_capability(caller, crate::security::capability::CAP_SYS_ADMIN);
    NVME_DIRECT_REGISTRY.unregister(id, caller, has_admin)
}

pub(crate) fn cleanup_owner(owner: u64) -> usize {
    NVME_DIRECT_REGISTRY.cleanup_owner(owner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::capability::{CAP_DMA, CapabilityError, CapabilityManager, CapabilitySet};

    fn grant(manager: &CapabilityManager, target: u64) -> u64 {
        manager.set_capabilities(100, CapabilitySet::with_permitted(CAP_DMA));
        manager
            .grant_capability_with_opts(100, target, CAP_DMA, None, false)
            .expect("DMA grant admission")
    }

    fn entry<'a>(manager: &'a CapabilityManager, owner: u64, token: u64) -> NvmeOpenEntry<'a> {
        NvmeOpenEntry {
            view: NvmeOpenView {
                device_id: 0x0100_0000_0000_0001,
                start_block: 0,
                block_count: 1,
                block_size: 512,
            },
            owner,
            _grant: Some(
                manager
                    .retain_token(owner, token, CAP_DMA)
                    .expect("grant retention"),
            ),
        }
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn revoked_grant_survives_foreign_close_and_retires_with_its_open_owner() {
        let manager = CapabilityManager::new();
        let token = grant(&manager, 101);
        let registry = NvmeDirectRegistry::new();
        let id = registry.register(entry(&manager, 101, token));
        let observation = registry.lookup_owned(id, 101).expect("open metadata");
        assert_eq!(observation.block_count, 1);
        assert!(matches!(
            registry.lookup_owned(id, 102),
            Err(NvmeOpenError::PermissionDenied)
        ));
        assert!(matches!(
            registry.unregister(id, 102, false),
            Err(NvmeOpenError::PermissionDenied)
        ));
        manager
            .revoke_grant(100, token, false)
            .expect("revoke new admission");
        assert_eq!(manager.in_flight_count(token), 1);
        assert_eq!(
            manager.reclaim_token(token),
            Err(CapabilityError::ReclamationBusy)
        );
        let retired = registry
            .unregister(id, 101, false)
            .expect("owner closes the open");
        assert!(matches!(
            registry.lookup_owned(id, 101),
            Err(NvmeOpenError::InvalidHandle)
        ));
        assert_eq!(manager.in_flight_count(token), 1);
        drop(retired);
        // Metadata observations cannot prolong grant usage or close a new owner.
        assert_eq!(observation.block_size, 512);
        assert_eq!(manager.in_flight_count(token), 0);
        assert_eq!(manager.reclaim_token(token), Ok(()));
        assert!(matches!(
            registry.unregister(id, 101, false),
            Err(NvmeOpenError::InvalidHandle)
        ));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn owner_cleanup_releases_only_that_owners_retained_grants() {
        let manager = CapabilityManager::new();
        let first = grant(&manager, 101);
        let second = grant(&manager, 102);
        let registry = NvmeDirectRegistry::new();
        registry.register(entry(&manager, 101, first));
        let second_id = registry.register(entry(&manager, 102, second));
        assert_eq!(registry.cleanup_owner(101), 1);
        assert_eq!(registry.cleanup_owner(101), 0);
        assert_eq!(manager.in_flight_count(first), 0);
        assert_eq!(manager.in_flight_count(second), 1);
        assert!(registry.lookup_owned(second_id, 102).is_ok());
        assert_eq!(registry.cleanup_owner(102), 1);
        assert_eq!(manager.in_flight_count(second), 0);
    }
}
