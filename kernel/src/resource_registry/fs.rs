use alloc::collections::BTreeMap;
use alloc::string::String;
use core::sync::atomic::{AtomicU64, Ordering};
use kernel_api::resource::fs::OpenMode;

use crate::sync::PoisonLock;

#[derive(Debug, Clone)]
pub(crate) struct FileHandleEntry {
    pub(crate) path: String,
    pub(crate) mode: OpenMode,
    pub(crate) position: u64,
    pub(crate) token: Option<u64>,
    pub(crate) owner: u64,
}

struct FileHandleRegistry {
    handles: PoisonLock<BTreeMap<u64, FileHandleEntry>>,
    next_id: AtomicU64,
}

impl FileHandleRegistry {
    const fn new() -> Self {
        Self {
            handles: PoisonLock::new(BTreeMap::new()),
            next_id: AtomicU64::new(1),
        }
    }

    fn register(&self, entry: FileHandleEntry) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.handles
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, entry);
        id
    }

    fn unregister(&self, id: u64) -> Option<FileHandleEntry> {
        self.handles
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&id)
    }
}

static FILE_HANDLE_REGISTRY: FileHandleRegistry = FileHandleRegistry::new();

pub(crate) fn register_handle(entry: FileHandleEntry) -> u64 {
    FILE_HANDLE_REGISTRY.register(entry)
}

pub(crate) fn unregister_handle(id: u64) -> Option<FileHandleEntry> {
    FILE_HANDLE_REGISTRY.unregister(id)
}

pub(crate) fn cleanup_owner(owner: u64) -> usize {
    let entries = {
        let mut handles = FILE_HANDLE_REGISTRY
            .handles
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let ids: alloc::vec::Vec<u64> = handles
            .iter()
            .filter_map(|(id, entry)| (entry.owner == owner).then_some(*id))
            .collect();
        let mut removed = alloc::vec::Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(entry) = handles.remove(&id) {
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
