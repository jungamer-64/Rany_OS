use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use spin::Mutex;
use crate::mm::slab_cache::SlabCache;

/// Flags configuring Slab Cache behavior
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SlabFlags {
    /// Allow merging with compatible caches
    pub mergeable: bool,
    /// Cache is effectively const (implied immutable data)
    pub read_only: bool,
}

impl Default for SlabFlags {
    fn default() -> Self {
        Self {
            mergeable: true,
            read_only: false,
        }
    }
}

/// Registry entry tracking a weak reference to a cache
struct RegistryEntry {
    object_size: usize,
    flags: SlabFlags,
    cache: Weak<Mutex<SlabCache>>,
}

/// Global registry for Slab Caches
///
/// Enables "Slab Merging": de-duplicating caches with the same object size and flags.
/// This reduces fragmentation by sharing pages between efficient but logically distinct caches.
pub struct SlabCacheRegistry {
    entries: Vec<RegistryEntry>,
}

// Global singleton instance
static REGISTRY: Mutex<SlabCacheRegistry> = Mutex::new(SlabCacheRegistry::new());

impl SlabCacheRegistry {
    const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Access the global registry
    pub fn global() -> spin::MutexGuard<'static, SlabCacheRegistry> {
        REGISTRY.lock()
    }

    /// Get an existing compatible cache or create a new one
    pub fn get_or_create(
        &mut self,
        object_size: usize,
        flags: SlabFlags,
    ) -> Arc<Mutex<SlabCache>> {
        // 1. Clean up dead references
        self.cleanup();

        // 2. Try to find existing compatible cache
        if flags.mergeable {
            for entry in &self.entries {
                if entry.object_size == object_size && entry.flags == flags {
                    if let Some(cache) = entry.cache.upgrade() {
                        return cache;
                    }
                }
            }
        }

        // 3. Create new cache
        let cache = Arc::new(Mutex::new(SlabCache::new(object_size)));
        
        // 4. Register if mergeable
        if flags.mergeable {
            self.entries.push(RegistryEntry {
                object_size,
                flags,
                cache: Arc::downgrade(&cache),
            });
        }

        cache
    }

    /// Remove dead weak references
    fn cleanup(&mut self) {
        self.entries.retain(|entry| entry.cache.strong_count() > 0);
    }
}
