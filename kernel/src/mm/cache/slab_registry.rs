use crate::mm::cache::slab_cache::SlabCache;
use crate::sync::PoisonLock;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

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
    cache: Weak<PoisonLock<SlabCache>>,
}

/// Global registry for Slab Caches
///
/// Enables "Slab Merging": de-duplicating caches with the same object size and flags.
/// This reduces fragmentation by sharing pages between efficient but logically distinct caches.
pub struct SlabCacheRegistry {
    entries: Vec<RegistryEntry>,
}

// Global singleton instance
static REGISTRY: PoisonLock<SlabCacheRegistry> = PoisonLock::new(SlabCacheRegistry::new());

impl SlabCacheRegistry {
    const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Access the global registry
    pub fn global() -> crate::sync::PoisonLockGuard<'static, SlabCacheRegistry> {
        REGISTRY.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Get an existing compatible cache or create a new one
    pub fn get_or_create(
        &mut self,
        object_size: usize,
        flags: SlabFlags,
    ) -> Arc<PoisonLock<SlabCache>> {
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
        let cache = Arc::new(PoisonLock::new(SlabCache::new(object_size)));

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
