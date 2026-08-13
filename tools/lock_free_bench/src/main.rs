use spin::Mutex;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::thread;
use std::time::Instant;

// ============================================================================
// Mock Types & Adapters
// ============================================================================
type DomainId = u64;
// Usage: PoisonLock::new(data) -> Mutex::new(data)
// Mutex::lock() -> Guard
type PoisonLock<T> = Mutex<T>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryError {
    AlreadyRegistered,
    NotFound,
    PermissionDenied,
    Overlapping,
}

// ============================================================================
// Heap Object & Shard
// ============================================================================

#[derive(Debug, Clone)]
pub struct HeapObject {
    pub address: usize,
    pub size: usize,
    pub owner: DomainId,
    pub type_id: u64,
    pub generation: u64,
    pub poisoned: bool,
}

#[derive(Debug)]
struct RegistryShard {
    objects: BTreeMap<usize, HeapObject>,
    owner_index: BTreeMap<DomainId, Vec<usize>>,
}

impl RegistryShard {
    fn new() -> Self {
        Self {
            objects: BTreeMap::new(),
            owner_index: BTreeMap::new(),
        }
    }
}

// ============================================================================
// HeapRegistry Implementation
// ============================================================================

pub struct HeapRegistry {
    shards: Vec<PoisonLock<RegistryShard>>,
    next_generation: AtomicU64,
    stats: RegistryStats,
}

#[derive(Debug, Default)]
pub struct RegistryStats {
    total_registered: AtomicU64,
    total_transferred: AtomicU64,
    total_freed: AtomicU64,
    access_checks: AtomicU64,
    access_denials: AtomicU64,
}

impl HeapRegistry {
    pub fn new(shard_count: usize) -> Self {
        let mut shards = Vec::with_capacity(shard_count);
        for _ in 0..shard_count {
            shards.push(PoisonLock::new(RegistryShard::new()));
        }

        Self {
            shards,
            next_generation: AtomicU64::new(1),
            stats: RegistryStats::default(),
        }
    }

    #[inline]
    fn get_shard_index(&self, address: usize) -> usize {
        (address >> 4) % self.shards.len()
    }

    fn shards_for_range(&self, address: usize, size: usize) -> Vec<usize> {
        let shard_count = self.shards.len();
        if shard_count == 0 {
            return Vec::new();
        }
        if size == 0 {
            return Vec::from([self.get_shard_index(address)]);
        }

        let end_addr = address.saturating_add(size.saturating_sub(1));
        let start_blk = address >> 4;
        let end_blk = end_addr >> 4;

        let span = end_blk.saturating_sub(start_blk).saturating_add(1);
        if span as usize >= shard_count {
            return (0..shard_count).collect();
        }

        let mut shards = Vec::new();
        let mut last: Option<usize> = None;
        for blk in start_blk..=end_blk {
            let idx = (blk as usize) % shard_count;
            if last != Some(idx) {
                shards.push(idx);
                last = Some(idx);
            }
        }
        shards
    }

    /// # Errors
    ///
    /// Returns [`RegistryError::AlreadyRegistered`] if `address` is already
    /// present in any shard covering the range.
    pub fn register(
        &self,
        address: usize,
        size: usize,
        owner: DomainId,
        type_id: u64,
    ) -> Result<u64, RegistryError> {
        let mut idxs = self.shards_for_range(address, size);
        idxs.sort_unstable();
        idxs.dedup();

        let mut guards = Vec::new();
        for idx in &idxs {
            guards.push(self.shards[*idx].lock());
        }

        for g in &guards {
            if g.objects.contains_key(&address) {
                return Err(RegistryError::AlreadyRegistered);
            }
            if self.check_overlap_internal(&*g, address, size) {
                return Err(RegistryError::Overlapping);
            }
        }

        let generation = self.next_generation.fetch_add(1, Ordering::SeqCst);
        let object = HeapObject {
            address,
            size,
            owner,
            type_id,
            generation,
            poisoned: false,
        };

        for g in guards.iter_mut() {
            g.objects.insert(address, object.clone());
            g.owner_index
                .entry(owner)
                .or_insert_with(Vec::new)
                .push(address);
        }

        self.stats.total_registered.fetch_add(1, Ordering::Relaxed);
        Ok(generation)
    }

    /// # Errors
    ///
    /// Returns an error if `address` is not registered or `owner` does not own
    /// the registered object.
    ///
    /// # Panics
    ///
    /// Panics only if the internally derived primary shard is absent from the
    /// locked shard set or its object disappears while all shard locks are held.
    pub fn unregister(&self, address: usize, owner: DomainId) -> Result<(), RegistryError> {
        let primary = self.get_shard_index(address);
        // Lock just purely to read size; optimizing this away is possible but
        // sticking to original logic for fidelity.
        let primary_guard = self.shards[primary].lock();
        let object = primary_guard
            .objects
            .get(&address)
            .ok_or(RegistryError::NotFound)?;

        if object.owner != owner {
            return Err(RegistryError::PermissionDenied);
        }

        let size = object.size;
        drop(primary_guard);

        let mut idxs = self.shards_for_range(address, size);
        idxs.sort_unstable();
        idxs.dedup();

        let mut guards = Vec::new();
        for idx in &idxs {
            guards.push(self.shards[*idx].lock());
        }

        let primary_pos = idxs
            .iter()
            .position(|&i| i == primary)
            .ok_or(RegistryError::NotFound)?;

        if !guards[primary_pos].objects.contains_key(&address) {
            return Err(RegistryError::NotFound);
        }

        if guards[primary_pos].objects.get(&address).unwrap().owner != owner {
            return Err(RegistryError::PermissionDenied);
        }

        for g in guards.iter_mut() {
            if g.objects.remove(&address).is_some() {
                if let Some(addrs) = g.owner_index.get_mut(&owner) {
                    addrs.retain(|a| *a != address);
                }
            }
        }

        self.stats.total_freed.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    pub fn check_access(&self, address: usize, accessor: DomainId) -> bool {
        self.stats.access_checks.fetch_add(1, Ordering::Relaxed);
        let shard_idx = self.get_shard_index(address);
        let shard = self.shards[shard_idx].lock();

        if let Some(object) = shard.objects.get(&address) {
            return object.owner == accessor;
        }

        // Approximate check:
        for (_, object) in shard.objects.range(..=address).rev().take(1) {
            if address < object.address + object.size {
                if object.owner == accessor {
                    return true;
                }
            }
        }

        self.stats.access_denials.fetch_add(1, Ordering::Relaxed);
        false
    }

    fn check_overlap_internal(&self, shard: &RegistryShard, address: usize, size: usize) -> bool {
        let end = address + size;
        for (_, obj) in shard.objects.range(..end) {
            let obj_end = obj.address + obj.size;
            if obj.address < end && address < obj_end {
                return true;
            }
        }
        false
    }
}

// ============================================================================
// Main Benchmark
// ============================================================================

fn main() {
    println!("Running Heap Registry Benchmark (Standalone)");
    println!("shards,threads,ops,elapsed_ms,ops/sec");

    let configs = [
        (32, 8, 200_000), // Reduced ops for quicker run
        (16, 16, 200_000),
        (8, 32, 200_000),
        (4, 64, 100_000),
    ];

    for (shard_count, num_threads, ops_per_thread) in configs {
        let registry = Arc::new(HeapRegistry::new(shard_count));

        let addresses_per_shard = 128;
        let mut pool = Vec::new();
        for s in 0..shard_count {
            for i in 0..addresses_per_shard {
                // Ensure distinct addresses
                let addr = (s << 4) + i * (shard_count << 4) + 0x100000;
                pool.push(addr);
            }
        }
        let pool = Arc::new(pool);

        let start = Instant::now();
        let mut handles = Vec::new();

        for t in 0..num_threads {
            let reg = Arc::clone(&registry);
            let pool = Arc::clone(&pool);

            handles.push(thread::spawn(move || {
                let owner = (t as u64) + 1;
                let mut rng = t as usize; // simple seed

                for _ in 0..ops_per_thread {
                    rng = rng.wrapping_add(1923); // fake random step
                    let idx = rng % pool.len();
                    let addr = pool[idx];

                    // Randomly register/unregister or check access
                    if (rng % 3) == 0 {
                        if let Ok(_) = reg.register(addr, 64, owner, 0) {
                            let _ = reg.unregister(addr, owner);
                        }
                    } else {
                        let _ = reg.check_access(addr, owner);
                    }
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        let elapsed = start.elapsed();
        let total_ops = (num_threads as u64) * (ops_per_thread as u64);
        let ops_sec = (total_ops as f64) / elapsed.as_secs_f64();

        println!(
            "{},{},{},{},{:.2}",
            shard_count,
            num_threads,
            total_ops,
            elapsed.as_millis(),
            ops_sec
        );
    }
}
