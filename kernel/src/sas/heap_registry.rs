// ============================================================================
// src/sas/heap_registry.rs - ヒープオブジェクト所有権レジストリ (Sharded)
// ============================================================================
//! SAS環境でのメモリ保護を実現するため、ヒープオブジェクトの所有者を追跡する。
//! コンパイラベースの保護と実行時チェックを組み合わせて安全性を確保。
//!
//! # Scalability Improvements
//! - Sharded Registry (32 shards) to reduce lock contention.
//! - Removed Reference Counting (Strict Single Ownership).
#![allow(dead_code)]

use crate::domain_system::DomainId;
use crate::sync::PoisonLock;
use alloc::{collections::{BTreeMap, BTreeSet}, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};

/// デフォルト・シャード数 (調整可能)
const DEFAULT_SHARD_COUNT: usize = 32;
const MIN_SHARD_COUNT: usize = 4;
const MAX_SHARD_COUNT: usize = 256;

/// ヒープオブジェクトのメタデータ
#[derive(Debug, Clone)]
pub struct HeapObject {
    /// オブジェクトの開始アドレス
    pub address: usize,
    /// オブジェクトのサイズ
    pub size: usize,
    /// 所有者のドメインID
    pub owner: DomainId,
    /// 型識別子（型安全な転送のため）
    pub type_id: u64,
    /// アロケーション世代（UAF検出用）
    pub generation: u64,
}

/// レジストリシャード
#[derive(Debug)]
struct RegistryShard {
    /// アドレス → オブジェクトのマッピング
    objects: BTreeMap<usize, HeapObject>,
    /// ドメイン → 所有オブジェクトアドレスのマッピング (このシャード内のみ)
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

    /// Measurement sweep for HeapRegistry: varies shard count and thread counts
    /// and prints CSV-style metrics for analysis.
    #[test]
    fn test_heap_registry_shard_sweep() {
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        let configs = [
            (32usize, 8usize, 200usize, 50u64),
            (16usize, 16usize, 300usize, 100u64),
            (8usize, 32usize, 300usize, 200u64),
            (4usize, 64usize, 150usize, 500u64),
        ];

        println!("shards,threads,ops,hold_us,acq_count,contention,avg_acq_ticks,object_count");

        for (shard_count, num_threads, ops, hold_us) in configs.iter().cloned() {
            reset_lock_metrics();

            let registry = Arc::new(HeapRegistry::new(shard_count));

            // address pool distributed across shards
            let addresses_per_shard = 16usize;
            let mut pool = Vec::new();
            for s in 0..shard_count {
                for i in 0..addresses_per_shard {
                    let addr = (s << 4) + i * (shard_count << 4);
                    pool.push(addr);
                }
            }
            let pool = Arc::new(pool);

            let mut handles = Vec::new();
            for t in 0..num_threads {
                let reg = Arc::clone(&registry);
                let pool = Arc::clone(&pool);
                let handle = thread::spawn(move || {
                    let owner = DomainId::new((t + 1) as u64);
                    for i in 0..ops {
                        let addr = pool[(i + t) % pool.len()];
                        match reg.register(addr, 64, owner, 0) {
                            Ok(_) => {
                                let _ = reg.unregister(addr, owner);
                            }
                            Err(_) => {
                                let _ = reg.check_access(addr, owner);
                            }
                        }
                        if hold_us > 0 {
                            thread::sleep(Duration::from_micros(hold_us));
                        }
                    }
                });
                handles.push(handle);
            }

            for h in handles {
                h.join().unwrap();
            }

            let m = get_lock_metrics();
            println!(
                "{},{},{},{},{},{},{},{}",
                shard_count,
                num_threads,
                ops,
                hold_us,
                m.acquire_count,
                m.contention_events,
                m.average_acquire_ticks,
                registry.object_count(),
            );
        }
    }

/// ヒープレジストリ (Sharded)
pub struct HeapRegistry {
    /// シャード化されたレジストリ（ランタイムサイズ）
    shards: alloc::vec::Vec<PoisonLock<RegistryShard>>,
    /// 次のオブジェクト世代 (Global atomic is fine for generation)
    next_generation: AtomicU64,
    /// 統計情報
    stats: RegistryStats,
}

/// レジストリ統計
#[derive(Debug, Default)]
pub struct RegistryStats {
    total_registered: AtomicU64,
    total_transferred: AtomicU64,
    total_freed: AtomicU64,
    access_checks: AtomicU64,
    access_denials: AtomicU64,
}

impl HeapRegistry {
    /// Create with explicit shard count
    pub fn new(shard_count: usize) -> Self {
        let shard_count = core::cmp::min(core::cmp::max(shard_count, MIN_SHARD_COUNT), MAX_SHARD_COUNT);
        let mut shards = alloc::vec::Vec::with_capacity(shard_count);
        for _ in 0..shard_count {
            shards.push(PoisonLock::new(RegistryShard::new()));
        }
        Self {
            shards,
            next_generation: AtomicU64::new(1),
            stats: RegistryStats::default(),
        }
    }

    /// Default initialization: choose shard count based on CPU count
    pub fn default() -> Self {
        let cpus = crate::smp::cpu_count() as usize;
        let cpus = if cpus == 0 { 1 } else { cpus };
        // 4 shards per CPU (rounded by next_power_of_two) is a practical default
        let shards = core::cmp::min(core::cmp::max((cpus.next_power_of_two()).saturating_mul(4), MIN_SHARD_COUNT), MAX_SHARD_COUNT);
        Self::new(shards)
    }

    /// シャードインデックスを計算
    #[inline]
    fn get_shard_index(&self, address: usize) -> usize {
        // Simple hash by shifted address modulo current shard count
        (address >> 4) % self.shards.len()
    }

    /// Determine the set of shard indices that cover the given address range.
    /// Uses 16-byte granularity matching the shard hashing (address >> 4).
    fn shards_for_range(&self, address: usize, size: usize) -> alloc::vec::Vec<usize> {
        let shard_count = self.shards.len();
        if shard_count == 0 {
            return alloc::vec::Vec::new();
        }

        if size == 0 {
            return alloc::vec::Vec::from([self.get_shard_index(address)]);
        }

        // Avoid overflow when computing end address
        let end_addr = address.saturating_add(size.saturating_sub(1));

        let start_blk = address >> 4;
        let end_blk = end_addr >> 4;

        // If the number of blocks spans all shards, return full range
        let span = end_blk.saturating_sub(start_blk).saturating_add(1);
        if span as usize >= shard_count {
            return (0..shard_count).collect();
        }

        let mut shards = alloc::vec::Vec::new();
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

    /// オブジェクトを登録
    pub fn register(
        &self,
        address: usize,
        size: usize,
        owner: DomainId,
        type_id: u64,
    ) -> Result<u64, RegistryError> {
        // Determine shards covering the object's address range and lock them
        let mut idxs = self.shards_for_range(address, size);
        idxs.sort_unstable();
        idxs.dedup();

        // Acquire guards for all involved shards in ascending order to avoid deadlocks
        let mut guards: alloc::vec::Vec<_> = alloc::vec::Vec::new();
        for idx in &idxs {
            guards.push(self.shards[*idx].lock().unwrap());
        }

        // Check duplicate registration across all involved shards
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
        };

        // Insert the object into all covered shards
        for g in guards.iter_mut() {
            g.objects.insert(address, object.clone());
            g.owner_index
                .entry(owner)
                .or_insert_with(Vec::new)
                .push(address);
        }

        // Count registration only once per logical object
        self.stats
            .total_registered
            .fetch_add(1, Ordering::Relaxed);

        Ok(generation)
    }

    /// オブジェクトの登録を解除
    pub fn unregister(&self, address: usize, owner: DomainId) -> Result<(), RegistryError> {
        // Find object in primary shard to determine its size
        let primary = self.get_shard_index(address);
        let primary_guard = self.shards[primary].lock().unwrap();
        let object = primary_guard
            .objects
            .get(&address)
            .ok_or(RegistryError::NotFound)?;

        if object.owner != owner {
            return Err(RegistryError::PermissionDenied);
        }

        let size = object.size;
        drop(primary_guard);

        // Determine all shards touched and lock them (ascending order)
        let mut idxs = self.shards_for_range(address, size);
        idxs.sort_unstable();
        idxs.dedup();

        let mut guards: alloc::vec::Vec<_> = alloc::vec::Vec::new();
        for idx in &idxs {
            guards.push(self.shards[*idx].lock().unwrap());
        }

        // Re-validate and remove from all shards
        // Use the primary shard position to verify ownership again
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

    /// 所有権を転送
    pub fn transfer_ownership(
        &self,
        address: usize,
        from: DomainId,
        to: DomainId,
    ) -> Result<(), RegistryError> {
        // Read size from primary shard first
        let primary = self.get_shard_index(address);
        let primary_guard = self.shards[primary].lock().unwrap();
        let object = primary_guard
            .objects
            .get(&address)
            .ok_or(RegistryError::NotFound)?;

        if object.owner != from {
            return Err(RegistryError::PermissionDenied);
        }

        let size = object.size;
        drop(primary_guard);

        // Lock all touched shards
        let mut idxs = self.shards_for_range(address, size);
        idxs.sort_unstable();
        idxs.dedup();

        let mut guards: alloc::vec::Vec<_> = alloc::vec::Vec::new();
        for idx in &idxs {
            guards.push(self.shards[*idx].lock().unwrap());
        }

        // Re-validate ownership and apply change across shards
        let primary_pos = idxs
            .iter()
            .position(|&i| i == primary)
            .ok_or(RegistryError::NotFound)?;

        if !guards[primary_pos].objects.contains_key(&address) {
            return Err(RegistryError::NotFound);
        }

        if guards[primary_pos].objects.get(&address).unwrap().owner != from {
            return Err(RegistryError::PermissionDenied);
        }

        for g in guards.iter_mut() {
            if let Some(obj) = g.objects.get_mut(&address) {
                obj.owner = to;
            }

            // update owner_index
            if let Some(addrs) = g.owner_index.get_mut(&from) {
                addrs.retain(|a| *a != address);
            }
            g.owner_index
                .entry(to)
                .or_insert_with(Vec::new)
                .push(address);
        }

        self.stats
            .total_transferred
            .fetch_add(1, Ordering::Relaxed);

        Ok(())
    }

    /// アクセス権をチェック
    pub fn check_access(&self, address: usize, accessor: DomainId) -> bool {
        self.stats.access_checks.fetch_add(1, Ordering::Relaxed);

        let shard_idx = self.get_shard_index(address);
        let shard = self.shards[shard_idx].lock().unwrap();

        // 直接マッチを試行
        if let Some(object) = shard.objects.get(&address) {
            return object.owner == accessor;
        }

        // 範囲検索（アドレスがオブジェクト内にあるか）
        // オブジェクト開始アドレスが別のシャードにある場合、ここでの検索は失敗する。
        // FIXME: Large objects spanning shards needs careful handling.
        // Assumption: Objects are accessed by their base address usually.
        // If pointers into middle of objects are checked, we need to search backward.
        // But "sharding by address" usually means sharding by Base Address logic?
        // No, current logic shards by query address.
        // If I ask `check_access(addr + 10)`, hash might be different.
        // Solutions:
        // A) Only allow checking base address (fastest). User must supply base.
        // B) Scan potential shards. (Expensive)
        // C) Store object ranges in a separate structure?
        //
        // Current implementation tries `range(..=address).rev().take(1)`. This only works if the base address is in the same map (shard).
        // Since we shard by `(address >> 4) % N`, small offsets (0..15) are in same shard.
        // Large offsets might jump shards.
        // Implementation Decision: `check_access` MUST receive the base address of the object, OR
        // we enforce that objects are small enough/aligned enough, OR we accept that checking inner pointers is not supported efficiently.
        //
        // However, `UnregisteredPointer` error implies we should find it.
        //
        // Compromise: Implementation supports finding objects where `base_address` is in the same shard as `query_address`.
        // This covers most small object cases. Large buffers should be checked by base address.

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

    // ... Additional Helper Methods ...

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

    // ========================================================================
    // SAS Manager Wrapper Methods
    // ========================================================================

    pub fn change_owner(
        &self,
        ptr: usize,
        from: DomainId,
        to: DomainId,
    ) -> Result<(), super::OwnershipError> {
        self.transfer_ownership(ptr, from, to).map_err(|e| match e {
            RegistryError::NotFound => super::OwnershipError::NotRegistered,
            RegistryError::PermissionDenied => super::OwnershipError::NotOwner,
            _ => super::OwnershipError::AlreadyTransferred,
        })
    }

    pub fn get_owner(&self, ptr: usize) -> Option<DomainId> {
        let shard_idx = self.get_shard_index(ptr);
        let shard = self.shards[shard_idx].lock().unwrap();

        if let Some(obj) = shard.objects.get(&ptr) {
            return Some(obj.owner);
        }

        // Range check in same shard
        for (_, object) in shard.objects.range(..=ptr).rev().take(1) {
            if ptr < object.address + object.size {
                return Some(object.owner);
            }
        }
        None
    }

    /// オブジェクトを無条件に登録解除し、情報を返す
    pub fn unregister_any(&self, address: usize) -> Option<(DomainId, usize)> {
        // Try find primary object to get size and owner
        let primary = self.get_shard_index(address);
        let primary_guard = self.shards[primary].lock().unwrap();
        let obj = primary_guard.objects.get(&address).cloned();
        drop(primary_guard);

        let (owner, size) = match obj {
            Some(o) => (o.owner, o.size),
            None => return None,
        };

        // Remove from all covered shards
        let mut idxs = self.shards_for_range(address, size);
        idxs.sort_unstable();
        idxs.dedup();

        let mut removed = false;
        for idx in &idxs {
            let mut g = self.shards[*idx].lock().unwrap();
            if g.objects.remove(&address).is_some() {
                if let Some(addrs) = g.owner_index.get_mut(&owner) {
                    addrs.retain(|a| *a != address);
                }
                removed = true;
            }
        }

        if removed {
            self.stats.total_freed.fetch_add(1, Ordering::Relaxed);
            Some((owner, size))
        } else {
            None
        }
    }

    pub fn register_simple(&self, ptr: usize, size: usize, owner: DomainId) {
        let _ = self.register(ptr, size, owner, 0);
    }

    // Legacy support (mostly for finding bugs)
    pub fn object_count(&self) -> usize {
        // Deduplicate addresses across shards to count logical objects
        let mut set: BTreeSet<usize> = BTreeSet::new();
        for shard in &self.shards {
            let g = shard.lock().unwrap();
            for addr in g.objects.keys() {
                set.insert(*addr);
            }
        }
        set.len()
    }

    pub fn reclaim_all(&self, domain: DomainId) -> usize {
        // Remove all objects owned by `domain` across all shards, deduplicate
        let mut removed_addrs: BTreeSet<usize> = BTreeSet::new();
        for shard in &self.shards {
            let mut g = shard.lock().unwrap();
            let mut to_remove: alloc::vec::Vec<usize> = alloc::vec::Vec::new();
            for (&addr, obj) in g.objects.iter() {
                if obj.owner == domain {
                    to_remove.push(addr);
                }
            }
            for addr in to_remove {
                g.objects.remove(&addr);
                if let Some(addrs) = g.owner_index.get_mut(&domain) {
                    addrs.retain(|a| *a != addr);
                }
                removed_addrs.insert(addr);
            }
        }
        let count = removed_addrs.len();
        self.stats
            .total_freed
            .fetch_add(count as u64, Ordering::Relaxed);
        count
    }
}

/// レジストリエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryError {
    AlreadyRegistered,
    NotFound,
    PermissionDenied,
    Overlapping,
}

// ============================================================================
// Tests / Micro-benchmarks
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    use crate::sync::poison_lock::{reset_lock_metrics, get_lock_metrics};

    /// 簡易コンテンションテスト：1スレッドがシャードを長時間保持し、別スレッドが同シャードにアクセスする。
    /// PoisonLock の計測 (コンテンション検知) が記録されることを確認する。
    #[test]
    fn test_shard_lock_contention() {
        // テスト用に計測値をリセット
        reset_lock_metrics();

        let registry = Arc::new(HeapRegistry::default());
        let shard_idx = core::cmp::min(3usize, registry.shards.len() - 1);

        // 長時間ロックを保持するスレッド
        let r1 = Arc::clone(&registry);
        let t1 = thread::spawn(move || {
            let _g = r1.shards[shard_idx].lock().unwrap();
            thread::sleep(Duration::from_millis(200));
        });

        // 少し待ってから別スレッドで同シャードにアクセスさせる（コンテンションを発生させる）
        thread::sleep(Duration::from_millis(10));

        let r2 = Arc::clone(&registry);
        let t2 = thread::spawn(move || {
            let addr = (shard_idx << 4) + 0usize;
            let owner = DomainId::new(1);
            // 登録操作はシャードロックを取るため、ここでスピンが発生するはず
            let _ = r2.register(addr, 64, owner, 0);
        });

        t2.join().unwrap();
        t1.join().unwrap();

        let m = get_lock_metrics();
        assert!(m.acquire_count >= 1, "expected at least one lock acquisition");
        assert!(m.contention_events >= 1, "expected at least one contention event");
    }

    /// マルチスレッド負荷テスト：複数スレッドで同一または近傍シャードに対して登録/解除を繰り返す。
    /// 実行時間が長くなりすぎないように控えめなループ回数を採用。
    #[test]
    fn test_heap_registry_multithreaded_stress() {
        reset_lock_metrics();

        let registry = Arc::new(HeapRegistry::default());
        let num_threads = 8;
        let ops_per_thread = 500usize;
        let shard_ids = [0usize, 1usize];
        let addresses_per_shard = 16usize;

        // アドレスプール（各アドレスは同一シャードにハッシュされるように算出）
        let shard_count = registry.shards.len();
        let mut pool: Vec<usize> = Vec::new();
        for &s_orig in &shard_ids {
            let s = s_orig % shard_count;
            for i in 0..addresses_per_shard {
                let addr = (s << 4) + i * (shard_count << 4);
                pool.push(addr);
            }
        }
        let pool = Arc::new(pool);

        let mut handles = Vec::new();
        for t in 0..num_threads {
            let reg = Arc::clone(&registry);
            let pool = Arc::clone(&pool);
            let handle = thread::spawn(move || {
                let owner = DomainId::new((t + 1) as u64);
                for i in 0..ops_per_thread {
                    let addr = pool[(i + t) % pool.len()];
                    match reg.register(addr, 64, owner, 0) {
                        Ok(_) => {
                            let _ = reg.unregister(addr, owner);
                        }
                        Err(_) => {
                            let _ = reg.check_access(addr, owner);
                        }
                    }
                }
            });
            handles.push(handle);
        }

        for h in handles {
            h.join().unwrap();
        }

        let m = get_lock_metrics();
        // 少なくともいくつかのロック獲得とコンテンションが発生していることを期待
        assert!(m.acquire_count > 0, "expected some lock activity");
        assert!(m.contention_events > 0, "expected some contention events");
    }

    #[test]
    fn test_register_spanning_shards() {
        reset_lock_metrics();

        let registry = HeapRegistry::new(4); // small shard count to force spanning
        let owner = DomainId::new(1);
        let addr = 0usize;
        let size = 64usize; // with 16-byte blocks and 4 shards this will cover all shards

        // Register spanning object
        let generation = registry.register(addr, size, owner, 0).expect("register failed");
        assert!(generation > 0);

        // Mid-range access should resolve to owner
        assert!(registry.check_access(addr + 32, owner));
        assert_eq!(registry.get_owner(addr + 32), Some(owner));

        // Object should appear in every shard
        for s in 0..registry.shards.len() {
            let g = registry.shards[s].lock().unwrap();
            assert!(g.objects.contains_key(&addr));
        }

        // Transfer ownership and validate across shards
        registry
            .transfer_ownership(addr, owner, DomainId::new(2))
            .expect("transfer failed");
        assert_eq!(registry.get_owner(addr + 1), Some(DomainId::new(2)));

        // Unregister should remove object from all shards
        registry
            .unregister(addr, DomainId::new(2))
            .expect("unregister failed");
        assert_eq!(registry.object_count(), 0);
        assert!(!registry.check_access(addr, DomainId::new(2)));
    }

    #[test]
    fn test_overlapping_detection_across_shards() {
        let registry = HeapRegistry::new(4);
        let owner = DomainId::new(1);

        // Register large object
        registry.register(0, 64, owner, 0).unwrap();

        // Attempt to register overlapping object at offset 48 (overlaps)
        match registry.register(48, 16, DomainId::new(2), 0) {
            Err(RegistryError::Overlapping) => {}
            _ => panic!("expected overlap error"),
        }
    }
}
