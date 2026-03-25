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

mod error_and_tests;
pub use error_and_tests::*;
mod reclaim_impl;
#[cfg(not(any(test, feature = "bench")))]
use crate::domain::DomainId;

// In lib test builds we prefer a lightweight `DomainId` provided by the
// parent `sas` module (a test-only fallback is defined in `sas::mod`).
#[cfg(any(test, feature = "bench"))]
use super::DomainId;
use crate::sync::PoisonLock;
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
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
    /// オブジェクトが「毒入れされた」状態か
    /// 設計書 8.4: オーナーがパニックした際にオブジェクトを無効化
    pub poisoned: bool,
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

/// ヒープレジストリ (Sharded)
pub struct HeapRegistry {
    /// シャード化されたレジストリ（ランタイムサイズ）
    shards: alloc::vec::Vec<PoisonLock<RegistryShard>>,
    /// シャード -> NUMAノードのオプショナルなマッピング
    shard_nodes: alloc::vec::Vec<Option<usize>>,
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
        let shard_count = core::cmp::min(
            core::cmp::max(shard_count, MIN_SHARD_COUNT),
            MAX_SHARD_COUNT,
        );
        let mut shards = alloc::vec::Vec::with_capacity(shard_count);
        for _ in 0..shard_count {
            shards.push(PoisonLock::new(RegistryShard::new()));
        }
        // Distribute shards across NUMA nodes (round-robin) to enable
        // simple locality-aware heuristics. If NUMA detection is unavailable in
        // lib-test builds, default to a single NUMA node (0).
        #[cfg(not(any(test, feature = "bench")))]
        let numa_nodes = crate::mm::numa::topology::num_nodes();
        #[cfg(any(test, feature = "bench"))]
        let numa_nodes = 1usize;

        let mut shard_nodes: alloc::vec::Vec<Option<usize>> =
            alloc::vec::Vec::with_capacity(shard_count);
        for i in 0..shard_count {
            if numa_nodes > 0 {
                shard_nodes.push(Some(i % numa_nodes));
            } else {
                shard_nodes.push(Some(0));
            }
        }

        Self {
            shards,
            shard_nodes,
            next_generation: AtomicU64::new(1),
            stats: RegistryStats::default(),
        }
    }

    /// Default initialization: choose shard count based on CPU count
    pub fn default() -> Self {
        // When running unit tests under `cargo test --lib`, the full
        // `smp` module may not be available; use a small default CPU
        // count to make shard-sizing deterministic in tests.
        #[cfg(not(any(test, feature = "bench")))]
        let cpus = crate::cpu::count() as usize;

        #[cfg(any(test, feature = "bench"))]
        let cpus = 4usize;
        let cpus = if cpus == 0 { 1 } else { cpus };
        // 4 shards per CPU (rounded by next_power_of_two) is a practical default
        let shards = core::cmp::min(
            core::cmp::max(
                (cpus.next_power_of_two()).saturating_mul(4),
                MIN_SHARD_COUNT,
            ),
            MAX_SHARD_COUNT,
        );
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

    fn lock_shards(
        &self,
        idxs: &[usize],
    ) -> Result<alloc::vec::Vec<crate::sync::PoisonLockGuard<'_, RegistryShard>>, RegistryError>
    {
        let mut guards = alloc::vec::Vec::new();
        for idx in idxs {
            match self.shards[*idx].lock() {
                Ok(g) => guards.push(g),
                Err(_) => {
                    log::error!("[HEAP] Registry shard lock poisoned - register failed");
                    return Err(RegistryError::PermissionDenied);
                }
            }
        }
        Ok(guards)
    }

    fn validate_no_overlap(
        &self,
        guards: &[crate::sync::PoisonLockGuard<'_, RegistryShard>],
        address: usize,
        size: usize,
    ) -> Result<(), RegistryError> {
        for g in guards {
            if g.objects.contains_key(&address) {
                return Err(RegistryError::AlreadyRegistered);
            }
            if self.check_overlap_internal(&*g, address, size) {
                return Err(RegistryError::Overlapping);
            }
        }
        Ok(())
    }

    /// オブジェクトを登録
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

        #[cfg(not(any(test, feature = "bench")))]
        {
            if let Some(owner_node) = crate::domain::get_domain_numa(owner) {
                idxs.sort_by_key(|i| {
                    if let Some(node) = self.shard_nodes.get(*i).copied().unwrap_or(None) {
                        if node == owner_node { 0usize } else { 1usize }
                    } else {
                        1usize
                    }
                });
            }
        }
        #[cfg(any(test, feature = "bench"))]
        {}

        let mut guards = self.lock_shards(&idxs)?;
        self.validate_no_overlap(&guards, address, size)?;

        let generation = self.next_generation.fetch_add(1, Ordering::SeqCst);
        let object = HeapObject {
            address,
            size,
            owner,
            type_id,
            generation,
            poisoned: false,
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
        self.stats.total_registered.fetch_add(1, Ordering::Relaxed);

        Ok(generation)
    }

    /// Look up object size from primary shard, validate owner, then lock all
    /// shards covering the range in ascending order. Returns (guards, primary_position).
    fn lock_shards_for_owner(
        &self,
        address: usize,
        owner: DomainId,
        op_name: &str,
    ) -> Result<
        (
            alloc::vec::Vec<crate::sync::PoisonLockGuard<'_, RegistryShard>>,
            usize,
        ),
        RegistryError,
    > {
        let primary = self.get_shard_index(address);
        let primary_guard = match self.shards[primary].lock() {
            Ok(g) => g,
            Err(_) => {
                log::error!("[HEAP] Registry shard lock poisoned - {} skipped", op_name);
                return Err(RegistryError::PermissionDenied);
            }
        };
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

        let mut guards = alloc::vec::Vec::new();
        for idx in &idxs {
            match self.shards[*idx].lock() {
                Ok(g) => guards.push(g),
                Err(_) => {
                    log::error!("[HEAP] Registry shard lock poisoned - {} skipped", op_name);
                    return Err(RegistryError::PermissionDenied);
                }
            }
        }

        let primary_pos = idxs
            .iter()
            .position(|&i| i == primary)
            .ok_or(RegistryError::NotFound)?;

        Ok((guards, primary_pos))
    }

    /// オブジェクトの登録を解除
    pub fn unregister(&self, address: usize, owner: DomainId) -> Result<(), RegistryError> {
        let (mut guards, primary_pos) = self.lock_shards_for_owner(address, owner, "unregister")?;

        // Re-validate and remove from all shards
        if !guards[primary_pos].objects.contains_key(&address) {
            return Err(RegistryError::NotFound);
        }
        if guards[primary_pos].objects.get(&address).unwrap().owner != owner {
            return Err(RegistryError::PermissionDenied);
        }

        for g in guards.iter_mut() {
            if g.objects.remove(&address).is_some() {
                if let Some(addrs) = g.owner_index.get_mut(&owner) {
                    let addrs: &mut alloc::vec::Vec<usize> = addrs;
                    addrs.retain(|a: &usize| *a != address);
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
        let (mut guards, primary_pos) = self.lock_shards_for_owner(address, from, "transfer")?;

        // Re-validate ownership and apply change across shards
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
                let addrs: &mut alloc::vec::Vec<usize> = addrs;
                addrs.retain(|a: &usize| *a != address);
            }
            g.owner_index
                .entry(to)
                .or_insert_with(Vec::new)
                .push(address);
        }

        self.stats.total_transferred.fetch_add(1, Ordering::Relaxed);

        Ok(())
    }

    /// アクセス権をチェック
    pub fn check_access(&self, address: usize, accessor: DomainId) -> bool {
        self.stats.access_checks.fetch_add(1, Ordering::Relaxed);

        let shard_idx = self.get_shard_index(address);
        let shard = match self.shards[shard_idx].lock() {
            Ok(g) => g,
            Err(_) => {
                log::error!("[HEAP] Registry shard lock poisoned (check_access) - returning false");
                return false;
            }
        };

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

    /// オブジェクトが毒入れされているかチェック
    /// 設計書 8.4: Exchange Heapへの適用
    pub fn is_poisoned(&self, address: usize) -> bool {
        let shard_idx = self.get_shard_index(address);
        let shard = match self.shards[shard_idx].lock() {
            Ok(g) => g,
            Err(_) => {
                // シャードロック自体がポイズンされている → オブジェクトも毒入れと見なす
                return true;
            }
        };

        if let Some(object) = shard.objects.get(&address) {
            return object.poisoned;
        }
        false
    }

    /// オブジェクトを毒入れする
    /// 設計書 8.4: オーナーがパニックした際にオブジェクトを無効化
    pub fn poison_object(&self, address: usize) -> Result<(), RegistryError> {
        let shard_idx = self.get_shard_index(address);
        let mut shard = match self.shards[shard_idx].lock() {
            Ok(g) => g,
            Err(_) => {
                log::error!("[HEAP] Registry shard lock poisoned (poison_object)");
                return Err(RegistryError::PermissionDenied);
            }
        };

        if let Some(object) = shard.objects.get_mut(&address) {
            object.poisoned = true;
            return Ok(());
        }
        Err(RegistryError::NotFound)
    }

    /// 指定ドメインが所有する全オブジェクトを毒入れ
    /// 設計書 8.4: ドメインパニック時の連鎖クラッシュ防止
    pub fn poison_domain_objects(&self, domain: DomainId) -> usize {
        let mut poisoned_count = 0;

        for shard in &self.shards {
            let mut guard = match shard.lock() {
                Ok(g) => g,
                Err(_) => continue,
            };

            if let Some(addresses) = guard.owner_index.get(&domain) {
                let addrs: Vec<usize> = addresses.clone();
                for addr in addrs {
                    if let Some(obj) = guard.objects.get_mut(&addr) {
                        if !obj.poisoned {
                            obj.poisoned = true;
                            poisoned_count += 1;
                        }
                    }
                }
            }
        }

        if poisoned_count > 0 {
            log::info!(
                "[HEAP] Poisoned {} objects owned by domain {}\n",
                poisoned_count,
                domain
            );
        }

        poisoned_count
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
        let shard = match self.shards[shard_idx].lock() {
            Ok(g) => g,
            Err(_) => {
                log::error!("[HEAP] Registry shard lock poisoned (get_owner) - returning None");
                return None;
            }
        };

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
        let primary_guard = match self.shards[primary].lock() {
            Ok(g) => g,
            Err(_) => {
                log::error!("[HEAP] Registry shard lock poisoned (unregister_any) - aborting");
                return None;
            }
        };
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
            let mut g = match self.shards[*idx].lock() {
                Ok(g) => g,
                Err(_) => {
                    log::error!("[HEAP] Registry shard lock poisoned (unregister_any) - aborting");
                    return None;
                }
            };
            if g.objects.remove(&address).is_some() {
                if let Some(addrs) = g.owner_index.get_mut(&owner) {
                    let addrs: &mut alloc::vec::Vec<usize> = addrs;
                    addrs.retain(|a: &usize| *a != address);
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
            match shard.lock() {
                Ok(g) => {
                    for addr in g.objects.keys() {
                        set.insert(*addr);
                    }
                }
                Err(_) => {
                    log::error!(
                        "[HEAP] Registry shard lock poisoned (object_count) - skipping shard"
                    );
                }
            }
        }
        set.len()
    }
}
