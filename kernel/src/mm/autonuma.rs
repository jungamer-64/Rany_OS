// ============================================================================
// src/mm/autonuma.rs - Automatic NUMA Page Migration
// 
// ## 概要
// 
// タスクがリモートNUMAノードのメモリにアクセスする場合、
// レイテンシとバンド幅が大幅に低下する。AutoNUMAは:
// 
// 1. **NUMA Hint Fault**: PTEのPresentビットを落とし、擬似的なページフォールトを発生
// 2. **アクセスパターン追跡**: どのCPUがどのページにアクセスしているか記録
// 3. **自動マイグレーション**: ホットなページをアクセス元CPUのローカルノードに移動
// 4. **ヒステリシス**: 頻繁すぎる移動を防止する重み付けロジック
// 
// ## 参考
// 
// - Linux kernel: Automatic NUMA Balancing
// - RedHat: NUMA balancing
// ============================================================================
#![allow(dead_code)]

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};
use alloc::vec::Vec;

use super::types::{FrameIndex, NumaNodeId};

// ============================================================================
// NUMA Hint Fault 定数
// ============================================================================

/// ページがNUMAヒントスキャンの対象になる最小アクセス間隔（ミリ秒）
const NUMA_HINT_FAULT_INTERVAL_MS: u64 = 1000;

/// マイグレーションを決定するための最小アクセス回数
const NUMA_MIGRATION_THRESHOLD: u32 = 4;

/// マイグレーション後の冷却期間（ミリ秒）
const NUMA_MIGRATION_COOLDOWN_MS: u64 = 10000;

/// 1スキャンサイクルでチェックする最大ページ数
const NUMA_SCAN_BATCH_SIZE: usize = 256;

/// スキャン間隔（ミリ秒）
const NUMA_SCAN_PERIOD_MS: u64 = 1000;

// ============================================================================
// ページアクセス統計
// ============================================================================

/// ページのNUMAアクセス統計
#[repr(C)]
pub struct PageNumaStats {
    /// ノードごとのアクセスカウント
    /// インデックス = NUMAノードID
    node_access_counts: [AtomicU32; 8],
    
    /// 最後にアクセスされた時刻（TSC or jiffies相当）
    last_access_time: AtomicU64,
    
    /// 現在配置されているNUMAノード
    current_node: AtomicU8,
    
    /// マイグレーション回数
    migration_count: AtomicU8,
    
    /// 最後のマイグレーション時刻
    last_migration_time: AtomicU64,
    
    /// ページフラグ
    flags: AtomicU32,
}

/// ページフラグ
pub mod page_flags {
    pub const NUMA_HINT_FAULT_PENDING: u32 = 1 << 0;
    pub const NUMA_MIGRATION_HOT: u32 = 1 << 1;
    pub const NUMA_PINNED: u32 = 1 << 2;  // マイグレーション禁止
    pub const NUMA_SHARED: u32 = 1 << 3;  // 複数ノードからアクセス
}

impl PageNumaStats {
    pub const fn new() -> Self {
        const ZERO: AtomicU32 = AtomicU32::new(0);
        Self {
            node_access_counts: [ZERO; 8],
            last_access_time: AtomicU64::new(0),
            current_node: AtomicU8::new(0),
            migration_count: AtomicU8::new(0),
            last_migration_time: AtomicU64::new(0),
            flags: AtomicU32::new(0),
        }
    }
    
    /// アクセスを記録
    #[inline]
    pub fn record_access(&self, node_id: usize, timestamp: u64) {
        if node_id < 8 {
            self.node_access_counts[node_id].fetch_add(1, Ordering::Relaxed);
        }
        self.last_access_time.store(timestamp, Ordering::Release);
    }
    
    /// 最もアクセスが多いノードを取得
    pub fn get_hottest_node(&self) -> (usize, u32) {
        let mut max_node = 0;
        let mut max_count = 0;
        
        for (node, counter) in self.node_access_counts.iter().enumerate() {
            let count = counter.load(Ordering::Relaxed);
            if count > max_count {
                max_count = count;
                max_node = node;
            }
        }
        
        (max_node, max_count)
    }
    
    /// 複数ノードからアクセスされているか
    pub fn is_shared(&self) -> bool {
        let mut active_nodes = 0;
        for counter in &self.node_access_counts {
            if counter.load(Ordering::Relaxed) > 0 {
                active_nodes += 1;
            }
        }
        active_nodes > 1
    }
    
    /// アクセスカウントをリセット
    pub fn reset_counts(&self) {
        for counter in &self.node_access_counts {
            counter.store(0, Ordering::Relaxed);
        }
    }
    
    /// マイグレーション可能かチェック
    pub fn can_migrate(&self, current_time: u64) -> bool {
        let flags = self.flags.load(Ordering::Acquire);
        if flags & page_flags::NUMA_PINNED != 0 {
            return false;
        }
        
        let last_migration = self.last_migration_time.load(Ordering::Acquire);
        if current_time.saturating_sub(last_migration) < NUMA_MIGRATION_COOLDOWN_MS {
            return false;
        }
        
        true
    }
}

// Global storage for PageNumaStats
// Using BTreeMap for sparse tracking. For production, a flat array or resizing Vec is better.
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use crate::sync::PoisonLock;

static PAGE_NUMA_STATS: PoisonLock<BTreeMap<FrameIndex, Arc<PageNumaStats>>> = PoisonLock::new(BTreeMap::new());

/// ページのNUMA統計を取得（存在しなければ作成）
pub fn get_page_numa_stats(frame: FrameIndex) -> Arc<PageNumaStats> {
    // Fast path: try to acquire lock for read
    if let Ok(guard) = PAGE_NUMA_STATS.lock() {
        if let Some(stats) = guard.get(&frame) {
            return stats.clone();
        }
    }

    // Slow path: acquire lock for write (insert if missing)
    match PAGE_NUMA_STATS.lock() {
        Ok(mut guard) => {
            guard.entry(frame)
                .or_insert_with(|| Arc::new(PageNumaStats::new()))
                .clone()
        }
        Err(poisoned) => {
            // If poisoned, recover the inner and use it
            let mut guard = poisoned.into_inner();
            guard.entry(frame)
                .or_insert_with(|| Arc::new(PageNumaStats::new()))
                .clone()
        }
    }
}

// ============================================================================
// NUMA Hint Fault ハンドラ
// ============================================================================

/// NUMA Hint Faultの結果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumaFaultAction {
    /// ページをそのまま（アクセスを記録しただけ）
    RecordOnly,
    /// ローカルノードにマイグレーション
    Migrate { from_node: u8, to_node: u8 },
    /// マイグレーション不可（pinned, shared, cooldown中など）
    CannotMigrate,
}

/// NUMA Hint Faultを処理
/// 
/// # 引数
/// 
/// - `page_stats`: ページのNUMA統計
/// - `faulting_node`: フォールトが発生したCPUのNUMAノード
/// - `current_time`: 現在時刻（TSC or monotonic）
/// 
/// # 戻り値
/// 
/// マイグレーションが必要かどうかと、その場合の移動先ノード
pub fn handle_numa_fault(
    page_stats: &PageNumaStats,
    faulting_node: u8,
    current_time: u64,
) -> NumaFaultAction {
    // アクセスを記録
    page_stats.record_access(faulting_node as usize, current_time);
    
    // 現在のノード
    let current_node = page_stats.current_node.load(Ordering::Acquire);
    
    // ローカルアクセスの場合は何もしない
    if current_node == faulting_node {
        return NumaFaultAction::RecordOnly;
    }
    
    // マイグレーション可能かチェック
    if !page_stats.can_migrate(current_time) {
        return NumaFaultAction::CannotMigrate;
    }
    
    // ホットネスをチェック
    let (hottest_node, access_count) = page_stats.get_hottest_node();
    
    // しきい値を超えていない場合は記録のみ
    if access_count < NUMA_MIGRATION_THRESHOLD {
        return NumaFaultAction::RecordOnly;
    }
    
    // 複数ノードから均等にアクセスされている場合はマイグレーションしない
    if page_stats.is_shared() {
        page_stats.flags.fetch_or(page_flags::NUMA_SHARED, Ordering::Release);
        return NumaFaultAction::CannotMigrate;
    }
    
    // ホットなノードが現在と異なる場合はマイグレーション
    if hottest_node as u8 != current_node {
        NumaFaultAction::Migrate {
            from_node: current_node,
            to_node: hottest_node as u8,
        }
    } else {
        NumaFaultAction::RecordOnly
    }
}

// ============================================================================
// NUMA ページスキャナ
// ============================================================================

/// NUMAスキャナ
/// 
/// プロセスのページテーブルをスキャンし、NUMA Hint Faultを設定する。
pub struct NumaScanner {
    /// 有効かどうか
    enabled: AtomicU64,
    
    /// 次のスキャン時刻
    next_scan_time: AtomicU64,
    
    /// スキャン間隔（ミリ秒）
    scan_period_ms: AtomicU64,
    
    /// 1スキャンあたりの最大ページ数
    scan_batch_size: AtomicU64,
    
    /// 統計: スキャンしたページ数
    pages_scanned: AtomicU64,
    
    /// 統計: NUMA Hint Faultを設定したページ数
    faults_set: AtomicU64,
}

impl NumaScanner {
    pub const fn new() -> Self {
        Self {
            enabled: AtomicU64::new(1),
            next_scan_time: AtomicU64::new(0),
            scan_period_ms: AtomicU64::new(NUMA_SCAN_PERIOD_MS),
            scan_batch_size: AtomicU64::new(NUMA_SCAN_BATCH_SIZE as u64),
            pages_scanned: AtomicU64::new(0),
            faults_set: AtomicU64::new(0),
        }
    }
    
    /// スキャナを有効/無効化
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(if enabled { 1 } else { 0 }, Ordering::Release);
    }
    
    /// スキャナが有効かどうか
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire) != 0
    }
    
    /// スキャン間隔を設定
    pub fn set_scan_period(&self, period_ms: u64) {
        self.scan_period_ms.store(period_ms, Ordering::Release);
    }
    
    /// スキャンが必要かどうか
    pub fn should_scan(&self, current_time: u64) -> bool {
        if !self.is_enabled() {
            return false;
        }
        
        let next_scan = self.next_scan_time.load(Ordering::Acquire);
        current_time >= next_scan
    }
    
    /// スキャン完了を記録
    pub fn record_scan(&self, current_time: u64, pages_scanned: u64, faults_set: u64) {
        let period = self.scan_period_ms.load(Ordering::Relaxed);
        self.next_scan_time.store(current_time + period, Ordering::Release);
        self.pages_scanned.fetch_add(pages_scanned, Ordering::Relaxed);
        self.faults_set.fetch_add(faults_set, Ordering::Relaxed);
    }
    
    /// 統計を取得
    pub fn stats(&self) -> (u64, u64) {
        (
            self.pages_scanned.load(Ordering::Relaxed),
            self.faults_set.load(Ordering::Relaxed),
        )
    }
    /// タスクのアドレス空間をスキャン
    pub fn scan_task(&self, task: &crate::task::process::ProcessInfo) {
        if !self.is_enabled() { return; }

        let current_time = crate::time::current_time_ns();
        if !self.should_scan(current_time) {
            return;
        }

        // 現在のタスクのみ対象（簡易実装: リモートスキャンはロックが必要なため）
        let current_pid = crate::task::process::get_current_process();
        if task.pid != current_pid {
            return;
        }

        let address_space_manager = crate::mm::address_space::address_space_manager();
        
        // スキャン位置を取得
        let scan_addr_val = task.numa_scan_addr.load(Ordering::Relaxed);
        let scan_addr = crate::mm::higher_half::VirtAddr::new(scan_addr_val);
        let batch_size = self.scan_batch_size.load(Ordering::Relaxed) as usize;

        // アドレス空間をスキャン
        if let Some((scanned, faults, next_addr)) = address_space_manager.scan_current_address_space(scan_addr, batch_size) {
            // 次のスキャン位置を保存
            // ユーザー空間の終端を超えたらループ
            let next_val = if next_addr.as_u64() >= crate::mm::address_space::USER_SPACE_END {
                crate::mm::address_space::USER_SPACE_START
            } else {
                next_addr.as_u64()
            };
            
            task.numa_scan_addr.store(next_val, Ordering::Release);
            self.record_scan(current_time, scanned as u64, faults as u64);
        }
    }
}

/// 現在のプロセスのAutoNUMAスキャンを試行
pub fn try_scan_current_process() {
    // TODO: Fix ProcessInfo type mismatch - scan_task expects a different struct
    // than what process::ProcessInfo provides. Need to either:
    // 1. Add numa_scan_addr field to process::ProcessInfo
    // 2. Create a separate NumaScanInfo trait/struct
    // 3. Change scan_task signature to accept just PID
    
    // Temporarily disabled until design is resolved.
    // use crate::task::process::{get_current_process, process_manager};
    // let pid = get_current_process();
    // if pid != crate::task::process::ProcessId::KERNEL {
    //     if let Some(proc_lock) = process_manager().get(pid) {
    //         // ...
    //     }
    // }
}

/// グローバルスキャナ
pub static NUMA_SCANNER: NumaScanner = NumaScanner::new();

// ============================================================================
// NUMA マイグレーションエンジン
// ============================================================================

/// マイグレーション要求
#[derive(Debug, Clone)]
pub struct MigrationRequest {
    /// 移動元フレーム
    pub src_frame: FrameIndex,
    /// 移動先NUMAノード
    pub dest_node: u8,
    /// 優先度（高いほど優先）
    pub priority: u8,
    /// タイムスタンプ
    pub timestamp: u64,
}

/// マイグレーション結果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationResult {
    /// 成功
    Success,
    /// 移動先ノードにメモリがない
    NoMemory,
    /// ページがロック中
    PageLocked,
    /// ページがpinned
    PagePinned,
    /// マイグレーション中に失敗
    Failed,
}

/// NUMAマイグレーションエンジン
pub struct MigrationEngine {
    /// 保留中のマイグレーション要求
    /// (priority, timestamp) でソートされるキュー
    pending_requests: spin::Mutex<Vec<MigrationRequest>>,
    
    /// 統計: 成功したマイグレーション数
    successful: AtomicU64,
    
    /// 統計: 失敗したマイグレーション数
    failed: AtomicU64,
    
    /// 統計: 移動したページのバイト数
    migrated_bytes: AtomicU64,
    
    /// 1バッチで処理する最大マイグレーション数
    batch_size: usize,
}

impl MigrationEngine {
    pub const fn new() -> Self {
        Self {
            pending_requests: spin::Mutex::new(Vec::new()),
            successful: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            migrated_bytes: AtomicU64::new(0),
            batch_size: 32,
        }
    }
    
    /// マイグレーション要求をキューに追加
    pub fn queue_migration(&self, request: MigrationRequest) {
        let mut pending = self.pending_requests.lock();
        pending.push(request);
        
        // 優先度とタイムスタンプでソート（優先度が高い・古い方が先）
        pending.sort_by(|a, b| {
            b.priority.cmp(&a.priority)
                .then_with(|| a.timestamp.cmp(&b.timestamp))
        });
    }
    
    /// 保留中のマイグレーションをバッチ処理
    /// 
    /// # Safety
    /// 
    /// - `migrate_page` は安全にページをマイグレーションする関数
    pub unsafe fn process_batch<F>(&self, mut migrate_page: F) -> usize
    where
        F: FnMut(FrameIndex, u8) -> MigrationResult,
    {
        let mut processed = 0;
        let mut pending = self.pending_requests.lock();
        
        while processed < self.batch_size && !pending.is_empty() {
            let request = pending.remove(0);
            
            let result = migrate_page(request.src_frame, request.dest_node);
            
            match result {
                MigrationResult::Success => {
                    self.successful.fetch_add(1, Ordering::Relaxed);
                    self.migrated_bytes.fetch_add(4096, Ordering::Relaxed);
                }
                _ => {
                    self.failed.fetch_add(1, Ordering::Relaxed);
                }
            }
            
            processed += 1;
        }
        
        processed
    }
    
    /// 統計を取得
    pub fn stats(&self) -> MigrationStats {
        MigrationStats {
            successful: self.successful.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            migrated_bytes: self.migrated_bytes.load(Ordering::Relaxed),
            pending: self.pending_requests.lock().len(),
        }
    }
}

/// マイグレーション統計
#[derive(Debug, Clone)]
pub struct MigrationStats {
    pub successful: u64,
    pub failed: u64,
    pub migrated_bytes: u64,
    pub pending: usize,
}

/// グローバルマイグレーションエンジン
pub static MIGRATION_ENGINE: MigrationEngine = MigrationEngine::new();

// ============================================================================
// NUMA Distance Cache - 最適ノード順序の事前計算
// ============================================================================

/// 最大NUMAノード数
pub const MAX_NUMA_NODES: usize = 8;

/// NUMAノード距離（SLIT形式、10 = 同一ノード）
pub type NumaDistance = u8;

/// NUMA距離キャッシュ
/// 
/// ACPIのSLIT（System Locality Information Table）から距離を取得し、
/// 各ノードから他のノードへの距離順リストを事前計算する。
/// 
/// ## 使用例
/// 
/// ```ignore
/// // ノード0からのアロケーション順序を取得
/// let order = NUMA_DISTANCE_CACHE.nodes_by_distance(0);
/// // order = [0, 1, 2, 3, ...] (距離順、自分が最初)
/// 
/// for node in order {
///     if try_alloc_from_node(*node) {
///         break;
///     }
/// }
/// ```
pub struct NumaDistanceCache {
    /// 距離テーブル: distance_table[from][to] = 距離
    distance_table: [[AtomicU8; MAX_NUMA_NODES]; MAX_NUMA_NODES],
    
    /// 事前計算済みの距離順ノードリスト
    /// sorted_nodes[from_node] = [node_ids sorted by distance from from_node]
    sorted_nodes: [[AtomicU8; MAX_NUMA_NODES]; MAX_NUMA_NODES],
    
    /// 有効なノード数
    num_nodes: AtomicU8,
    
    /// 初期化済みフラグ
    initialized: AtomicU8,
}

impl NumaDistanceCache {
    /// 新しいキャッシュを作成
    pub const fn new() -> Self {
        const ZERO_U8: AtomicU8 = AtomicU8::new(0);
        const LOCAL_DIST: AtomicU8 = AtomicU8::new(10);  // 同一ノード距離
        
        // 対角線は10（ローカル）、それ以外は0で初期化
        const ROW_ZERO: [AtomicU8; MAX_NUMA_NODES] = [ZERO_U8; MAX_NUMA_NODES];
        const NODE_ZERO: [AtomicU8; MAX_NUMA_NODES] = [ZERO_U8; MAX_NUMA_NODES];
        
        Self {
            distance_table: [ROW_ZERO; MAX_NUMA_NODES],
            sorted_nodes: [NODE_ZERO; MAX_NUMA_NODES],
            num_nodes: AtomicU8::new(1),
            initialized: AtomicU8::new(0),
        }
    }
    
    /// ACPI SLITテーブルから初期化
    /// 
    /// # Arguments
    /// * `num_nodes` - NUMAノード数
    /// * `distances` - 距離テーブル（SLITフォーマット、num_nodes x num_nodes）
    pub fn init_from_slit(&self, num_nodes: usize, distances: &[&[u8]]) {
        let num = num_nodes.min(MAX_NUMA_NODES);
        self.num_nodes.store(num as u8, Ordering::Relaxed);
        
        // 距離テーブルをコピー
        for from in 0..num {
            for to in 0..num {
                let dist = if from < distances.len() && to < distances[from].len() {
                    distances[from][to]
                } else if from == to {
                    10  // ローカル距離
                } else {
                    20  // デフォルトリモート距離
                };
                self.distance_table[from][to].store(dist, Ordering::Relaxed);
            }
        }
        
        // 各ノードからの距離順リストを事前計算
        self.compute_sorted_nodes(num);
        
        self.initialized.store(1, Ordering::Release);
    }
    
    /// 距離順のノードリストを事前計算
    fn compute_sorted_nodes(&self, num_nodes: usize) {
        for from in 0..num_nodes {
            // (node_id, distance) のペアを作成
            let mut nodes_with_dist: [(u8, u8); MAX_NUMA_NODES] = [(0, 255); MAX_NUMA_NODES];
            
            for to in 0..num_nodes {
                let dist = self.distance_table[from][to].load(Ordering::Relaxed);
                nodes_with_dist[to] = (to as u8, dist);
            }
            
            // 距離でソート（insertion sort、小さい配列なので十分）
            for i in 1..num_nodes {
                let mut j = i;
                while j > 0 && nodes_with_dist[j - 1].1 > nodes_with_dist[j].1 {
                    nodes_with_dist.swap(j - 1, j);
                    j -= 1;
                }
            }
            
            // ソート結果を保存
            for (idx, (node_id, _)) in nodes_with_dist.iter().enumerate().take(num_nodes) {
                self.sorted_nodes[from][idx].store(*node_id, Ordering::Relaxed);
            }
        }
    }
    
    /// 指定ノードからの距離順でノードリストを取得
    /// 
    /// 返されるスライスは距離の近い順（自ノードが最初）にソートされている。
    /// メモリアロケーション時にフォールバック順序として使用。
    #[inline]
    pub fn nodes_by_distance(&self, from_node: usize) -> &[AtomicU8; MAX_NUMA_NODES] {
        let from = from_node.min(MAX_NUMA_NODES - 1);
        &self.sorted_nodes[from]
    }
    
    /// 2ノード間の距離を取得
    #[inline]
    pub fn get_distance(&self, from: usize, to: usize) -> u8 {
        if from >= MAX_NUMA_NODES || to >= MAX_NUMA_NODES {
            return 255;  // 無効
        }
        self.distance_table[from][to].load(Ordering::Relaxed)
    }
    
    /// 有効なノード数を取得
    #[inline]
    pub fn node_count(&self) -> usize {
        self.num_nodes.load(Ordering::Relaxed) as usize
    }
    
    /// 初期化済みかどうか
    #[inline]
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::Acquire) != 0
    }
    
    /// 距離順でイテレート（コピーして返す）
    pub fn iter_by_distance(&self, from_node: usize) -> impl Iterator<Item = u8> + '_ {
        let num = self.node_count();
        let from = from_node.min(MAX_NUMA_NODES - 1);
        
        (0..num).map(move |idx| {
            self.sorted_nodes[from][idx].load(Ordering::Relaxed)
        })
    }
}

/// グローバルNUMA距離キャッシュ
pub static NUMA_DISTANCE_CACHE: NumaDistanceCache = NumaDistanceCache::new();

// ============================================================================
// Phase 7: NUMA Page Migration Implementation
// ============================================================================

/// NUMAページマイグレーションを実行
/// 
/// # Arguments
/// * `src_frame` - 移動元フレームインデックス
/// * `dest_node` - 移動先NUMAノード
/// 
/// # Returns
/// * `MigrationResult` - マイグレーション結果
/// 
/// # Safety
/// 
/// - src_frameが有効なフレームであること
/// - ページテーブルエントリの更新は呼び出し側で行うこと
pub unsafe fn migrate_numa_page(src_frame: FrameIndex, dest_node: u8) -> MigrationResult {
    use super::buddy_allocator;
    use super::types::PAGE_SIZE_4K;
    
    // 1. 移動先ノードからフレームを確保
    let dest_frame = match buddy_allocator::buddy_alloc_frame_on_node(NumaNodeId::new(dest_node)) {
        Some(frame) => frame,
        None => return MigrationResult::NoMemory,
    };
    
    // 2. ページ内容をコピー（NT Store使用で高速化）
    let src_phys = (src_frame.as_usize() * PAGE_SIZE_4K) as u64;
    let dst_phys = dest_frame.start_address().as_u64();
    
    let offset = super::mapping::physical_memory_offset();
    let src_virt = (src_phys + offset) as *const u8;
    let dst_virt = (dst_phys + offset) as *mut u8;
    
    // Non-temporal storeを使用（キャッシュを汚染しない）
    #[cfg(target_arch = "x86_64")]
    {
        use core::arch::x86_64::{_mm_stream_si64, _mm_sfence};
        
        let src_ptr = src_virt as *const i64;
        let dst_ptr = dst_virt as *mut i64;
        
        // 4KB = 512 * 8バイト
        for i in 0..512 {
            let val = core::ptr::read_volatile(src_ptr.add(i));
            _mm_stream_si64(dst_ptr.add(i), val);
        }
        
        // メモリバリア
        _mm_sfence();
    }
    
    #[cfg(not(target_arch = "x86_64"))]
    {
        core::ptr::copy_nonoverlapping(src_virt, dst_virt, PAGE_SIZE_4K);
    }
    
    // 3. 統計更新
    MIGRATION_ENGINE.migrated_bytes.fetch_add(PAGE_SIZE_4K as u64, Ordering::Relaxed);
    
    // 4. 古いフレームを解放
    use x86_64::structures::paging::PhysFrame;
    let old_frame = PhysFrame::from_start_address(x86_64::PhysAddr::new(src_phys)).unwrap();
    buddy_allocator::buddy_dealloc_frame(old_frame);
    
    MigrationResult::Success
}

/// バッチマイグレーション処理
/// 
/// 保留中のマイグレーション要求を一括処理する。
/// アイドル時またはメモリプレッシャー時に呼び出す。
pub fn process_pending_migrations() -> usize {
    unsafe {
        MIGRATION_ENGINE.process_batch(|src_frame, dest_node| {
            migrate_numa_page(src_frame, dest_node)
        })
    }
}

/// タスクのNUMAアフィニティに基づいてマイグレーション要求を生成
/// 
/// # Arguments
/// * `task_preferred_node` - タスクが優先するNUMAノード
/// * `page_stats` - ページのNUMA統計
/// * `frame` - 対象フレーム
/// * `current_time` - 現在時刻
pub fn suggest_migration(
    task_preferred_node: u8,
    page_stats: &PageNumaStats,
    frame: FrameIndex,
    current_time: u64,
) -> Option<MigrationRequest> {
    let current_node = page_stats.current_node.load(Ordering::Acquire);
    
    // 既にローカルなら不要
    if current_node == task_preferred_node {
        return None;
    }
    
    // マイグレーション可能かチェック
    if !page_stats.can_migrate(current_time) {
        return None;
    }
    
    // アクセスパターンから優先度を計算
    let (hottest_node, access_count) = page_stats.get_hottest_node();
    
    // アクセス数が少ない場合は優先度を下げる
    let priority = if access_count >= NUMA_MIGRATION_THRESHOLD * 2 {
        10  // 高優先度
    } else if access_count >= NUMA_MIGRATION_THRESHOLD {
        5   // 中優先度
    } else {
        return None;  // しきい値未満
    };
    
    // 移動先ノードを決定
    // タスクの優先ノードかホットなノードのいずれか
    let dest_node = if hottest_node as u8 == task_preferred_node {
        task_preferred_node
    } else {
        // より近いノードを選択
        let dist_to_task = NUMA_DISTANCE_CACHE.get_distance(
            current_node as usize, 
            task_preferred_node as usize
        );
        let dist_to_hot = NUMA_DISTANCE_CACHE.get_distance(
            current_node as usize,
            hottest_node
        );
        
        if dist_to_task <= dist_to_hot {
            task_preferred_node
        } else {
            hottest_node as u8
        }
    };
    
    Some(MigrationRequest {
        src_frame: frame,
        dest_node,
        priority,
        timestamp: current_time,
    })
}

/// NUMA統計の概要を取得
pub fn get_numa_migration_summary() -> NumaMigrationSummary {
    let engine_stats = MIGRATION_ENGINE.stats();
    let (pages_scanned, faults_set) = NUMA_SCANNER.stats();
    
    NumaMigrationSummary {
        pages_scanned,
        faults_set,
        migrations_successful: engine_stats.successful,
        migrations_failed: engine_stats.failed,
        migrated_bytes: engine_stats.migrated_bytes,
        pending_migrations: engine_stats.pending,
    }
}

/// NUMA統計サマリー
#[derive(Debug, Clone)]
pub struct NumaMigrationSummary {
    pub pages_scanned: u64,
    pub faults_set: u64,
    pub migrations_successful: u64,
    pub migrations_failed: u64,
    pub migrated_bytes: u64,
    pub pending_migrations: usize,
}

// ============================================================================
// PTEヘルパー（NUMA Hint Fault設定用）
// ============================================================================

/// PTE (Page Table Entry) のNUMAヒントビットを操作するトレイト
pub trait NumaPteOps {
    /// PTEからNUMA Hint Faultを有効化（Presentビットを落とす）
    /// 
    /// # Safety
    /// 
    /// - PTEが有効なページを指していること
    /// - TLBフラッシュが必要な場合は呼び出し側で行うこと
    unsafe fn set_numa_hint(&mut self);
    
    /// NUMA Hint Faultを解除（Presentビットを立てる）
    /// 
    /// # Safety
    /// 
    /// - PTEが有効なページを指していること
    unsafe fn clear_numa_hint(&mut self);
    
    /// NUMA Hint Faultが設定されているか
    fn has_numa_hint(&self) -> bool;
}

/// x86_64 PTEフラグ定数
pub mod pte_flags {
    /// Present bit
    pub const PRESENT: u64 = 1 << 0;
    /// Accessed bit
    pub const ACCESSED: u64 = 1 << 5;
    /// NUMA hint（カスタムビット、ソフトウェア定義）
    /// bit 62 を使用（x86_64では未使用）
    pub const NUMA_HINT: u64 = 1 << 62;
}

/// 64ビットPTE
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct RawPte(pub u64);

impl NumaPteOps for RawPte {
    unsafe fn set_numa_hint(&mut self) {
        // Presentを落とし、NUMA_HINTを立てる
        self.0 = (self.0 & !pte_flags::PRESENT) | pte_flags::NUMA_HINT;
    }
    
    unsafe fn clear_numa_hint(&mut self) {
        // Presentを立て、NUMA_HINTを落とす
        self.0 = (self.0 | pte_flags::PRESENT) & !pte_flags::NUMA_HINT;
    }
    
    fn has_numa_hint(&self) -> bool {
        // Presentがなく、NUMA_HINTが立っている
        (self.0 & pte_flags::PRESENT) == 0 && (self.0 & pte_flags::NUMA_HINT) != 0
    }
}

// ============================================================================
// 設定
// ============================================================================

/// AutoNUMA設定
pub struct AutoNumaConfig {
    /// 有効かどうか
    pub enabled: bool,
    /// マイグレーションしきい値（アクセス回数）
    pub migration_threshold: u32,
    /// 冷却期間（ミリ秒）
    pub cooldown_ms: u64,
    /// スキャン間隔（ミリ秒）
    pub scan_period_ms: u64,
    /// 1スキャンあたりの最大ページ数
    pub scan_batch_size: usize,
}

impl Default for AutoNumaConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            migration_threshold: NUMA_MIGRATION_THRESHOLD,
            cooldown_ms: NUMA_MIGRATION_COOLDOWN_MS,
            scan_period_ms: NUMA_SCAN_PERIOD_MS,
            scan_batch_size: NUMA_SCAN_BATCH_SIZE,
        }
    }
}

/// グローバル設定を適用
pub fn apply_config(config: &AutoNumaConfig) {
    NUMA_SCANNER.set_enabled(config.enabled);
    NUMA_SCANNER.set_scan_period(config.scan_period_ms);
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_page_numa_stats_access() {
        let stats = PageNumaStats::new();
        
        stats.record_access(0, 1000);
        stats.record_access(0, 2000);
        stats.record_access(1, 3000);
        
        let (hottest, count) = stats.get_hottest_node();
        assert_eq!(hottest, 0);
        assert_eq!(count, 2);
    }
    
    #[test]
    fn test_page_numa_stats_shared() {
        let stats = PageNumaStats::new();
        
        stats.record_access(0, 1000);
        assert!(!stats.is_shared());
        
        stats.record_access(1, 2000);
        assert!(stats.is_shared());
    }
    
    #[test]
    fn test_numa_fault_action_local() {
        let stats = PageNumaStats::new();
        stats.current_node.store(0, Ordering::Relaxed);
        
        let action = handle_numa_fault(&stats, 0, 1000);
        assert_eq!(action, NumaFaultAction::RecordOnly);
    }
    
    #[test]
    fn test_raw_pte_numa_hint() {
        let mut pte = RawPte(pte_flags::PRESENT);
        assert!(!pte.has_numa_hint());
        
        unsafe { pte.set_numa_hint(); }
        assert!(pte.has_numa_hint());
        assert_eq!(pte.0 & pte_flags::PRESENT, 0);
        
        unsafe { pte.clear_numa_hint(); }
        assert!(!pte.has_numa_hint());
        assert_ne!(pte.0 & pte_flags::PRESENT, 0);
    }
    #[test]
    fn test_numa_fault_action_migrate() {
        let stats = PageNumaStats::new();
        stats.current_node.store(0, Ordering::Relaxed);
        
        // Remote access from Node 1
        // Threshold is 4, so we need > 4 accesses
        let access_count = NUMA_MIGRATION_THRESHOLD + 1;
        for _ in 0..access_count {
            stats.record_access(1, 1000);
        }
        
        // Simulate elapsed time > cooldown (to allow migration)
        // Last migration was 0 (init), current time needs to be > cooldown
        let current_time = NUMA_MIGRATION_COOLDOWN_MS + 1000;
        
        // Node 1 should be hottest
        let (hottest, count) = stats.get_hottest_node();
        assert_eq!(hottest, 1);
        assert!(count >= access_count);
        
        // Should trigger migration to Node 1
        let action = handle_numa_fault(&stats, 1, current_time);
        
        if let NumaFaultAction::Migrate { from_node, to_node } = action {
            assert_eq!(from_node, 0);
            assert_eq!(to_node, 1);
        } else {
            panic!("Expected Migrate action, got {:?}", action);
        }
    }
}
