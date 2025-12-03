// ============================================================================
// src/net/optimization.rs - Network Performance Optimization
// 設計書 6章: 高性能ネットワーク最適化
// ============================================================================

//! # ネットワーク性能最適化
//! 
//! このモジュールは以下の最適化を提供します:
//! - バッチ処理 (Batching)
//! - NUMA対応メモリ配置
//! - CPU親和性設定
//! - インテリジェント割り込み合体 (Interrupt Coalescing)
//! - GROv2 (Generic Receive Offload)
//! - TSOシミュレーション (TCP Segmentation Offload)

use core::sync::atomic::{AtomicU64, AtomicUsize, AtomicBool, Ordering};
use alloc::vec::Vec;
use alloc::boxed::Box;
use spin::Mutex;

// ============================================================================
// Batch Processing - バッチ処理
// ============================================================================

/// 最大バッチサイズ (DPDK/NAPIの典型値)
pub const MAX_BATCH_SIZE: usize = 64;

/// パケットバッチ - 複数パケットをまとめて処理
pub struct PacketBatch {
    /// バッファへのポインタ配列
    buffers: [Option<usize>; MAX_BATCH_SIZE],  // *mut u8をusizeとして保持
    /// 各パケットの長さ
    lengths: [u16; MAX_BATCH_SIZE],
    /// バッチ内のパケット数
    count: usize,
    /// バッチサイズ上限
    capacity: usize,
}

// Safety: PacketBatchはunsafe操作でのみアクセスされ、適切に同期される
unsafe impl Send for PacketBatch {}
unsafe impl Sync for PacketBatch {}

impl PacketBatch {
    /// 新しい空のバッチを作成
    pub const fn new() -> Self {
        Self {
            buffers: [None; MAX_BATCH_SIZE],
            lengths: [0; MAX_BATCH_SIZE],
            count: 0,
            capacity: MAX_BATCH_SIZE,
        }
    }
    
    /// パケットをバッチに追加
    /// 
    /// # Safety
    /// `buffer`は有効なメモリを指している必要があります
    pub unsafe fn push(&mut self, buffer: *mut u8, length: u16) -> bool {
        if self.count >= self.capacity {
            return false;
        }
        self.buffers[self.count] = Some(buffer as usize);
        self.lengths[self.count] = length;
        self.count += 1;
        true
    }
    
    /// バッチが満杯か
    #[inline]
    pub fn is_full(&self) -> bool {
        self.count >= self.capacity
    }
    
    /// バッチが空か
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
    
    /// バッチ内のパケット数
    #[inline]
    pub fn len(&self) -> usize {
        self.count
    }
    
    /// バッチをクリア
    pub fn clear(&mut self) {
        for i in 0..self.count {
            self.buffers[i] = None;
            self.lengths[i] = 0;
        }
        self.count = 0;
    }
    
    /// イテレータを取得
    pub fn iter(&self) -> impl Iterator<Item = (*mut u8, u16)> + '_ {
        (0..self.count).filter_map(move |i| {
            self.buffers[i].map(|buf| (buf as *mut u8, self.lengths[i]))
        })
    }
}

impl Default for PacketBatch {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Batch Processor - バッチ処理エンジン
// ============================================================================

/// バッチ処理統計
#[derive(Debug, Default)]
pub struct BatchStats {
    /// 処理したバッチ数
    pub batches_processed: AtomicU64,
    /// 処理したパケット総数
    pub packets_processed: AtomicU64,
    /// 平均バッチサイズ (x100)
    pub avg_batch_size_x100: AtomicU64,
    /// 最大バッチサイズ
    pub max_batch_size: AtomicUsize,
    /// フラッシュ回数
    pub flush_count: AtomicU64,
    /// タイムアウトフラッシュ回数
    pub timeout_flushes: AtomicU64,
}

impl BatchStats {
    pub const fn new() -> Self {
        Self {
            batches_processed: AtomicU64::new(0),
            packets_processed: AtomicU64::new(0),
            avg_batch_size_x100: AtomicU64::new(0),
            max_batch_size: AtomicUsize::new(0),
            flush_count: AtomicU64::new(0),
            timeout_flushes: AtomicU64::new(0),
        }
    }
    
    fn record_batch(&self, size: usize) {
        let total = self.batches_processed.fetch_add(1, Ordering::Relaxed);
        let packets = self.packets_processed.fetch_add(size as u64, Ordering::Relaxed);
        
        // 移動平均の更新
        if total > 0 {
            let new_avg = (packets + size as u64) * 100 / (total + 1);
            self.avg_batch_size_x100.store(new_avg, Ordering::Relaxed);
        }
        
        // 最大サイズの更新
        let mut current_max = self.max_batch_size.load(Ordering::Relaxed);
        while size > current_max {
            match self.max_batch_size.compare_exchange_weak(
                current_max, size, Ordering::Relaxed, Ordering::Relaxed
            ) {
                Ok(_) => break,
                Err(new) => current_max = new,
            }
        }
    }
}

/// バッチ処理設定
#[derive(Debug, Clone, Copy)]
pub struct BatchConfig {
    /// 最大バッチサイズ
    pub max_batch_size: usize,
    /// フラッシュまでの最大待ち時間 (マイクロ秒)
    pub max_delay_us: u32,
    /// バッチ処理を有効にする最小パケット数/秒
    pub min_pps_threshold: u64,
    /// 動的バッチサイズ調整を有効化
    pub adaptive_batching: bool,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            max_batch_size: 32,
            max_delay_us: 50,
            min_pps_threshold: 10000,
            adaptive_batching: true,
        }
    }
}

/// バッチプロセッサ
pub struct BatchProcessor {
    config: BatchConfig,
    current_batch: Mutex<PacketBatch>,
    stats: BatchStats,
    last_flush_tsc: AtomicU64,
    enabled: AtomicBool,
}

impl BatchProcessor {
    pub const fn new(config: BatchConfig) -> Self {
        Self {
            config,
            current_batch: Mutex::new(PacketBatch::new()),
            stats: BatchStats::new(),
            last_flush_tsc: AtomicU64::new(0),
            enabled: AtomicBool::new(true),
        }
    }
    
    /// パケットをバッチに追加
    /// 
    /// # Safety
    /// `buffer`は有効なメモリを指している必要があります
    pub unsafe fn enqueue(&self, buffer: *mut u8, length: u16) -> Option<PacketBatch> {
        if !self.enabled.load(Ordering::Relaxed) {
            // バッチ処理無効時は即座に単一パケットバッチを返す
            let mut batch = PacketBatch::new();
            batch.push(buffer, length);
            return Some(batch);
        }
        
        let mut batch = self.current_batch.lock();
        batch.push(buffer, length);
        
        if batch.is_full() {
            let ready_batch = core::mem::take(&mut *batch);
            self.stats.record_batch(ready_batch.len());
            self.stats.flush_count.fetch_add(1, Ordering::Relaxed);
            Some(ready_batch)
        } else {
            None
        }
    }
    
    /// バッチを強制フラッシュ
    pub fn flush(&self) -> Option<PacketBatch> {
        let mut batch = self.current_batch.lock();
        if batch.is_empty() {
            return None;
        }
        
        let ready_batch = core::mem::take(&mut *batch);
        self.stats.record_batch(ready_batch.len());
        self.stats.flush_count.fetch_add(1, Ordering::Relaxed);
        Some(ready_batch)
    }
    
    /// タイムアウトチェック
    #[inline]
    pub fn check_timeout(&self, current_tsc: u64, tsc_freq_mhz: u64) -> Option<PacketBatch> {
        let last = self.last_flush_tsc.load(Ordering::Relaxed);
        let elapsed_us = (current_tsc - last) / tsc_freq_mhz;
        
        if elapsed_us >= self.config.max_delay_us as u64 {
            self.last_flush_tsc.store(current_tsc, Ordering::Relaxed);
            self.stats.timeout_flushes.fetch_add(1, Ordering::Relaxed);
            self.flush()
        } else {
            None
        }
    }
    
    /// バッチ処理を有効/無効化
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }
    
    /// 統計を取得
    pub fn stats(&self) -> &BatchStats {
        &self.stats
    }
}

// ============================================================================
// NUMA-aware Memory Allocation
// ============================================================================

/// NUMAノード情報
#[derive(Debug, Clone, Copy)]
pub struct NumaNode {
    /// ノードID
    pub id: u8,
    /// このノードに属するCPU (ビットマスク)
    pub cpu_mask: u64,
    /// メモリ開始アドレス
    pub memory_start: u64,
    /// メモリサイズ
    pub memory_size: u64,
    /// 他ノードへの距離 (0-255)
    pub distances: [u8; 8],
}

/// NUMAトポロジー
pub struct NumaTopology {
    nodes: Vec<NumaNode>,
    cpu_to_node: [u8; 256],
}

impl NumaTopology {
    /// システムからNUMAトポロジーを検出
    pub fn detect() -> Self {
        // 実際の実装ではACPI SRATテーブルを解析
        // ここではデフォルトの単一ノード構成を返す
        Self {
            nodes: alloc::vec![NumaNode {
                id: 0,
                cpu_mask: u64::MAX,
                memory_start: 0,
                memory_size: 0,
                distances: [10, 20, 20, 20, 20, 20, 20, 20],
            }],
            cpu_to_node: [0; 256],
        }
    }
    
    /// CPUが属するNUMAノードを取得
    #[inline]
    pub fn cpu_node(&self, cpu_id: usize) -> u8 {
        if cpu_id < 256 {
            self.cpu_to_node[cpu_id]
        } else {
            0
        }
    }
    
    /// ノード数を取得
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
    
    /// ノード情報を取得
    pub fn node(&self, id: u8) -> Option<&NumaNode> {
        self.nodes.iter().find(|n| n.id == id)
    }
}

/// NUMA対応メモリプール
pub struct NumaMempool {
    /// ノードごとのメモリプール（usizeとして保持）
    pools: Vec<Mutex<Vec<usize>>>,
    /// バッファサイズ
    buffer_size: usize,
    /// トポロジー参照
    topology: &'static NumaTopology,
}

impl NumaMempool {
    /// 新しいNUMA対応メモリプールを作成
    /// 
    /// # Safety
    /// メモリ割り当てに失敗した場合の動作は未定義
    pub unsafe fn new(
        buffer_size: usize,
        buffers_per_node: usize,
        topology: &'static NumaTopology,
    ) -> Self {
        let mut pools = Vec::with_capacity(topology.node_count());
        
        for _node_id in 0..topology.node_count() {
            // 各ノードでメモリを割り当て
            // 実際の実装ではnuma_alloc_onnode()相当を使用
            let mut node_pool = Vec::with_capacity(buffers_per_node);
            
            for _ in 0..buffers_per_node {
                let layout = alloc::alloc::Layout::from_size_align(buffer_size, 64)
                    .expect("Invalid layout");
                let ptr = alloc::alloc::alloc(layout);
                if !ptr.is_null() {
                    node_pool.push(ptr as usize);
                }
            }
            
            pools.push(Mutex::new(node_pool));
        }
        
        Self {
            pools,
            buffer_size,
            topology,
        }
    }
    
    /// 現在のCPUのNUMAノードからバッファを割り当て
    pub fn alloc(&self, cpu_id: usize) -> Option<*mut u8> {
        let node_id = self.topology.cpu_node(cpu_id) as usize;
        
        // まず同一ノードから試みる
        if let Some(ptr) = self.alloc_from_node(node_id) {
            return Some(ptr);
        }
        
        // 空いているノードから割り当て
        for i in 0..self.pools.len() {
            if i != node_id {
                if let Some(ptr) = self.alloc_from_node(i) {
                    return Some(ptr);
                }
            }
        }
        
        None
    }
    
    fn alloc_from_node(&self, node_id: usize) -> Option<*mut u8> {
        if node_id < self.pools.len() {
            self.pools[node_id].lock().pop().map(|addr| addr as *mut u8)
        } else {
            None
        }
    }
    
    /// バッファを解放
    /// 
    /// # Safety
    /// `ptr`はこのプールから割り当てられたものである必要があります
    pub unsafe fn free(&self, ptr: *mut u8, cpu_id: usize) {
        let node_id = self.topology.cpu_node(cpu_id) as usize;
        if node_id < self.pools.len() {
            self.pools[node_id].lock().push(ptr as usize);
        }
    }
}

// ============================================================================
// CPU Affinity - CPU親和性
// ============================================================================

/// CPU親和性設定
#[derive(Debug, Clone, Copy)]
pub struct CpuAffinity {
    /// 許可されるCPUのビットマスク
    pub mask: u64,
}

impl CpuAffinity {
    /// 全CPU許可
    pub const fn all() -> Self {
        Self { mask: u64::MAX }
    }
    
    /// 特定CPUのみ
    pub const fn single(cpu_id: usize) -> Self {
        Self { mask: 1 << cpu_id }
    }
    
    /// CPUリストから作成
    pub fn from_cpus(cpus: &[usize]) -> Self {
        let mut mask = 0u64;
        for &cpu in cpus {
            if cpu < 64 {
                mask |= 1 << cpu;
            }
        }
        Self { mask }
    }
    
    /// CPUが許可されているか
    #[inline]
    pub fn allows(&self, cpu_id: usize) -> bool {
        if cpu_id >= 64 {
            return false;
        }
        (self.mask & (1 << cpu_id)) != 0
    }
    
    /// 許可されているCPU数
    pub fn count(&self) -> usize {
        self.mask.count_ones() as usize
    }
}

/// ネットワークフロー用CPU親和性マネージャ
pub struct FlowAffinity {
    /// フローハッシュ -> CPU マッピング
    flow_table: [u8; 256],
    /// 使用可能なCPU
    available_cpus: CpuAffinity,
    /// Receive Side Scaling (RSS) 有効
    rss_enabled: bool,
}

impl FlowAffinity {
    pub fn new(available_cpus: CpuAffinity) -> Self {
        let mut table = [0u8; 256];
        let cpu_count = available_cpus.count();
        
        if cpu_count > 0 {
            let mut cpu_idx = 0;
            for (i, entry) in table.iter_mut().enumerate() {
                // Round-robinでCPUを割り当て
                while !available_cpus.allows(cpu_idx) {
                    cpu_idx = (cpu_idx + 1) % 64;
                }
                *entry = cpu_idx as u8;
                cpu_idx = (cpu_idx + 1) % 64;
                let _ = i; // suppress unused warning
            }
        }
        
        Self {
            flow_table: table,
            available_cpus,
            rss_enabled: true,
        }
    }
    
    /// フローハッシュからCPUを決定
    #[inline]
    pub fn cpu_for_flow(&self, flow_hash: u32) -> usize {
        if self.rss_enabled {
            self.flow_table[(flow_hash & 0xFF) as usize] as usize
        } else {
            0
        }
    }
    
    /// 5タプルからフローハッシュを計算
    pub fn hash_5tuple(
        src_ip: u32,
        dst_ip: u32,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
    ) -> u32 {
        // Toeplitz hashの簡易版
        let mut hash = src_ip;
        hash ^= dst_ip.rotate_left(5);
        hash ^= (src_port as u32) << 16 | (dst_port as u32);
        hash ^= (protocol as u32) << 24;
        
        // Mix
        hash ^= hash >> 16;
        hash = hash.wrapping_mul(0x85ebca6b);
        hash ^= hash >> 13;
        hash = hash.wrapping_mul(0xc2b2ae35);
        hash ^= hash >> 16;
        
        hash
    }
}

// ============================================================================
// Interrupt Coalescing - 割り込み合体
// ============================================================================

/// 割り込み合体設定
#[derive(Debug, Clone, Copy)]
pub struct InterruptCoalescing {
    /// RX合体: パケット数閾値
    pub rx_max_packets: u16,
    /// RX合体: 最大待ち時間 (マイクロ秒)
    pub rx_max_usec: u16,
    /// TX合体: パケット数閾値
    pub tx_max_packets: u16,
    /// TX合体: 最大待ち時間 (マイクロ秒)
    pub tx_max_usec: u16,
    /// 適応型合体を有効化
    pub adaptive: bool,
}

impl Default for InterruptCoalescing {
    fn default() -> Self {
        Self {
            rx_max_packets: 64,
            rx_max_usec: 100,
            tx_max_packets: 128,
            tx_max_usec: 200,
            adaptive: true,
        }
    }
}

/// 適応型割り込み合体コントローラ
pub struct AdaptiveCoalescing {
    config: InterruptCoalescing,
    current_rx_usec: AtomicU64,
    current_tx_usec: AtomicU64,
    packets_per_second: AtomicU64,
    last_update_tsc: AtomicU64,
    packet_count: AtomicU64,
}

impl AdaptiveCoalescing {
    pub const fn new(config: InterruptCoalescing) -> Self {
        Self {
            config,
            current_rx_usec: AtomicU64::new(config.rx_max_usec as u64),
            current_tx_usec: AtomicU64::new(config.tx_max_usec as u64),
            packets_per_second: AtomicU64::new(0),
            last_update_tsc: AtomicU64::new(0),
            packet_count: AtomicU64::new(0),
        }
    }
    
    /// パケット処理を記録
    pub fn record_packet(&self) {
        self.packet_count.fetch_add(1, Ordering::Relaxed);
    }
    
    /// 割り込み合体設定を更新
    pub fn update(&self, current_tsc: u64, tsc_freq_mhz: u64) {
        if !self.config.adaptive {
            return;
        }
        
        let last = self.last_update_tsc.load(Ordering::Relaxed);
        let elapsed_us = (current_tsc - last) / tsc_freq_mhz;
        
        // 100ms毎に更新
        if elapsed_us < 100_000 {
            return;
        }
        
        self.last_update_tsc.store(current_tsc, Ordering::Relaxed);
        
        let packets = self.packet_count.swap(0, Ordering::Relaxed);
        let pps = packets * 1_000_000 / elapsed_us;
        self.packets_per_second.store(pps, Ordering::Relaxed);
        
        // パケットレートに基づいて合体時間を調整
        let new_rx_usec = if pps > 1_000_000 {
            // 高負荷: 合体時間を延長
            self.config.rx_max_usec as u64
        } else if pps > 100_000 {
            // 中負荷
            self.config.rx_max_usec as u64 / 2
        } else {
            // 低負荷: 合体時間を短縮
            10
        };
        
        self.current_rx_usec.store(new_rx_usec, Ordering::Relaxed);
    }
    
    /// 現在のRX合体時間を取得
    pub fn rx_usec(&self) -> u64 {
        self.current_rx_usec.load(Ordering::Relaxed)
    }
    
    /// 現在のTX合体時間を取得
    pub fn tx_usec(&self) -> u64 {
        self.current_tx_usec.load(Ordering::Relaxed)
    }
    
    /// 推定パケットレート
    pub fn packets_per_second(&self) -> u64 {
        self.packets_per_second.load(Ordering::Relaxed)
    }
}

// ============================================================================
// GRO - Generic Receive Offload
// ============================================================================

/// GROセグメント
pub struct GroSegment {
    /// 先頭パケットバッファ（usizeとして保持）
    pub head: usize,
    /// 結合データサイズ
    pub total_len: u32,
    /// 結合パケット数
    pub packet_count: u16,
    /// フローハッシュ
    pub flow_hash: u32,
    /// シーケンス番号
    pub seq: u32,
    /// 次に期待するシーケンス番号
    pub next_seq: u32,
    /// タイムスタンプ (TSC)
    pub timestamp: u64,
}

// Safety: GroSegmentはunsafe操作でのみアクセスされ、適切に同期される
unsafe impl Send for GroSegment {}
unsafe impl Sync for GroSegment {}

impl GroSegment {
    /// バッファポインタを取得
    #[inline]
    pub fn head_ptr(&self) -> *mut u8 {
        self.head as *mut u8
    }
}

/// GROテーブル
pub struct GroTable {
    segments: [Option<GroSegment>; GRO_TABLE_SIZE],
    count: usize,
    max_age_tsc: u64,
}

const GRO_TABLE_SIZE: usize = 16;
const GRO_MAX_PACKETS: u16 = 64;

impl GroTable {
    pub const fn new() -> Self {
        const NONE: Option<GroSegment> = None;
        Self {
            segments: [NONE; GRO_TABLE_SIZE],
            count: 0,
            max_age_tsc: 0,
        }
    }
    
    /// パケットをGRO処理
    /// 
    /// # Safety
    /// `buffer`は有効なメモリを指している必要があります
    pub unsafe fn process(
        &mut self,
        buffer: *mut u8,
        len: u16,
        flow_hash: u32,
        seq: u32,
        current_tsc: u64,
    ) -> Option<GroSegment> {
        // 既存セグメントを検索
        for segment in self.segments.iter_mut().flatten() {
            if segment.flow_hash == flow_hash && segment.next_seq == seq {
                // 結合可能
                segment.total_len += len as u32;
                segment.packet_count += 1;
                segment.next_seq = seq.wrapping_add(len as u32);
                
                if segment.packet_count >= GRO_MAX_PACKETS {
                    // 最大サイズに達した - フラッシュ
                    return self.take_segment(flow_hash);
                }
                return None;
            }
        }
        
        // 新しいセグメントを作成
        if self.count < GRO_TABLE_SIZE {
            let new_segment = GroSegment {
                head: buffer as usize,
                total_len: len as u32,
                packet_count: 1,
                flow_hash,
                seq,
                next_seq: seq.wrapping_add(len as u32),
                timestamp: current_tsc,
            };
            
            for slot in self.segments.iter_mut() {
                if slot.is_none() {
                    *slot = Some(new_segment);
                    self.count += 1;
                    break;
                }
            }
        }
        
        None
    }
    
    /// タイムアウトしたセグメントをフラッシュ
    pub fn flush_aged(&mut self, current_tsc: u64) -> Vec<GroSegment> {
        let mut flushed = Vec::new();
        
        for slot in self.segments.iter_mut() {
            let should_flush = slot.as_ref()
                .map(|segment| current_tsc - segment.timestamp > self.max_age_tsc)
                .unwrap_or(false);
            
            if should_flush {
                if let Some(seg) = slot.take() {
                    self.count -= 1;
                    flushed.push(seg);
                }
            }
        }
        
        flushed
    }
    
    fn take_segment(&mut self, flow_hash: u32) -> Option<GroSegment> {
        for slot in self.segments.iter_mut() {
            let matches = slot.as_ref()
                .map(|segment| segment.flow_hash == flow_hash)
                .unwrap_or(false);
            
            if matches {
                self.count -= 1;
                return slot.take();
            }
        }
        None
    }
}

// ============================================================================
// TSO - TCP Segmentation Offload (ソフトウェアエミュレーション)
// ============================================================================

/// TSOコンテキスト
pub struct TsoContext {
    /// MSS (Maximum Segment Size)
    pub mss: u16,
    /// 送信バッファ（usizeとして保持）
    pub buffer: usize,
    /// 総データサイズ
    pub total_len: u32,
    /// 現在のオフセット
    pub offset: u32,
    /// 送信済みセグメント数
    pub segments_sent: u32,
}

// Safety: TsoContextはunsafe操作でのみアクセスされ、適切に同期される
unsafe impl Send for TsoContext {}
unsafe impl Sync for TsoContext {}

impl TsoContext {
    /// TSOセグメントを生成
    /// 
    /// # Safety
    /// `buffer`は有効なメモリを指している必要があります
    pub unsafe fn new(buffer: *mut u8, total_len: u32, mss: u16) -> Self {
        Self {
            mss,
            buffer: buffer as usize,
            total_len,
            offset: 0,
            segments_sent: 0,
        }
    }
    
    /// 次のセグメントを取得
    pub fn next_segment(&mut self) -> Option<(*mut u8, u16)> {
        if self.offset >= self.total_len {
            return None;
        }
        
        let remaining = self.total_len - self.offset;
        let seg_len = core::cmp::min(remaining, self.mss as u32) as u16;
        
        let ptr = unsafe { (self.buffer as *mut u8).add(self.offset as usize) };
        self.offset += seg_len as u32;
        self.segments_sent += 1;
        
        Some((ptr, seg_len))
    }
    
    /// 残りセグメント数
    pub fn remaining_segments(&self) -> u32 {
        if self.offset >= self.total_len {
            return 0;
        }
        let remaining = self.total_len - self.offset;
        (remaining + self.mss as u32 - 1) / self.mss as u32
    }
}

// ============================================================================
// Performance Metrics
// ============================================================================

/// ネットワーク性能メトリクス
#[derive(Debug, Default)]
pub struct NetworkMetrics {
    /// 受信パケット数
    pub rx_packets: AtomicU64,
    /// 送信パケット数
    pub tx_packets: AtomicU64,
    /// 受信バイト数
    pub rx_bytes: AtomicU64,
    /// 送信バイト数
    pub tx_bytes: AtomicU64,
    /// 受信ドロップ数
    pub rx_drops: AtomicU64,
    /// 送信ドロップ数
    pub tx_drops: AtomicU64,
    /// 受信エラー数
    pub rx_errors: AtomicU64,
    /// 送信エラー数
    pub tx_errors: AtomicU64,
    /// GROマージ数
    pub gro_merges: AtomicU64,
    /// TSOセグメント数
    pub tso_segments: AtomicU64,
    /// バッチ処理数
    pub batched_packets: AtomicU64,
}

impl NetworkMetrics {
    pub const fn new() -> Self {
        Self {
            rx_packets: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_drops: AtomicU64::new(0),
            tx_drops: AtomicU64::new(0),
            rx_errors: AtomicU64::new(0),
            tx_errors: AtomicU64::new(0),
            gro_merges: AtomicU64::new(0),
            tso_segments: AtomicU64::new(0),
            batched_packets: AtomicU64::new(0),
        }
    }
    
    /// パケットスループット (pps) を計算
    pub fn calculate_pps(&self, elapsed_secs: f64) -> (f64, f64) {
        let rx_pps = self.rx_packets.load(Ordering::Relaxed) as f64 / elapsed_secs;
        let tx_pps = self.tx_packets.load(Ordering::Relaxed) as f64 / elapsed_secs;
        (rx_pps, tx_pps)
    }
    
    /// バイトスループット (bps) を計算
    pub fn calculate_bps(&self, elapsed_secs: f64) -> (f64, f64) {
        let rx_bps = self.rx_bytes.load(Ordering::Relaxed) as f64 * 8.0 / elapsed_secs;
        let tx_bps = self.tx_bytes.load(Ordering::Relaxed) as f64 * 8.0 / elapsed_secs;
        (rx_bps, tx_bps)
    }
    
    /// メトリクスをリセット
    pub fn reset(&self) {
        self.rx_packets.store(0, Ordering::Relaxed);
        self.tx_packets.store(0, Ordering::Relaxed);
        self.rx_bytes.store(0, Ordering::Relaxed);
        self.tx_bytes.store(0, Ordering::Relaxed);
        self.rx_drops.store(0, Ordering::Relaxed);
        self.tx_drops.store(0, Ordering::Relaxed);
        self.rx_errors.store(0, Ordering::Relaxed);
        self.tx_errors.store(0, Ordering::Relaxed);
        self.gro_merges.store(0, Ordering::Relaxed);
        self.tso_segments.store(0, Ordering::Relaxed);
        self.batched_packets.store(0, Ordering::Relaxed);
    }
}

// ============================================================================
// Global instances
// ============================================================================

static BATCH_PROCESSOR: spin::Once<BatchProcessor> = spin::Once::new();
static NUMA_TOPOLOGY: spin::Once<NumaTopology> = spin::Once::new();
static FLOW_AFFINITY: spin::Once<FlowAffinity> = spin::Once::new();
static ADAPTIVE_COALESCING: spin::Once<AdaptiveCoalescing> = spin::Once::new();
static NETWORK_METRICS: NetworkMetrics = NetworkMetrics::new();

/// ネットワーク最適化を初期化
pub fn init() {
    BATCH_PROCESSOR.call_once(|| BatchProcessor::new(BatchConfig::default()));
    NUMA_TOPOLOGY.call_once(NumaTopology::detect);
    
    let topology = NUMA_TOPOLOGY.get().unwrap();
    FLOW_AFFINITY.call_once(|| FlowAffinity::new(CpuAffinity::all()));
    
    ADAPTIVE_COALESCING.call_once(|| AdaptiveCoalescing::new(InterruptCoalescing::default()));
    
    let _ = topology; // avoid unused warning
}

/// バッチプロセッサを取得
pub fn batch_processor() -> Option<&'static BatchProcessor> {
    BATCH_PROCESSOR.get()
}

/// NUMAトポロジーを取得
pub fn numa_topology() -> Option<&'static NumaTopology> {
    NUMA_TOPOLOGY.get()
}

/// フローアフィニティを取得
pub fn flow_affinity() -> Option<&'static FlowAffinity> {
    FLOW_AFFINITY.get()
}

/// 適応型割り込み合体を取得
pub fn adaptive_coalescing() -> Option<&'static AdaptiveCoalescing> {
    ADAPTIVE_COALESCING.get()
}

/// グローバルメトリクスを取得
pub fn metrics() -> &'static NetworkMetrics {
    &NETWORK_METRICS
}
