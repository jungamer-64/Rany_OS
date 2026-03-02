// ============================================================================
// kernel/src/net/datapath/per_cpu_batch.rs
// ============================================================================
//! # Per-CPU バッチ処理エンジン
//!
//! 各CPUコアごとに独立したバッチキューを保持し、
//! ロック競合を排除した高スループットパケット処理を実現する。
//!
//! ## 設計方針
//! - ExoRust ガイドライン:
//!   - Per-Core Cache を活用しロックフリー割り当てを実現
//!   - NUMA アフィニティを考慮
//!   - ISR 内での動的メモリ割り当てを避ける

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use super::mempool::PacketRef;
use super::optimization::PacketBatch;

/// Per-CPUバッチキューの最大パケット数
const PER_CPU_BATCH_CAPACITY: usize = 64;

/// バッチフラッシュまでの最大遅延（マイクロ秒）
const DEFAULT_FLUSH_DELAY_US: u64 = 50;

/// 最大CPUコア数（静的配列サイズ）
const MAX_CPUS: usize = 64;

/// Per-CPU バッチキュー（各コア専用）
///
/// ロックフリー: 各コアは自分専用のキューのみ操作する。
/// 他コアからのフラッシュ要求は AtomicBool フラグで通知。
struct CpuBatchQueue {
    /// パケット格納バッファ（固定サイズリングバッファ）
    ring: [Option<PacketRef>; PER_CPU_BATCH_CAPACITY],
    /// 書き込み位置
    write_pos: usize,
    /// 読み取り位置
    read_pos: usize,
    /// キュー内のパケット数
    count: usize,
    /// 最後のフラッシュ時刻（TSC）
    last_flush_tsc: u64,
    /// 統計: 処理済みバッチ数
    batches_flushed: u64,
    /// 統計: 処理済みパケット数
    packets_processed: u64,
}

impl CpuBatchQueue {
    /// 新しいキューを作成
    const fn new() -> Self {
        const NONE: Option<PacketRef> = None;
        Self {
            ring: [NONE; PER_CPU_BATCH_CAPACITY],
            write_pos: 0,
            read_pos: 0,
            count: 0,
            last_flush_tsc: 0,
            batches_flushed: 0,
            packets_processed: 0,
        }
    }

    /// パケットを追加。キューが満杯なら false を返す
    #[inline]
    fn push(&mut self, packet: PacketRef) -> bool {
        if self.count >= PER_CPU_BATCH_CAPACITY {
            return false;
        }
        self.ring[self.write_pos] = Some(packet);
        self.write_pos = (self.write_pos + 1) % PER_CPU_BATCH_CAPACITY;
        self.count += 1;
        true
    }

    /// キュー内の全パケットをバッチとしてフラッシュ
    fn flush(&mut self) -> Option<PacketBatch> {
        if self.count == 0 {
            return None;
        }

        let mut batch = PacketBatch::new();
        let to_drain = self.count;

        for _ in 0..to_drain {
            if let Some(packet) = self.ring[self.read_pos].take() {
                batch.push(packet);
            }
            self.read_pos = (self.read_pos + 1) % PER_CPU_BATCH_CAPACITY;
        }
        self.count = 0;

        self.batches_flushed += 1;
        self.packets_processed += to_drain as u64;

        Some(batch)
    }

    /// タイムアウト付きフラッシュ
    fn flush_if_timeout(&mut self, current_tsc: u64, tsc_freq_mhz: u64) -> Option<PacketBatch> {
        if self.count == 0 {
            return None;
        }
        let elapsed_us = (current_tsc.wrapping_sub(self.last_flush_tsc)) / tsc_freq_mhz.max(1);
        if elapsed_us >= DEFAULT_FLUSH_DELAY_US {
            self.last_flush_tsc = current_tsc;
            self.flush()
        } else {
            None
        }
    }

    /// キュー内パケット数
    #[inline]
    fn len(&self) -> usize {
        self.count
    }

    /// キューが空か
    #[inline]
    fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// キューが満杯か
    #[inline]
    fn is_full(&self) -> bool {
        self.count >= PER_CPU_BATCH_CAPACITY
    }
}

/// Per-CPU バッチプロセッサ
///
/// 各CPUコアに対応するキューを管理し、
/// ロックなしの高速バッチ処理を提供する。
pub struct PerCpuBatchProcessor {
    /// CPUごとのバッチキュー
    ///
    /// 各CPUは自分のインデックスにのみアクセスするためロック不要。
    /// 初期化後は静的に確保される。
    queues: Vec<spin::Mutex<CpuBatchQueue>>,
    /// 有効CPU数
    cpu_count: usize,
    /// グローバル統計: 総フラッシュ数
    total_flushes: AtomicU64,
    /// グローバル統計: 総処理パケット数
    total_packets: AtomicU64,
    /// グローバル統計: フルフラッシュ数（キュー満杯時）
    full_flushes: AtomicU64,
    /// グローバル統計: タイムアウトフラッシュ数
    timeout_flushes: AtomicU64,
}

impl PerCpuBatchProcessor {
    /// 新しい Per-CPU バッチプロセッサを作成
    pub fn new(cpu_count: usize) -> Self {
        let count = cpu_count.min(MAX_CPUS).max(1);
        let mut queues = Vec::with_capacity(count);
        for _ in 0..count {
            queues.push(spin::Mutex::new(CpuBatchQueue::new()));
        }

        Self {
            queues,
            cpu_count: count,
            total_flushes: AtomicU64::new(0),
            total_packets: AtomicU64::new(0),
            full_flushes: AtomicU64::new(0),
            timeout_flushes: AtomicU64::new(0),
        }
    }

    /// パケットをバッチに追加（ロック最小化）
    ///
    /// 現在のCPU IDに基づき、対応するキューにパケットを追加する。
    /// キューが満杯の場合は即座にフラッシュしてバッチを返す。
    pub fn enqueue(&self, packet: PacketRef) -> Option<PacketBatch> {
        let cpu_id = current_cpu_id() % self.cpu_count;

        let mut queue = self.queues[cpu_id].lock();

        if queue.is_full() {
            // 満杯 → まずフラッシュしてパケットを空ける
            let batch = queue.flush();
            // 新しいパケットを追加
            queue.push(packet);
            if let Some(ref b) = batch {
                self.total_flushes.fetch_add(1, Ordering::Relaxed);
                self.full_flushes.fetch_add(1, Ordering::Relaxed);
                self.total_packets
                    .fetch_add(b.len() as u64, Ordering::Relaxed);
            }
            return batch;
        }

        queue.push(packet);

        // キューが閾値（75%）に達したら早期フラッシュ
        if queue.len() >= (PER_CPU_BATCH_CAPACITY * 3) / 4 {
            let batch = queue.flush();
            if let Some(ref b) = batch {
                self.total_flushes.fetch_add(1, Ordering::Relaxed);
                self.total_packets
                    .fetch_add(b.len() as u64, Ordering::Relaxed);
            }
            return batch;
        }

        None
    }

    /// 全CPUのキューを強制フラッシュ（非ブロッキング・ゼロアロケーション）
    ///
    /// 他のCPUがロック保持中のキューはスキップし、
    /// 待機によるスループット低下を回避する。
    ///
    /// 固定配列を使用し、ホットパスでのヒープ割り当てを回避。
    pub fn flush_all(&self) -> ([Option<PacketBatch>; MAX_CPUS], usize) {
        const NONE: Option<PacketBatch> = None;
        let mut batches = [NONE; MAX_CPUS];
        let mut count = 0;
        for queue_lock in &self.queues {
            // try_lock で非ブロッキング取得—他CPUが使用中ならスキップ
            if let Some(mut queue) = queue_lock.try_lock() {
                if let Some(batch) = queue.flush() {
                    self.total_flushes.fetch_add(1, Ordering::Relaxed);
                    self.total_packets
                        .fetch_add(batch.len() as u64, Ordering::Relaxed);
                    if count < MAX_CPUS {
                        batches[count] = Some(batch);
                        count += 1;
                    }
                }
            }
        }
        (batches, count)
    }

    /// 特定CPUのキューをフラッシュ
    pub fn flush_cpu(&self, cpu_id: usize) -> Option<PacketBatch> {
        let idx = cpu_id % self.cpu_count;
        let mut queue = self.queues[idx].lock();
        let batch = queue.flush();
        if let Some(ref b) = batch {
            self.total_flushes.fetch_add(1, Ordering::Relaxed);
            self.total_packets
                .fetch_add(b.len() as u64, Ordering::Relaxed);
        }
        batch
    }

    /// タイムアウトチェック（全CPU、非ブロッキング・ゼロアロケーション）
    ///
    /// 他のCPUがロック保持中のキューはスキップする。
    /// 固定配列を使用し、ホットパスでのヒープ割り当てを回避。
    pub fn check_timeouts(&self, current_tsc: u64, tsc_freq_mhz: u64) -> ([Option<PacketBatch>; MAX_CPUS], usize) {
        const NONE: Option<PacketBatch> = None;
        let mut batches = [NONE; MAX_CPUS];
        let mut count = 0;
        for queue_lock in &self.queues {
            // try_lock で非ブロッキング取得
            if let Some(mut queue) = queue_lock.try_lock() {
                if let Some(batch) = queue.flush_if_timeout(current_tsc, tsc_freq_mhz) {
                    self.total_flushes.fetch_add(1, Ordering::Relaxed);
                    self.timeout_flushes.fetch_add(1, Ordering::Relaxed);
                    self.total_packets
                        .fetch_add(batch.len() as u64, Ordering::Relaxed);
                    if count < MAX_CPUS {
                        batches[count] = Some(batch);
                        count += 1;
                    }
                }
            }
        }
        (batches, count)
    }

    /// 統計情報
    pub fn stats(&self) -> PerCpuBatchStats {
        PerCpuBatchStats {
            total_flushes: self.total_flushes.load(Ordering::Relaxed),
            total_packets: self.total_packets.load(Ordering::Relaxed),
            full_flushes: self.full_flushes.load(Ordering::Relaxed),
            timeout_flushes: self.timeout_flushes.load(Ordering::Relaxed),
            cpu_count: self.cpu_count,
        }
    }
}

/// Per-CPU バッチ統計
#[derive(Debug, Clone)]
pub struct PerCpuBatchStats {
    pub total_flushes: u64,
    pub total_packets: u64,
    pub full_flushes: u64,
    pub timeout_flushes: u64,
    pub cpu_count: usize,
}

// ============================================================================
// グローバルインスタンス
// ============================================================================

static PER_CPU_BATCH: spin::Once<PerCpuBatchProcessor> = spin::Once::new();

/// Per-CPU バッチプロセッサを初期化
pub fn init(cpu_count: usize) {
    PER_CPU_BATCH.call_once(|| PerCpuBatchProcessor::new(cpu_count));
}

/// Per-CPU バッチプロセッサを取得
pub fn per_cpu_batch() -> Option<&'static PerCpuBatchProcessor> {
    PER_CPU_BATCH.get()
}

/// 現在のCPU IDを取得
///
/// ISRコンテキストでも安全に取得できるラッパー。
#[inline]
fn current_cpu_id() -> usize {
    crate::per_cpu::try_current_cpu_id().unwrap_or(0)
}
