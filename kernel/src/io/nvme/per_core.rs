// ============================================================================
// src/io/nvme/per_core.rs - Per-Core NVMe Queue Management
// ============================================================================
//!
//! # コアごとのNVMeキュー管理
//!
//! キャッシュライン整列されたコアローカルキューと統計管理。
//! ロックフリーアクセスで最大スループットを実現。
//!
//! ## 特徴
//! - 64バイトキャッシュライン整列（偽共有防止）
//! - UnsafeCellによるロックフリーアクセス
//! - ドアベルバッチ処理
//! - 詳細な統計収集

#![allow(dead_code)]

use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use super::commands::{NvmeCommand, NvmeCompletion};
use super::queue::{QueuePair, SubmissionQueue};
use super::defs::{SECTOR_SIZE, DOORBELL_BATCH_THRESHOLD};

// ============================================================================
// Queue Statistics
// ============================================================================

/// キュー統計（キャッシュライン整列）
#[repr(C, align(64))]
#[derive(Debug, Default)]
pub struct NvmeQueueStats {
    pub commands_submitted: AtomicU64,
    pub commands_completed: AtomicU64,
    pub read_bytes: AtomicU64,
    pub write_bytes: AtomicU64,
    pub errors: AtomicU64,
    pub poll_cycles: AtomicU64,
    pub doorbell_writes: AtomicU64,
    pub batched_commands: AtomicU64,
    _padding: [u8; 0], // 64バイト境界にパディング
}

// ============================================================================
// Per-Core Queue
// ============================================================================

/// コアごとのNVMeキュー（キャッシュライン整列、ロックフリー）
///
/// 64バイトアラインメントにより、異なるコア間での
/// 偽共有（false sharing）を防止し、キャッシュ効率を最大化。
///
/// UnsafeCellにより、各コアが自身のキューにロックフリーでアクセス可能。
/// （コアアフィニティによりレースコンディションは発生しない）
#[repr(C, align(64))]
pub struct PerCoreNvmeQueue {
    /// キューペア（UnsafeCellでロックフリーアクセス）
    inner: UnsafeCell<Option<QueuePair>>,
    /// コアID
    core_id: u32,
    /// 初期化完了フラグ
    initialized: AtomicBool,
    /// ドアベルバッチカウンタ（保留中のコマンド数）
    pending_commands: AtomicU32,
    /// 統計（別キャッシュライン）
    stats: NvmeQueueStats,
}

// Safety: PerCoreNvmeQueueは各コア固有のキューとして使用され、
// コアアフィニティによりシングルスレッドアクセスが保証される。
// 初期化以外の操作は所有コアからのみ行われる。
unsafe impl Sync for PerCoreNvmeQueue {}
unsafe impl Send for PerCoreNvmeQueue {}

impl PerCoreNvmeQueue {
    /// 新しいコアキューを作成
    pub const fn new(core_id: u32) -> Self {
        Self {
            inner: UnsafeCell::new(None),
            core_id,
            initialized: AtomicBool::new(false),
            pending_commands: AtomicU32::new(0),
            stats: NvmeQueueStats {
                commands_submitted: AtomicU64::new(0),
                commands_completed: AtomicU64::new(0),
                read_bytes: AtomicU64::new(0),
                write_bytes: AtomicU64::new(0),
                errors: AtomicU64::new(0),
                poll_cycles: AtomicU64::new(0),
                doorbell_writes: AtomicU64::new(0),
                batched_commands: AtomicU64::new(0),
                _padding: [],
            },
        }
    }

    /// キューペアを設定（初期化時のみ呼び出し）
    ///
    /// # Safety
    /// 初期化中にのみ呼び出すこと。他のスレッドから同時アクセスがないことを保証。
    pub unsafe fn set_queue_pair(&self, qp: QueuePair) {
        let ptr = self.inner.get();
        unsafe { (*ptr) = Some(qp) };
        self.initialized.store(true, Ordering::Release);
    }

    /// キューが初期化済みかチェック
    #[inline]
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::Acquire)
    }

    /// ロックフリーでキューペアにアクセス（所有コアのみ）
    ///
    /// # Safety
    /// 現在のコアがこのPerCoreNvmeQueueの所有者であることを呼び出し側が保証。
    #[inline]
    pub(crate) unsafe fn get_queue_pair(&self) -> Option<&QueuePair> {
        unsafe { (*self.inner.get()).as_ref() }
    }

    /// ロックフリーでキューペアに可変アクセス（所有コアのみ）
    ///
    /// # Safety
    /// 現在のコアがこのPerCoreNvmeQueueの所有者であることを呼び出し側が保証。
    #[inline]
    #[allow(dead_code)]
    pub(crate) unsafe fn get_queue_pair_mut(&self) -> Option<&mut QueuePair> {
        unsafe { (*self.inner.get()).as_mut() }
    }

    /// 読み取り操作を発行（ドアベルバッチ対応）
    ///
    /// # Safety
    /// 現在のコアがこのキューの所有者であることを呼び出し側が保証。
    pub unsafe fn read(
        &self,
        nsid: u32,
        lba: u64,
        blocks: u16,
        prp1: u64,
        prp2: u64,
    ) -> Result<u16, &'static str> {
        let qp = unsafe { self.get_queue_pair() }.ok_or("Queue not initialized")?;

        // CIDはSQのtailから取得
        let cid = qp.sq().tail();
        let cmd = NvmeCommand::read(cid, nsid, lba, blocks, prp1, prp2);
        let _tail = qp.sq().submit_no_doorbell(&cmd)?;

        self.stats
            .commands_submitted
            .fetch_add(1, Ordering::Relaxed);
        self.stats
            .read_bytes
            .fetch_add((blocks as u64) * (SECTOR_SIZE as u64), Ordering::Relaxed);

        // バッチカウンタをインクリメント
        let pending = self.pending_commands.fetch_add(1, Ordering::Relaxed) + 1;

        // 閾値を超えたらドアベルをフラッシュ
        if pending >= DOORBELL_BATCH_THRESHOLD as u32 {
            unsafe { self.flush_doorbell() };
        }

        Ok(cid)
    }

    /// 読み取り操作を即時発行（ドアベルを即座に書き込み）
    ///
    /// # Safety
    /// 現在のコアがこのキューの所有者であることを呼び出し側が保証。
    pub unsafe fn read_immediate(
        &self,
        nsid: u32,
        lba: u64,
        blocks: u16,
        prp1: u64,
        prp2: u64,
    ) -> Result<u16, &'static str> {
        let qp = unsafe { self.get_queue_pair() }.ok_or("Queue not initialized")?;

        // CIDはSQのtailから取得
        let cid = qp.sq().tail();
        let cmd = NvmeCommand::read(cid, nsid, lba, blocks, prp1, prp2);
        qp.submit(&cmd)?;

        self.stats
            .commands_submitted
            .fetch_add(1, Ordering::Relaxed);
        self.stats
            .read_bytes
            .fetch_add((blocks as u64) * (SECTOR_SIZE as u64), Ordering::Relaxed);
        self.stats.doorbell_writes.fetch_add(1, Ordering::Relaxed);

        Ok(cid)
    }

    /// 書き込み操作を発行（ドアベルバッチ対応）
    ///
    /// # Safety
    /// 現在のコアがこのキューの所有者であることを呼び出し側が保証。
    pub unsafe fn write(
        &self,
        nsid: u32,
        lba: u64,
        blocks: u16,
        prp1: u64,
        prp2: u64,
    ) -> Result<u16, &'static str> {
        let qp = unsafe { self.get_queue_pair() }.ok_or("Queue not initialized")?;

        // CIDはSQのtailから取得
        let cid = qp.sq().tail();
        let cmd = NvmeCommand::write(cid, nsid, lba, blocks, prp1, prp2);
        let _tail = qp.sq().submit_no_doorbell(&cmd)?;

        self.stats
            .commands_submitted
            .fetch_add(1, Ordering::Relaxed);
        self.stats
            .write_bytes
            .fetch_add((blocks as u64) * (SECTOR_SIZE as u64), Ordering::Relaxed);

        // バッチカウンタをインクリメント
        let pending = self.pending_commands.fetch_add(1, Ordering::Relaxed) + 1;

        // 閾値を超えたらドアベルをフラッシュ
        if pending >= DOORBELL_BATCH_THRESHOLD as u32 {
            unsafe { self.flush_doorbell() };
        }

        Ok(cid)
    }

    /// 書き込み操作を即時発行（ドアベルを即座に書き込み）
    ///
    /// # Safety
    /// 現在のコアがこのキューの所有者であることを呼び出し側が保証。
    pub unsafe fn write_immediate(
        &self,
        nsid: u32,
        lba: u64,
        blocks: u16,
        prp1: u64,
        prp2: u64,
    ) -> Result<u16, &'static str> {
        let qp = unsafe { self.get_queue_pair() }.ok_or("Queue not initialized")?;

        // CIDはSQのtailから取得
        let cid = qp.sq().tail();
        let cmd = NvmeCommand::write(cid, nsid, lba, blocks, prp1, prp2);
        qp.submit(&cmd)?;

        self.stats
            .commands_submitted
            .fetch_add(1, Ordering::Relaxed);
        self.stats
            .write_bytes
            .fetch_add((blocks as u64) * (SECTOR_SIZE as u64), Ordering::Relaxed);
        self.stats.doorbell_writes.fetch_add(1, Ordering::Relaxed);

        Ok(cid)
    }

    /// 保留中のコマンドをフラッシュ（ドアベル書き込み）
    ///
    /// # Safety
    /// 現在のコアがこのキューの所有者であることを呼び出し側が保証。
    pub unsafe fn flush_doorbell(&self) {
        if let Some(qp) = unsafe { self.get_queue_pair() } {
            let pending = self.pending_commands.swap(0, Ordering::Relaxed);
            if pending > 0 {
                qp.sq().ring_doorbell();
                self.stats.doorbell_writes.fetch_add(1, Ordering::Relaxed);
                self.stats
                    .batched_commands
                    .fetch_add(pending as u64, Ordering::Relaxed);
            }
        }
    }

    /// 完了をポーリング
    ///
    /// # Safety
    /// 現在のコアがこのキューの所有者であることを呼び出し側が保証。
    pub unsafe fn poll(&self) -> Option<NvmeCompletion> {
        let qp = unsafe { self.get_queue_pair() }?;

        self.stats.poll_cycles.fetch_add(1, Ordering::Relaxed);

        if let Some(cqe) = qp.poll_completion() {
            self.stats
                .commands_completed
                .fetch_add(1, Ordering::Relaxed);
            if !cqe.is_success() {
                self.stats.errors.fetch_add(1, Ordering::Relaxed);
            }
            Some(cqe)
        } else {
            None
        }
    }

    /// バッチポーリング（複数の完了を一度に処理）
    ///
    /// # Safety
    /// 現在のコアがこのキューの所有者であることを呼び出し側が保証。
    pub unsafe fn poll_batch(&self, max_completions: usize) -> Vec<NvmeCompletion> {
        let mut completions = Vec::with_capacity(max_completions);

        for _ in 0..max_completions {
            if let Some(cqe) = unsafe { self.poll() } {
                completions.push(cqe);
            } else {
                break;
            }
        }

        completions
    }

    /// 高性能ポーリングループ（PAUSE命令による効率化）
    ///
    /// # Safety
    /// 現在のコアがこのキューの所有者であることを呼び出し側が保証。
    pub unsafe fn poll_spin(&self, max_spins: u32) -> Option<NvmeCompletion> {
        for _ in 0..max_spins {
            if let Some(cqe) = unsafe { self.poll() } {
                return Some(cqe);
            }
            // PAUSE命令でCPUリソースを節約
            #[cfg(target_arch = "x86_64")]
            unsafe { core::arch::x86_64::_mm_pause() };
        }
        None
    }

    /// 統計を取得
    pub fn stats(&self) -> &NvmeQueueStats {
        &self.stats
    }

    /// コアIDを取得
    pub fn core_id(&self) -> u32 {
        self.core_id
    }

    /// 保留中のコマンド数を取得
    pub fn pending_commands(&self) -> u32 {
        self.pending_commands.load(Ordering::Relaxed)
    }
}
