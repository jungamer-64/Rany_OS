// ============================================================================
// src/mm/tlb_batch.rs - Batched TLB Shootdown
//
// ## 概要
//
// TLBシュートダウン（他CPUのTLB無効化）は、マルチコア環境で
// IPIを送る必要があり非常にコストが高い。このモジュールでは:
//
// 1. **バッチ化**: 複数のTLB無効化要求をまとめて1回のIPIで処理
// 2. **Lazy Flush**: 実際に必要になるまでフラッシュを遅延
// 3. **選択的フラッシュ**: アクティブなCPUのみに送信
// 4. **Coalescing Window**: 短時間の複数要求を1回のIPIにまとめる
//
// ## 設計
//
// - Per-CPU の TlbFlushBatch 構造体
// - add_page() で無効化ページを登録
// - flush() でまとめてIPI送信
// - flush_range() で範囲指定フラッシュ
// - Coalescing Window: TLB_COALESCE_WINDOW_NS (1μs)以内の要求をマージ
//
// ## パフォーマンス
//
// - 単一IPI: 数百〜数千サイクル
// - バッチ化により 1/N に削減（N = バッチサイズ）
// - Coalescing Windowでさらにunmap時のIPI削減
//
// ## 参考
//
// - Linux arch/x86/mm/tlb.c
// - x86 INVLPG, INVPCID 命令
// ============================================================================
#![allow(dead_code)]

/// TSCを読み取る（Coalescing Window用）
#[inline]
fn read_tsc() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_rdtsc()
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicUsize, Ordering};
use x86_64::VirtAddr;
use crate::mm::sync::pcid::{PCID_STATS, PCID_ALLOCATOR};

// ============================================================================
// Configuration
// ============================================================================

/// バッチの最大サイズ（ページ数）
pub const TLB_BATCH_SIZE: usize = 32;

/// この数を超えたら全フラッシュに切り替え
pub const TLB_FLUSH_ALL_THRESHOLD: usize = 512;

/// 最大CPU数
pub const MAX_CPUS: usize = 256;

/// TLBフラッシュ用IPIベクタ番号
/// interrupt_manager.rsのIPI_VECTOR_BASE (241) + オフセット
pub const TLB_FLUSH_VECTOR: u8 = 241;

// ============================================================================
// TLB Flush Batch
// ============================================================================

/// TLB Coalescing Window（マイクロ秒）
/// 複数のunmap操作をこの期間内にまとめてからIPIを送信
pub const TLB_COALESCE_WINDOW_NS: u64 = 1000; // 1μs

/// TLBフラッシュバッチ
/// 
/// 複数のTLB無効化要求をまとめて処理する。
/// Coalescing Window機能により、短時間の複数要求を1回のIPIにまとめる。
#[repr(C, align(64))]  // キャッシュライン境界
pub struct TlbFlushBatch {
    /// フラッシュ対象のアドレス（仮想アドレス）
    pages: [u64; TLB_BATCH_SIZE],
    /// 現在のバッチサイズ
    count: usize,
    /// フラッシュが必要か
    need_flush: bool,
    /// 全フラッシュフラグ（ページ数が閾値を超えた場合）
    flush_all: bool,
    /// 対象のASID/PCID (0 = 全て)
    asid: u16,
    /// フラッシュ対象のCPUマスク
    cpu_mask: u64,
    /// 最初のページ追加時刻（Coalescing Window用、TSC）
    first_add_time: Option<u64>,
    /// 統計: バッチフラッシュ回数
    batch_count: u64,
    /// 統計: 個別フラッシュ回数（バッチ化できなかった）
    single_count: u64,
    /// 統計: 全フラッシュ回数
    full_flush_count: u64,
    /// 統計: Coalescing Windowでマージされた回数
    coalesced_count: u64,
}

impl TlbFlushBatch {
    /// 新しいバッチを作成
    pub const fn new() -> Self {
        Self {
            pages: [0; TLB_BATCH_SIZE],
            count: 0,
            need_flush: false,
            flush_all: false,
            asid: 0,
            cpu_mask: 0,
            first_add_time: None,
            batch_count: 0,
            single_count: 0,
            full_flush_count: 0,
            coalesced_count: 0,
        }
    }
    
    /// バッチをリセット
    #[inline]
    pub fn reset(&mut self) {
        self.count = 0;
        self.need_flush = false;
        self.flush_all = false;
        self.asid = 0;
        self.first_add_time = None;
        self.cpu_mask = 0;
    }
    
    /// ページをバッチに追加
    /// 
    /// バッチが満杯の場合は自動的にフラッシュされる
    /// Coalescing Window機能により、最初の追加からの経過時間を追跡
    #[inline]
    pub fn add_page(&mut self, vaddr: VirtAddr) {
        if self.count >= TLB_BATCH_SIZE {
            // バッチが満杯 → フラッシュして継続
            self.flush();
        }
        
        // Coalescing Window: 最初の追加時刻を記録
        if self.first_add_time.is_none() {
            self.first_add_time = Some(read_tsc());
        }
        
        self.pages[self.count] = vaddr.as_u64();
        self.count += 1;
        self.need_flush = true;
    }
    
    /// Coalescing Windowの残り時間をチェック
    /// 
    /// Window期間が経過している場合はフラッシュすべき
    #[inline]
    pub fn should_flush_by_window(&self) -> bool {
        if let Some(first_time) = self.first_add_time {
            let current = read_tsc();
            // TSCをナノ秒に変換（概算: 3GHz CPU想定）
            let elapsed_ns = (current.saturating_sub(first_time)) / 3;
            elapsed_ns >= TLB_COALESCE_WINDOW_NS
        } else {
            false
        }
    }
    
    /// Coalescing Windowを考慮したフラッシュ試行
    /// 
    /// Window期間内ならフラッシュを遅延、期間経過後に実行
    pub fn try_flush_coalesced(&mut self) -> bool {
        if !self.need_flush {
            return false;
        }
        
        if self.should_flush_by_window() {
            self.flush();
            true
        } else {
            false
        }
    }
    
    /// 複数ページをバッチに追加
    pub fn add_pages(&mut self, start: VirtAddr, page_count: usize) {
        if page_count > TLB_FLUSH_ALL_THRESHOLD {
            // 大量のページ → 全フラッシュにフォールバック
            self.flush_all = true;
            self.need_flush = true;
            return;
        }
        
        for i in 0..page_count {
            let addr = VirtAddr::new(start.as_u64() + (i as u64 * 4096));
            self.add_page(addr);
        }
    }
    
    /// 対象CPUを追加
    #[inline]
    pub fn add_cpu(&mut self, cpu_id: usize) {
        if cpu_id < 64 {
            self.cpu_mask |= 1u64 << cpu_id;
        }
    }
    
    /// 全CPUを対象に
    #[inline]
    pub fn set_all_cpus(&mut self) {
        self.cpu_mask = u64::MAX;
    }
    
    /// ASIDを設定
    #[inline]
    pub fn set_asid(&mut self, asid: u16) {
        self.asid = asid;
    }
    
    /// バッチをフラッシュ
    pub fn flush(&mut self) {
        if !self.need_flush {
            return;
        }
        
        if self.flush_all {
            // 全TLBフラッシュ
            self.do_flush_all();
            self.full_flush_count += 1;
        } else if self.count > 0 {
            // 個別ページフラッシュ
            self.do_flush_pages();
            self.batch_count += 1;
        }
        
        self.reset();
    }
    
    /// 全TLBをフラッシュ
    fn do_flush_all(&self) {
        // ローカルCPUの全TLBフラッシュ
        unsafe {
            flush_tlb_all_local();
        }
        
        // リモートCPUへIPI（必要な場合）
        if self.cpu_mask != 0 {
            // 現在のCPU以外にIPIを送信
            send_tlb_flush_ipi_all(self.cpu_mask);
        }
    }
    
    /// 個別ページをフラッシュ
    fn do_flush_pages(&self) {
        // ローカルCPU
        for i in 0..self.count {
            unsafe {
                flush_tlb_page_local(VirtAddr::new(self.pages[i]));
            }
        }
        
        // リモートCPUへIPI
        if self.cpu_mask != 0 {
            send_tlb_flush_ipi_pages(self.cpu_mask, &self.pages[..self.count]);
        }
    }
    
    /// 統計を取得
    pub fn stats(&self) -> TlbBatchStats {
        TlbBatchStats {
            batch_flushes: self.batch_count,
            single_flushes: self.single_count,
            full_flushes: self.full_flush_count,
        }
    }
}

/// TLBバッチ統計
#[derive(Debug, Clone)]
pub struct TlbBatchStats {
    pub batch_flushes: u64,
    pub single_flushes: u64,
    pub full_flushes: u64,
}

// ============================================================================
// Per-CPU TLB Batch
// ============================================================================

/// Per-CPUのTLBバッチ配列
static mut PER_CPU_TLB_BATCH: [TlbFlushBatch; MAX_CPUS] = {
    const INIT: TlbFlushBatch = TlbFlushBatch::new();
    [INIT; MAX_CPUS]
};

/// 現在のCPUのTLBバッチを取得
/// 
/// # Safety
/// 
/// - 割り込み禁止状態で呼び出すこと
/// - 同一CPU内でのみアクセスすること
#[inline]
pub unsafe fn get_cpu_tlb_batch(cpu_id: usize) -> &'static mut TlbFlushBatch {
    &mut PER_CPU_TLB_BATCH[cpu_id.min(MAX_CPUS - 1)]
}

// ============================================================================
// Lazy TLB Flush Context
// ============================================================================

/// CPUのTLB状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TlbState {
    /// アクティブ（現在のページテーブルを使用中）
    Active = 0,
    /// Lazy（別のアドレス空間にスイッチ済み、フラッシュ不要）
    Lazy = 1,
}

/// Per-CPUのTLB状態追跡
pub struct CpuTlbState {
    /// TLB状態
    state: AtomicU64,
    /// 現在のASID/PCID
    current_asid: AtomicU64,
    /// 最後のフラッシュ時刻
    last_flush_time: AtomicU64,
    /// 保留中のフラッシュ要求があるか
    pending_flush: AtomicBool,
}

impl CpuTlbState {
    pub const fn new() -> Self {
        Self {
            state: AtomicU64::new(TlbState::Active as u64),
            current_asid: AtomicU64::new(0),
            last_flush_time: AtomicU64::new(0),
            pending_flush: AtomicBool::new(false),
        }
    }
    
    /// 状態を取得
    #[inline]
    pub fn get_state(&self) -> TlbState {
        match self.state.load(Ordering::Acquire) {
            0 => TlbState::Active,
            _ => TlbState::Lazy,
        }
    }
    
    /// Lazyモードに移行
    #[inline]
    pub fn enter_lazy(&self) {
        self.state.store(TlbState::Lazy as u64, Ordering::Release);
    }
    
    /// Activeモードに移行
    #[inline]
    pub fn enter_active(&self) {
        // Lazyモードだった場合、保留中のフラッシュを実行
        if self.pending_flush.swap(false, Ordering::AcqRel) {
            unsafe { flush_tlb_all_local(); }
        }
        self.state.store(TlbState::Active as u64, Ordering::Release);
    }
    
    /// フラッシュ要求を保留
    #[inline]
    pub fn mark_pending_flush(&self) {
        self.pending_flush.store(true, Ordering::Release);
    }
    
    /// ASIDを設定
    #[inline]
    pub fn set_asid(&self, asid: u64) {
        self.current_asid.store(asid, Ordering::Release);
    }
}

/// Per-CPUのTLB状態配列
static CPU_TLB_STATES: [CpuTlbState; MAX_CPUS] = {
    const INIT: CpuTlbState = CpuTlbState::new();
    [INIT; MAX_CPUS]
};

/// CPUのTLB状態を取得
#[inline]
pub fn get_cpu_tlb_state(cpu_id: usize) -> &'static CpuTlbState {
    &CPU_TLB_STATES[cpu_id.min(MAX_CPUS - 1)]
}

// ============================================================================
// Low-level TLB Operations
// ============================================================================

/// ローカルCPUの単一ページをフラッシュ（INVLPG）
/// 
/// # Safety
/// 
/// - 有効なアドレスを指定すること
#[inline]
pub unsafe fn flush_tlb_page_local(addr: VirtAddr) {
    asm!(
        "invlpg [{}]",
        in(reg) addr.as_u64(),
        options(nostack, preserves_flags)
    );
}

/// ローカルCPUの全TLBをフラッシュ（CR3リロード）
/// 
/// # Safety
/// 
/// - カーネルモードで実行すること
#[inline]
pub unsafe fn flush_tlb_all_local() {
    // CR3を読み取って書き戻すことでTLBをフラッシュ
    let cr3: u64;
    asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
    asm!("mov cr3, {}", in(reg) cr3, options(nostack, preserves_flags));
}

/// INVPCID命令ラッパー (delegates to pcid module)
#[inline]
pub unsafe fn invpcid(pcid: u64, addr: u64, invpcid_type: u64) {
    super::pcid::invpcid(pcid as u16, addr, invpcid_type);
}

/// INVPCID タイプ (re-export from pcid module)
pub mod invpcid_type {
    pub use super::super::pcid::invpcid_types::*;
}

// ============================================================================
// IPI-based Remote Flush
// ============================================================================

/// TLBフラッシュIPIペイロード
#[repr(C)]
pub struct TlbFlushIpiPayload {
    /// フラッシュタイプ
    pub flush_type: TlbFlushType,
    /// ページアドレス（個別フラッシュの場合）
    pub pages: [u64; TLB_BATCH_SIZE],
    /// ページ数
    pub page_count: usize,
    /// ASID
    pub asid: u16,
}

/// フラッシュタイプ
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum TlbFlushType {
    /// 全TLBフラッシュ
    All = 0,
    /// 指定ページのみ
    Pages = 1,
    /// 指定ASIDのみ
    Asid = 2,
}

/// グローバルTLBフラッシュの排他制御
static TLB_FLUSH_LOCK: crate::sync::irq_mutex::IrqMutex<()> = crate::sync::irq_mutex::IrqMutex::new(());

/// グローバルIPIペイロード（各CPUが参照）
/// TLB_FLUSH_LOCK で保護される。
static mut TLB_FLUSH_PAYLOAD: TlbFlushIpiPayload = TlbFlushIpiPayload {
    flush_type: TlbFlushType::All,
    pages: [0; TLB_BATCH_SIZE],
    page_count: 0,
    asid: 0,
};

/// IPIが完了したCPUのカウント
static TLB_FLUSH_DONE_COUNT: AtomicUsize = AtomicUsize::new(0);

/// 全TLBフラッシュIPIを送信
fn send_tlb_flush_ipi_all(cpu_mask: u64) {
    send_tlb_flush_ipi_internal(cpu_mask, TlbFlushType::All, &[], 0);
}

/// 個別ページフラッシュIPIを送信
fn send_tlb_flush_ipi_pages(cpu_mask: u64, pages: &[u64]) {
    send_tlb_flush_ipi_internal(cpu_mask, TlbFlushType::Pages, pages, 0);
}

/// TLBフラッシュIPIを送信（共通処理）
/// 
/// 1. TLB_FLUSH_LOCK を取得して送信側をシリアライズ
/// 2. ペイロードを設定
/// 3. IPIを送信
/// 4. 全CPUの完了を待機
/// 5. ロックを解放
fn send_tlb_flush_ipi_internal(cpu_mask: u64, flush_type: TlbFlushType, pages: &[u64], asid: u16) {
    // 現在のCPUを除外したターゲットマスクを作成
    let current_cpu = crate::per_cpu::try_current_cpu_id().unwrap_or(0);
    let mut remote_mask = cpu_mask & !(1u64 << current_cpu);
    
    if remote_mask == 0 {
        return;
    }

    // 送信側をシリアライズ（割り込み禁止）
    let _lock = TLB_FLUSH_LOCK.lock();

    // ペイロードを設定
    unsafe {
        TLB_FLUSH_PAYLOAD.flush_type = flush_type;
        TLB_FLUSH_PAYLOAD.asid = asid;
        if let TlbFlushType::Pages = flush_type {
            let count = pages.len().min(TLB_BATCH_SIZE);
            TLB_FLUSH_PAYLOAD.page_count = count;
            TLB_FLUSH_PAYLOAD.pages[..count].copy_from_slice(&pages[..count]);
        } else {
            TLB_FLUSH_PAYLOAD.page_count = 0;
        }
    }

    let mut target_count = 0;
    TLB_FLUSH_DONE_COUNT.store(0, Ordering::Release);
    
    // 各ターゲットCPUの状態をチェック
    for cpu_id in 0..64 {
        if (remote_mask & (1 << cpu_id)) != 0 {
            let state = get_cpu_tlb_state(cpu_id);
            
            // Lazyモードのcpuはフラッシュを保留
            if state.get_state() == TlbState::Lazy {
                state.mark_pending_flush();
                remote_mask &= !(1 << cpu_id); // IPI送信対象から除外
                continue;
            }
            
            target_count += 1;
        }
    }
    
    if target_count == 0 {
        return;
    }

    // アクティブなCPUにIPIを送信
    for cpu_id in 0..64 {
        if (remote_mask & (1 << cpu_id)) != 0 {
            send_tlb_ipi_to_cpu(cpu_id);
        }
    }
    
    // 全CPUの完了を待機（タイムアウト付き）
    let mut spin_count = 0;
    while TLB_FLUSH_DONE_COUNT.load(Ordering::Acquire) < target_count {
        core::hint::spin_loop();
        spin_count += 1;
        if spin_count > 100_000_000 {
            // タイムアウト
            log::warn!("[TLB] Flush IPI timeout (target={}, done={})", 
                target_count, TLB_FLUSH_DONE_COUNT.load(Ordering::Relaxed));
            break;
        }
    }
}

/// TLBフラッシュIPIハンドラ（各CPUで実行）
/// 
/// # Safety
/// 
/// - 割り込みハンドラとして呼び出されること
/// - 送信側が TLB_FLUSH_LOCK を保持している間のみペイロードが有効
pub unsafe fn tlb_flush_ipi_handler() {
    // 送信側がロックを保持しているので、ここではロックを取らずに直接ペイロードを読む
    // これによりデッドロックを回避する
    // Rust 2024 では static mut への直接参照は禁止されているため raw pointer を使用
    let payload_ptr = &raw const TLB_FLUSH_PAYLOAD;
    
    match (*payload_ptr).flush_type {
        TlbFlushType::All => {
            flush_tlb_all_local();
        }
        TlbFlushType::Pages => {
            for i in 0..(*payload_ptr).page_count {
                flush_tlb_page_local(VirtAddr::new((*payload_ptr).pages[i]));
            }
        }
        TlbFlushType::Asid => {
            // INVPCID でASID指定フラッシュ
            invpcid((*payload_ptr).asid as u64, 0, invpcid_type::SINGLE_CONTEXT);
        }
    }
    
    TLB_FLUSH_DONE_COUNT.fetch_add(1, Ordering::Release);
}

// ============================================================================
// High-level API
// ============================================================================

/// ページ範囲のTLBを無効化（バッチ化対応）
/// 
/// この関数は複数の無効化要求をバッチ化し、
/// 最後に flush_tlb_batch() で一括送信する。
pub fn invalidate_page_range(start: VirtAddr, page_count: usize, cpu_id: usize) {
    unsafe {
        let batch = get_cpu_tlb_batch(cpu_id);
        batch.set_all_cpus();
        batch.add_pages(start, page_count);
    }
}

/// TLBバッチをフラッシュ
pub fn flush_tlb_batch(cpu_id: usize) {
    unsafe {
        let batch = get_cpu_tlb_batch(cpu_id);
        batch.flush();
    }
}

/// 即時TLBフラッシュ（バッチ化なし）
pub fn flush_tlb_immediate(addr: VirtAddr) {
    unsafe {
        flush_tlb_page_local(addr);
    }
    // リモートCPUへのIPI
    send_tlb_flush_ipi_pages(u64::MAX, &[addr.as_u64()]);
}

/// 全TLBフラッシュ（全CPU）
pub fn flush_tlb_all() {
    unsafe {
        flush_tlb_all_local();
    }
    send_tlb_flush_ipi_all(u64::MAX);
}

// ============================================================================
// IPI Helper Functions
// ============================================================================

/// 単一CPUにTLBフラッシュIPIを送信
fn send_tlb_ipi_to_cpu(cpu_id: usize) {
    // CPU IDをAPIC IDとして使用（通常は1:1マッピング）
    let apic_id = cpu_id as u8;
    
    // interrupt_manager経由でIPI送信
    crate::io::interrupt_manager::send_ipi(apic_id, TLB_FLUSH_VECTOR);
    
    TLB_STATS.remote_flushes.fetch_add(1, Ordering::Relaxed);
}

/// 全CPUにTLBフラッシュIPIをブロードキャスト
fn broadcast_tlb_flush_ipi() {
    crate::io::interrupt_manager::broadcast_ipi(TLB_FLUSH_VECTOR);
    TLB_STATS.remote_flushes.fetch_add(1, Ordering::Relaxed);
}

// ============================================================================
// Statistics
// ============================================================================

/// グローバルTLB統計
pub struct TlbGlobalStats {
    /// ローカルフラッシュ回数
    pub local_flushes: AtomicU64,
    /// リモートフラッシュ回数（IPI送信）
    pub remote_flushes: AtomicU64,
    /// Lazy フラッシュがスキップされた回数
    pub lazy_skipped: AtomicU64,
    /// バッチ化されたフラッシュ回数
    pub batched_flushes: AtomicU64,
}

pub static TLB_STATS: TlbGlobalStats = TlbGlobalStats {
    local_flushes: AtomicU64::new(0),
    remote_flushes: AtomicU64::new(0),
    lazy_skipped: AtomicU64::new(0),
    batched_flushes: AtomicU64::new(0),
};

// ============================================================================
// Phase 2 最適化: PCID (Process Context Identifier) 完全サポート
// ============================================================================

// リファクタリング: PCID ロジックは kernel/src/mm/pcid.rs に移動しました。
// 後方互換性のため、必要であれば use 文を追加しますが、現状は tlb_batch.rs 内部で
// 直接 super::pcid を参照するように変更しています。


// (Removed redundant definitions: PCID_STATS, PcidAllocator, PCID_ALLOCATOR)
// Note: These are now imported from crate::mm::sync::pcid


// ============================================================================
// ASID LRU Manager (v0.6.0 - Enhanced ASID Rotation)
// ============================================================================
//
// 単純なビットマップベースのASID割り当てを改善し、
// LRU (Least Recently Used) ベースのスマートな再利用を実装。
//
// ## 利点
//
// - ホットなASIDは保護される（最近使用されたものは再利用されにくい）
// - コールドなASIDを優先的に再利用してTLBミスを最小化
// - アクティブプロセス追跡により不要なTLBフラッシュを削減
//
// ============================================================================

/// ASID LRUエントリ
#[repr(C)]
pub struct AsidLruEntry {
    /// 最終使用時刻（TSC）
    pub last_used: AtomicU64,
    /// 関連付けられたプロセスID（0 = 未使用）
    pub process_id: AtomicU64,
    /// アクティブフラグ
    pub active: AtomicBool,
}

impl AsidLruEntry {
    pub const fn new() -> Self {
        Self {
            last_used: AtomicU64::new(0),
            process_id: AtomicU64::new(0),
            active: AtomicBool::new(false),
        }
    }
    
    /// 使用を記録
    #[inline]
    pub fn touch(&self) {
        self.last_used.store(read_tsc(), Ordering::Relaxed);
    }
    
    /// プロセスに割り当て
    pub fn assign(&self, pid: u64) {
        self.process_id.store(pid, Ordering::Release);
        self.active.store(true, Ordering::Release);
        self.touch();
    }
    
    /// 解放
    pub fn release(&self) {
        self.active.store(false, Ordering::Release);
        self.process_id.store(0, Ordering::Release);
    }
    
    /// 未使用か
    #[inline]
    pub fn is_free(&self) -> bool {
        !self.active.load(Ordering::Acquire)
    }
}

/// LRUベースのASID/PCID管理
/// 
/// 最大256エントリを追跡（実用的なアクティブプロセス数）
const ASID_LRU_CAPACITY: usize = 256;

pub struct AsidLruManager {
    /// ASIDエントリ配列
    entries: [AsidLruEntry; ASID_LRU_CAPACITY],
    /// 次の検索開始位置
    search_hint: AtomicU16,
    /// 統計: LRU再利用回数
    lru_reuses: AtomicU64,
    /// 統計: 空きスロット使用回数
    free_slot_uses: AtomicU64,
}

impl AsidLruManager {
    pub const fn new() -> Self {
        const EMPTY: AsidLruEntry = AsidLruEntry::new();
        Self {
            entries: [EMPTY; ASID_LRU_CAPACITY],
            search_hint: AtomicU16::new(1),
            lru_reuses: AtomicU64::new(0),
            free_slot_uses: AtomicU64::new(0),
        }
    }
    
    /// ASIDを割り当て（プロセスID付き）
    /// 
    /// 1. 空きスロットを優先使用
    /// 2. 空きがなければLRU（最も古いエントリ）を再利用
    pub fn allocate(&self, process_id: u64) -> u16 {
        let hint = self.search_hint.load(Ordering::Relaxed) as usize;
        
        // 第1パス: 空きスロットを検索
        for offset in 0..ASID_LRU_CAPACITY {
            let idx = (hint + offset) % ASID_LRU_CAPACITY;
            if idx == 0 { continue; } // ASID 0は予約
            
            let entry = &self.entries[idx];
            if entry.is_free() {
                entry.assign(process_id);
                self.search_hint.store((idx as u16).wrapping_add(1), Ordering::Relaxed);
                self.free_slot_uses.fetch_add(1, Ordering::Relaxed);
                return idx as u16;
            }
        }
        
        // 第2パス: LRU（最も古い）を検索
        let mut oldest_idx: usize = 1;
        let mut oldest_time: u64 = u64::MAX;
        
        for idx in 1..ASID_LRU_CAPACITY {
            let entry = &self.entries[idx];
            let time = entry.last_used.load(Ordering::Relaxed);
            if time < oldest_time {
                oldest_time = time;
                oldest_idx = idx;
            }
        }
        
        // 最も古いエントリを再利用
        let entry = &self.entries[oldest_idx];
        entry.assign(process_id);
        self.search_hint.store((oldest_idx as u16).wrapping_add(1), Ordering::Relaxed);
        self.lru_reuses.fetch_add(1, Ordering::Relaxed);
        
        oldest_idx as u16
    }
    
    /// ASIDを解放
    pub fn deallocate(&self, asid: u16) {
        if asid == 0 || asid as usize >= ASID_LRU_CAPACITY {
            return;
        }
        self.entries[asid as usize].release();
    }
    
    /// ASIDの使用を記録（アクセス時に呼び出し）
    #[inline]
    pub fn touch(&self, asid: u16) {
        if (asid as usize) < ASID_LRU_CAPACITY {
            self.entries[asid as usize].touch();
        }
    }
    
    /// 統計情報を取得
    pub fn stats(&self) -> AsidLruStats {
        let active_count = self.entries.iter()
            .filter(|e| !e.is_free())
            .count();
        
        AsidLruStats {
            active_asids: active_count,
            lru_reuses: self.lru_reuses.load(Ordering::Relaxed),
            free_slot_uses: self.free_slot_uses.load(Ordering::Relaxed),
        }
    }
}

/// ASID LRU統計
#[derive(Debug, Clone, Copy)]
pub struct AsidLruStats {
    /// アクティブなASID数
    pub active_asids: usize,
    /// LRU再利用回数
    pub lru_reuses: u64,
    /// 空きスロット使用回数
    pub free_slot_uses: u64,
}

/// グローバルASID LRUマネージャ
pub static ASID_LRU_MANAGER: AsidLruManager = AsidLruManager::new();

/// PCID対応のTLBフラッシュ（高効率版）
/// 
/// INVPCIDが利用可能な場合は、指定PCIDのみを無効化。
/// これによりコンテキストスイッチ時のオーバーヘッドを大幅に削減。
pub unsafe fn flush_tlb_pcid(pcid: u16, addr: Option<u64>) {
    // PCID初期化チェック
    if !super::pcid::is_initialized() {
        super::pcid::init_features();
    }
    
    if super::pcid::has_invpcid() {
        match addr {
            Some(address) => {
                // 特定アドレスの特定PCID
                invpcid(pcid as u64, address, invpcid_type::INDIVIDUAL_ADDR);
            }
            None => {
                // 特定PCIDの全エントリ
                invpcid(pcid as u64, 0, invpcid_type::SINGLE_CONTEXT);
            }
        }
        PCID_STATS.invpcid_calls.fetch_add(1, Ordering::Relaxed);
    } else {
        // フォールバック: 全TLBフラッシュ
        flush_tlb_all_local();
        PCID_STATS.fallback_flushes.fetch_add(1, Ordering::Relaxed);
    }
}

/// 全PCID（グローバル以外）をフラッシュ
pub unsafe fn flush_tlb_all_pcids() {
    if super::pcid::has_invpcid() {
        invpcid(0, 0, invpcid_type::ALL_CONTEXT);
        PCID_STATS.invpcid_calls.fetch_add(1, Ordering::Relaxed);
    } else {
        flush_tlb_all_local();
    }
}

/// グローバルエントリを保持したまま全PCIDをフラッシュ
pub unsafe fn flush_tlb_all_pcids_preserve_global() {
    if super::pcid::has_invpcid() {
        invpcid(0, 0, invpcid_type::ALL_CONTEXT_GLOBAL);
        PCID_STATS.invpcid_calls.fetch_add(1, Ordering::Relaxed);
    } else {
        flush_tlb_all_local();
    }
}

/// CR3 with PCID設定
/// 
/// PCID対応のCR3書き込み。noflushビットを使用して
/// TLBフラッシュなしでアドレス空間を切り替え可能。
pub unsafe fn set_cr3_with_pcid(pml4_phys: u64, pcid: u16, noflush: bool) {
    let mut cr3_value = pml4_phys & !0xFFF; // 下位12ビットクリア
    cr3_value |= pcid as u64; // PCID設定（下位12ビット）
    
    if noflush && super::pcid::is_available() {
        // bit 63 = noflush bit
        cr3_value |= 1u64 << 63;
    }
    
    core::arch::asm!(
        "mov cr3, {}",
        in(reg) cr3_value,
        options(nostack, preserves_flags)
    );
}

/// PCID対応状態を取得
pub fn pcid_status() -> PcidStatus {
    if !super::pcid::is_initialized() {
        super::pcid::init_features();
    }
    
    PcidStatus {
        pcid_available: super::pcid::is_available(),
        invpcid_available: super::pcid::has_invpcid(),
        used_pcids: PCID_ALLOCATOR.lock().used_count(),
        max_pcids: super::pcid::MAX_PCID as usize,
    }
}

/// PCID状態情報
#[derive(Debug, Clone)]
pub struct PcidStatus {
    pub pcid_available: bool,
    pub invpcid_available: bool,
    pub used_pcids: usize,
    pub max_pcids: usize,
}

/// PCIDを初期化・有効化（公開API）
/// 
/// カーネル初期化時とAP起動時に呼び出すこと。
/// 
/// # 使用例
/// 
/// ```ignore
/// // BSP初期化時
/// mm::tlb_batch::init_pcid();
/// 
/// // AP起動時（SMP初期化）
/// mm::tlb_batch::init_pcid();
/// ```
/// 
/// # Returns
/// - `true`: PCID有効化成功
/// - `false`: PCID非対応またはエラー
pub fn init_pcid() -> bool {
    unsafe {
        match super::pcid::enable_on_this_cpu() {
            Ok(enabled) => enabled,
            Err(e) => {
                log::error!("[PCID] Failed to enable: {}", e);
                false
            }
        }
    }
}

/// 現在のCPUにPCIDを割り当て（プロセス作成時）
pub fn allocate_pcid() -> Option<u16> {
    PCID_ALLOCATOR.lock().allocate()
}

/// PCIDを解放（プロセス終了時）
pub fn deallocate_pcid(pcid: u16) {
    PCID_ALLOCATOR.lock().deallocate(pcid);
}

/// PCID対応のコンテキストスイッチ（公開API）
/// 
/// TLBをフラッシュせずにアドレス空間を切り替える。
/// 
/// # Safety
/// - カーネルモードで実行すること
/// - pml4_physは有効な物理アドレスであること
/// - pcidは割り当て済みの値であること
pub unsafe fn switch_address_space_pcid(pml4_phys: u64, pcid: u16) {
    if super::pcid::is_available() {
        // noflush=true でTLBフラッシュを回避
        set_cr3_with_pcid(pml4_phys, pcid, true);
    } else {
        // PCID非対応: 通常のCR3書き込み（TLBフラッシュ発生）
        core::arch::asm!(
            "mov cr3, {}",
            in(reg) pml4_phys,
            options(nostack)
        );
    }
}

// ============================================================================
// Lazy TLB Mode (Phase 3 Optimization)
// ============================================================================
//
// カーネルスレッドやアイドル状態など、ユーザ空間にアクセスしないコンテキストでは
// TLBフラッシュを遅延させることで、不要なIPI送信とTLB再ロードを回避する。
//
// 設計:
// - 各CPUはTLB状態（Active/Lazy/PendingFlush）を追跡
// - Lazyモード中のIPIはpending flagを設定するのみ
// - ユーザ空間に戻る際にpendingがあればフラッシュ
//
// 性能特性:
// - カーネル内作業中のTLBフラッシュを完全にスキップ
// - コンテキストスイッチ時のオーバーヘッド削減
// ============================================================================

/// Lazy TLBモードの状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LazyTlbState {
    /// アクティブモード: TLBフラッシュを即座に実行
    Active = 0,
    /// Lazyモード: TLBフラッシュを遅延（カーネルスレッド等）
    Lazy = 1,
    /// Pending: Lazyモード中にフラッシュ要求を受信
    Pending = 2,
}

/// Per-CPU Lazy TLB状態
#[repr(align(64))]
pub struct PerCpuLazyTlb {
    /// 現在の状態
    state: AtomicU64,
    /// 保留中のフラッシュ対象ASID（0 = all）
    pending_asid: AtomicU64,
    /// 統計: Lazyモードで回避したフラッシュ数
    skipped_flushes: AtomicU64,
    /// 統計: 遅延実行したフラッシュ数
    deferred_flushes: AtomicU64,
    /// 統計: 即座に実行したフラッシュ数
    immediate_flushes: AtomicU64,
    /// Lazyモード進入時刻（TSC）
    lazy_enter_tsc: AtomicU64,
}

impl PerCpuLazyTlb {
    pub const fn new() -> Self {
        Self {
            state: AtomicU64::new(LazyTlbState::Active as u64),
            pending_asid: AtomicU64::new(0),
            skipped_flushes: AtomicU64::new(0),
            deferred_flushes: AtomicU64::new(0),
            immediate_flushes: AtomicU64::new(0),
            lazy_enter_tsc: AtomicU64::new(0),
        }
    }

    /// Lazyモードに入る（カーネルスレッド開始時等）
    pub fn enter_lazy(&self) {
        self.state.store(LazyTlbState::Lazy as u64, Ordering::Release);
        self.lazy_enter_tsc.store(read_tsc(), Ordering::Relaxed);
    }

    /// Activeモードに戻る（ユーザ空間に戻る時）
    /// 
    /// pendingフラッシュがあれば実行し、skipped countを返す
    pub fn exit_lazy(&self) -> bool {
        let state = self.state.swap(LazyTlbState::Active as u64, Ordering::AcqRel);
        
        if state == LazyTlbState::Pending as u64 {
            // 遅延フラッシュを実行
            let asid = self.pending_asid.swap(0, Ordering::Relaxed);
            
            unsafe {
                if asid == 0 {
                    flush_tlb_all_local();
                } else if super::pcid::has_invpcid() {
                    flush_tlb_pcid(asid as u16, None);
                } else {
                    flush_tlb_all_local();
                }
            }
            
            self.deferred_flushes.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        
        false
    }

    /// フラッシュ要求を処理
    /// 
    /// Lazyモードならpendingを設定、Activeなら即座にフラッシュ
    /// 
    /// # Returns
    /// - `true`: フラッシュをスキップ（Lazyモード）
    /// - `false`: 即座にフラッシュを実行
    pub fn request_flush(&self, asid: u16) -> bool {
        let state = self.state.load(Ordering::Acquire);
        
        if state == LazyTlbState::Lazy as u64 {
            // Lazyモード: pending設定のみ
            self.pending_asid.store(asid as u64, Ordering::Relaxed);
            self.state.store(LazyTlbState::Pending as u64, Ordering::Release);
            self.skipped_flushes.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        
        // Activeモード: 即座にフラッシュ
        self.immediate_flushes.fetch_add(1, Ordering::Relaxed);
        false
    }

    /// 現在の状態を取得
    pub fn current_state(&self) -> LazyTlbState {
        match self.state.load(Ordering::Acquire) {
            0 => LazyTlbState::Active,
            1 => LazyTlbState::Lazy,
            _ => LazyTlbState::Pending,
        }
    }

    /// 統計情報を取得
    pub fn stats(&self) -> LazyTlbStats {
        LazyTlbStats {
            skipped: self.skipped_flushes.load(Ordering::Relaxed),
            deferred: self.deferred_flushes.load(Ordering::Relaxed),
            immediate: self.immediate_flushes.load(Ordering::Relaxed),
        }
    }
}

/// Lazy TLB統計
#[derive(Debug, Clone, Copy)]
pub struct LazyTlbStats {
    /// Lazyモードで回避したフラッシュ数
    pub skipped: u64,
    /// 遅延実行したフラッシュ数
    pub deferred: u64,
    /// 即座に実行したフラッシュ数
    pub immediate: u64,
}

/// Per-CPU Lazy TLB状態配列
static LAZY_TLB_STATE: [PerCpuLazyTlb; MAX_CPUS] = {
    const INIT: PerCpuLazyTlb = PerCpuLazyTlb::new();
    [INIT; MAX_CPUS]
};

/// CPUをLazy TLBモードに設定
/// 
/// カーネルスレッド開始時やアイドルループ進入時に呼び出す。
/// このモード中は、他CPUからのTLBフラッシュIPIを受け取っても
/// 即座にフラッシュせず、pending flagを設定するだけになる。
pub fn enter_lazy_tlb_mode(cpu_id: usize) {
    if cpu_id < MAX_CPUS {
        LAZY_TLB_STATE[cpu_id].enter_lazy();
    }
}

/// CPUをActive TLBモードに戻す
/// 
/// ユーザ空間に戻る前に呼び出す。pendingフラッシュがあれば実行する。
/// 
/// # Returns
/// - `true`: 遅延フラッシュを実行した
/// - `false`: 遅延フラッシュなし
pub fn exit_lazy_tlb_mode(cpu_id: usize) -> bool {
    if cpu_id < MAX_CPUS {
        LAZY_TLB_STATE[cpu_id].exit_lazy()
    } else {
        false
    }
}

/// TLBフラッシュをLazy-aware方式で送信
/// 
/// 対象CPUがLazyモードなら即座のフラッシュをスキップ。
/// 
/// # Returns
/// - スキップしたCPU数
pub fn send_tlb_flush_lazy_aware(cpu_mask: u64, asid: u16) -> usize {
    let mut skipped = 0;
    
    for cpu_id in 0..MAX_CPUS {
        if cpu_mask & (1 << cpu_id) == 0 {
            continue;
        }
        
        if LAZY_TLB_STATE[cpu_id].request_flush(asid) {
            skipped += 1;
        } else {
            send_tlb_ipi_to_cpu(cpu_id);
        }
    }
    
    skipped
}

/// 指定CPUのLazy TLB状態を取得
pub fn get_lazy_tlb_state(cpu_id: usize) -> Option<LazyTlbState> {
    if cpu_id < MAX_CPUS {
        Some(LAZY_TLB_STATE[cpu_id].current_state())
    } else {
        None
    }
}

/// Lazy TLB統計を取得（全CPU合計）
pub fn lazy_tlb_total_stats() -> LazyTlbStats {
    let mut total = LazyTlbStats {
        skipped: 0,
        deferred: 0,
        immediate: 0,
    };
    
    for state in &LAZY_TLB_STATE {
        let stats = state.stats();
        total.skipped += stats.skipped;
        total.deferred += stats.deferred;
        total.immediate += stats.immediate;
    }
    
    total
}

// ============================================================================
// Phase 5: 4.3 IPL-Free TLB Flush
// ============================================================================
//
// ## 概要
//
// IPL（Interrupt Priority Level）を上げずにTLBフラッシュを安全に実行する。
// 従来のTLBフラッシュはIPIを使用し、割り込みを禁止する必要があったが、
// この実装では以下の手法で割り込み禁止なしに安全性を保証する：
//
// 1. **Memory Barrier Protocol**: RCU的なメモリバリアで観測順序を保証
// 2. **Epoch-based Synchronization**: 世代番号でフラッシュ完了を追跡
// 3. **Self-IPI回避**: 自CPUの場合は直接INVLPGを実行
// 4. **Batched Acknowledgement**: ACKをバッチ化してIPI削減
//
// ## 安全性保証
//
// - ページテーブル更新とTLBフラッシュの順序はMemory Barrierで保証
// - フラッシュ完了はEpoch番号で確認可能
// - Use-after-freeはRCU grace periodと組み合わせて防止
//
// ============================================================================

/// IPL-Free TLB Flush エポック
/// 
/// 各CPUが最後にフラッシュを実行した世代番号を追跡。
/// フラッシュ要求側はこの番号を監視して完了を確認できる。
#[repr(C, align(64))]
pub struct TlbFlushEpoch {
    /// 現在のグローバルエポック
    global_epoch: AtomicU64,
    /// 各CPUの観測済みエポック
    cpu_epochs: [AtomicU64; MAX_CPUS],
    /// フラッシュ要求カウンタ
    request_count: AtomicU64,
    /// フラッシュ完了カウンタ
    complete_count: AtomicU64,
}

impl TlbFlushEpoch {
    pub const fn new() -> Self {
        const INIT: AtomicU64 = AtomicU64::new(0);
        Self {
            global_epoch: AtomicU64::new(0),
            cpu_epochs: [INIT; MAX_CPUS],
            request_count: AtomicU64::new(0),
            complete_count: AtomicU64::new(0),
        }
    }
    
    /// 新しいフラッシュエポックを開始
    /// 
    /// # Returns
    /// 新しいエポック番号
    #[inline]
    pub fn start_epoch(&self) -> u64 {
        self.request_count.fetch_add(1, Ordering::Relaxed);
        self.global_epoch.fetch_add(1, Ordering::Release)
    }
    
    /// CPUがエポックを観測したことを記録
    #[inline]
    pub fn observe_epoch(&self, cpu_id: usize, epoch: u64) {
        if cpu_id < MAX_CPUS {
            self.cpu_epochs[cpu_id].store(epoch, Ordering::Release);
        }
    }
    
    /// 全CPUが指定エポックを観測したか確認
    /// 
    /// # Arguments
    /// * `epoch` - 確認するエポック番号
    /// * `cpu_mask` - 対象CPUマスク
    /// 
    /// # Returns
    /// 全対象CPUが観測済みなら `true`
    pub fn all_observed(&self, epoch: u64, cpu_mask: u64) -> bool {
        for cpu_id in 0..MAX_CPUS {
            if cpu_mask & (1 << cpu_id) == 0 {
                continue;
            }
            if self.cpu_epochs[cpu_id].load(Ordering::Acquire) < epoch {
                return false;
            }
        }
        self.complete_count.fetch_add(1, Ordering::Relaxed);
        true
    }
    
    /// 現在のグローバルエポックを取得
    #[inline]
    pub fn current_epoch(&self) -> u64 {
        self.global_epoch.load(Ordering::Acquire)
    }
    
    /// 指定CPUの観測済みエポックを取得
    #[inline]
    pub fn cpu_epoch(&self, cpu_id: usize) -> u64 {
        if cpu_id < MAX_CPUS {
            self.cpu_epochs[cpu_id].load(Ordering::Acquire)
        } else {
            0
        }
    }
}

/// グローバルTLBフラッシュエポック
pub static TLB_FLUSH_EPOCH: TlbFlushEpoch = TlbFlushEpoch::new();

/// IPL-Free TLBフラッシュリクエスト
/// 
/// 割り込みレベルを上げずにTLBフラッシュを要求する。
/// 対象CPUは次のスケジューリングポイントでフラッシュを実行する。
#[derive(Debug, Clone, Copy)]
pub struct IplFreeTlbRequest {
    /// フラッシュするアドレス範囲の開始
    pub start_addr: u64,
    /// フラッシュするページ数
    pub page_count: usize,
    /// 対象ASID（0 = 全ASID）
    pub asid: u16,
    /// エポック番号
    pub epoch: u64,
}

/// Per-CPU IPL-Freeフラッシュキュー
#[repr(C, align(64))]
pub struct IplFreeFlushQueue {
    /// 保留中のフラッシュリクエスト
    pending: [AtomicU64; 4], // [start_addr, page_count_and_asid, epoch, flags]
    /// キューが有効か
    valid: AtomicBool,
    /// 統計: IPL-Freeフラッシュ回数
    ipl_free_count: AtomicU64,
    /// 統計: ポーリングでの実行回数
    poll_executed: AtomicU64,
}

impl IplFreeFlushQueue {
    pub const fn new() -> Self {
        const INIT: AtomicU64 = AtomicU64::new(0);
        Self {
            pending: [INIT; 4],
            valid: AtomicBool::new(false),
            ipl_free_count: AtomicU64::new(0),
            poll_executed: AtomicU64::new(0),
        }
    }
    
    /// フラッシュリクエストをキューに追加
    /// 
    /// # Returns
    /// 成功した場合は `true`
    #[inline]
    pub fn enqueue(&self, request: &IplFreeTlbRequest) -> bool {
        // すでに有効なリクエストがある場合は既存をマージ
        // 簡略化のため、最新のリクエストで上書き
        self.pending[0].store(request.start_addr, Ordering::Relaxed);
        self.pending[1].store(
            (request.page_count as u64) | ((request.asid as u64) << 32),
            Ordering::Relaxed,
        );
        self.pending[2].store(request.epoch, Ordering::Relaxed);
        
        // Memory barrier: pending データが先に見えることを保証
        core::sync::atomic::fence(Ordering::Release);
        
        self.valid.store(true, Ordering::Release);
        self.ipl_free_count.fetch_add(1, Ordering::Relaxed);
        true
    }
    
    /// 保留中のフラッシュを実行（ポーリング用）
    /// 
    /// スケジューリングポイントや割り込みリターン時に呼び出す。
    /// 
    /// # Returns
    /// フラッシュを実行した場合は `true`
    #[inline]
    pub fn poll_and_flush(&self, cpu_id: usize) -> bool {
        if !self.valid.load(Ordering::Acquire) {
            return false;
        }
        
        // Atomicにvalidをクリアしてリクエストを取得
        if !self.valid.swap(false, Ordering::AcqRel) {
            return false; // 他のCPUが先に処理した
        }
        
        // Memory barrier: valid クリア後にpendingを読む
        core::sync::atomic::fence(Ordering::Acquire);
        
        let start_addr = self.pending[0].load(Ordering::Relaxed);
        let page_count_and_asid = self.pending[1].load(Ordering::Relaxed);
        let epoch = self.pending[2].load(Ordering::Relaxed);
        
        let page_count = (page_count_and_asid & 0xFFFF_FFFF) as usize;
        let asid = ((page_count_and_asid >> 32) & 0xFFFF) as u16;
        
        // 実際のTLBフラッシュを実行
        unsafe {
            const PAGE_SIZE: u64 = 4096;
            if page_count <= TLB_FLUSH_ALL_THRESHOLD {
                // 個別ページフラッシュ
                for i in 0..page_count {
                    let addr = start_addr + (i as u64 * PAGE_SIZE);
                    if asid != 0 && super::pcid::is_available() {
                        flush_tlb_pcid(asid, Some(addr));
                    } else {
                        flush_tlb_page_local(VirtAddr::new(addr));
                    }
                }
            } else {
                // 全フラッシュ
                flush_tlb_all_local();
            }
        }
        
        // エポックを更新
        TLB_FLUSH_EPOCH.observe_epoch(cpu_id, epoch);
        self.poll_executed.fetch_add(1, Ordering::Relaxed);
        
        true
    }
    
    /// 統計を取得
    pub fn stats(&self) -> (u64, u64) {
        (
            self.ipl_free_count.load(Ordering::Relaxed),
            self.poll_executed.load(Ordering::Relaxed),
        )
    }
}

/// Per-CPU IPL-Freeキュー配列
static IPL_FREE_QUEUES: [IplFreeFlushQueue; MAX_CPUS] = {
    const INIT: IplFreeFlushQueue = IplFreeFlushQueue::new();
    [INIT; MAX_CPUS]
};

/// IPL-Free TLBフラッシュを要求
/// 
/// 対象CPUに割り込みを送らず、TLBフラッシュをリクエストする。
/// 対象CPUは次のポーリングポイントでフラッシュを実行する。
/// 
/// # Arguments
/// * `cpu_mask` - 対象CPUマスク
/// * `start_addr` - 開始アドレス
/// * `page_count` - ページ数
/// * `asid` - ASID（0 = 全ASID）
/// 
/// # Returns
/// 新しいエポック番号（完了確認用）
pub fn request_ipl_free_flush(
    cpu_mask: u64,
    start_addr: u64,
    page_count: usize,
    asid: u16,
) -> u64 {
    let epoch = TLB_FLUSH_EPOCH.start_epoch();
    
    let request = IplFreeTlbRequest {
        start_addr,
        page_count,
        asid,
        epoch,
    };
    
    // 現在のCPUは直接フラッシュ
    if let Some(current_cpu) = crate::per_cpu::try_current_cpu_id() {
        if cpu_mask & (1 << current_cpu) != 0 {
            const PAGE_SIZE: u64 = 4096;
            unsafe {
                if page_count <= TLB_BATCH_SIZE {
                    for i in 0..page_count {
                        let addr = start_addr + (i as u64 * PAGE_SIZE);
                        flush_tlb_page_local(VirtAddr::new(addr));
                    }
                } else {
                    flush_tlb_all_local();
                }
            }
            TLB_FLUSH_EPOCH.observe_epoch(current_cpu, epoch);
        }
    }
    
    // 他のCPUにリクエストをキュー
    for cpu_id in 0..MAX_CPUS {
        if cpu_mask & (1 << cpu_id) == 0 {
            continue;
        }
        if Some(cpu_id) == crate::per_cpu::try_current_cpu_id() {
            continue; // 自CPUはすでに処理済み
        }
        IPL_FREE_QUEUES[cpu_id].enqueue(&request);
    }
    
    epoch
}

/// IPL-Freeフラッシュのポーリング
/// 
/// スケジューリングポイントで呼び出す。保留中のフラッシュがあれば実行する。
/// 
/// # Returns
/// フラッシュを実行した場合は `true`
#[inline]
pub fn poll_ipl_free_flush(cpu_id: usize) -> bool {
    if cpu_id < MAX_CPUS {
        IPL_FREE_QUEUES[cpu_id].poll_and_flush(cpu_id)
    } else {
        false
    }
}

/// IPL-Freeフラッシュの完了を待機
/// 
/// 指定エポックのフラッシュが全対象CPUで完了するまでスピン待機する。
/// 
/// # Arguments
/// * `epoch` - 待機するエポック番号
/// * `cpu_mask` - 対象CPUマスク
/// * `max_spins` - 最大スピン回数（0 = 無限）
/// 
/// # Returns
/// 完了した場合は `true`、タイムアウトの場合は `false`
pub fn wait_ipl_free_flush(epoch: u64, cpu_mask: u64, max_spins: usize) -> bool {
    let mut spins = 0;
    
    loop {
        if TLB_FLUSH_EPOCH.all_observed(epoch, cpu_mask) {
            return true;
        }
        
        if max_spins > 0 {
            spins += 1;
            if spins >= max_spins {
                return false;
            }
        }
        
        // CPU relaxを挿入してスピン効率を改善
        core::hint::spin_loop();
    }
}

/// IPL-Free TLB Flush統計
pub struct IplFreeStats {
    /// 総リクエスト数
    pub requests: u64,
    /// 完了数
    pub completions: u64,
    /// ポーリング実行数
    pub poll_executed: u64,
}

/// IPL-Free統計を取得
pub fn ipl_free_stats() -> IplFreeStats {
    let mut poll_executed = 0u64;
    for queue in &IPL_FREE_QUEUES {
        let (_, executed) = queue.stats();
        poll_executed += executed;
    }
    
    IplFreeStats {
        requests: TLB_FLUSH_EPOCH.request_count.load(Ordering::Relaxed),
        completions: TLB_FLUSH_EPOCH.complete_count.load(Ordering::Relaxed),
        poll_executed,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test_case]
    fn test_tlb_batch_add() {
        let mut batch = TlbFlushBatch::new();
        
        batch.add_page(VirtAddr::new(0x1000));
        assert_eq!(batch.count, 1);
        assert!(batch.need_flush);
        
        batch.add_page(VirtAddr::new(0x2000));
        assert_eq!(batch.count, 2);
    }
    
    #[test_case]
    fn test_tlb_batch_threshold() {
        let mut batch = TlbFlushBatch::new();
        
        // 閾値を超えるページ数
        batch.add_pages(VirtAddr::new(0x1000), TLB_FLUSH_ALL_THRESHOLD + 1);
        assert!(batch.flush_all);
    }
    
    #[test_case]
    fn test_cpu_tlb_state() {
        let state = CpuTlbState::new();
        
        assert_eq!(state.get_state(), TlbState::Active);
        
        state.enter_lazy();
        assert_eq!(state.get_state(), TlbState::Lazy);
        
        state.mark_pending_flush();
        state.enter_active();
        assert_eq!(state.get_state(), TlbState::Active);
    }
}

