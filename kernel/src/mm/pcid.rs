// ============================================================================
// src/mm/pcid.rs - Process Context ID Management
// ============================================================================
//
// ## 概要
//
// PCID (Process Context Identifier) は、TLBエントリにタグ付けを行い、
// CR3書き換え（コンテキストスイッチ）時のTLB全フラッシュを回避する機能。
//
// This module provides:
// 1. PCID / INVPCID feature detection and enabling
// 2. PcidAllocator for managing limited PCID space (4096 IDs)
// 3. Helper functions for context switching with PCID
//
// ## 設計
//
// - PCID 0 is reserved for Kernel.
// - PCIDs 1-4095 are allocated to user processes.
// - Using a bitmap to track allocated PCIDs.
// - When PCID space is exhausted, we flush all TLBs and reset allocations (Simple approach)
//   or implement LRU eviction (Advanced).
//
// ## References
// - Intel SDM Vol. 3A 4.10.1 Process-Context Identifiers (PCIDs)
// ============================================================================

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use spin::Mutex;

/// 最大PCID数（12ビット = 4096）
pub const MAX_PCID: usize = 4096;
/// 予約済みPCID（カーネル用）
pub const KERNEL_PCID: u16 = 0;

/// PCID機能フラグ
static PCID_AVAILABLE: AtomicBool = AtomicBool::new(false);
static INVPCID_AVAILABLE: AtomicBool = AtomicBool::new(false);
static PCID_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// CR4.PCIDE ビット（bit 17）
const CR4_PCIDE: u64 = 1 << 17;

/// PCIDアロケータ
///
/// 4096個のIDをビットマップで管理する。
pub struct PcidAllocator {
    /// 割り当てビットマップ (4096 bits / 64 = 64 u64 words)
    map: [u64; MAX_PCID / 64],
    /// 次回探索開始位置（ラウンドロビン用）
    next_hint: usize,
    /// 使用中のPCID数
    used_count: usize,
    /// 世代番号（PCID空間が枯渇してフラッシュされた回数）
    generation: u64,
}

impl PcidAllocator {
    pub const fn new() -> Self {
        Self {
            map: [0; MAX_PCID / 64],
            next_hint: 1, // 0はカーネル予約
            used_count: 1, // カーネル分
            generation: 0,
        }
    }

    /// 初期化（カーネルPCIDを予約）
    pub fn init(&mut self) {
        self.map[0] |= 1; // PCID 0 is reserved
    }

    /// 新しいPCIDを割り当て
    /// 
    /// 空きがない場合は None を返す（呼び出し元で全フラッシュ等の対応が必要）
    pub fn allocate(&mut self) -> Option<u16> {
        if self.used_count >= MAX_PCID {
            return None;
        }

        // Hintから検索開始
        for i in 0..MAX_PCID {
            let idx = (self.next_hint + i) % MAX_PCID;
            if idx == 0 { continue; } // Skip kernel PCID

            let word_idx = idx / 64;
            let bit_idx = idx % 64;

            if (self.map[word_idx] & (1 << bit_idx)) == 0 {
                // Found free PCID
                self.map[word_idx] |= 1 << bit_idx;
                self.used_count += 1;
                self.next_hint = (idx + 1) % MAX_PCID;
                return Some(idx as u16);
            }
        }

        None
    }

    /// PCIDを解放
    pub fn deallocate(&mut self, pcid: u16) {
        if pcid == 0 { return; } // Cannot deallocate kernel PCID

        let idx = pcid as usize;
        let word_idx = idx / 64;
        let bit_idx = idx % 64;

        if (self.map[word_idx] & (1 << bit_idx)) != 0 {
            self.map[word_idx] &= !(1 << bit_idx);
            self.used_count -= 1;
        }
    }

    /// 全PCIDをリセット（空間枯渇時の対応）
    /// 
    /// 世代番号をインクリメントし、マップをクリアする。
    /// カーネルPCID(0)は維持される。
    pub fn reset_all(&mut self) {
        self.map.fill(0);
        self.map[0] = 1; // Reserve kernel PCID
        self.used_count = 1;
        self.next_hint = 1;
        self.generation += 1;
    }
    
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// 使用中のPCID数を取得
    pub fn used_count(&self) -> usize {
        self.used_count
    }
}

/// グローバルPCIDアロケータ
pub static PCID_ALLOCATOR: Mutex<PcidAllocator> = Mutex::new(PcidAllocator::new());

/// PCID機能を初期化
pub fn init_features() {
    if PCID_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    #[cfg(target_arch = "x86_64")]
    unsafe {
        // CPUID.01H:ECX.PCID[bit 17]
        let cpuid1 = core::arch::x86_64::__cpuid(1);
        let pcid = (cpuid1.ecx >> 17) & 1 != 0;
        PCID_AVAILABLE.store(pcid, Ordering::Release);
        
        // CPUID.07H:EBX.INVPCID[bit 10]
        let cpuid7 = core::arch::x86_64::__cpuid_count(7, 0);
        let invpcid = (cpuid7.ebx >> 10) & 1 != 0;
        INVPCID_AVAILABLE.store(invpcid, Ordering::Release);
    }
    
    PCID_INITIALIZED.store(true, Ordering::Release);
    
    // アロケータ初期化
    PCID_ALLOCATOR.lock().init();
}

/// PCIDが使用可能か
#[inline]
pub fn is_available() -> bool {
    PCID_AVAILABLE.load(Ordering::Relaxed)
}

/// INVPCIDが使用可能か
#[inline]
pub fn has_invpcid() -> bool {
    INVPCID_AVAILABLE.load(Ordering::Relaxed)
}

/// PCID機能が初期化済みか
#[inline]
pub fn is_initialized() -> bool {
    PCID_INITIALIZED.load(Ordering::Relaxed)
}

/// 現在のCPUでPCIDを有効化
///
/// # Safety
/// must be called in kernel mode with CR3 PCID 0
pub unsafe fn enable_on_this_cpu() -> Result<bool, &'static str> {
    if !is_available() {
        return Ok(false);
    }

    // Read CR4
    let cr4: u64;
    core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));

    if (cr4 & CR4_PCIDE) != 0 {
        return Ok(true); // Already enabled
    }

    // Enable CR4.PCIDE
    // Note: This operation requires CR3 to be PCID 0 (bits 0-11 must be 0)
    // which is the default for kernel page table.
    let new_cr4 = cr4 | CR4_PCIDE;
    core::arch::asm!("mov cr4, {}", in(reg) new_cr4, options(nostack, preserves_flags));

    Ok(true)
}

/// INVPCID命令ラッパー
///
/// # Safety
/// INVPCID instruction must be supported
#[inline]
pub unsafe fn invpcid(pcid: u16, addr: u64, type_: u64) {
    let descriptor: [u64; 2] = [pcid as u64, addr];
    core::arch::asm!(
        "invpcid {}, [{}]",
        in(reg) type_,
        in(reg) descriptor.as_ptr(),
        options(nostack, preserves_flags)
    );
}

/// INVPCIDタイプ定数
pub mod invpcid_types {
    /// 個別アドレス無効化
    pub const INDIVIDUAL_ADDR: u64 = 0;
    /// 単一コンテキスト無効化
    pub const SINGLE_CONTEXT: u64 = 1;
    /// 全コンテキスト無効化
    pub const ALL_CONTEXT: u64 = 2;
    /// グローバルページを除く全コンテキスト無効化
    pub const ALL_CONTEXT_GLOBAL: u64 = 3;
}

/// PCID統計
pub struct PcidStats {
    /// PCID割り当て回数
    pub allocations: AtomicU64,
    /// PCID解放回数
    pub deallocations: AtomicU64,
    /// PCIDサイクル（最大値到達後のリセット）回数
    pub cycles: AtomicU64,
    /// INVPCID使用回数
    pub invpcid_calls: AtomicU64,
    /// PCIDなしフォールバック回数
    pub fallback_flushes: AtomicU64,
}

impl PcidStats {
    pub const fn new() -> Self {
        Self {
            allocations: AtomicU64::new(0),
            deallocations: AtomicU64::new(0),
            cycles: AtomicU64::new(0),
            invpcid_calls: AtomicU64::new(0),
            fallback_flushes: AtomicU64::new(0),
        }
    }
}

/// グローバルPCID統計
pub static PCID_STATS: PcidStats = PcidStats::new();
