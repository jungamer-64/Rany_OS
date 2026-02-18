// ============================================================================
// src/mm/zero_page.rs - 高速ゼロクリア戦略
// 
// ## 概要
// 
// ページのゼロクリアは頻繁に発生する操作だが、通常の memset は
// CPUキャッシュを汚染し、有効なデータを追い出してしまう。
// 
// ## 戦略
// 
// 1. **Non-Temporal (NT) Stores**: キャッシュをバイパスして直接メモリへ書き込み
// 2. **Zero-on-Free vs Zero-on-Idle**: 状況に応じた動的切り替え
// 3. **バックグラウンドスクラビング**: アイドル時にページをプリゼロ化
// 
// ## x86_64 命令
// 
// - MOVNTDQ: 128ビット Non-Temporal Store
// - MOVNTPS: 128ビット Non-Temporal Store (float)
// - SFENCE: Store Fence (NT Store完了を保証)
// 
// ## 参考
// 
// - Intel Optimization Manual: Non-Temporal Store Hints
// - Linux kernel: clear_page_nt(), clear_huge_page()
// ============================================================================
#![allow(dead_code)]

use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// ページサイズ定数
const PAGE_SIZE_4K: usize = 4096;
const PAGE_SIZE_2M: usize = 2 * 1024 * 1024;

/// Non-Temporal Storeが利用可能かどうか
/// CPUID で SSE2 をチェック（x86_64 では常に利用可能）
static NT_STORE_AVAILABLE: AtomicBool = AtomicBool::new(true);

/// ゼロクリア統計
pub struct ZeroPageStats {
    /// NT Storeでゼロクリアしたページ数
    pub nt_zeroed: AtomicU64,
    /// 通常のmemsetでゼロクリアしたページ数
    pub memset_zeroed: AtomicU64,
    /// バックグラウンドスクラブしたページ数
    pub scrubbed: AtomicU64,
    /// Zero-on-Freeで処理したページ数
    pub zero_on_free: AtomicU64,
    /// Zero-on-Allocで処理したページ数
    pub zero_on_alloc: AtomicU64,
}

impl ZeroPageStats {
    pub const fn new() -> Self {
        Self {
            nt_zeroed: AtomicU64::new(0),
            memset_zeroed: AtomicU64::new(0),
            scrubbed: AtomicU64::new(0),
            zero_on_free: AtomicU64::new(0),
            zero_on_alloc: AtomicU64::new(0),
        }
    }
}

/// グローバル統計
pub static ZERO_PAGE_STATS: ZeroPageStats = ZeroPageStats::new();

// ============================================================================
// Non-Temporal Store 実装
// ============================================================================

/// 4KBページをNon-Temporal Storeでゼロクリア
/// 
/// # Safety
/// 
/// - `addr` は有効な4KBアラインされたメモリ領域を指す必要がある
/// - 他のCPUが同時にこの領域にアクセスしていないこと
#[inline]
pub unsafe fn clear_page_nt(addr: *mut u8) {
    if !NT_STORE_AVAILABLE.load(Ordering::Relaxed) {
        clear_page_memset(addr);
        return;
    }
    
    // 16バイトアライメントチェック
    debug_assert!(addr as usize % 16 == 0, "Address must be 16-byte aligned for NT stores");
    
    // MOVNTDQ を使用して 128ビット（16バイト）ずつゼロクリア
    // 4KB / 16B = 256 iterations
    // アンロールして4つずつ処理（64バイト/iteration、キャッシュライン単位）
    let mut ptr = addr;
    let end = addr.add(PAGE_SIZE_4K);
    
    // XMM0 をゼロクリア
    asm!(
        "xorps xmm0, xmm0",
        options(nomem, nostack, preserves_flags)
    );
    
    while ptr < end {
        asm!(
            // 64バイト（1キャッシュライン）をゼロクリア
            "movntdq [{ptr}], xmm0",
            "movntdq [{ptr} + 16], xmm0",
            "movntdq [{ptr} + 32], xmm0",
            "movntdq [{ptr} + 48], xmm0",
            ptr = in(reg) ptr,
            options(nostack, preserves_flags)
        );
        ptr = ptr.add(64);
    }
    
    // SFENCE: NT Storeの完了を保証
    asm!("sfence", options(nostack, preserves_flags));
    
    ZERO_PAGE_STATS.nt_zeroed.fetch_add(1, Ordering::Relaxed);
}

/// 2MBページ（512 x 4KB）をNon-Temporal Storeでゼロクリア
/// 
/// # Safety
/// 
/// - `addr` は有効な2MBアラインされたメモリ領域を指す必要がある
#[inline]
pub unsafe fn clear_huge_page_nt(addr: *mut u8) {
    if !NT_STORE_AVAILABLE.load(Ordering::Relaxed) {
        clear_huge_page_memset(addr);
        return;
    }
    
    let mut ptr = addr;
    let end = addr.add(PAGE_SIZE_2M);
    
    // XMM0 をゼロクリア
    asm!(
        "xorps xmm0, xmm0",
        options(nomem, nostack, preserves_flags)
    );
    
    // より大きな単位でアンロール（256バイト/iteration）
    while ptr < end {
        asm!(
            // 256バイト（4キャッシュライン）をゼロクリア
            "movntdq [{ptr}], xmm0",
            "movntdq [{ptr} + 16], xmm0",
            "movntdq [{ptr} + 32], xmm0",
            "movntdq [{ptr} + 48], xmm0",
            "movntdq [{ptr} + 64], xmm0",
            "movntdq [{ptr} + 80], xmm0",
            "movntdq [{ptr} + 96], xmm0",
            "movntdq [{ptr} + 112], xmm0",
            "movntdq [{ptr} + 128], xmm0",
            "movntdq [{ptr} + 144], xmm0",
            "movntdq [{ptr} + 160], xmm0",
            "movntdq [{ptr} + 176], xmm0",
            "movntdq [{ptr} + 192], xmm0",
            "movntdq [{ptr} + 208], xmm0",
            "movntdq [{ptr} + 224], xmm0",
            "movntdq [{ptr} + 240], xmm0",
            ptr = in(reg) ptr,
            options(nostack, preserves_flags)
        );
        ptr = ptr.add(256);
    }
    
    asm!("sfence", options(nostack, preserves_flags));
    
    ZERO_PAGE_STATS.nt_zeroed.fetch_add(512, Ordering::Relaxed);
}

/// 通常の memset による4KBページゼロクリア（フォールバック）
/// 
/// # Safety
/// 
/// - `addr` は有効な4KBメモリ領域を指す必要がある
#[inline]
pub unsafe fn clear_page_memset(addr: *mut u8) {
    core::ptr::write_bytes(addr, 0, PAGE_SIZE_4K);
    ZERO_PAGE_STATS.memset_zeroed.fetch_add(1, Ordering::Relaxed);
}

/// 通常の memset による2MBページゼロクリア（フォールバック）
/// 
/// # Safety
/// 
/// - `addr` は有効な2MBメモリ領域を指す必要がある
#[inline]
pub unsafe fn clear_huge_page_memset(addr: *mut u8) {
    core::ptr::write_bytes(addr, 0, PAGE_SIZE_2M);
    ZERO_PAGE_STATS.memset_zeroed.fetch_add(512, Ordering::Relaxed);
}

// ============================================================================
// REP STOSQ 最適化版（小さいページ向け）
// ============================================================================

/// REP STOSQ を使用した高速ゼロクリア
/// 
/// 4KB未満の小さな領域や、NT Storeが効率的でない場合に使用。
/// CPU内部で最適化される。
/// 
/// # Safety
/// 
/// - `addr` は有効なメモリ領域を指す必要がある
/// - `size` は8の倍数であること
#[inline]
pub unsafe fn zero_memory_rep_stosq(addr: *mut u64, count: usize) {
    asm!(
        "rep stosq",
        inout("rdi") addr => _,
        inout("rcx") count => _,
        in("rax") 0u64,
        options(nostack, preserves_flags)
    );
}

/// ERMS対応: ERMSが有効かどうか（CPUID.07H:EBX.ERMS[bit 9]）
static ERMS_AVAILABLE: AtomicBool = AtomicBool::new(false);

/// ERMSの利用可能性をチェック
pub fn init_erms() {
    #[cfg(target_arch = "x86_64")]
    {
        // CPUID.07H:EBX.ERMS[bit 9]をチェック
        let cpuid_result = core::arch::x86_64::__cpuid_count(7, 0);
        let erms_supported = (cpuid_result.ebx >> 9) & 1 != 0;
        ERMS_AVAILABLE.store(erms_supported, Ordering::Release);
    }
}

/// ERMSが利用可能かどうか
#[inline]
pub fn has_erms() -> bool {
    ERMS_AVAILABLE.load(Ordering::Relaxed)
}

/// REP STOSB を使用した高速ゼロクリア（ERMS対応）
/// 
/// ERMS（Enhanced REP MOVSB/STOSB）が有効な場合、CPUはREP STOSBを
/// 内部で最適化し、大きなブロックに対して非常に効率的に動作する。
/// 特にIvy Bridge以降のIntel CPUで有効。
/// 
/// ## パフォーマンス特性
/// 
/// - 小さい領域（< 256バイト）: REP MOVSBは高速
/// - 中程度（256B-4KB）: ERMSにより内部でベクトル化
/// - 大きい領域（> 4KB）: NT Storeと同等以上の場合も
/// 
/// # Safety
/// 
/// - `addr` は有効なメモリ領域を指す必要がある
/// - `size` バイトが書き込み可能であること
#[inline]
pub unsafe fn zero_memory_rep_stosb(addr: *mut u8, size: usize) {
    asm!(
        "rep stosb",
        inout("rdi") addr => _,
        inout("rcx") size => _,
        in("al") 0u8,
        options(nostack, preserves_flags)
    );
}

/// ERMSを考慮した4KBページのゼロクリア
/// 
/// ERMSが有効な場合はREP STOSBを使用。NT Storeとほぼ同等の性能で、
/// キャッシュをウォームアップする利点がある（すぐにアクセスする場合）。
/// 
/// # Safety
/// 
/// - `addr` は有効な4KBアラインされたメモリ領域を指す必要がある
#[inline]
pub unsafe fn clear_page_erms(addr: *mut u8) {
    if has_erms() {
        zero_memory_rep_stosb(addr, PAGE_SIZE_4K);
    } else {
        // ERMSなしの場合はREP STOSQ（8バイト単位）
        zero_memory_rep_stosq(addr as *mut u64, PAGE_SIZE_4K / 8);
    }
    ZERO_PAGE_STATS.memset_zeroed.fetch_add(1, Ordering::Relaxed);
}

// ============================================================================
// ゼロクリア戦略の選択
// ============================================================================

/// ゼロクリア戦略
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZeroStrategy {
    /// Non-Temporal Store（大きなページ、キャッシュ汚染回避）
    NonTemporal,
    /// 通常の memset（小さな領域、キャッシュに残したい場合）
    Memset,
    /// REP STOSQ（中程度のサイズ）
    RepStosq,
    /// ゼロクリアしない（呼び出し側で対処）
    None,
}

/// ページサイズとコンテキストに基づいてゼロクリア戦略を選択
/// 
/// # 戦略選択基準
/// 
/// - 2MB以上: Non-Temporal（キャッシュ汚染が深刻）
/// - 4KB〜2MB: Non-Temporal（一般的なケース）
/// - 4KB未満: REP STOSQ or Memset
/// - 割り込みコンテキスト: Memset（FPUレジスタ使用不可）
pub fn choose_zero_strategy(size: usize, in_interrupt: bool) -> ZeroStrategy {
    if in_interrupt {
        // 割り込みコンテキストではXMMレジスタを使用できない
        return ZeroStrategy::Memset;
    }
    
    if size >= PAGE_SIZE_2M {
        ZeroStrategy::NonTemporal
    } else if size >= PAGE_SIZE_4K {
        ZeroStrategy::NonTemporal
    } else if size >= 64 && size % 8 == 0 {
        ZeroStrategy::RepStosq
    } else {
        ZeroStrategy::Memset
    }
}

/// 戦略に基づいてページをゼロクリア
/// 
/// # Safety
/// 
/// - `addr` は有効なアラインされたメモリ領域を指す必要がある
/// - `size` はページサイズ（4KB or 2MB）であること
pub unsafe fn zero_page_with_strategy(addr: *mut u8, size: usize, strategy: ZeroStrategy) {
    match strategy {
        ZeroStrategy::NonTemporal => {
            if size >= PAGE_SIZE_2M {
                clear_huge_page_nt(addr);
            } else {
                clear_page_nt(addr);
            }
        }
        ZeroStrategy::Memset => {
            core::ptr::write_bytes(addr, 0, size);
            ZERO_PAGE_STATS.memset_zeroed.fetch_add(
                (size / PAGE_SIZE_4K).max(1) as u64,
                Ordering::Relaxed
            );
        }
        ZeroStrategy::RepStosq => {
            zero_memory_rep_stosq(addr as *mut u64, size / 8);
        }
        ZeroStrategy::None => {}
    }
}

// ============================================================================
// Zero-on-Free / Zero-on-Alloc / Zero-on-Idle 制御
// ============================================================================

/// ゼロクリアポリシー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZeroPolicy {
    /// 解放時にゼロクリア（セキュリティ重視）
    ZeroOnFree,
    /// 割り当て時にゼロクリア（従来方式）
    ZeroOnAlloc,
    /// アイドル時にバックグラウンドでゼロクリア（ハイブリッド）
    ZeroOnIdle,
    /// ゼロクリアしない（信頼されたコンテキストのみ）
    NoZero,
}

/// 現在のゼロクリアポリシー
static CURRENT_ZERO_POLICY: AtomicU64 = AtomicU64::new(ZeroPolicy::ZeroOnIdle as u64);

/// ゼロクリアポリシーを設定
pub fn set_zero_policy(policy: ZeroPolicy) {
    CURRENT_ZERO_POLICY.store(policy as u64, Ordering::Release);
}

/// 現在のゼロクリアポリシーを取得
pub fn get_zero_policy() -> ZeroPolicy {
    match CURRENT_ZERO_POLICY.load(Ordering::Acquire) {
        0 => ZeroPolicy::ZeroOnFree,
        1 => ZeroPolicy::ZeroOnAlloc,
        2 => ZeroPolicy::ZeroOnIdle,
        _ => ZeroPolicy::NoZero,
    }
}

/// ページ解放時のゼロクリアを実行（ポリシーに従う）
/// 
/// # Safety
/// 
/// - `addr` は有効なページアラインされたメモリ領域を指す必要がある
pub unsafe fn zero_on_free_if_policy(addr: *mut u8, size: usize) -> bool {
    match get_zero_policy() {
        ZeroPolicy::ZeroOnFree => {
            let strategy = choose_zero_strategy(size, false);
            zero_page_with_strategy(addr, size, strategy);
            ZERO_PAGE_STATS.zero_on_free.fetch_add(1, Ordering::Relaxed);
            true
        }
        _ => false,
    }
}

/// ページ割り当て時のゼロクリアを実行（ポリシーに従う）
/// 
/// # Safety
/// 
/// - `addr` は有効なページアラインされたメモリ領域を指す必要がある
/// - `already_zeroed` が true の場合はスキップ
pub unsafe fn zero_on_alloc_if_needed(addr: *mut u8, size: usize, already_zeroed: bool) {
    if already_zeroed {
        return;
    }
    
    match get_zero_policy() {
        ZeroPolicy::ZeroOnAlloc | ZeroPolicy::ZeroOnIdle => {
            // ZeroOnIdleでも、プリゼロ化されていなければ割り当て時にゼロクリア
            let strategy = choose_zero_strategy(size, false);
            zero_page_with_strategy(addr, size, strategy);
            ZERO_PAGE_STATS.zero_on_alloc.fetch_add(1, Ordering::Relaxed);
        }
        _ => {}
    }
}

// ============================================================================
// バックグラウンドスクラビング
// ============================================================================

/// バックグラウンドスクラバー
/// 
/// アイドル時に空きページをゼロクリアし、割り当て時のレイテンシを削減。
pub struct BackgroundScrubber {
    /// 有効かどうか
    enabled: AtomicBool,
    /// スクラブ済みページ数
    scrubbed_pages: AtomicU64,
    /// 1回のスクラブサイクルでの最大ページ数
    max_pages_per_cycle: usize,
}

impl BackgroundScrubber {
    pub const fn new() -> Self {
        Self {
            enabled: AtomicBool::new(true),
            scrubbed_pages: AtomicU64::new(0),
            max_pages_per_cycle: 64, // 256KB per cycle
        }
    }
    
    /// スクラバーを有効/無効化
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Release);
    }
    
    /// スクラバーが有効かどうか
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }
    
    /// 1サイクル分のスクラビングを実行
    /// 
    /// # Safety
    /// 
    /// - 呼び出し側が適切なコンテキスト（アイドルスレッド等）で実行すること
    /// - `get_dirty_page` は有効な未ゼロクリアページを返すこと
    pub unsafe fn scrub_cycle<F, M>(&self, mut get_dirty_page: F, mut mark_zeroed: M) -> usize
    where
        F: FnMut() -> Option<*mut u8>,
        M: FnMut(*mut u8),
    {
        if !self.is_enabled() {
            return 0;
        }
        
        let mut scrubbed = 0;
        
        for _ in 0..self.max_pages_per_cycle {
            match get_dirty_page() {
                Some(addr) => {
                    // NT Storeでゼロクリア
                    clear_page_nt(addr);
                    mark_zeroed(addr);
                    scrubbed += 1;
                }
                None => break,
            }
        }
        
        if scrubbed > 0 {
            self.scrubbed_pages.fetch_add(scrubbed as u64, Ordering::Relaxed);
            ZERO_PAGE_STATS.scrubbed.fetch_add(scrubbed as u64, Ordering::Relaxed);
        }
        
        scrubbed
    }
    
    /// スクラブ済みページ数を取得
    pub fn scrubbed_count(&self) -> u64 {
        self.scrubbed_pages.load(Ordering::Relaxed)
    }
}

/// グローバルスクラバー
pub static BACKGROUND_SCRUBBER: BackgroundScrubber = BackgroundScrubber::new();

// ============================================================================
// PREFETCHNTA (Non-Temporal Prefetch)
// ============================================================================

/// Non-Temporal Prefetch
/// 
/// データをキャッシュのL1に持ってくるが、LRU的に「すぐ追い出される」
/// ヒントを付ける。一度だけ参照するデータの先読みに適している。
/// 
/// # Safety
/// 
/// - `addr` は有効なメモリ領域を指す必要がある
#[inline]
pub unsafe fn prefetch_nta(addr: *const u8) {
    asm!(
        "prefetchnta [{}]",
        in(reg) addr,
        options(nostack, preserves_flags)
    );
}

/// 複数キャッシュラインのNon-Temporal Prefetch
/// 
/// # Safety
/// 
/// - `addr` は有効なメモリ領域を指す必要がある
/// - `lines` は先読みするキャッシュライン数（64B単位）
#[inline]
pub unsafe fn prefetch_nta_range(addr: *const u8, lines: usize) {
    let mut ptr = addr;
    for _ in 0..lines {
        prefetch_nta(ptr);
        ptr = ptr.add(64);
    }
}

// ============================================================================
// Phase 1 最適化: NT Store + Prefetch 統合版
// ============================================================================

/// ゼロクリア統計（拡張版）
pub static NT_PREFETCH_STATS: NtPrefetchStats = NtPrefetchStats::new();

/// NT Store + Prefetch統合版の統計
pub struct NtPrefetchStats {
    /// NT + Prefetchでゼロクリアしたページ数
    pub nt_prefetch_zeroed: AtomicU64,
    /// プリフェッチ先行距離（キャッシュライン）
    pub prefetch_distance: AtomicU64,
}

impl NtPrefetchStats {
    pub const fn new() -> Self {
        Self {
            nt_prefetch_zeroed: AtomicU64::new(0),
            prefetch_distance: AtomicU64::new(8), // 8キャッシュライン = 512バイト先行
        }
    }
}

/// 4KBページをNT Store + Prefetchでゼロクリア（最適化版）
/// 
/// プリフェッチを使用してメモリレイテンシを隠蔽しつつ、
/// NT Storeでキャッシュ汚染を回避する。
/// 
/// ## 最適化手法
/// 
/// 1. 書き込み先を先行してプリフェッチ（prefetchnta）
/// 2. NT Store（movntdq）でキャッシュバイパス書き込み
/// 3. パイプライン化: プリフェッチと書き込みをオーバーラップ
/// 
/// ## パフォーマンス
/// 
/// - メモリレイテンシ隠蔽: プリフェッチが先行
/// - キャッシュ汚染回避: NT Storeでバイパス
/// - 帯域幅最大化: キャッシュライン単位の連続アクセス
/// 
/// # Safety
/// 
/// - `addr` は有効な4KBアラインされたメモリ領域を指す必要がある
/// - 他のCPUが同時にこの領域にアクセスしていないこと
#[inline]
pub unsafe fn clear_page_nt_prefetch(addr: *mut u8) {
    if !NT_STORE_AVAILABLE.load(Ordering::Relaxed) {
        clear_page_memset(addr);
        return;
    }
    
    // 16バイトアライメントチェック
    debug_assert!(addr as usize % 16 == 0, "Address must be 16-byte aligned");
    
    // プリフェッチ先行距離（キャッシュライン数）
    const PREFETCH_AHEAD: usize = 8; // 512バイト先行
    const CACHE_LINE_SIZE: usize = 64;
    
    // 4KB / 64B = 64 キャッシュライン
    const TOTAL_LINES: usize = PAGE_SIZE_4K / CACHE_LINE_SIZE;
    
    // XMM0 をゼロクリア
    asm!(
        "xorps xmm0, xmm0",
        options(nomem, nostack, preserves_flags)
    );
    
    let mut ptr = addr;
    
    // フェーズ1: 最初のPREFETCH_AHEADキャッシュラインをプリフェッチ
    for i in 0..PREFETCH_AHEAD.min(TOTAL_LINES) {
        asm!(
            "prefetchnta [{ptr}]",
            ptr = in(reg) addr.add(i * CACHE_LINE_SIZE),
            options(nostack, preserves_flags)
        );
    }
    
    // フェーズ2: プリフェッチと書き込みをパイプライン化
    for line in 0..TOTAL_LINES {
        // 先行プリフェッチ（境界チェック）
        let prefetch_line = line + PREFETCH_AHEAD;
        if prefetch_line < TOTAL_LINES {
            asm!(
                "prefetchnta [{ptr}]",
                ptr = in(reg) addr.add(prefetch_line * CACHE_LINE_SIZE),
                options(nostack, preserves_flags)
            );
        }
        
        // 現在のキャッシュラインをNT Storeでゼロクリア（64バイト = 4 x 16バイト）
        asm!(
            "movntdq [{ptr}], xmm0",
            "movntdq [{ptr} + 16], xmm0",
            "movntdq [{ptr} + 32], xmm0",
            "movntdq [{ptr} + 48], xmm0",
            ptr = in(reg) ptr,
            options(nostack, preserves_flags)
        );
        
        ptr = ptr.add(CACHE_LINE_SIZE);
    }
    
    // SFENCE: NT Storeの完了を保証
    asm!("sfence", options(nostack, preserves_flags));
    
    NT_PREFETCH_STATS.nt_prefetch_zeroed.fetch_add(1, Ordering::Relaxed);
    ZERO_PAGE_STATS.nt_zeroed.fetch_add(1, Ordering::Relaxed);
}

/// 2MBページをNT Store + Prefetchでゼロクリア（最適化版）
/// 
/// 大容量ページ向けに最適化。より積極的なプリフェッチ。
/// 
/// # Safety
/// 
/// - `addr` は有効な2MBアラインされたメモリ領域を指す必要がある
#[inline]
pub unsafe fn clear_huge_page_nt_prefetch(addr: *mut u8) {
    if !NT_STORE_AVAILABLE.load(Ordering::Relaxed) {
        clear_huge_page_memset(addr);
        return;
    }
    
    const PREFETCH_AHEAD: usize = 16; // 1KBバイト先行（大容量向け）
    const CACHE_LINE_SIZE: usize = 64;
    const TOTAL_LINES: usize = PAGE_SIZE_2M / CACHE_LINE_SIZE;
    
    // XMM0 をゼロクリア
    asm!(
        "xorps xmm0, xmm0",
        options(nomem, nostack, preserves_flags)
    );
    
    let mut ptr = addr;
    
    // 初期プリフェッチ
    for i in 0..PREFETCH_AHEAD.min(TOTAL_LINES) {
        asm!(
            "prefetchnta [{ptr}]",
            ptr = in(reg) addr.add(i * CACHE_LINE_SIZE),
            options(nostack, preserves_flags)
        );
    }
    
    // メインループ: 4キャッシュライン（256バイト）ずつ処理
    const UNROLL_FACTOR: usize = 4;
    for chunk in 0..(TOTAL_LINES / UNROLL_FACTOR) {
        let base_line = chunk * UNROLL_FACTOR;
        
        // 先行プリフェッチ
        for i in 0..UNROLL_FACTOR {
            let prefetch_line = base_line + PREFETCH_AHEAD + i;
            if prefetch_line < TOTAL_LINES {
                asm!(
                    "prefetchnta [{ptr}]",
                    ptr = in(reg) addr.add(prefetch_line * CACHE_LINE_SIZE),
                    options(nostack, preserves_flags)
                );
            }
        }
        
        // 4キャッシュライン（256バイト）をNT Storeでゼロクリア
        asm!(
            // Line 0
            "movntdq [{ptr}], xmm0",
            "movntdq [{ptr} + 16], xmm0",
            "movntdq [{ptr} + 32], xmm0",
            "movntdq [{ptr} + 48], xmm0",
            // Line 1
            "movntdq [{ptr} + 64], xmm0",
            "movntdq [{ptr} + 80], xmm0",
            "movntdq [{ptr} + 96], xmm0",
            "movntdq [{ptr} + 112], xmm0",
            // Line 2
            "movntdq [{ptr} + 128], xmm0",
            "movntdq [{ptr} + 144], xmm0",
            "movntdq [{ptr} + 160], xmm0",
            "movntdq [{ptr} + 176], xmm0",
            // Line 3
            "movntdq [{ptr} + 192], xmm0",
            "movntdq [{ptr} + 208], xmm0",
            "movntdq [{ptr} + 224], xmm0",
            "movntdq [{ptr} + 240], xmm0",
            ptr = in(reg) ptr,
            options(nostack, preserves_flags)
        );
        
        ptr = ptr.add(CACHE_LINE_SIZE * UNROLL_FACTOR);
    }
    
    // SFENCE: NT Storeの完了を保証
    asm!("sfence", options(nostack, preserves_flags));
    
    NT_PREFETCH_STATS.nt_prefetch_zeroed.fetch_add(512, Ordering::Relaxed);
    ZERO_PAGE_STATS.nt_zeroed.fetch_add(512, Ordering::Relaxed);
}

/// ゼロクリア戦略の選択（拡張版）- Prefetch版を優先
/// 
/// 大きなページではPrefetch統合版を使用してレイテンシを隠蔽
pub fn choose_zero_strategy_v2(size: usize, in_interrupt: bool, use_prefetch: bool) -> ZeroStrategy {
    if in_interrupt {
        return ZeroStrategy::Memset;
    }
    
    if use_prefetch && size >= PAGE_SIZE_4K {
        ZeroStrategy::NonTemporal // NT + Prefetch版を使用
    } else if size >= PAGE_SIZE_4K {
        ZeroStrategy::NonTemporal
    } else if size >= 64 && size % 8 == 0 {
        ZeroStrategy::RepStosq
    } else {
        ZeroStrategy::Memset
    }
}

/// Prefetch統合版でページをゼロクリア
/// 
/// # Safety
/// 
/// - `addr` は有効なアラインされたメモリ領域を指す必要がある
pub unsafe fn zero_page_with_prefetch(addr: *mut u8, size: usize) {
    if size >= PAGE_SIZE_2M {
        clear_huge_page_nt_prefetch(addr);
    } else if size >= PAGE_SIZE_4K {
        clear_page_nt_prefetch(addr);
    } else {
        // 小さい領域は従来方式
        let strategy = choose_zero_strategy(size, false);
        zero_page_with_strategy(addr, size, strategy);
    }
}

// ============================================================================
// テスト
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test_case]
    fn test_choose_zero_strategy() {
        assert_eq!(
            choose_zero_strategy(PAGE_SIZE_4K, false),
            ZeroStrategy::NonTemporal
        );
        assert_eq!(
            choose_zero_strategy(PAGE_SIZE_2M, false),
            ZeroStrategy::NonTemporal
        );
        assert_eq!(
            choose_zero_strategy(PAGE_SIZE_4K, true),
            ZeroStrategy::Memset
        );
        assert_eq!(
            choose_zero_strategy(64, false),
            ZeroStrategy::RepStosq
        );
        assert_eq!(
            choose_zero_strategy(32, false),
            ZeroStrategy::Memset
        );
    }
    
    #[test_case]
    fn test_zero_policy() {
        set_zero_policy(ZeroPolicy::ZeroOnFree);
        assert_eq!(get_zero_policy(), ZeroPolicy::ZeroOnFree);
        
        set_zero_policy(ZeroPolicy::ZeroOnIdle);
        assert_eq!(get_zero_policy(), ZeroPolicy::ZeroOnIdle);
    }
}

