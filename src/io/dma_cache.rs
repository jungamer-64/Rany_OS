// ============================================================================
// src/io/dma_cache.rs - DMA Cache Coherency Management
// 設計書 5.4 改善: DMAとキャッシュの一貫性
//
// 課題:
// - 「単一アドレス空間」かつ「ゼロコピー」でDMAを行う場合、
//   CPUのキャッシュとメインメモリの整合性が問題になる
// - アプリケーションがバッファを読み書きする際、
//   CPUキャッシュに残った古いデータを見てしまう可能性
//
// 解決策:
// - x86_64ではハードウェアがコヒーレンシを管理するが、
//   PCIeデバイスとのやり取りには追加の対策が必要
// - 適切なメモリバリア（fence命令）
// - ページテーブルでの Write-Through / Uncacheable 設定
// - CLFLUSH/CLWB/CLFLUSHOPT 命令によるキャッシュ制御
// ============================================================================
#![allow(dead_code)]

use core::arch::asm;
use core::ptr::NonNull;
use x86_64::PhysAddr;
use x86_64::structures::paging::PageTableFlags;

/// キャッシュモード
///
/// x86_64 ページテーブルのPAT/PCD/PWTビットで制御される
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CacheMode {
    /// Write-Back (通常のキャッシュ)
    /// デフォルトモード。キャッシュライン単位でライトバック
    WriteBack = 0,

    /// Write-Through
    /// 書き込みは即座にメモリに反映、読み込みはキャッシュ可能
    WriteThrough = 1,

    /// Uncacheable (UC)
    /// キャッシュ完全無効。MMIO領域やDMAバッファに使用
    Uncacheable = 2,

    /// Write-Combining (WC)
    /// 書き込みを結合してバースト転送。グラフィックスメモリに最適
    WriteCombining = 3,

    /// Write-Protected (WP)
    /// 読み込みはキャッシュ、書き込みはスルー
    WriteProtected = 4,
}

impl CacheMode {
    /// ページテーブルフラグに変換
    pub fn to_page_flags(self) -> PageTableFlags {
        match self {
            CacheMode::WriteBack => PageTableFlags::empty(),
            CacheMode::WriteThrough => PageTableFlags::WRITE_THROUGH,
            CacheMode::Uncacheable => PageTableFlags::NO_CACHE | PageTableFlags::WRITE_THROUGH,
            CacheMode::WriteCombining => {
                // WCはPAT MSRの設定が必要
                // ここでは近似としてUCを使用
                PageTableFlags::NO_CACHE
            }
            CacheMode::WriteProtected => PageTableFlags::WRITE_THROUGH,
        }
    }
}

// ============================================================================
// キャッシュ制御命令
// ============================================================================

/// CLFLUSH: キャッシュラインをフラッシュ（無効化+書き戻し）
///
/// 指定アドレスを含むキャッシュラインをメモリに書き戻し、無効化する。
/// シリアライズ命令ではないため、前後にMFENCEが必要な場合がある。
#[inline(always)]
pub fn clflush(addr: *const u8) {
    unsafe {
        asm!(
            "clflush [{}]",
            in(reg) addr,
            options(nostack, preserves_flags)
        );
    }
}

/// CLFLUSHOPT: 最適化されたキャッシュラインフラッシュ
///
/// CLFLUSHより高速だが、順序保証が緩い。
/// 複数のキャッシュラインをフラッシュする場合に効率的。
#[inline(always)]
pub fn clflushopt(addr: *const u8) {
    unsafe {
        asm!(
            "clflushopt [{}]",
            in(reg) addr,
            options(nostack, preserves_flags)
        );
    }
}

/// CLWB: キャッシュラインを書き戻し（無効化なし）
///
/// キャッシュラインの内容をメモリに書き戻すが、キャッシュには残す。
/// 永続メモリ（Intel Optane等）との同期に使用。
#[inline(always)]
pub fn clwb(addr: *const u8) {
    unsafe {
        asm!(
            "clwb [{}]",
            in(reg) addr,
            options(nostack, preserves_flags)
        );
    }
}

/// MFENCE: メモリフェンス
///
/// 全てのロード/ストア操作が完了するまで待機。
/// DMA転送の前後で使用してメモリ一貫性を保証。
#[inline(always)]
pub fn mfence() {
    unsafe {
        asm!("mfence", options(nostack, preserves_flags));
    }
}

/// SFENCE: ストアフェンス
///
/// 全てのストア操作が完了するまで待機。
/// DMA転送開始前（CPU→デバイス）に使用。
#[inline(always)]
pub fn sfence() {
    unsafe {
        asm!("sfence", options(nostack, preserves_flags));
    }
}

/// LFENCE: ロードフェンス
///
/// 全てのロード操作が完了するまで待機。
/// DMA転送完了後（デバイス→CPU）に使用。
#[inline(always)]
pub fn lfence() {
    unsafe {
        asm!("lfence", options(nostack, preserves_flags));
    }
}

// ============================================================================
// キャッシュ範囲操作
// ============================================================================

/// キャッシュラインサイズ（x86_64では通常64バイト）
pub const CACHE_LINE_SIZE: usize = 64;

/// 指定範囲のキャッシュをフラッシュ
///
/// DMA転送開始前（CPU→デバイス）にCPUキャッシュの内容を
/// メインメモリに書き戻す。
pub fn flush_cache_range(addr: *const u8, size: usize) {
    let start = addr as usize;
    let end = start + size;

    // キャッシュライン境界にアライン
    let aligned_start = start & !(CACHE_LINE_SIZE - 1);

    let mut current = aligned_start;
    while current < end {
        clflushopt(current as *const u8);
        current += CACHE_LINE_SIZE;
    }

    // フラッシュ完了を待機
    sfence();
}

/// 指定範囲のキャッシュを無効化
///
/// DMA転送完了後（デバイス→CPU）にCPUキャッシュを無効化して、
/// 次回のアクセスでメインメモリから読み込むようにする。
pub fn invalidate_cache_range(addr: *const u8, size: usize) {
    // x86_64ではCLFLUSHが書き戻し+無効化を行う
    // 純粋な無効化は存在しないが、整合性は保証される
    flush_cache_range(addr, size);

    // 読み込み順序を保証
    lfence();
}

/// 指定範囲のキャッシュを書き戻し（無効化なし）
///
/// 永続メモリとの同期に使用。通常のDRAMには不要。
pub fn writeback_cache_range(addr: *const u8, size: usize) {
    let start = addr as usize;
    let end = start + size;
    let aligned_start = start & !(CACHE_LINE_SIZE - 1);

    let mut current = aligned_start;
    while current < end {
        clwb(current as *const u8);
        current += CACHE_LINE_SIZE;
    }

    sfence();
}

// ============================================================================
// DMA用メモリ属性管理
// ============================================================================

/// DMAメモリ属性
#[derive(Debug, Clone, Copy)]
pub struct DmaMemoryAttributes {
    /// キャッシュモード
    pub cache_mode: CacheMode,
    /// 物理連続性が必要か
    pub contiguous: bool,
    /// DMA方向
    pub direction: DmaDirection,
}

/// DMA転送方向
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaDirection {
    /// CPU → デバイス
    ToDevice,
    /// デバイス → CPU
    FromDevice,
    /// 双方向
    Bidirectional,
}

impl DmaMemoryAttributes {
    /// CPU→デバイス転送用のデフォルト属性
    pub const TO_DEVICE: Self = Self {
        cache_mode: CacheMode::WriteBack,
        contiguous: true,
        direction: DmaDirection::ToDevice,
    };

    /// デバイス→CPU転送用のデフォルト属性
    pub const FROM_DEVICE: Self = Self {
        cache_mode: CacheMode::WriteBack,
        contiguous: true,
        direction: DmaDirection::FromDevice,
    };

    /// MMIOマッピング用属性（アンキャッシュ）
    pub const MMIO: Self = Self {
        cache_mode: CacheMode::Uncacheable,
        contiguous: true,
        direction: DmaDirection::Bidirectional,
    };

    /// フレームバッファ用属性（Write-Combining）
    pub const FRAMEBUFFER: Self = Self {
        cache_mode: CacheMode::WriteCombining,
        contiguous: true,
        direction: DmaDirection::ToDevice,
    };
}

// ============================================================================
// キャッシュ一貫性保証付きDMAバッファ
// ============================================================================

use alloc::alloc::{Layout, alloc, dealloc};

/// キャッシュ一貫性を自動管理するDMAバッファ
///
/// - 転送開始時に自動でキャッシュフラッシュ
/// - 転送完了時に自動でキャッシュ無効化
/// - ページテーブル属性を適切に設定（オプション）
pub struct CoherentDmaBuffer {
    /// バッファポインタ
    ptr: NonNull<u8>,
    /// サイズ
    size: usize,
    /// レイアウト
    layout: Layout,
    /// 物理アドレス
    phys_addr: PhysAddr,
    /// メモリ属性
    attributes: DmaMemoryAttributes,
}

impl CoherentDmaBuffer {
    /// DMAアライメント（4KiB）
    const DMA_ALIGNMENT: usize = 4096;

    /// 新しいDMAバッファを割り当て
    pub fn new(size: usize, attributes: DmaMemoryAttributes) -> Option<Self> {
        let layout = Layout::from_size_align(size, Self::DMA_ALIGNMENT).ok()?;

        let ptr = unsafe { alloc(layout) };
        if ptr.is_null() {
            return None;
        }

        // ゼロで初期化
        unsafe {
            core::ptr::write_bytes(ptr, 0, size);
        }

        let phys_addr = PhysAddr::new(ptr as u64);

        Some(Self {
            ptr: unsafe { NonNull::new_unchecked(ptr) },
            size,
            layout,
            phys_addr,
            attributes,
        })
    }

    /// DMA転送を準備（CPU→デバイス）
    ///
    /// CPUキャッシュをフラッシュしてメモリ一貫性を保証。
    pub fn prepare_for_device(&self) {
        match self.attributes.direction {
            DmaDirection::ToDevice | DmaDirection::Bidirectional => {
                // CPUキャッシュをメインメモリに書き戻し
                flush_cache_range(self.ptr.as_ptr(), self.size);
            }
            DmaDirection::FromDevice => {
                // デバイスから受信する場合は不要
            }
        }
    }

    /// DMA転送完了を処理（デバイス→CPU）
    ///
    /// CPUキャッシュを無効化して、メインメモリからの読み込みを強制。
    pub fn finish_from_device(&self) {
        match self.attributes.direction {
            DmaDirection::FromDevice | DmaDirection::Bidirectional => {
                // CPUキャッシュを無効化
                invalidate_cache_range(self.ptr.as_ptr(), self.size);
            }
            DmaDirection::ToDevice => {
                // デバイスに送信する場合は不要
            }
        }
    }

    /// スライスとして取得
    ///
    /// # Safety
    /// DMA転送中に呼び出してはならない
    pub unsafe fn as_slice(&self) -> &[u8] { unsafe {
        core::slice::from_raw_parts(self.ptr.as_ptr(), self.size)
    }}

    /// 可変スライスとして取得
    ///
    /// # Safety
    /// DMA転送中に呼び出してはならない
    pub unsafe fn as_mut_slice(&mut self) -> &mut [u8] { unsafe {
        core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.size)
    }}

    /// 物理アドレスを取得（DMAエンジン用）
    pub fn phys_addr(&self) -> PhysAddr {
        self.phys_addr
    }

    /// サイズを取得
    pub fn size(&self) -> usize {
        self.size
    }
}

impl Drop for CoherentDmaBuffer {
    fn drop(&mut self) {
        unsafe {
            dealloc(self.ptr.as_ptr(), self.layout);
        }
    }
}

// Send は安全（バッファの所有権を別コアに転送可能）
unsafe impl Send for CoherentDmaBuffer {}

// ============================================================================
// ストリーミングDMA（高性能用）
// ============================================================================

/// ストリーミングDMAマッピング
///
/// 一時的なDMAマッピング。バッファを都度マップ/アンマップする。
/// 高頻度の小さな転送に適している。
pub struct StreamingDmaMapping<'a> {
    /// バッファへの参照
    buffer: &'a [u8],
    /// 物理アドレス
    phys_addr: PhysAddr,
    /// 転送方向
    direction: DmaDirection,
}

impl<'a> StreamingDmaMapping<'a> {
    /// 既存のバッファをDMAマッピング
    pub fn map(buffer: &'a [u8], direction: DmaDirection) -> Self {
        let phys_addr = PhysAddr::new(buffer.as_ptr() as u64);

        // マッピング時にキャッシュを同期
        match direction {
            DmaDirection::ToDevice | DmaDirection::Bidirectional => {
                flush_cache_range(buffer.as_ptr(), buffer.len());
            }
            DmaDirection::FromDevice => {
                // 何もしない
            }
        }

        Self {
            buffer,
            phys_addr,
            direction,
        }
    }

    /// 物理アドレスを取得
    pub fn phys_addr(&self) -> PhysAddr {
        self.phys_addr
    }

    /// サイズを取得
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// DMA転送完了を通知（Drop前に呼び出す）
    pub fn sync_for_cpu(&self) {
        match self.direction {
            DmaDirection::FromDevice | DmaDirection::Bidirectional => {
                invalidate_cache_range(self.buffer.as_ptr(), self.buffer.len());
            }
            DmaDirection::ToDevice => {
                // 何もしない
            }
        }
    }
}

impl<'a> Drop for StreamingDmaMapping<'a> {
    fn drop(&mut self) {
        // ドロップ時にも同期を保証
        self.sync_for_cpu();
    }
}

// ============================================================================
// IOMMU連携（追加の保護層）
// ============================================================================

/// IOMMUを使用したDMAアドレス変換
///
/// IOMMUが利用可能な場合、物理アドレスではなくIOVA（I/O仮想アドレス）を使用。
/// これにより、デバイスが不正なメモリにアクセスすることを防止。
pub struct IommuDmaBuffer {
    /// 内部バッファ
    inner: CoherentDmaBuffer,
    /// IOVA（IOMMUが有効な場合）
    iova: Option<u64>,
}

impl IommuDmaBuffer {
    /// 新しいIOMMU保護付きDMAバッファを割り当て
    pub fn new(size: usize, attributes: DmaMemoryAttributes) -> Option<Self> {
        let inner = CoherentDmaBuffer::new(size, attributes)?;

        // IOMMUマッピング（IOMMUが有効な場合）
        let iova = if crate::io::iommu::is_iommu_enabled() {
            crate::io::iommu::map_for_dma(inner.phys_addr(), size as u64).ok()
        } else {
            None
        };

        Some(Self { inner, iova })
    }

    /// デバイスに渡すアドレスを取得
    ///
    /// IOMMUが有効ならIOVA、無効なら物理アドレスを返す
    pub fn device_addr(&self) -> u64 {
        self.iova.unwrap_or(self.inner.phys_addr().as_u64())
    }

    /// DMA転送を準備
    pub fn prepare_for_device(&self) {
        self.inner.prepare_for_device();
    }

    /// DMA転送完了を処理
    pub fn finish_from_device(&self) {
        self.inner.finish_from_device();
    }
}

impl Drop for IommuDmaBuffer {
    fn drop(&mut self) {
        // IOMMUマッピングを解除
        if let Some(iova) = self.iova {
            let _ = crate::io::iommu::unmap_dma(iova, self.inner.size() as u64);
        }
    }
}

// ============================================================================
// CPU機能検出
// ============================================================================

/// CLFLUSHOPT命令のサポートを確認
pub fn supports_clflushopt() -> bool {
    // CPUID.07H:EBX.CLFLUSHOPT[bit 23]
    let result: u32;
    unsafe {
        asm!(
            "mov eax, 7",
            "xor ecx, ecx",
            "cpuid",
            "mov {}, ebx",
            out(reg) result,
            out("eax") _,
            out("ecx") _,
            out("edx") _,
            options(nostack, preserves_flags)
        );
    }
    (result & (1 << 23)) != 0
}

/// CLWB命令のサポートを確認
pub fn supports_clwb() -> bool {
    // CPUID.07H:EBX.CLWB[bit 24]
    let result: u32;
    unsafe {
        asm!(
            "mov eax, 7",
            "xor ecx, ecx",
            "cpuid",
            "mov {}, ebx",
            out(reg) result,
            out("eax") _,
            out("ecx") _,
            out("edx") _,
            options(nostack, preserves_flags)
        );
    }
    (result & (1 << 24)) != 0
}

/// キャッシュラインサイズを取得
pub fn cache_line_size() -> usize {
    // CPUID.01H:EBX[15:8] * 8
    let result: u32;
    unsafe {
        asm!(
            "mov eax, 1",
            "cpuid",
            "mov {}, ebx",
            out(reg) result,
            out("eax") _,
            out("ecx") _,
            out("edx") _,
            options(nostack, preserves_flags)
        );
    }
    (((result >> 8) & 0xFF) * 8) as usize
}
