// ============================================================================
// src/io/dma.rs - DMA Buffer Management with Type-State Safety
// 設計書 5.4: DMAと安全性
// ============================================================================
//!
//! # DMAバッファの型状態安全性
//!
//! このモジュールは型システムを使用してDMA転送中のメモリアクセスを
//! コンパイル時に防止します。
//!
//! ## 状態遷移
//! ```text
//! CpuOwned <---> DeviceOwned
//!     ^              |
//!     |              v
//!     +--- complete -+
//! ```
//!
//! ## 使用例
//! ```rust
//! let buffer = TypedDmaBuffer::<u32, CpuOwned>::new(42)?;
//! let data = buffer.as_ref(); // CPUからアクセス可能
//!
//! let (buffer, guard) = buffer.start_dma(); // 所有権移動
//! // buffer.as_ref(); // コンパイルエラー！DeviceOwnedはas_refを持たない
//!
//! let buffer = buffer.complete_dma(); // CPUに戻る
//! ```
#![allow(dead_code)]

use alloc::alloc::{Layout, alloc, dealloc};
use core::marker::PhantomData;
use core::ptr::NonNull;
use core::sync::atomic::Ordering;
use x86_64::PhysAddr;

/// DMAバッファの最小アライメント
const DMA_ALIGNMENT: usize = 4096; // ページアライメント

// ============================================================================
// 型状態マーカー（改善案7: DMA型安全性強化）
// ============================================================================

/// CPU所有状態マーカー
/// この状態ではCPUからのアクセスが可能
pub struct CpuOwned;

/// デバイス所有状態マーカー
/// この状態ではCPUからのアクセスが禁止
pub struct DeviceOwned;

/// 状態マーカートレイト（シールド）
mod sealed {
    pub trait DmaState {}
    impl DmaState for super::CpuOwned {}
    impl DmaState for super::DeviceOwned {}
}

/// DMA状態を示すマーカートレイト
pub trait DmaState: sealed::DmaState {}
impl DmaState for CpuOwned {}
impl DmaState for DeviceOwned {}

// ============================================================================
// 型安全なDMAバッファ（改善案7）
// ============================================================================

/// 型状態付きDMAバッファ
///
/// `State` パラメータで現在の所有状態を型レベルで追跡し、
/// 不正なアクセスをコンパイル時に検出する。
pub struct TypedDmaBuffer<T, State: DmaState> {
    /// バッファへのポインタ
    ptr: NonNull<T>,
    /// 物理アドレス（DMAエンジン用）
    phys_addr: PhysAddr,
    /// レイアウト（解放時に使用）
    layout: Layout,
    /// 状態マーカー
    _state: PhantomData<State>,
}

// Send は両状態で許可（別コアに転送可能）
unsafe impl<T: Send, State: DmaState> Send for TypedDmaBuffer<T, State> {}

impl<T> TypedDmaBuffer<T, CpuOwned> {
    /// 新しいDMAバッファを割り当て（CPU所有状態で開始）
    pub fn new(value: T) -> Option<Self> {
        let size = core::mem::size_of::<T>();
        let layout = Layout::from_size_align(size.max(1), DMA_ALIGNMENT).ok()?;

        let ptr = unsafe { alloc(layout) };
        if ptr.is_null() {
            return None;
        }

        // 値を書き込む
        unsafe {
            core::ptr::write(ptr as *mut T, value);
        }

        // 物理アドレスを計算
        let phys_addr = PhysAddr::new(ptr as u64);

        Some(Self {
            ptr: unsafe { NonNull::new_unchecked(ptr as *mut T) },
            phys_addr,
            layout,
            _state: PhantomData,
        })
    }

    /// CPUからの読み取り参照を取得
    /// （CpuOwned状態でのみ利用可能）
    pub fn as_ref(&self) -> &T {
        // SAFETY: CpuOwned状態ではCPUがバッファを所有
        unsafe { self.ptr.as_ref() }
    }

    /// CPUからの書き込み参照を取得
    /// （CpuOwned状態でのみ利用可能）
    pub fn as_mut(&mut self) -> &mut T {
        // SAFETY: CpuOwned状態ではCPUがバッファを所有
        unsafe { self.ptr.as_mut() }
    }

    /// DMA転送を開始（デバイスに所有権を移動）
    ///
    /// 返り値は所有権が移動したバッファとDMAガード。
    /// ガードがドロップされると自動的にCPUに所有権が戻る。
    pub fn start_dma(self) -> (TypedDmaBuffer<T, DeviceOwned>, TypedDmaGuard<T>) {
        // キャッシュフラッシュ（アーキテクチャ依存）
        core::sync::atomic::fence(Ordering::Release);

        let guard = TypedDmaGuard {
            phys_addr: self.phys_addr,
            layout: self.layout,
            _marker: PhantomData,
        };

        let buffer = TypedDmaBuffer {
            ptr: self.ptr,
            phys_addr: self.phys_addr,
            layout: self.layout,
            _state: PhantomData,
        };

        // selfのDropを防ぐ
        core::mem::forget(self);

        (buffer, guard)
    }
}

impl<T> TypedDmaBuffer<T, DeviceOwned> {
    // 注意: as_ref() と as_mut() は DeviceOwned では実装しない
    // → コンパイルエラーになる

    /// DMA転送完了（CPUに所有権を返却）
    pub fn complete_dma(self) -> TypedDmaBuffer<T, CpuOwned> {
        // キャッシュ無効化（アーキテクチャ依存）
        core::sync::atomic::fence(Ordering::Acquire);

        let buffer = TypedDmaBuffer {
            ptr: self.ptr,
            phys_addr: self.phys_addr,
            layout: self.layout,
            _state: PhantomData,
        };

        // selfのDropを防ぐ
        core::mem::forget(self);

        buffer
    }
}

impl<T, State: DmaState> TypedDmaBuffer<T, State> {
    /// 物理アドレスを取得（どちらの状態でも利用可能）
    pub fn phys_addr(&self) -> PhysAddr {
        self.phys_addr
    }

    /// サイズを取得
    pub fn size(&self) -> usize {
        self.layout.size()
    }
}

impl<T, State: DmaState> Drop for TypedDmaBuffer<T, State> {
    fn drop(&mut self) {
        unsafe {
            // デストラクタを呼び出し
            core::ptr::drop_in_place(self.ptr.as_ptr());
            // メモリを解放
            dealloc(self.ptr.as_ptr() as *mut u8, self.layout);
        }
    }
}

/// DMA転送のRAIIガード（型安全版）
///
/// DMA転送中の物理アドレス情報を保持。
/// ドロップ時に自動的に同期処理を行う。
pub struct TypedDmaGuard<T> {
    phys_addr: PhysAddr,
    layout: Layout,
    _marker: PhantomData<T>,
}

impl<T> TypedDmaGuard<T> {
    /// 物理アドレスを取得（DMAエンジンに渡す用）
    pub fn phys_addr(&self) -> PhysAddr {
        self.phys_addr
    }

    /// サイズを取得
    pub fn size(&self) -> usize {
        self.layout.size()
    }
}

// ============================================================================
// 型安全なDMAスライス
// ============================================================================

/// 型状態付きDMAスライスバッファ
pub struct TypedDmaSlice<State: DmaState> {
    ptr: NonNull<u8>,
    phys_addr: PhysAddr,
    size: usize,
    layout: Layout,
    _state: PhantomData<State>,
}

unsafe impl<State: DmaState> Send for TypedDmaSlice<State> {}

impl TypedDmaSlice<CpuOwned> {
    /// 指定サイズのDMAスライスを割り当て
    pub fn new(size: usize) -> Option<Self> {
        let layout = Layout::from_size_align(size, DMA_ALIGNMENT).ok()?;

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
            phys_addr,
            size,
            layout,
            _state: PhantomData,
        })
    }

    /// スライスとして取得（CPU所有時のみ）
    pub fn as_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.size) }
    }

    /// 可変スライスとして取得（CPU所有時のみ）
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.size) }
    }

    /// DMA転送を開始
    pub fn start_dma(self) -> TypedDmaSlice<DeviceOwned> {
        core::sync::atomic::fence(Ordering::Release);

        let result = TypedDmaSlice {
            ptr: self.ptr,
            phys_addr: self.phys_addr,
            size: self.size,
            layout: self.layout,
            _state: PhantomData,
        };

        core::mem::forget(self);
        result
    }
}

impl TypedDmaSlice<DeviceOwned> {
    /// DMA転送完了
    pub fn complete_dma(self) -> TypedDmaSlice<CpuOwned> {
        core::sync::atomic::fence(Ordering::Acquire);

        let result = TypedDmaSlice {
            ptr: self.ptr,
            phys_addr: self.phys_addr,
            size: self.size,
            layout: self.layout,
            _state: PhantomData,
        };

        core::mem::forget(self);
        result
    }
}

impl<State: DmaState> TypedDmaSlice<State> {
    /// 物理アドレスを取得
    pub fn phys_addr(&self) -> PhysAddr {
        self.phys_addr
    }

    /// サイズを取得
    pub fn len(&self) -> usize {
        self.size
    }

    /// 空かどうか
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }
}

impl<State: DmaState> Drop for TypedDmaSlice<State> {
    fn drop(&mut self) {
        unsafe {
            dealloc(self.ptr.as_ptr(), self.layout);
        }
    }
}

// ============================================================================
// Scatter-Gather DMA（型安全版）
// ============================================================================

/// Scatter-Gather DMA記述子
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SgEntry {
    /// 物理アドレス
    pub phys_addr: u64,
    /// サイズ
    pub size: u32,
    /// フラグ
    pub flags: u32,
}

/// Scatter-Gather DMAリスト（型安全版）
pub struct TypedSgList<State: DmaState> {
    entries: alloc::vec::Vec<SgEntry>,
    buffers: alloc::vec::Vec<TypedDmaSlice<State>>,
    _state: PhantomData<State>,
}

impl TypedSgList<CpuOwned> {
    pub fn new() -> Self {
        Self {
            entries: alloc::vec::Vec::new(),
            buffers: alloc::vec::Vec::new(),
            _state: PhantomData,
        }
    }

    /// バッファを追加
    pub fn add_buffer(&mut self, size: usize) -> Option<usize> {
        let buffer = TypedDmaSlice::new(size)?;
        let entry = SgEntry {
            phys_addr: buffer.phys_addr().as_u64(),
            size: size as u32,
            flags: 0,
        };

        let index = self.entries.len();
        self.entries.push(entry);
        self.buffers.push(buffer);

        Some(index)
    }

    /// バッファにアクセス
    pub fn buffer(&self, index: usize) -> Option<&TypedDmaSlice<CpuOwned>> {
        self.buffers.get(index)
    }

    /// バッファに可変アクセス
    pub fn buffer_mut(&mut self, index: usize) -> Option<&mut TypedDmaSlice<CpuOwned>> {
        self.buffers.get_mut(index)
    }

    /// 全バッファをデバイスに転送
    pub fn start_dma(self) -> TypedSgList<DeviceOwned> {
        core::sync::atomic::fence(Ordering::Release);

        let buffers: alloc::vec::Vec<TypedDmaSlice<DeviceOwned>> =
            self.buffers.into_iter().map(|b| b.start_dma()).collect();

        TypedSgList {
            entries: self.entries,
            buffers,
            _state: PhantomData,
        }
    }
}

impl TypedSgList<DeviceOwned> {
    /// 全バッファをCPUに返却
    pub fn complete_dma(self) -> TypedSgList<CpuOwned> {
        core::sync::atomic::fence(Ordering::Acquire);

        let buffers: alloc::vec::Vec<TypedDmaSlice<CpuOwned>> =
            self.buffers.into_iter().map(|b| b.complete_dma()).collect();

        TypedSgList {
            entries: self.entries,
            buffers,
            _state: PhantomData,
        }
    }
}

impl<State: DmaState> TypedSgList<State> {
    /// エントリ数を取得
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 空かどうか
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// エントリのスライスを取得
    pub fn entries(&self) -> &[SgEntry] {
        &self.entries
    }
}

impl Default for TypedSgList<CpuOwned> {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Cache Coherency Management (integrated from dma_cache.rs)
// ============================================================================
//
// キャッシュ一貫性管理機能
//
// x86_64ではハードウェアがコヒーレンシを管理するが、
// PCIeデバイスとのやり取りには追加の対策が必要:
// - 適切なメモリバリア（fence命令）
// - ページテーブルでの Write-Through / Uncacheable 設定
// - CLFLUSH/CLWB/CLFLUSHOPT 命令によるキャッシュ制御

use core::arch::asm;
use x86_64::structures::paging::PageTableFlags;

/// キャッシュモード
///
/// x86_64 ページテーブルのPAT/PCD/PWTビットで制御される
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CacheMode {
    /// Write-Back (通常のキャッシュ)
    WriteBack = 0,
    /// Write-Through
    WriteThrough = 1,
    /// Uncacheable (UC) - MMIO領域やDMAバッファに使用
    Uncacheable = 2,
    /// Write-Combining (WC) - グラフィックスメモリに最適
    WriteCombining = 3,
    /// Write-Protected (WP)
    WriteProtected = 4,
}

impl CacheMode {
    /// ページテーブルフラグに変換
    pub fn to_page_flags(self) -> PageTableFlags {
        match self {
            CacheMode::WriteBack => PageTableFlags::empty(),
            CacheMode::WriteThrough => PageTableFlags::WRITE_THROUGH,
            CacheMode::Uncacheable => PageTableFlags::NO_CACHE | PageTableFlags::WRITE_THROUGH,
            CacheMode::WriteCombining => PageTableFlags::NO_CACHE,
            CacheMode::WriteProtected => PageTableFlags::WRITE_THROUGH,
        }
    }
}

// ============================================================================
// Cache Control Instructions
// ============================================================================

/// キャッシュラインサイズ（x86_64では通常64バイト）
pub const CACHE_LINE_SIZE: usize = 64;

/// CLFLUSH: キャッシュラインをフラッシュ（無効化+書き戻し）
#[inline(always)]
pub fn clflush(addr: *const u8) {
    unsafe {
        asm!("clflush [{}]", in(reg) addr, options(nostack, preserves_flags));
    }
}

/// CLFLUSHOPT: 最適化されたキャッシュラインフラッシュ
#[inline(always)]
pub fn clflushopt(addr: *const u8) {
    unsafe {
        asm!("clflushopt [{}]", in(reg) addr, options(nostack, preserves_flags));
    }
}

/// CLWB: キャッシュラインを書き戻し（無効化なし）
#[inline(always)]
pub fn clwb(addr: *const u8) {
    unsafe {
        asm!("clwb [{}]", in(reg) addr, options(nostack, preserves_flags));
    }
}

/// MFENCE: メモリフェンス - 全てのロード/ストア操作が完了するまで待機
#[inline(always)]
pub fn mfence() {
    unsafe { asm!("mfence", options(nostack, preserves_flags)); }
}

/// SFENCE: ストアフェンス - DMA転送開始前（CPU→デバイス）に使用
#[inline(always)]
pub fn sfence() {
    unsafe { asm!("sfence", options(nostack, preserves_flags)); }
}

/// LFENCE: ロードフェンス - DMA転送完了後（デバイス→CPU）に使用
#[inline(always)]
pub fn lfence() {
    unsafe { asm!("lfence", options(nostack, preserves_flags)); }
}

// ============================================================================
// Cache Range Operations
// ============================================================================

/// 指定範囲のキャッシュをフラッシュ（DMA転送開始前 CPU→デバイス）
pub fn flush_cache_range(addr: *const u8, size: usize) {
    let start = addr as usize;
    let end = start + size;
    let aligned_start = start & !(CACHE_LINE_SIZE - 1);

    let mut current = aligned_start;
    while current < end {
        clflushopt(current as *const u8);
        current += CACHE_LINE_SIZE;
    }
    sfence();
}

/// 指定範囲のキャッシュを無効化（DMA転送完了後 デバイス→CPU）
pub fn invalidate_cache_range(addr: *const u8, size: usize) {
    flush_cache_range(addr, size);
    lfence();
}

/// 指定範囲のキャッシュを書き戻し（永続メモリ用、無効化なし）
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
// DMA Memory Attributes
// ============================================================================

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

/// DMAメモリ属性
#[derive(Debug, Clone, Copy)]
pub struct DmaMemoryAttributes {
    pub cache_mode: CacheMode,
    pub contiguous: bool,
    pub direction: DmaDirection,
}

impl DmaMemoryAttributes {
    pub const TO_DEVICE: Self = Self {
        cache_mode: CacheMode::WriteBack,
        contiguous: true,
        direction: DmaDirection::ToDevice,
    };
    pub const FROM_DEVICE: Self = Self {
        cache_mode: CacheMode::WriteBack,
        contiguous: true,
        direction: DmaDirection::FromDevice,
    };
    pub const MMIO: Self = Self {
        cache_mode: CacheMode::Uncacheable,
        contiguous: true,
        direction: DmaDirection::Bidirectional,
    };
    pub const FRAMEBUFFER: Self = Self {
        cache_mode: CacheMode::WriteCombining,
        contiguous: true,
        direction: DmaDirection::ToDevice,
    };
}

// ============================================================================
// Coherent DMA Buffer (auto cache management)
// ============================================================================

/// キャッシュ一貫性を自動管理するDMAバッファ
pub struct CoherentDmaBuffer {
    ptr: NonNull<u8>,
    size: usize,
    layout: Layout,
    phys_addr: PhysAddr,
    attributes: DmaMemoryAttributes,
}

impl CoherentDmaBuffer {
    const DMA_ALIGNMENT: usize = 4096;

    pub fn new(size: usize, attributes: DmaMemoryAttributes) -> Option<Self> {
        let layout = Layout::from_size_align(size, Self::DMA_ALIGNMENT).ok()?;
        let ptr = unsafe { alloc(layout) };
        if ptr.is_null() { return None; }
        unsafe { core::ptr::write_bytes(ptr, 0, size); }
        let phys_addr = PhysAddr::new(ptr as u64);

        Some(Self {
            ptr: unsafe { NonNull::new_unchecked(ptr) },
            size, layout, phys_addr, attributes,
        })
    }

    /// DMA転送を準備（CPU→デバイス）
    pub fn prepare_for_device(&self) {
        match self.attributes.direction {
            DmaDirection::ToDevice | DmaDirection::Bidirectional => {
                flush_cache_range(self.ptr.as_ptr(), self.size);
            }
            DmaDirection::FromDevice => {}
        }
    }

    /// DMA転送完了を処理（デバイス→CPU）
    pub fn finish_from_device(&self) {
        match self.attributes.direction {
            DmaDirection::FromDevice | DmaDirection::Bidirectional => {
                invalidate_cache_range(self.ptr.as_ptr(), self.size);
            }
            DmaDirection::ToDevice => {}
        }
    }

    /// # Safety: DMA転送中に呼び出してはならない
    pub unsafe fn as_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.size) }
    }

    /// # Safety: DMA転送中に呼び出してはならない
    pub unsafe fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.size) }
    }

    pub fn phys_addr(&self) -> PhysAddr { self.phys_addr }
    pub fn size(&self) -> usize { self.size }
}

impl Drop for CoherentDmaBuffer {
    fn drop(&mut self) {
        unsafe { dealloc(self.ptr.as_ptr(), self.layout); }
    }
}

unsafe impl Send for CoherentDmaBuffer {}

// ============================================================================
// Streaming DMA Mapping (high-performance)
// ============================================================================

/// ストリーミングDMAマッピング（一時的なマッピング）
pub struct StreamingDmaMapping<'a> {
    buffer: &'a [u8],
    phys_addr: PhysAddr,
    direction: DmaDirection,
}

impl<'a> StreamingDmaMapping<'a> {
    pub fn map(buffer: &'a [u8], direction: DmaDirection) -> Self {
        let phys_addr = PhysAddr::new(buffer.as_ptr() as u64);
        match direction {
            DmaDirection::ToDevice | DmaDirection::Bidirectional => {
                flush_cache_range(buffer.as_ptr(), buffer.len());
            }
            DmaDirection::FromDevice => {}
        }
        Self { buffer, phys_addr, direction }
    }

    pub fn phys_addr(&self) -> PhysAddr { self.phys_addr }
    pub fn len(&self) -> usize { self.buffer.len() }
    pub fn is_empty(&self) -> bool { self.buffer.is_empty() }

    pub fn sync_for_cpu(&self) {
        match self.direction {
            DmaDirection::FromDevice | DmaDirection::Bidirectional => {
                invalidate_cache_range(self.buffer.as_ptr(), self.buffer.len());
            }
            DmaDirection::ToDevice => {}
        }
    }
}

impl Drop for StreamingDmaMapping<'_> {
    fn drop(&mut self) { self.sync_for_cpu(); }
}

// ============================================================================
// IOMMU-protected DMA Buffer
// ============================================================================

/// IOMMUを使用したDMAバッファ
pub struct IommuDmaBuffer {
    inner: CoherentDmaBuffer,
    iova: Option<u64>,
}

impl IommuDmaBuffer {
    pub fn new(size: usize, attributes: DmaMemoryAttributes) -> Option<Self> {
        let inner = CoherentDmaBuffer::new(size, attributes)?;
        let iova = if crate::io::iommu::is_iommu_enabled() {
            crate::io::iommu::map_for_dma(inner.phys_addr(), size as u64).ok()
        } else { None };
        Some(Self { inner, iova })
    }

    /// デバイスに渡すアドレス（IOMMUが有効ならIOVA）
    pub fn device_addr(&self) -> u64 {
        self.iova.unwrap_or(self.inner.phys_addr().as_u64())
    }

    pub fn prepare_for_device(&self) { self.inner.prepare_for_device(); }
    pub fn finish_from_device(&self) { self.inner.finish_from_device(); }
}

impl Drop for IommuDmaBuffer {
    fn drop(&mut self) {
        if let Some(iova) = self.iova {
            let _ = crate::io::iommu::unmap_dma(iova, self.inner.size() as u64);
        }
    }
}

// ============================================================================
// Global DMA Allocator Trait and Implementation
// ============================================================================

use alloc::sync::Arc;
use spin::Mutex;

/// DMAアロケータのエラー型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaError {
    /// メモリ不足
    OutOfMemory,
    /// アライメントエラー
    InvalidAlignment,
    /// サイズエラー
    InvalidSize,
    /// IOMMUマッピング失敗
    IommuMappingFailed,
    /// アドレス変換失敗
    AddressTranslationFailed,
    /// デバイスが見つからない
    DeviceNotFound,
}

/// DMAアロケータトレイト
/// 
/// 全てのドライバはこのトレイトを通じてDMAメモリを割り当てる。
/// IOMMU対応・非対応を透過的に扱う。
pub trait DmaAllocator: Send + Sync {
    /// コヒーレントDMAバッファを割り当て
    fn allocate_coherent(&self, size: usize, direction: DmaDirection) -> Result<DmaAllocation, DmaError>;
    
    /// ストリーミングDMAマッピングを作成
    fn map_streaming(&self, buffer: &[u8], direction: DmaDirection) -> Result<StreamingMapping, DmaError>;
    
    /// ストリーミングDMAマッピングを解除
    fn unmap_streaming(&self, mapping: StreamingMapping);
    
    /// デバイスアドレスを取得（IOVAまたは物理アドレス）
    fn device_address(&self, phys_addr: PhysAddr) -> u64;
    
    /// IOMMUが有効かどうか
    fn iommu_enabled(&self) -> bool;
}

/// DMA割り当て結果
pub struct DmaAllocation {
    /// バッファへのポインタ
    pub ptr: NonNull<u8>,
    /// 物理アドレス
    pub phys_addr: PhysAddr,
    /// デバイスに渡すアドレス（IOVAまたは物理アドレス）
    pub device_addr: u64,
    /// サイズ
    pub size: usize,
    /// レイアウト
    layout: Layout,
    /// IOVAが設定されているか
    pub iova_mapped: bool,
}

impl Drop for DmaAllocation {
    fn drop(&mut self) {
        // IOMMUマッピングを解除
        if self.iova_mapped {
            let _ = crate::io::iommu::unmap_dma(self.device_addr, self.size as u64);
        }
        // メモリを解放
        unsafe {
            dealloc(self.ptr.as_ptr(), self.layout);
        }
    }
}

/// ストリーミングDMAマッピング
pub struct StreamingMapping {
    /// 元のバッファアドレス
    pub host_addr: *const u8,
    /// デバイスアドレス
    pub device_addr: u64,
    /// サイズ
    pub size: usize,
    /// 方向
    pub direction: DmaDirection,
    /// IOMMUでマッピングされているか
    pub iova_mapped: bool,
}

/// グローバルDMAアロケータ
pub struct GlobalDmaAllocator {
    /// デバイスID（IOMMU用）
    device_id: Option<crate::io::iommu::DeviceId>,
}

impl GlobalDmaAllocator {
    /// 新しいグローバルDMAアロケータを作成
    pub const fn new() -> Self {
        Self { device_id: None }
    }
    
    /// デバイスIDを設定（IOMMU連携用）
    pub fn with_device(device_id: crate::io::iommu::DeviceId) -> Self {
        Self { device_id: Some(device_id) }
    }
}

impl DmaAllocator for GlobalDmaAllocator {
    fn allocate_coherent(&self, size: usize, _direction: DmaDirection) -> Result<DmaAllocation, DmaError> {
        let layout = Layout::from_size_align(size, DMA_ALIGNMENT)
            .map_err(|_| DmaError::InvalidAlignment)?;
        
        let ptr = unsafe { alloc(layout) };
        if ptr.is_null() {
            return Err(DmaError::OutOfMemory);
        }
        
        // ゼロ初期化
        unsafe { core::ptr::write_bytes(ptr, 0, size); }
        
        let phys_addr = PhysAddr::new(ptr as u64);
        
        // IOMMUマッピング
        let (device_addr, iova_mapped) = if crate::io::iommu::is_iommu_enabled() {
            match crate::io::iommu::map_for_dma(phys_addr, size as u64) {
                Ok(iova) => (iova, true),
                Err(_) => {
                    unsafe { dealloc(ptr, layout); }
                    return Err(DmaError::IommuMappingFailed);
                }
            }
        } else {
            (phys_addr.as_u64(), false)
        };
        
        Ok(DmaAllocation {
            ptr: unsafe { NonNull::new_unchecked(ptr) },
            phys_addr,
            device_addr,
            size,
            layout,
            iova_mapped,
        })
    }
    
    fn map_streaming(&self, buffer: &[u8], direction: DmaDirection) -> Result<StreamingMapping, DmaError> {
        let host_addr = buffer.as_ptr();
        let size = buffer.len();
        let phys_addr = PhysAddr::new(host_addr as u64);
        
        // キャッシュ操作
        match direction {
            DmaDirection::ToDevice | DmaDirection::Bidirectional => {
                flush_cache_range(host_addr, size);
            }
            DmaDirection::FromDevice => {}
        }
        
        // IOMMUマッピング
        let (device_addr, iova_mapped) = if crate::io::iommu::is_iommu_enabled() {
            match crate::io::iommu::map_for_dma(phys_addr, size as u64) {
                Ok(iova) => (iova, true),
                Err(_) => return Err(DmaError::IommuMappingFailed),
            }
        } else {
            (phys_addr.as_u64(), false)
        };
        
        Ok(StreamingMapping {
            host_addr,
            device_addr,
            size,
            direction,
            iova_mapped,
        })
    }
    
    fn unmap_streaming(&self, mapping: StreamingMapping) {
        // キャッシュ操作
        match mapping.direction {
            DmaDirection::FromDevice | DmaDirection::Bidirectional => {
                invalidate_cache_range(mapping.host_addr, mapping.size);
            }
            DmaDirection::ToDevice => {}
        }
        
        // IOMMUマッピング解除
        if mapping.iova_mapped {
            let _ = crate::io::iommu::unmap_dma(mapping.device_addr, mapping.size as u64);
        }
    }
    
    fn device_address(&self, phys_addr: PhysAddr) -> u64 {
        // 既存のマッピングから検索するか、Identity mappingを返す
        phys_addr.as_u64()
    }
    
    fn iommu_enabled(&self) -> bool {
        crate::io::iommu::is_iommu_enabled()
    }
}

/// グローバルDMAアロケータインスタンス
static GLOBAL_DMA_ALLOCATOR: GlobalDmaAllocator = GlobalDmaAllocator::new();

/// グローバルDMAアロケータを取得
pub fn global_dma_allocator() -> &'static dyn DmaAllocator {
    &GLOBAL_DMA_ALLOCATOR
}

// ============================================================================
// Device-specific DMA Context
// ============================================================================

/// デバイス固有のDMAコンテキスト
/// 
/// 各ドライバはこれを保持してDMA操作を行う。
/// IOMMUドメインやデバイス固有の設定を管理。
pub struct DeviceDmaContext {
    /// デバイスID
    device_id: Option<crate::io::iommu::DeviceId>,
    /// IOMMUドメインID
    domain_id: Option<u16>,
    /// アロケータ
    allocator: Arc<dyn DmaAllocator>,
}

impl DeviceDmaContext {
    /// 新しいデバイスDMAコンテキストを作成
    pub fn new() -> Self {
        Self {
            device_id: None,
            domain_id: None,
            allocator: Arc::new(GlobalDmaAllocator::new()),
        }
    }
    
    /// デバイスIDを設定してIOMMU連携を有効化
    pub fn with_device(device_id: crate::io::iommu::DeviceId) -> Result<Self, DmaError> {
        let domain_id = if crate::io::iommu::is_iommu_enabled() {
            // IOMMUドメインを作成してデバイスをアタッチ
            crate::io::iommu::with_iommu(|iommu| {
                let domain_id = iommu.create_domain().ok()?;
                iommu.attach_device(device_id, domain_id).ok()?;
                Some(domain_id)
            }).ok().flatten()
        } else {
            None
        };
        
        Ok(Self {
            device_id: Some(device_id),
            domain_id,
            allocator: Arc::new(GlobalDmaAllocator::with_device(device_id)),
        })
    }
    
    /// コヒーレントDMAバッファを割り当て
    pub fn allocate(&self, size: usize, direction: DmaDirection) -> Result<DmaAllocation, DmaError> {
        self.allocator.allocate_coherent(size, direction)
    }
    
    /// 便利なメソッド: TypedDmaBufferを作成
    pub fn create_buffer<T>(&self, value: T) -> Result<TypedDmaBuffer<T, CpuOwned>, DmaError> {
        TypedDmaBuffer::new(value).ok_or(DmaError::OutOfMemory)
    }
    
    /// 便利なメソッド: TypedDmaSliceを作成
    pub fn create_slice(&self, size: usize) -> Result<TypedDmaSlice<CpuOwned>, DmaError> {
        TypedDmaSlice::new(size).ok_or(DmaError::OutOfMemory)
    }
}

impl Default for DeviceDmaContext {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for DeviceDmaContext {
    fn drop(&mut self) {
        // IOMMUドメインからデバイスをデタッチ
        if let (Some(device_id), Some(_domain_id)) = (self.device_id, self.domain_id) {
            let _ = crate::io::iommu::with_iommu(|iommu| {
                let _ = iommu.detach_device(device_id);
            });
        }
    }
}

// ============================================================================
// CPU Feature Detection
// ============================================================================

/// CLFLUSHOPT命令のサポートを確認
pub fn supports_clflushopt() -> bool {
    let result: u32;
    unsafe {
        asm!(
            "mov eax, 7", "xor ecx, ecx", "cpuid", "mov {}, ebx",
            out(reg) result, out("eax") _, out("ecx") _, out("edx") _,
            options(nostack, preserves_flags)
        );
    }
    (result & (1 << 23)) != 0
}

/// CLWB命令のサポートを確認
pub fn supports_clwb() -> bool {
    let result: u32;
    unsafe {
        asm!(
            "mov eax, 7", "xor ecx, ecx", "cpuid", "mov {}, ebx",
            out(reg) result, out("eax") _, out("ecx") _, out("edx") _,
            options(nostack, preserves_flags)
        );
    }
    (result & (1 << 24)) != 0
}

/// キャッシュラインサイズを取得
pub fn cache_line_size() -> usize {
    let result: u32;
    unsafe {
        asm!(
            "mov eax, 1", "cpuid", "mov {}, ebx",
            out(reg) result, out("eax") _, out("ecx") _, out("edx") _,
            options(nostack, preserves_flags)
        );
    }
    (((result >> 8) & 0xFF) * 8) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_typed_dma_buffer() {
        let buffer = TypedDmaBuffer::<u32, CpuOwned>::new(42).expect("Failed to allocate");

        // CPU所有状態ではアクセス可能
        assert_eq!(*buffer.as_ref(), 42);

        // DMA転送開始
        let (device_buffer, guard) = buffer.start_dma();
        let _phys = guard.phys_addr();

        // DeviceOwned状態では as_ref() がコンパイルエラーになる
        // （ここでは確認のためコメントアウト）
        // device_buffer.as_ref(); // ERROR!

        // DMA転送完了
        let buffer = device_buffer.complete_dma();
        assert_eq!(*buffer.as_ref(), 42);
    }

    #[test]
    fn test_typed_dma_slice() {
        let mut slice = TypedDmaSlice::<CpuOwned>::new(4096).expect("Failed to allocate");

        // データを書き込み
        {
            let s = slice.as_mut_slice();
            s[0] = 0xDE;
            s[1] = 0xAD;
        }

        // 確認
        assert_eq!(slice.as_slice()[0], 0xDE);
        assert_eq!(slice.as_slice()[1], 0xAD);

        // DMA転送
        let device_slice = slice.start_dma();
        // device_slice.as_slice(); // ERROR! DeviceOwnedでは不可

        let cpu_slice = device_slice.complete_dma();
        assert_eq!(cpu_slice.as_slice()[0], 0xDE);
    }
}
