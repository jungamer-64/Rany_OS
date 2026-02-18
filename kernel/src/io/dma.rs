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
//! let buffer = guard.complete(buffer); // CPUに戻る
//! ```
//!
//! ## RRef-backed DMA mapping
//! `RRefDmaBuffer<T>` provides a safe IOMMU mapping for Exchange Heap-backed data.
//! Use `DeviceDmaContext::map_rref_kernel` or `map_rref_buffer`, and explicitly
//! unmap to recover the `RRef<T>`.
//! For dynamic buffers, create `RRef<[T]>` with `RRef::new_slice_default_aligned`
//! and map it via `DeviceDmaContext::map_rref_slice` (ensure
//! `len * size_of::<T>` is 4K-aligned when IOMMU is enabled).
//! For byte buffers with arbitrary sizes, use `DeviceDmaContext::map_rref_kernel_bytes`
//! to get a page-aligned mapping and keep the logical length.
//! If you already have an aligned `RRef<[u8]>`, use `DeviceDmaContext::map_rref_bytes`.
//! Note: When IOMMU is enabled, the mapped buffer must be 4K-aligned in address
//! and size, otherwise mapping returns `InvalidAlignment`.
#![allow(dead_code)]

use alloc::alloc::{Layout, alloc, dealloc};
use core::marker::PhantomData;
use core::ptr::NonNull;
use core::sync::atomic::Ordering;
use x86_64::PhysAddr;

/// DMAバッファの最小アライメント
mod cache_ops;
pub use cache_ops::*;
const DMA_ALIGNMENT: usize = 4096; // ページアライメント

fn align_up(value: usize, align: usize) -> Option<usize> {
    if !align.is_power_of_two() {
        return None;
    }
    value.checked_add(align - 1).map(|v| v & !(align - 1))
}

pub(crate) fn iommu_align_len(len: usize) -> Option<usize> {
    align_up(len, DMA_ALIGNMENT)
}

pub(crate) fn iommu_needs_bounce(phys_addr: u64, len: usize) -> bool {
    (phys_addr & (DMA_ALIGNMENT as u64 - 1) != 0) || (len & (DMA_ALIGNMENT - 1) != 0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IommuBounceAllocError {
    InvalidLen,
    AllocFailed,
}

pub(crate) fn allocate_iommu_bounce_bytes(
    len: usize,
) -> Result<crate::ipc::RRef<[u8]>, IommuBounceAllocError> {
    let aligned_len = iommu_align_len(len).ok_or(IommuBounceAllocError::InvalidLen)?;
    if aligned_len == 0 {
        return Err(IommuBounceAllocError::InvalidLen);
    }
    crate::ipc::RRef::new_slice_default_aligned(
        crate::ipc::DomainId::KERNEL,
        aligned_len,
        DMA_ALIGNMENT,
    )
    .ok_or(IommuBounceAllocError::AllocFailed)
}

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
    pub trait DmaState {
        /// この状態でDropした時にメモリを解放するか
        /// CpuOwned: true (解放する)
        /// DeviceOwned: false (no-op、Guardが管理)
        const OWNS_ALLOC: bool;
    }
    impl DmaState for super::CpuOwned {
        const OWNS_ALLOC: bool = true;
    }
    impl DmaState for super::DeviceOwned {
        const OWNS_ALLOC: bool = false;
    }
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
        crate::util::write_to_addr(ptr as usize, value);

        // 仮想アドレスを物理アドレスに変換
        let phys_addr = crate::memory::virt_to_phys(x86_64::VirtAddr::new(ptr as u64));

        let res = Some(Self {
            ptr: NonNull::new(ptr as *mut T).expect("alloc returned null pointer"),
            phys_addr,
            layout,
            _state: PhantomData,
        });

        #[cfg(debug_assertions)]
        crate::memory::verify_buddy_integrity();

        res
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
    /// 完了時は `guard.complete(dev)` を呼ぶ。
    pub fn start_dma(self) -> (TypedDmaBuffer<T, DeviceOwned>, TypedDmaGuard<T>) {
        core::sync::atomic::fence(Ordering::Release);

        let guard = TypedDmaGuard {
            ptr: self.ptr,
            phys_addr: self.phys_addr,
            layout: self.layout,
            completed: false,
            _marker: PhantomData,
        };

        let buffer = TypedDmaBuffer {
            ptr: self.ptr,
            phys_addr: self.phys_addr,
            layout: self.layout,
            _state: PhantomData,
        };

        core::mem::forget(self); // CpuOwned の Drop を止める
        (buffer, guard)
    }
}

// TypedDmaBuffer<T, DeviceOwned> には complete_dma は実装しない。
// 完了は guard.complete(dev) 経由でのみ可能。

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
        // DeviceOwned: no-op (Guard が管理)
        // CpuOwned: デストラクタ呼び出し + 解放
        if <State as sealed::DmaState>::OWNS_ALLOC {
            unsafe {
                core::ptr::drop_in_place(self.ptr.as_ptr());
                dealloc(self.ptr.as_ptr() as *mut u8, self.layout);
            }
        }
    }
}

/// DMA転送中のメタデータ保持構造体（TypedDmaBuffer用）
///
/// 注意: この構造体は自動同期を行いません。
/// `complete()` を必ず呼んでください。
#[must_use = "DMA in-flight guard must be completed; dropping leaks in release / panics in debug"]
pub struct TypedDmaGuard<T> {
    ptr: NonNull<T>,
    phys_addr: PhysAddr,
    layout: Layout,
    completed: bool,
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

    /// DMA完了。GuardとDeviceOwnedハンドルを消費してCpuOwnedを返す。
    pub fn complete(mut self, dev: TypedDmaBuffer<T, DeviceOwned>) -> TypedDmaBuffer<T, CpuOwned> {
        debug_assert_eq!(self.ptr, dev.ptr);
        core::sync::atomic::fence(Ordering::Acquire);
        self.completed = true;
        // dev は Drop しても no-op (DeviceOwned) なのでそのまま捨ててOK
        core::mem::drop(dev);
        TypedDmaBuffer {
            ptr: self.ptr,
            phys_addr: self.phys_addr,
            layout: self.layout,
            _state: PhantomData,
        }
    }
}

impl<T> Drop for TypedDmaGuard<T> {
    fn drop(&mut self) {
        if !self.completed {
            #[cfg(debug_assertions)]
            panic!(
                "TypedDmaGuard dropped without complete()! phys={:?} size={}",
                self.phys_addr,
                self.layout.size()
            );
            #[cfg(not(debug_assertions))]
            log::warn!(
                "TypedDmaGuard leaked: complete() not called (phys={:?}, size={})",
                self.phys_addr,
                self.layout.size()
            );
        }
    }
}

// ============================================================================
// SliceDmaGuard - DMAスライス用ガード
// ============================================================================

/// DMA転送中のスライスバッファ所有権管理ガード
///
/// `complete()` を呼ばずに drop すると:
/// - debug: panic（バグ検出）
/// - release: warn + メモリリーク（DMA安全優先）
#[must_use = "DMA in-flight guard must be completed; dropping leaks in release / panics in debug"]
pub struct SliceDmaGuard {
    ptr: NonNull<u8>,
    phys_addr: PhysAddr,
    size: usize,
    layout: Layout,
    completed: bool,
}

impl SliceDmaGuard {
    /// 物理アドレスを取得
    pub fn phys_addr(&self) -> PhysAddr {
        self.phys_addr
    }

    /// サイズを取得
    pub fn size(&self) -> usize {
        self.size
    }

    /// DMA完了。GuardとDeviceOwnedハンドルを消費してCpuOwnedを返す。
    pub fn complete(mut self, dev: TypedDmaSlice<DeviceOwned>) -> TypedDmaSlice<CpuOwned> {
        debug_assert_eq!(self.ptr, dev.ptr);
        debug_assert_eq!(self.size, dev.size);
        core::sync::atomic::fence(Ordering::Acquire);
        self.completed = true;
        // dev は Drop しても no-op (DeviceOwned) なのでそのまま捨ててOK
        core::mem::drop(dev);
        TypedDmaSlice {
            ptr: self.ptr,
            phys_addr: self.phys_addr,
            size: self.size,
            layout: self.layout,
            _state: PhantomData,
        }
    }
}

impl Drop for SliceDmaGuard {
    fn drop(&mut self) {
        if !self.completed {
            #[cfg(debug_assertions)]
            panic!(
                "SliceDmaGuard dropped without complete()! phys={:?} size={}",
                self.phys_addr, self.size
            );
            #[cfg(not(debug_assertions))]
            log::warn!(
                "SliceDmaGuard leaked: complete() not called (phys={:?}, size={})",
                self.phys_addr,
                self.size
            );
        }
    }
}

// SAFETY: SliceDmaGuard only holds a raw pointer and allocation metadata for a DMA buffer.
// Moving it between threads is safe as long as the guard's `complete()` is called exactly once
// and caller ensures proper synchronization. We assert Send here to allow completion hooks
// to be executed on poll handlers which may run on other CPUs.
unsafe impl Send for SliceDmaGuard {}

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
    ///
    /// # Physical Memory Contiguity
    /// The global allocator uses a Buddy allocator backed by contiguous
    /// physical memory. Allocations are guaranteed to be physically contiguous.
    ///
    /// # Returns
    /// `None` if size is 0 or allocation fails.
    pub fn new(size: usize) -> Option<Self> {
        // size=0 はDMAでは無効（バグの可能性が高い）
        if size == 0 {
            return None;
        }

        let layout = Layout::from_size_align(size, DMA_ALIGNMENT).ok()?;

        let non_null = crate::util::allocate_zeroed(layout)?;
        let ptr = non_null.as_ptr();

        // 仮想アドレスを物理アドレスに変換
        let phys_addr = crate::memory::virt_to_phys(x86_64::VirtAddr::new(ptr as u64));

        // Diagnostic: log DMA allocation info
        crate::io::log::early_print("[DMA] TypedDmaSlice alloc size=");
        crate::io::log::early_print_dec(size as u64);
        crate::io::log::early_print(" phys=");
        crate::io::log::early_print_hex(phys_addr.as_u64());
        crate::io::log::early_print("\n");

        Some(Self {
            ptr: NonNull::new(ptr).expect("alloc returned null pointer"),
            phys_addr,
            size,
            layout,
            _state: PhantomData,
        })
    }

    /// スライスとして取得（CPU所有時のみ）
    pub fn as_slice(&self) -> &[u8] {
        unsafe { crate::util::raw_ptr_as_slice(self.ptr.as_ptr(), self.size) }
    }

    /// 可変スライスとして取得（CPU所有時のみ）
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { crate::util::raw_ptr_as_slice_mut(self.ptr.as_ptr(), self.size) }
    }

    /// DMA転送を開始。GuardとDeviceOwnedハンドルを返す。
    ///
    /// 完了時は `guard.complete(dev)` を呼ぶ。
    pub fn start_dma(self) -> (TypedDmaSlice<DeviceOwned>, SliceDmaGuard) {
        // Diagnostic: log DMA transfer start
        crate::io::log::early_print("[DMA] TypedDmaSlice start_dma phys=");
        crate::io::log::early_print_hex(self.phys_addr.as_u64());
        crate::io::log::early_print(" size=");
        crate::io::log::early_print_dec(self.size as u64);
        crate::io::log::early_print("\n");

        // Debug: verify buddy integrity after DMA start to catch early corruption
        #[cfg(debug_assertions)]
        crate::memory::verify_buddy_integrity();

        core::sync::atomic::fence(Ordering::Release);

        let guard = SliceDmaGuard {
            ptr: self.ptr,
            phys_addr: self.phys_addr,
            size: self.size,
            layout: self.layout,
            completed: false,
        };

        let dev = TypedDmaSlice {
            ptr: self.ptr,
            phys_addr: self.phys_addr,
            size: self.size,
            layout: self.layout, // Drop が no-op なので持っててOK
            _state: PhantomData,
        };

        core::mem::forget(self); // CpuOwned の Drop（解放）を止める
        (dev, guard)
    }
}

// TypedDmaSlice<DeviceOwned> には complete_dma は実装しない。
// 完了は guard.complete(dev) 経由でのみ可能。

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
        // DeviceOwned: no-op (Guard が管理)
        // CpuOwned: 解放
        if <State as sealed::DmaState>::OWNS_ALLOC {
            unsafe {
                dealloc(self.ptr.as_ptr(), self.layout);
            }
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

/// Scatter-Gather DMA用ガード
///
/// 複数のSliceDmaGuardをまとめて管理。
/// `complete_all()` でDeviceOwnedリストと一緒に消費してCpuOwnedリストを返す。
#[must_use = "SG DMA guard must be completed; dropping leaks in release / panics in debug"]
pub struct SgDmaGuard {
    guards: alloc::vec::Vec<SliceDmaGuard>,
}

impl SgDmaGuard {
    /// SG全体のDMA完了。GuardとDeviceOwnedリストをペアで消費。
    pub fn complete_all(self, list: TypedSgList<DeviceOwned>) -> TypedSgList<CpuOwned> {
        debug_assert_eq!(self.guards.len(), list.buffers.len());

        let buffers = self
            .guards
            .into_iter()
            .zip(list.buffers.into_iter())
            .map(|(g, dev)| g.complete(dev))
            .collect();

        TypedSgList {
            entries: list.entries,
            buffers,
            _state: PhantomData,
        }
    }
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

    /// 全バッファをデバイスに転送。GuardとDeviceOwnedリストを返す。
    ///
    /// 完了時は `guard.complete_all(list)` を呼ぶ。
    pub fn start_dma(self) -> (TypedSgList<DeviceOwned>, SgDmaGuard) {
        core::sync::atomic::fence(Ordering::Release);

        let mut guards = alloc::vec::Vec::with_capacity(self.buffers.len());
        let buffers = self
            .buffers
            .into_iter()
            .map(|b| {
                let (dev, g) = b.start_dma();
                guards.push(g);
                dev
            })
            .collect();

        (
            TypedSgList {
                entries: self.entries,
                buffers,
                _state: PhantomData,
            },
            SgDmaGuard { guards },
        )
    }
}

// TypedSgList<DeviceOwned> には complete_dma は実装しない。
// 完了は guard.complete_all(list) 経由でのみ可能。

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

use core::sync::atomic::AtomicBool;

/// キャッシュラインサイズ（x86_64では通常64バイト）
pub const CACHE_LINE_SIZE: usize = 64;

/// CPU feature flags (ブート時に一度だけ設定)
static SUPPORTS_CLFLUSHOPT: AtomicBool = AtomicBool::new(false);
static SUPPORTS_CLWB: AtomicBool = AtomicBool::new(false);

/// ブート時にCPUキャッシュフィーチャーを検出
///
/// # Safety
/// カーネル初期化時に一度だけ呼ぶこと
pub fn init_cache_features() {
    // CPUID.07H:EBX.CLFLUSHOPT[bit 23]
    // CPUID.07H:EBX.CLWB[bit 24]
    let result = core::arch::x86_64::__cpuid_count(0x07, 0);
    SUPPORTS_CLFLUSHOPT.store((result.ebx & (1 << 23)) != 0, Ordering::Relaxed);
    SUPPORTS_CLWB.store((result.ebx & (1 << 24)) != 0, Ordering::Relaxed);
}

/// CLFLUSHOPT/CLWB がサポートされているか
#[inline]
pub fn supports_clflushopt() -> bool {
    SUPPORTS_CLFLUSHOPT.load(Ordering::Relaxed)
}

#[inline]
pub fn supports_clwb() -> bool {
    SUPPORTS_CLWB.load(Ordering::Relaxed)
}

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

/// 1キャッシュラインをフラッシュ（CPU検出に基づく自動選択）
#[inline(always)]
fn flush_line(addr: *const u8) {
    if SUPPORTS_CLFLUSHOPT.load(Ordering::Relaxed) {
        clflushopt(addr);
    } else {
        clflush(addr);
    }
}

/// MFENCE: メモリフェンス - 全てのロード/ストア操作が完了するまで待機
#[inline(always)]
pub fn mfence() {
    unsafe {
        asm!("mfence", options(nostack, preserves_flags));
    }
}

/// SFENCE: ストアフェンス - DMA転送開始前（CPU→デバイス）に使用
#[inline(always)]
pub fn sfence() {
    unsafe {
        asm!("sfence", options(nostack, preserves_flags));
    }
}

/// LFENCE: ロードフェンス - DMA転送完了後（デバイス→CPU）に使用
#[inline(always)]
pub fn lfence() {
    unsafe {
        asm!("lfence", options(nostack, preserves_flags));
    }
}
