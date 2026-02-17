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

// ============================================================================
// Cache Range Operations
// ============================================================================

/// 指定範囲のキャッシュをフラッシュ（DMA転送開始前 CPU→デバイス）
pub fn flush_cache_range(addr: *const u8, size: usize) {
    let start = addr as usize;
    let end = start.checked_add(size).unwrap_or(usize::MAX);
    let aligned_start = start & !(CACHE_LINE_SIZE - 1);

    let mut current = aligned_start;
    while current < end {
        flush_line(current as *const u8);
        current += CACHE_LINE_SIZE;
    }
    // CLFLUSH は MFENCE が必要、CLFLUSHOPT は SFENCE で十分だが
    // 互換性のため MFENCE を使用
    mfence();
}

/// 指定範囲のキャッシュを無効化（DMA転送完了後 デバイス→CPU）
pub fn invalidate_cache_range(addr: *const u8, size: usize) {
    flush_cache_range(addr, size);
    lfence();
}

/// 指定範囲のキャッシュを書き戻し（永続メモリ用、無効化なし）
pub fn writeback_cache_range(addr: *const u8, size: usize) {
    let start = addr as usize;
    let end = start.checked_add(size).unwrap_or(usize::MAX);
    let aligned_start = start & !(CACHE_LINE_SIZE - 1);

    let mut current = aligned_start;
    while current < end {
        // CLWBがサポートされていればCLWB、なければCLFLUSHOPT/CLFLUSHにフォールバック
        if SUPPORTS_CLWB.load(Ordering::Relaxed) {
            clwb(current as *const u8);
        } else {
            flush_line(current as *const u8);
        }
        current += CACHE_LINE_SIZE;
    }
    mfence();
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

impl From<DmaDirection> for crate::io::iommu::api::DmaDirection {
    fn from(direction: DmaDirection) -> Self {
        match direction {
            DmaDirection::ToDevice => crate::io::iommu::api::DmaDirection::ToDevice,
            DmaDirection::FromDevice => crate::io::iommu::api::DmaDirection::FromDevice,
            DmaDirection::Bidirectional => crate::io::iommu::api::DmaDirection::Bidirectional,
        }
    }
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
// RRef-backed DMA Mapping
// ============================================================================

/// RRef-backed DMA mapping that must be explicitly unmapped.
///
/// Note: `T` should be a DMA-safe value stored inline in the RRef allocation
/// (e.g., a fixed-size buffer or packet struct), not a pointer to other data.
#[derive(Debug)]
pub struct RRefDmaBuffer<T: ?Sized + 'static> {
    handle: crate::io::iommu::api::DmaHandle<T>,
}

/// Byte-oriented DMA buffer with a logical length and padded capacity.
#[derive(Debug)]
pub struct RRefDmaBytes {
    buffer: RRefDmaBuffer<[u8]>,
    len: usize,
}

/// Errors for kernel-owned slice allocation + DMA mapping.
#[derive(Debug)]
pub enum RRefSliceMapError<T: 'static> {
    /// Exchange Heap allocation failed.
    AllocFailed,
    /// IOMMU mapping failed (returns the RRef on error).
    MapError(crate::io::iommu::api::MapError<[T]>),
}

/// Errors for kernel-owned single value allocation + DMA mapping.
#[derive(Debug)]
pub enum RRefMapError<T: 'static> {
    /// Exchange Heap allocation failed.
    AllocFailed,
    /// IOMMU mapping failed (returns the RRef on error).
    MapError(crate::io::iommu::api::MapError<T>),
}

impl<T: 'static> RRefDmaBuffer<T> {
    /// Map an `RRef<T>` using the device context's IOMMU settings.
    pub fn map(
        ctx: &DeviceDmaContext,
        rref: crate::ipc::RRef<T>,
        direction: DmaDirection,
    ) -> Result<Self, crate::io::iommu::api::MapError<T>> {
        ctx.map_rref(rref, direction).map(|handle| Self { handle })
    }

    /// Allocate an `RRef<T>` in the kernel domain and map it for DMA.
    pub fn map_kernel(
        ctx: &DeviceDmaContext,
        value: T,
        direction: DmaDirection,
    ) -> Result<Self, crate::io::iommu::api::MapError<T>> {
        let rref = crate::ipc::RRef::new(crate::ipc::DomainId::KERNEL, value);
        Self::map(ctx, rref, direction)
    }

    /// Allocate a default `T` in the kernel domain and map it for DMA.
    pub fn map_kernel_default(
        ctx: &DeviceDmaContext,
        direction: DmaDirection,
    ) -> Result<Self, crate::io::iommu::api::MapError<T>>
    where
        T: Default,
    {
        Self::map_kernel(ctx, T::default(), direction)
    }

    /// Try to allocate a kernel-owned `RRef<T>` and map it for DMA.
    pub fn try_map_kernel(
        ctx: &DeviceDmaContext,
        value: T,
        direction: DmaDirection,
    ) -> Result<Self, RRefMapError<T>> {
        let rref = crate::ipc::RRef::try_new(crate::ipc::DomainId::KERNEL, value)
            .ok_or(RRefMapError::AllocFailed)?;
        Self::map(ctx, rref, direction).map_err(RRefMapError::MapError)
    }

    /// Try to allocate a default `T` in the kernel domain and map it for DMA.
    pub fn try_map_kernel_default(
        ctx: &DeviceDmaContext,
        direction: DmaDirection,
    ) -> Result<Self, RRefMapError<T>>
    where
        T: Default,
    {
        Self::try_map_kernel(ctx, T::default(), direction)
    }

    /// IOVA assigned for this mapping.
    pub fn iova(&self) -> u64 {
        self.handle.iova()
    }

    /// Physical address of the mapped buffer.
    pub fn phys_addr(&self) -> PhysAddr {
        PhysAddr::new(self.handle.phys_addr())
    }

    /// Size of the mapped buffer in bytes.
    pub fn size(&self) -> u64 {
        self.handle.size()
    }

    /// Unmap and recover the original `RRef<T>`.
    pub fn unmap(self) -> Result<crate::ipc::RRef<T>, crate::io::iommu::api::UnmapError<T>> {
        self.handle.unmap()
    }

    /// Async unmap and recover the original `RRef<T>`.
    pub async fn unmap_async(
        self,
    ) -> Result<crate::ipc::RRef<T>, crate::io::iommu::api::UnmapError<T>> {
        self.handle.unmap_async().await
    }

    /// Consume and return the underlying IOMMU handle.
    pub fn into_handle(self) -> crate::io::iommu::api::DmaHandle<T> {
        self.handle
    }

    /// Access the underlying IOMMU handle.
    pub fn handle(&self) -> &crate::io::iommu::api::DmaHandle<T> {
        &self.handle
    }
}

impl<T: 'static> RRefDmaBuffer<[T]> {
    /// IOVA assigned for this mapping.
    pub fn iova(&self) -> u64 {
        self.handle.iova()
    }

    /// Physical address of the mapped buffer.
    pub fn phys_addr(&self) -> PhysAddr {
        PhysAddr::new(self.handle.phys_addr())
    }

    /// Size of the mapped buffer in bytes.
    pub fn size(&self) -> u64 {
        self.handle.size()
    }

    /// Unmap and recover the original `RRef<[T]>`.
    pub fn unmap(self) -> Result<crate::ipc::RRef<[T]>, crate::io::iommu::api::UnmapError<[T]>> {
        self.handle.unmap()
    }

    /// Async unmap and recover the original `RRef<[T]>`.
    pub async fn unmap_async(
        self,
    ) -> Result<crate::ipc::RRef<[T]>, crate::io::iommu::api::UnmapError<[T]>> {
        self.handle.unmap_async().await
    }

    /// Access the underlying IOMMU handle.
    pub fn handle(&self) -> &crate::io::iommu::api::DmaHandle<[T]> {
        &self.handle
    }

    /// Number of elements in the mapped slice.
    pub fn len(&self) -> usize {
        let elem_size = core::mem::size_of::<T>() as u64;
        if elem_size == 0 {
            return 0;
        }
        (self.size() / elem_size) as usize
    }

    /// Whether the mapped slice is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl RRefDmaBytes {
    /// Number of bytes requested by the caller.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Total mapped capacity in bytes (page-aligned).
    pub fn capacity(&self) -> usize {
        self.buffer.len()
    }

    /// Whether the requested length is zero.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// IOVA assigned for this mapping.
    pub fn iova(&self) -> u64 {
        self.buffer.iova()
    }

    /// Physical address of the mapped buffer.
    pub fn phys_addr(&self) -> PhysAddr {
        self.buffer.phys_addr()
    }

    /// Unmap and recover the original `RRef<[u8]>` plus the logical length.
    pub fn unmap(
        self,
    ) -> Result<(crate::ipc::RRef<[u8]>, usize), crate::io::iommu::api::UnmapError<[u8]>> {
        let RRefDmaBytes { buffer, len } = self;
        buffer.unmap().map(|rref| (rref, len))
    }

    /// Async unmap and recover the original `RRef<[u8]>` plus the logical length.
    pub async fn unmap_async(
        self,
    ) -> Result<(crate::ipc::RRef<[u8]>, usize), crate::io::iommu::api::UnmapError<[u8]>> {
        let RRefDmaBytes { buffer, len } = self;
        buffer.unmap_async().await.map(|rref| (rref, len))
    }

    /// Access the underlying IOMMU handle.
    pub fn handle(&self) -> &crate::io::iommu::api::DmaHandle<[u8]> {
        self.buffer.handle()
    }

    /// Access the underlying `RRefDmaBuffer<[u8]>`.
    pub fn buffer(&self) -> &RRefDmaBuffer<[u8]> {
        &self.buffer
    }

    /// Consume and return the underlying `RRefDmaBuffer<[u8]>`.
    pub fn into_buffer(self) -> RRefDmaBuffer<[u8]> {
        self.buffer
    }
}

// ============================================================================
// Coherent DMA Buffer (auto cache management)
// ============================================================================

/// キャッシュ一貫性を自動管理するDMAバッファ
///
/// IOMMU有効時は `new_for_device()` で作成すると自動的にIOMMUマッピングが行われ、
/// `device_addr()` でデバイスに渡すアドレス（IOVA）を取得できる。
/// Drop時にIOMMUマッピングは自動的に解除される。
pub struct CoherentDmaBuffer {
    ptr: NonNull<u8>,
    size: usize,
    layout: Layout,
    phys_addr: PhysAddr,
    attributes: DmaMemoryAttributes,
    /// IOMMU有効時のIOVA（None = IOMMU未使用、物理アドレスを直接使用）
    iova: Option<u64>,
    /// IOMMUマッピング先のデバイスID（unmap時に必要）
    iommu_device: Option<crate::io::iommu::types::DeviceId>,
}

impl CoherentDmaBuffer {
    const DMA_ALIGNMENT: usize = 4096;

    /// IOMMUマッピングなしのDMAバッファを割り当てる。
    ///
    /// IOMMU有効環境ではデバイスからアクセスできない可能性があるため、
    /// デバイスDMAに使用する場合は `new_for_device()` を推奨。
    pub fn new(size: usize, attributes: DmaMemoryAttributes) -> Option<Self> {
        Self::new_internal(size, attributes, None)
    }

    /// 指定デバイスのIOMMUドメインにマッピングされたDMAバッファを割り当てる。
    ///
    /// IOMMU有効時はIOVAが自動的に割り当てられ、`device_addr()` でデバイスに
    /// 渡すアドレスを取得できる。IOMMU無効時は `new()` と同じ動作。
    /// Drop時にIOMMUマッピングは自動的に解除される。
    pub fn new_for_device(
        size: usize,
        attributes: DmaMemoryAttributes,
        device: &crate::io::iommu::types::DeviceId,
    ) -> Option<Self> {
        Self::new_internal(size, attributes, Some(device))
    }

    /// 内部実装: DMAバッファの割り当てとオプショナルなIOMMUマッピング
    fn new_internal(
        size: usize,
        attributes: DmaMemoryAttributes,
        device: Option<&crate::io::iommu::types::DeviceId>,
    ) -> Option<Self> {
        let layout = Layout::from_size_align(size, Self::DMA_ALIGNMENT).ok()?;
        let ptr = unsafe { alloc(layout) };
        if ptr.is_null() {
            return None;
        }
        unsafe {
            core::ptr::write_bytes(ptr, 0, size);
        }
        // 仮想アドレスを物理アドレスに変換
        let phys_addr = crate::memory::virt_to_phys(x86_64::VirtAddr::new(ptr as u64));

        // Diagnostic: log Coherent DMA allocation
        crate::io::log::early_print("[DMA] CoherentDmaBuffer alloc size=");
        crate::io::log::early_print_dec(size as u64);
        crate::io::log::early_print(" phys=");
        crate::io::log::early_print_hex(phys_addr.as_u64());
        crate::io::log::early_print("\n");

        // IOMMUマッピング（デバイスID指定時かつIOMMU有効時）
        let (iova, iommu_device) = if let Some(dev) = device {
            if crate::io::iommu::registry::is_iommu_enabled() {
                // ページアライメントされたサイズでマッピング（4K境界）
                let aligned_size = iommu_align_len(size).unwrap_or(size);
                let (read, write) = match attributes.direction {
                    DmaDirection::ToDevice => (true, false),
                    DmaDirection::FromDevice => (false, true),
                    DmaDirection::Bidirectional => (true, true),
                };
                // SAFETY: phys_addr は上記で割り当てた有効な物理メモリを指す。
                // aligned_size は4Kアライメント済み。メモリはDrop時まで有効。
                match unsafe {
                    crate::io::iommu::api::map_for_device_with_perms(
                        dev,
                        phys_addr,
                        aligned_size as u64,
                        read,
                        write,
                    )
                } {
                    Ok(iova) => {
                        log::debug!(
                            "[DMA] CoherentDmaBuffer IOMMU mapped: phys=0x{:x} -> iova=0x{:x} size={}",
                            phys_addr.as_u64(), iova, aligned_size
                        );
                        (Some(iova), Some(*dev))
                    }
                    Err(e) => {
                        log::warn!(
                            "[DMA] CoherentDmaBuffer IOMMU map failed: {:?}, falling back to phys_addr",
                            e
                        );
                        // IOMMUマッピング失敗時: IOMMU必須ならバッファ解放して失敗
                        if crate::io::iommu::api::is_iommu_required() {
                            unsafe { dealloc(ptr, layout); }
                            return None;
                        }
                        (None, None)
                    }
                }
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        Some(Self {
            ptr: NonNull::new(ptr).expect("alloc returned null pointer"),
            size,
            layout,
            phys_addr,
            attributes,
            iova,
            iommu_device,
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

    pub fn phys_addr(&self) -> PhysAddr {
        self.phys_addr
    }

    /// デバイスに渡すアドレスを取得する。
    ///
    /// IOMMU有効時はIOVA（I/O仮想アドレス）を返し、
    /// IOMMU無効時は物理アドレスを返す。
    /// デバイスのDMAアドレスレジスタに設定する際はこのメソッドを使用すること。
    pub fn device_addr(&self) -> u64 {
        self.iova.unwrap_or(self.phys_addr.as_u64())
    }

    /// IOMMUマッピングが有効かどうかを返す
    pub fn is_iommu_mapped(&self) -> bool {
        self.iova.is_some()
    }

    pub fn size(&self) -> usize {
        self.size
    }
}

impl Drop for CoherentDmaBuffer {
    fn drop(&mut self) {
        // IOMMUマッピングの解除
        if let (Some(iova), Some(ref device)) = (self.iova, self.iommu_device) {
            let aligned_size = iommu_align_len(self.size).unwrap_or(self.size);
            if let Err(e) = crate::io::iommu::api::unmap_for_device(
                device,
                iova,
                aligned_size as u64,
            ) {
                log::warn!(
                    "[DMA] CoherentDmaBuffer IOMMU unmap failed: {:?} (iova=0x{:x})",
                    e, iova
                );
            } else {
                log::debug!(
                    "[DMA] CoherentDmaBuffer IOMMU unmapped: iova=0x{:x} size={}",
                    iova, aligned_size
                );
            }
        }
        // メモリ解放
        unsafe {
            dealloc(self.ptr.as_ptr(), self.layout);
        }
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
        let phys_addr = crate::memory::virt_to_phys(x86_64::VirtAddr::new(buffer.as_ptr() as u64));
        match direction {
            DmaDirection::ToDevice | DmaDirection::Bidirectional => {
                flush_cache_range(buffer.as_ptr(), buffer.len());
            }
            DmaDirection::FromDevice => {}
        }
        Self {
            buffer,
            phys_addr,
            direction,
        }
    }

    pub fn phys_addr(&self) -> PhysAddr {
        self.phys_addr
    }
    pub fn len(&self) -> usize {
        self.buffer.len()
    }
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

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
    fn drop(&mut self) {
        self.sync_for_cpu();
    }
}

// ============================================================================
// IOMMU-protected DMA Buffer
// ============================================================================

/// IOMMUを使用したDMAバッファ
pub struct IommuDmaBuffer {
    inner: CoherentDmaBuffer,
    iova: Option<u64>,
    device_id: Option<crate::io::iommu::types::DeviceId>,
}

impl IommuDmaBuffer {
    pub fn new(size: usize, attributes: DmaMemoryAttributes) -> Option<Self> {
        let inner = CoherentDmaBuffer::new(size, attributes)?;
        let iova = if crate::io::iommu::api::is_iommu_enabled() {
            if size % DMA_ALIGNMENT != 0 {
                log::error!(
                    "[DMA] IOMMU mapping requires 4K-aligned size (got {} bytes)",
                    size
                );
                return None;
            }
            // SAFETY: CoherentDmaBuffer owns this memory, safe for DMA
            match unsafe { crate::io::iommu::api::map_for_dma(inner.phys_addr(), size as u64) } {
                Ok(iova) => Some(iova),
                Err(e) => {
                    log::error!("[DMA] IOMMU map_for_dma failed: {:?}", e);
                    return None;
                }
            }
        } else {
            if crate::io::iommu::api::is_iommu_required() {
                log::error!(
                    "[DMA] IOMMU required but not enabled: failing IOMMU DMA buffer allocation"
                );
                return None;
            }
            log::warn!("[DMA] IOMMU not enabled: IOMMU-based buffer not available");
            None
        };
        Some(Self {
            inner,
            iova,
            device_id: None,
        })
    }

    /// 特定のデバイス向けにDMAバッファを作成（ドメイン分離対応）
    pub fn new_for_device(
        size: usize,
        attributes: DmaMemoryAttributes,
        device: crate::io::iommu::types::DeviceId,
    ) -> Option<Self> {
        let inner = CoherentDmaBuffer::new(size, attributes)?;
        let iova = if crate::io::iommu::api::is_iommu_enabled() {
            if size % DMA_ALIGNMENT != 0 {
                log::error!(
                    "[DMA] IOMMU mapping requires 4K-aligned size (got {} bytes)",
                    size
                );
                return None;
            }
            // SAFETY: CoherentDmaBuffer owns this memory, safe for device DMA
            match unsafe { crate::io::iommu::api::map_for_device(&device, inner.phys_addr(), size as u64) } {
                Ok(iova) => Some(iova),
                Err(e) => {
                    log::error!("[DMA] IOMMU map_for_device failed: {:?}", e);
                    None
                }
            }
        } else {
            if crate::io::iommu::api::is_iommu_required() {
                log::error!(
                    "[DMA] IOMMU required but not enabled: failing device IOMMU allocation"
                );
                return None;
            }
            log::warn!("[DMA] IOMMU not enabled: device IOMMU allocation unavailable");
            None
        };
        Some(Self {
            inner,
            iova,
            device_id: Some(device),
        })
    }

    /// Async constructor that awaits mapping completion when a controller CommandQueue is present
    pub async fn new_for_device_async(
        size: usize,
        attributes: DmaMemoryAttributes,
        device: crate::io::iommu::types::DeviceId,
    ) -> Option<Self> {
        let inner = CoherentDmaBuffer::new(size, attributes)?;
        let iova = if crate::io::iommu::api::is_iommu_enabled() {
            if size % DMA_ALIGNMENT != 0 {
                log::error!(
                    "[DMA] IOMMU mapping requires 4K-aligned size (got {} bytes)",
                    size
                );
                return None;
            }
            // SAFETY: CoherentDmaBuffer owns this memory, safe for async device DMA
            match unsafe { crate::io::iommu::api::map_for_device_async(&device, inner.phys_addr(), size as u64).await } {
                Ok(iova) => Some(iova),
                Err(e) => {
                    log::error!("[DMA] IOMMU map_for_device_async failed: {:?}", e);
                    None
                }
            }
        } else {
            if crate::io::iommu::api::is_iommu_required() {
                log::error!(
                    "[DMA] IOMMU required but not enabled: failing async device IOMMU allocation"
                );
                return None;
            }
            log::warn!("[DMA] IOMMU not enabled: async device IOMMU allocation unavailable");
            None
        };
        Some(Self {
            inner,
            iova,
            device_id: Some(device),
        })
    }

    /// デバイスに渡すアドレス（IOMMUが有効ならIOVA）
    pub fn device_addr(&self) -> u64 {
        self.iova.unwrap_or(self.inner.phys_addr().as_u64())
    }

    pub fn prepare_for_device(&self) {
        self.inner.prepare_for_device();
    }
    pub fn finish_from_device(&self) {
        self.inner.finish_from_device();
    }
}

impl Drop for IommuDmaBuffer {
    fn drop(&mut self) {
        if let Some(iova) = self.iova {
            if let Some(device) = self.device_id {
                let _ = crate::io::iommu::api::unmap_for_device(
                    &device,
                    iova,
                    self.inner.size() as u64,
                );
            } else {
                let _ = crate::io::iommu::api::unmap_dma(iova, self.inner.size() as u64);
            }
        }
    }
}

// ============================================================================
// Global DMA Allocator Trait and Implementation
// ============================================================================

use alloc::sync::Arc;
// // use spin::Mutex;

/// DMAアロケータのエラー型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaError {
    /// メモリ不足
    OutOfMemory,
    /// アライメントエラー
    InvalidAlignment,
    /// サイズエラー
    InvalidSize,
    /// アドレス範囲が無効
    InvalidAddress,
    /// IOMMUマッピング失敗
    IommuMappingFailed,
    /// アドレス変換失敗
    AddressTranslationFailed,
    /// デバイスが見つからない
    DeviceNotFound,
    /// IOMMUが必須だが利用できない
    IommuRequired,
}

/// DMAアロケータトレイト
///
/// 全てのドライバはこのトレイトを通じてDMAメモリを割り当てる。
/// IOMMU対応・非対応を透過的に扱う。
pub trait DmaAllocator: Send + Sync {
    /// コヒーレントDMAバッファを割り当て
    fn allocate_coherent(
        &self,
        size: usize,
        direction: DmaDirection,
    ) -> Result<DmaAllocation, DmaError>;

    /// ストリーミングDMAマッピングを作成
    fn map_streaming(
        &self,
        buffer: &[u8],
        direction: DmaDirection,
    ) -> Result<StreamingMapping, DmaError>;

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
            let _ = crate::io::iommu::api::unmap_dma(self.device_addr, self.size as u64);
        }
        // メモリを解放
        unsafe {
            dealloc(self.ptr.as_ptr(), self.layout);
        }
    }
}

/// ストリーミングDMAマッピング
#[must_use = "streaming DMA mappings must be unmapped via DmaAllocator::unmap_streaming"]
pub struct StreamingMapping {
    /// 元のバッファアドレス
    pub host_addr: *const u8,
    /// デバイスアドレス
    pub device_addr: u64,
    /// サイズ
    pub size: usize,
    /// マップされたサイズ（IOMMU用のアライメント込み）
    mapped_len: usize,
    /// 方向
    pub direction: DmaDirection,
    /// IOMMUでマッピングされているか
    pub iova_mapped: bool,
    /// IOMMUバウンス用バッファ（必要時のみ）
    bounce: Option<crate::ipc::RRef<[u8]>>,
}

impl Drop for StreamingMapping {
    fn drop(&mut self) {
        if self.iova_mapped {
            // Release: IOMMU unmap を試みる（デバイスを fault させる方が安全）
            // DMA中かもしれないが、解放後アクセスよりデバイス fault の方がマシ
            let _ = crate::io::iommu::api::unmap_dma(self.device_addr, self.mapped_len as u64);

            // bounce バッファは解放して回収
            if let Some(bounce) = self.bounce.take() {
                drop(bounce);
            }

            #[cfg(debug_assertions)]
            {
                panic!(
                    "Streaming DMA mapping leaked! addr=0x{:x}, size={}, mapped_len={} (IOMMU unmapped)",
                    self.device_addr, self.size, self.mapped_len
                );
            }
            #[cfg(not(debug_assertions))]
            {
                log::error!(
                    "[DMA] streaming mapping leaked: addr=0x{:x}, size={}, mapped_len={} (IOMMU unmapped, device may fault)",
                    self.device_addr,
                    self.size,
                    self.mapped_len
                );
            }
        }
    }
}

/// グローバルDMAアロケータ
pub struct GlobalDmaAllocator {
    /// デバイスID（IOMMU用）
    device_id: Option<crate::io::iommu::types::DeviceId>,
}

impl GlobalDmaAllocator {
    /// 新しいグローバルDMAアロケータを作成
    pub const fn new() -> Self {
        Self { device_id: None }
    }

    /// デバイスIDを設定（IOMMU連携用）
    pub fn with_device(device_id: crate::io::iommu::types::DeviceId) -> Self {
        Self {
            device_id: Some(device_id),
        }
    }

    /// バウンスバッファの準備（必要な場合）とキャッシュフラッシュ
    fn prepare_streaming_buffer(
        buffer: &[u8],
        phys_addr: x86_64::PhysAddr,
        direction: DmaDirection,
    ) -> Result<(x86_64::PhysAddr, usize, Option<crate::ipc::RRef<[u8]>>), DmaError> {
        let host_addr = buffer.as_ptr();
        let size = buffer.len();

        if crate::io::iommu::api::is_iommu_enabled() && iommu_needs_bounce(phys_addr.as_u64(), size) {
            let mut rref = allocate_iommu_bounce_bytes(size).map_err(|err| match err {
                IommuBounceAllocError::InvalidLen => DmaError::InvalidAlignment,
                IommuBounceAllocError::AllocFailed => DmaError::OutOfMemory,
            })?;

            if matches!(direction, DmaDirection::ToDevice | DmaDirection::Bidirectional) {
                rref[..size].copy_from_slice(buffer);
                flush_cache_range(rref.as_ptr(), rref.len());
            }

            let bounce_phys = crate::memory::virt_to_phys(x86_64::VirtAddr::new(rref.as_ptr() as u64));
            let mapped_len = rref.len();
            Ok((bounce_phys, mapped_len, Some(rref)))
        } else {
            if matches!(direction, DmaDirection::ToDevice | DmaDirection::Bidirectional) {
                flush_cache_range(host_addr, size);
            }
            Ok((phys_addr, size, None))
        }
    }

    /// IOMMUマッピングを解決してデバイスアドレスを取得
    fn resolve_iommu_device_addr(
        &self,
        phys_addr: x86_64::PhysAddr,
        mapped_len: usize,
    ) -> Result<(u64, bool), DmaError> {
        if crate::io::iommu::api::is_iommu_enabled() {
            let map_result = if let Some(ref dev) = self.device_id {
                unsafe { crate::io::iommu::api::map_for_device(dev, phys_addr, mapped_len as u64) }
            } else {
                unsafe { crate::io::iommu::api::map_for_dma(phys_addr, mapped_len as u64) }
            };
            match map_result {
                Ok(iova) => Ok((iova, true)),
                Err(_) => Err(DmaError::IommuMappingFailed),
            }
        } else if crate::io::iommu::api::is_iommu_required() {
            Err(DmaError::IommuRequired)
        } else {
            if !crate::io::iommu::api::is_unsafe_identity_mapping_allowed() {
                return Err(DmaError::IommuRequired);
            }
            log::warn!("[DMA] IOMMU is not enabled; falling back to identity mapping (insecure)");
            Ok((phys_addr.as_u64(), false))
        }
    }
}

impl DmaAllocator for GlobalDmaAllocator {
    fn allocate_coherent(
        &self,
        size: usize,
        _direction: DmaDirection,
    ) -> Result<DmaAllocation, DmaError> {
        if crate::io::iommu::api::is_iommu_enabled() && size % DMA_ALIGNMENT != 0 {
            return Err(DmaError::InvalidAlignment);
        }
        let layout =
            Layout::from_size_align(size, DMA_ALIGNMENT).map_err(|_| DmaError::InvalidAlignment)?;

        let ptr = unsafe { alloc(layout) };
        if ptr.is_null() {
            return Err(DmaError::OutOfMemory);
        }

        // ゼロ初期化
        unsafe {
            core::ptr::write_bytes(ptr, 0, size);
        }

        // 仮想アドレスを物理アドレスに変換
        let phys_addr = crate::memory::virt_to_phys(x86_64::VirtAddr::new(ptr as u64));

        // IOMMUマッピング（セキュリティ方針: IOMMU_REQUIRED が真ならエラー）
        // device_id があればデバイス固有ドメインにマップ
        let (device_addr, iova_mapped) = if crate::io::iommu::api::is_iommu_enabled() {
            // SAFETY: Just allocated DMA-capable memory that we own
            let map_result = if let Some(ref dev) = self.device_id {
                unsafe { crate::io::iommu::api::map_for_device(dev, phys_addr, size as u64) }
            } else {
                unsafe { crate::io::iommu::api::map_for_dma(phys_addr, size as u64) }
            };
            match map_result {
                Ok(iova) => (iova, true),
                Err(_) => {
                    unsafe {
                        dealloc(ptr, layout);
                    }
                    return Err(DmaError::IommuMappingFailed);
                }
            }
        } else if crate::io::iommu::api::is_iommu_required() {
            // IOMMUが必須と設定されているが無効 -> エラー
            unsafe {
                dealloc(ptr, layout);
            }
            return Err(DmaError::IommuRequired);
        } else {
            if !crate::io::iommu::api::is_unsafe_identity_mapping_allowed() {
                unsafe {
                    dealloc(ptr, layout);
                }
                return Err(DmaError::IommuRequired);
            }
            // IOMMUが無効だが必須ではない: 警告を出してフォールバック（開発用）
            log::warn!("[DMA] IOMMU is not enabled; falling back to identity mapping (insecure)");
            (phys_addr.as_u64(), false)
        };

        Ok(DmaAllocation {
            ptr: NonNull::new(ptr).expect("alloc returned null pointer"),
            phys_addr,
            device_addr,
            size,
            layout,
            iova_mapped,
        })
    }

    fn map_streaming(
        &self,
        buffer: &[u8],
        direction: DmaDirection,
    ) -> Result<StreamingMapping, DmaError> {
        let host_addr = buffer.as_ptr();
        let size = buffer.len();
        if size == 0 {
            return Err(DmaError::InvalidSize);
        }
        let phys_addr = crate::memory::virt_to_phys(x86_64::VirtAddr::new(host_addr as u64));

        let (final_phys, mapped_len, bounce) =
            Self::prepare_streaming_buffer(buffer, phys_addr, direction)?;

        let (device_addr, iova_mapped) = self.resolve_iommu_device_addr(final_phys, mapped_len)?;

        Ok(StreamingMapping {
            host_addr,
            device_addr,
            size,
            mapped_len,
            direction,
            iova_mapped,
            bounce,
        })
    }

    fn unmap_streaming(&self, mut mapping: StreamingMapping) {
        if let Some(bounce) = mapping.bounce.as_mut() {
            if matches!(
                mapping.direction,
                DmaDirection::FromDevice | DmaDirection::Bidirectional
            ) {
                invalidate_cache_range(bounce.as_ptr(), mapping.mapped_len);
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        bounce.as_ptr(),
                        mapping.host_addr as *mut u8,
                        mapping.size,
                    );
                }
            }

            if mapping.iova_mapped {
                let _ = crate::io::iommu::api::unmap_dma(
                    mapping.device_addr,
                    mapping.mapped_len as u64,
                );
            }

            mapping.iova_mapped = false;
            mapping.bounce = None;
            return;
        }

        // キャッシュ操作
        if matches!(
            mapping.direction,
            DmaDirection::FromDevice | DmaDirection::Bidirectional
        ) {
            invalidate_cache_range(mapping.host_addr, mapping.size);
        }

        // IOMMUマッピング解除
        if mapping.iova_mapped {
            let _ =
                crate::io::iommu::api::unmap_dma(mapping.device_addr, mapping.mapped_len as u64);
        }
        mapping.iova_mapped = false;
    }

    fn device_address(&self, phys_addr: PhysAddr) -> u64 {
        // 既存のマッピングから検索するか、Identity mappingを返す
        phys_addr.as_u64()
    }

    fn iommu_enabled(&self) -> bool {
        crate::io::iommu::api::is_iommu_enabled()
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
    device_id: Option<crate::io::iommu::types::DeviceId>,
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
    ///
    /// DMAアドレス幅を制限する場合は `with_device_dma_mask` / `with_device_dma_width`
    /// を使用する。
    pub fn with_device(device_id: crate::io::iommu::types::DeviceId) -> Result<Self, DmaError> {
        let domain_id = if crate::io::iommu::api::is_iommu_enabled() {
            // IOMMUドメインを作成してデバイスをアタッチ
            crate::io::iommu::api::with_iommu(|iommu| {
                let numa_hint = Some(crate::mm::numa::current_node());
                let domain_id = iommu
                    .create_domain(
                        numa_hint,
                        crate::io::iommu::types::IommuDomainType::Translated,
                    )
                    .ok()?;
                iommu.attach_device(device_id.clone(), domain_id).ok()?;
                Some(domain_id)
            })
            .ok()
            .flatten()
        } else {
            None
        };

        Ok(Self {
            device_id: Some(device_id),
            domain_id,
            allocator: Arc::new(GlobalDmaAllocator::with_device(device_id.clone())),
        })
    }

    /// デバイスのDMAアドレスマスクを登録してからコンテキストを作成
    pub fn with_device_dma_mask(
        device_id: crate::io::iommu::types::DeviceId,
        mask: u64,
    ) -> Result<Self, DmaError> {
        crate::io::iommu::api::register_device_dma_mask(device_id, mask);
        Self::with_device(device_id)
    }

    /// デバイスのDMAアドレス幅を登録してからコンテキストを作成
    pub fn with_device_dma_width(
        device_id: crate::io::iommu::types::DeviceId,
        bits: u8,
    ) -> Result<Self, DmaError> {
        crate::io::iommu::api::register_device_dma_width(device_id, bits)
            .map_err(|_| DmaError::InvalidAddress)?;
        Self::with_device(device_id)
    }

    /// コヒーレントDMAバッファを割り当て
    pub fn allocate(
        &self,
        size: usize,
        direction: DmaDirection,
    ) -> Result<DmaAllocation, DmaError> {
        self.allocator.allocate_coherent(size, direction)
    }

    /// RRef-backed DMA mapping (safe IOMMU API)
    ///
    /// Returns a `DmaHandle<T>` that must be explicitly unmapped to recover the `RRef<T>`.
    pub fn map_rref<T>(
        &self,
        rref: crate::ipc::RRef<T>,
        direction: DmaDirection,
    ) -> Result<crate::io::iommu::api::DmaHandle<T>, crate::io::iommu::api::MapError<T>> {
        let iommu_direction = direction.into();
        if let Some(device) = self.device_id {
            crate::io::iommu::api::map_rref_for_device(rref, &device, iommu_direction)
        } else {
            let domain_id = self.domain_id.unwrap_or(0);
            crate::io::iommu::dma_handle::DmaHandle::map_rref(rref, domain_id, iommu_direction)
        }
    }

    /// RRef-backed DMA slice mapping (safe IOMMU API)
    ///
    /// Returns a `DmaHandle<[T]>` that must be explicitly unmapped to recover the `RRef<[T]>`.
    pub fn map_rref_slice<T>(
        &self,
        rref: crate::ipc::RRef<[T]>,
        direction: DmaDirection,
    ) -> Result<crate::io::iommu::api::DmaHandle<[T]>, crate::io::iommu::api::MapError<[T]>> {
        let iommu_direction = direction.into();
        if let Some(device) = self.device_id {
            crate::io::iommu::api::map_rref_slice_for_device(rref, &device, iommu_direction)
        } else {
            let domain_id = self.domain_id.unwrap_or(0);
            crate::io::iommu::dma_handle::DmaHandle::map_rref_slice(
                rref,
                domain_id,
                iommu_direction,
            )
        }
    }

    /// Map an `RRef<T>` into IOMMU space and return a DMA buffer handle.
    pub fn map_rref_buffer<T>(
        &self,
        rref: crate::ipc::RRef<T>,
        direction: DmaDirection,
    ) -> Result<RRefDmaBuffer<T>, crate::io::iommu::api::MapError<T>> {
        RRefDmaBuffer::map(self, rref, direction)
    }

    /// Map an `RRef<[T]>` slice into IOMMU space and return a DMA buffer handle.
    pub fn map_rref_slice_buffer<T>(
        &self,
        rref: crate::ipc::RRef<[T]>,
        direction: DmaDirection,
    ) -> Result<RRefDmaBuffer<[T]>, crate::io::iommu::api::MapError<[T]>> {
        self.map_rref_slice(rref, direction)
            .map(|handle| RRefDmaBuffer { handle })
    }

    /// Map an `RRef<[u8]>` slice into IOMMU space and return a byte buffer handle.
    pub fn map_rref_bytes(
        &self,
        rref: crate::ipc::RRef<[u8]>,
        direction: DmaDirection,
    ) -> Result<RRefDmaBytes, crate::io::iommu::api::MapError<[u8]>> {
        let len = rref.len();
        self.map_rref_slice_buffer(rref, direction)
            .map(|buffer| RRefDmaBytes { buffer, len })
    }

    /// Allocate a kernel-owned `RRef<[T]>` slice (4K-aligned) and map it into IOMMU space.
    pub fn map_rref_kernel_slice_default<T>(
        &self,
        len: usize,
        direction: DmaDirection,
    ) -> Result<RRefDmaBuffer<[T]>, crate::io::iommu::api::MapError<[T]>>
    where
        T: Default,
    {
        let rref = crate::ipc::RRef::new_slice_default_aligned(
            crate::ipc::DomainId::KERNEL,
            len,
            crate::mm::PAGE_SIZE_4K,
        )
        .expect("exchange heap allocation failed");
        self.map_rref_slice_buffer(rref, direction)
    }

    /// Allocate a kernel-owned byte buffer (page-aligned size) and map it.
    pub fn map_rref_kernel_bytes(
        &self,
        len: usize,
        direction: DmaDirection,
    ) -> Result<RRefDmaBytes, crate::io::iommu::api::MapError<[u8]>> {
        if len == 0 {
            panic!("zero-length DMA buffer");
        }
        let rref = allocate_iommu_bounce_bytes(len).unwrap_or_else(|err| match err {
            IommuBounceAllocError::InvalidLen => panic!("invalid alignment"),
            IommuBounceAllocError::AllocFailed => panic!("exchange heap allocation failed"),
        });
        self.map_rref_slice_buffer(rref, direction)
            .map(|buffer| RRefDmaBytes { buffer, len })
    }

    /// Try to allocate a kernel-owned `RRef<[T]>` slice (4K-aligned) and map it into IOMMU space.
    pub fn try_map_rref_kernel_slice_default<T>(
        &self,
        len: usize,
        direction: DmaDirection,
    ) -> Result<RRefDmaBuffer<[T]>, RRefSliceMapError<T>>
    where
        T: Default,
    {
        let rref = crate::ipc::RRef::new_slice_default_aligned(
            crate::ipc::DomainId::KERNEL,
            len,
            crate::mm::PAGE_SIZE_4K,
        )
        .ok_or(RRefSliceMapError::AllocFailed)?;
        self.map_rref_slice_buffer(rref, direction)
            .map_err(RRefSliceMapError::MapError)
    }

    /// Try to allocate a kernel-owned byte buffer (page-aligned size) and map it.
    pub fn try_map_rref_kernel_bytes(
        &self,
        len: usize,
        direction: DmaDirection,
    ) -> Result<RRefDmaBytes, RRefSliceMapError<u8>> {
        if len == 0 {
            return Err(RRefSliceMapError::AllocFailed);
        }
        let rref = allocate_iommu_bounce_bytes(len).map_err(|_| RRefSliceMapError::AllocFailed)?;
        self.map_rref_slice_buffer(rref, direction)
            .map(|buffer| RRefDmaBytes { buffer, len })
            .map_err(RRefSliceMapError::MapError)
    }

    /// Allocate a kernel-owned `RRef<[T]>` slice (4K-aligned) with an initializer and map it.
    pub fn map_rref_kernel_slice_with<T, F>(
        &self,
        len: usize,
        init: F,
        direction: DmaDirection,
    ) -> Result<RRefDmaBuffer<[T]>, crate::io::iommu::api::MapError<[T]>>
    where
        F: FnMut(usize) -> T,
    {
        let rref = crate::ipc::RRef::new_slice_with_aligned(
            crate::ipc::DomainId::KERNEL,
            len,
            crate::mm::PAGE_SIZE_4K,
            init,
        )
        .expect("exchange heap allocation failed");
        self.map_rref_slice_buffer(rref, direction)
    }

    /// Try to allocate a kernel-owned `RRef<[T]>` slice (4K-aligned) with an initializer and map it.
    pub fn try_map_rref_kernel_slice_with<T, F>(
        &self,
        len: usize,
        init: F,
        direction: DmaDirection,
    ) -> Result<RRefDmaBuffer<[T]>, RRefSliceMapError<T>>
    where
        F: FnMut(usize) -> T,
    {
        let rref = crate::ipc::RRef::new_slice_with_aligned(
            crate::ipc::DomainId::KERNEL,
            len,
            crate::mm::PAGE_SIZE_4K,
            init,
        )
        .ok_or(RRefSliceMapError::AllocFailed)?;
        self.map_rref_slice_buffer(rref, direction)
            .map_err(RRefSliceMapError::MapError)
    }

    /// Allocate a kernel-owned `RRef<T>` and map it into IOMMU space.
    pub fn map_rref_kernel<T>(
        &self,
        value: T,
        direction: DmaDirection,
    ) -> Result<RRefDmaBuffer<T>, crate::io::iommu::api::MapError<T>> {
        RRefDmaBuffer::map_kernel(self, value, direction)
    }

    /// Try to allocate a kernel-owned `RRef<T>` and map it into IOMMU space.
    pub fn try_map_rref_kernel<T>(
        &self,
        value: T,
        direction: DmaDirection,
    ) -> Result<RRefDmaBuffer<T>, RRefMapError<T>> {
        RRefDmaBuffer::try_map_kernel(self, value, direction)
    }

    /// Try to allocate a default kernel-owned `RRef<T>` and map it into IOMMU space.
    pub fn try_map_rref_kernel_default<T>(
        &self,
        direction: DmaDirection,
    ) -> Result<RRefDmaBuffer<T>, RRefMapError<T>>
    where
        T: Default,
    {
        RRefDmaBuffer::try_map_kernel_default(self, direction)
    }

    /// Allocate a default kernel-owned `RRef<T>` and map it into IOMMU space.
    pub fn map_rref_kernel_default<T>(
        &self,
        direction: DmaDirection,
    ) -> Result<RRefDmaBuffer<T>, crate::io::iommu::api::MapError<T>>
    where
        T: Default,
    {
        RRefDmaBuffer::map_kernel_default(self, direction)
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
            let _ = crate::io::iommu::api::with_iommu(|iommu| {
                let _ = iommu.detach_device(device_id);
            });
        }
    }
}

/// キャッシュラインサイズを取得
pub fn cache_line_size() -> usize {
    let result: u32;
    unsafe {
        asm!(
            "mov eax, 1", "cpuid", "mov {0:e}, ebx",
            out(reg) result, out("eax") _, out("ecx") _, out("edx") _,
            options(nostack, preserves_flags)
        );
    }
    (((result >> 8) & 0xFF) * 8) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
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

        // DMA転送完了 (guard.complete(dev) を使用)
        let buffer = guard.complete(device_buffer);
        assert_eq!(*buffer.as_ref(), 42);
    }

    #[test_case]
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
        let (device_slice, guard) = slice.start_dma();
        // device_slice.as_slice(); // ERROR! DeviceOwnedでは不可

        // DMA転送完了 (guard.complete(dev) を使用)
        let cpu_slice = guard.complete(device_slice);
        assert_eq!(cpu_slice.as_slice()[0], 0xDE);
    }
}

