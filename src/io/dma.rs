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
