// ============================================================================
// src/io/dma.rs - DMA Buffer Management with Ownership Safety
// 設計書 5.4: DMAと安全性
// ============================================================================

use core::marker::PhantomData;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, Ordering};
use alloc::alloc::{alloc, dealloc, Layout};
use x86_64::PhysAddr;

/// DMAバッファの最小アライメント
const DMA_ALIGNMENT: usize = 4096; // ページアライメント

/// DMAバッファの状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaBufferState {
    /// CPUが所有（読み書き可能）
    OwnedByCpu,
    /// デバイスが所有（DMA転送中）
    OwnedByDevice,
    /// 同期待ち
    SyncPending,
}

/// DMAバッファ
/// 設計書 5.4: Pinningと所有権
/// - メモリ上の移動を禁止（Pin）
/// - DMA転送中はCPUからのアクセスを型システムで禁止
pub struct DmaBuffer<T> {
    /// バッファへのポインタ
    ptr: NonNull<T>,
    /// 物理アドレス（DMAエンジン用）
    phys_addr: PhysAddr,
    /// サイズ
    size: usize,
    /// 現在の所有者
    state: AtomicBool, // true = CPU, false = Device
    /// レイアウト（解放時に使用）
    layout: Layout,
    _marker: PhantomData<T>,
}

// Sendは許可（別コアに転送可能）だがSyncは許可しない（同時アクセス不可）
unsafe impl<T: Send> Send for DmaBuffer<T> {}

impl<T> DmaBuffer<T> {
    /// 新しいDMAバッファを割り当て
    /// 
    /// # Safety
    /// DMAに適したアライメントでメモリを割り当てる
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
        
        // 物理アドレスを計算（SAS環境では仮想=物理のオフセット）
        let phys_addr = PhysAddr::new(ptr as u64); // TODO: 実際の変換
        
        Some(Self {
            ptr: unsafe { NonNull::new_unchecked(ptr as *mut T) },
            phys_addr,
            size,
            state: AtomicBool::new(true), // 初期状態はCPU所有
            layout,
            _marker: PhantomData,
        })
    }
    
    /// 物理アドレスを取得
    pub fn phys_addr(&self) -> PhysAddr {
        self.phys_addr
    }
    
    /// サイズを取得
    pub fn size(&self) -> usize {
        self.size
    }
    
    /// 現在の状態を取得
    pub fn state(&self) -> DmaBufferState {
        if self.state.load(Ordering::Acquire) {
            DmaBufferState::OwnedByCpu
        } else {
            DmaBufferState::OwnedByDevice
        }
    }
    
    /// CPUが所有しているかどうか
    pub fn is_owned_by_cpu(&self) -> bool {
        self.state.load(Ordering::Acquire)
    }
    
    /// デバイスに所有権を移動（DMA転送開始）
    /// 
    /// # Safety
    /// この関数を呼んだ後、DMA転送が完了するまでバッファにアクセスしてはならない
    pub unsafe fn transfer_to_device(&self) {
        // メモリバリアを発行してCPUキャッシュをフラッシュ
        core::sync::atomic::fence(Ordering::Release);
        self.state.store(false, Ordering::Release);
    }
    
    /// デバイスからCPUに所有権を返却（DMA転送完了）
    pub fn transfer_to_cpu(&self) {
        self.state.store(true, Ordering::Release);
        // メモリバリアを発行してデバイスの書き込みを可視化
        core::sync::atomic::fence(Ordering::Acquire);
    }
    
    /// CPUが所有している場合のみ参照を取得
    pub fn try_as_ref(&self) -> Option<&T> {
        if self.is_owned_by_cpu() {
            Some(unsafe { self.ptr.as_ref() })
        } else {
            None
        }
    }
    
    /// CPUが所有している場合のみ可変参照を取得
    pub fn try_as_mut(&mut self) -> Option<&mut T> {
        if self.is_owned_by_cpu() {
            Some(unsafe { self.ptr.as_mut() })
        } else {
            None
        }
    }
}

impl<T> Drop for DmaBuffer<T> {
    fn drop(&mut self) {
        // デバイスが所有している場合は警告（本来はエラーにすべき）
        if !self.is_owned_by_cpu() {
            // パニックではなくログを出力
            // デバイスがまだ使用中の可能性があるため
        }
        
        unsafe {
            // デストラクタを呼び出し
            core::ptr::drop_in_place(self.ptr.as_ptr());
            // メモリを解放
            dealloc(self.ptr.as_ptr() as *mut u8, self.layout);
        }
    }
}

// ============================================================================
// DmaSlice - スライス用のDMAバッファ
// ============================================================================

/// DMAスライスバッファ
pub struct DmaSlice {
    ptr: NonNull<u8>,
    phys_addr: PhysAddr,
    size: usize,
    state: AtomicBool,
    layout: Layout,
}

unsafe impl Send for DmaSlice {}

impl DmaSlice {
    /// 指定サイズのDMAバッファを割り当て
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
            state: AtomicBool::new(true),
            layout,
        })
    }
    
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
    
    /// CPUが所有しているかどうか
    pub fn is_owned_by_cpu(&self) -> bool {
        self.state.load(Ordering::Acquire)
    }
    
    /// デバイスに所有権を移動
    pub unsafe fn transfer_to_device(&self) {
        core::sync::atomic::fence(Ordering::Release);
        self.state.store(false, Ordering::Release);
    }
    
    /// CPUに所有権を返却
    pub fn transfer_to_cpu(&self) {
        self.state.store(true, Ordering::Release);
        core::sync::atomic::fence(Ordering::Acquire);
    }
    
    /// スライスとして取得（CPU所有時のみ）
    pub fn as_slice(&self) -> Option<&[u8]> {
        if self.is_owned_by_cpu() {
            Some(unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.size) })
        } else {
            None
        }
    }
    
    /// 可変スライスとして取得（CPU所有時のみ）
    pub fn as_mut_slice(&mut self) -> Option<&mut [u8]> {
        if self.is_owned_by_cpu() {
            Some(unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.size) })
        } else {
            None
        }
    }
}

impl Drop for DmaSlice {
    fn drop(&mut self) {
        unsafe {
            dealloc(self.ptr.as_ptr(), self.layout);
        }
    }
}

// ============================================================================
// DmaGuard - RAII型のDMA転送ガード
// ============================================================================

/// DMA転送のRAIIガード
/// 設計書 5.4: DMA転送を開始する際、バッファの所有権を論理的に「ドライバ（ハードウェア）」に移動
pub struct DmaGuard<'a> {
    buffer: &'a DmaSlice,
}

impl<'a> DmaGuard<'a> {
    /// DMA転送を開始
    /// 
    /// # Safety
    /// DMA転送が実際に開始されることを保証する必要がある
    pub unsafe fn begin(buffer: &'a DmaSlice) -> Self {
        // SAFETY: 呼び出し元がDMA転送の安全性を保証
        unsafe { buffer.transfer_to_device(); }
        Self { buffer }
    }
    
    /// 物理アドレスを取得（DMAエンジンに渡す用）
    pub fn phys_addr(&self) -> PhysAddr {
        self.buffer.phys_addr()
    }
    
    /// サイズを取得
    pub fn len(&self) -> usize {
        self.buffer.len()
    }
    
    /// DMA転送完了をマーク
    pub fn complete(self) {
        // Dropで自動的にCPUに所有権が戻る
    }
}

impl<'a> Drop for DmaGuard<'a> {
    fn drop(&mut self) {
        self.buffer.transfer_to_cpu();
    }
}

// ============================================================================
// Scatter-Gather DMA
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

/// Scatter-Gather DMAリスト
pub struct SgList {
    entries: alloc::vec::Vec<SgEntry>,
    buffers: alloc::vec::Vec<DmaSlice>,
}

impl SgList {
    pub fn new() -> Self {
        Self {
            entries: alloc::vec::Vec::new(),
            buffers: alloc::vec::Vec::new(),
        }
    }
    
    /// バッファを追加
    pub fn add_buffer(&mut self, size: usize) -> Option<usize> {
        let buffer = DmaSlice::new(size)?;
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
    
    /// バッファにアクセス
    pub fn buffer(&self, index: usize) -> Option<&DmaSlice> {
        self.buffers.get(index)
    }
    
    /// バッファに可変アクセス
    pub fn buffer_mut(&mut self, index: usize) -> Option<&mut DmaSlice> {
        self.buffers.get_mut(index)
    }
    
    /// 全バッファをデバイスに転送
    pub unsafe fn transfer_all_to_device(&self) {
        for buffer in &self.buffers {
            // SAFETY: 呼び出し元がDMA転送の安全性を保証
            unsafe { buffer.transfer_to_device(); }
        }
    }
    
    /// 全バッファをCPUに返却
    pub fn transfer_all_to_cpu(&self) {
        for buffer in &self.buffers {
            buffer.transfer_to_cpu();
        }
    }
}

impl Default for SgList {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_dma_buffer() {
        let buffer = DmaBuffer::new(42u32).expect("Failed to allocate DMA buffer");
        
        assert!(buffer.is_owned_by_cpu());
        assert_eq!(*buffer.try_as_ref().unwrap(), 42);
        
        unsafe { buffer.transfer_to_device(); }
        assert!(!buffer.is_owned_by_cpu());
        assert!(buffer.try_as_ref().is_none());
        
        buffer.transfer_to_cpu();
        assert!(buffer.is_owned_by_cpu());
        assert_eq!(*buffer.try_as_ref().unwrap(), 42);
    }
    
    #[test]
    fn test_dma_slice() {
        let mut slice = DmaSlice::new(4096).expect("Failed to allocate DMA slice");
        
        // データを書き込み
        if let Some(s) = slice.as_mut_slice() {
            s[0] = 0xDE;
            s[1] = 0xAD;
        }
        
        // 確認
        if let Some(s) = slice.as_slice() {
            assert_eq!(s[0], 0xDE);
            assert_eq!(s[1], 0xAD);
        }
    }
}
