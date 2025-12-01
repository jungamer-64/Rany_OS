// ============================================================================
// src/io/virtio_net.rs - VirtIO Network Device Driver
// 設計書 6.2: ネットワークスタック：真のゼロコピー
// 設計書 7.1: VirtIOドライバのRust実装
// ============================================================================
#![allow(dead_code)]

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use core::sync::atomic::{AtomicU16, AtomicU32, AtomicBool, Ordering};
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

use super::dma::{TypedDmaBuffer, CpuOwned, DeviceOwned, DmaState};

// ============================================================================
// VirtIO Net Device Feature Flags
// ============================================================================

pub mod features {
    /// デバイスはチェックサムオフロードをサポート
    pub const VIRTIO_NET_F_CSUM: u64 = 1 << 0;
    /// ゲストはチェックサムオフロードを使用可能
    pub const VIRTIO_NET_F_GUEST_CSUM: u64 = 1 << 1;
    /// MTU設定をサポート
    pub const VIRTIO_NET_F_MTU: u64 = 1 << 3;
    /// MACアドレスをサポート
    pub const VIRTIO_NET_F_MAC: u64 = 1 << 5;
    /// TCPセグメンテーションオフロード
    pub const VIRTIO_NET_F_GSO: u64 = 1 << 6;
    /// ゲストTSO4
    pub const VIRTIO_NET_F_GUEST_TSO4: u64 = 1 << 7;
    /// ゲストTSO6
    pub const VIRTIO_NET_F_GUEST_TSO6: u64 = 1 << 8;
    /// マルチキューサポート
    pub const VIRTIO_NET_F_MQ: u64 = 1 << 22;
    /// CTRL_VQサポート
    pub const VIRTIO_NET_F_CTRL_VQ: u64 = 1 << 17;
    /// 割り込み抑制
    pub const VIRTIO_NET_F_NOTIF_COAL: u64 = 1 << 52;
}

// ============================================================================
// VirtIO Net Header
// ============================================================================

/// VirtIO ネットワークヘッダ
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtioNetHeader {
    /// フラグ
    pub flags: u8,
    /// GSOタイプ
    pub gso_type: u8,
    /// ヘッダ長
    pub hdr_len: u16,
    /// GSOサイズ
    pub gso_size: u16,
    /// チェックサム開始オフセット
    pub csum_start: u16,
    /// チェックサムオフセット
    pub csum_offset: u16,
    /// バッファ数（マルチバッファモード用）
    pub num_buffers: u16,
}

impl VirtioNetHeader {
    pub const SIZE: usize = core::mem::size_of::<Self>();
    
    /// 単純な送信用ヘッダを作成
    pub fn new_tx() -> Self {
        Self::default()
    }
}

// ============================================================================
// VirtQueue for Network
// ============================================================================

/// VirtQueue ディスクリプタ
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VringDesc {
    /// バッファの物理アドレス
    pub addr: u64,
    /// バッファの長さ
    pub len: u32,
    /// フラグ
    pub flags: u16,
    /// 次のディスクリプタのインデックス
    pub next: u16,
}

impl VringDesc {
    /// 書き込み可能フラグ
    pub const VRING_DESC_F_WRITE: u16 = 2;
    /// 次のディスクリプタが続くフラグ
    pub const VRING_DESC_F_NEXT: u16 = 1;
}

/// VirtQueue Available Ring
#[repr(C)]
pub struct VringAvail {
    pub flags: u16,
    pub idx: u16,
    pub ring: [u16; 256],
}

/// VirtQueue Used Ring Element
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VringUsedElem {
    pub id: u32,
    pub len: u32,
}

/// VirtQueue Used Ring
#[repr(C)]
pub struct VringUsed {
    pub flags: u16,
    pub idx: u16,
    pub ring: [VringUsedElem; 256],
}

/// ネットワーク VirtQueue
pub struct NetVirtQueue {
    /// キューインデックス (0=RX, 1=TX)
    pub index: u16,
    /// キューサイズ
    pub size: u16,
    /// ディスクリプタテーブル
    desc_table: *mut VringDesc,
    /// Available Ring
    avail_ring: *mut VringAvail,
    /// Used Ring
    used_ring: *mut VringUsed,
    /// 次の空きディスクリプタ
    next_free_desc: AtomicU16,
    /// 最後に処理した Used インデックス
    last_used_idx: AtomicU16,
    /// 割り込み待機中のWaker
    pending_wakers: Mutex<Vec<Waker>>,
    /// ペンディングバッファの追跡 (desc_id -> callback)
    pending_buffers: Mutex<Vec<Option<PendingBuffer>>>,
}

/// ペンディングバッファ情報
struct PendingBuffer {
    /// 元のバッファアドレス
    buffer_addr: usize,
    /// バッファサイズ
    buffer_size: usize,
    /// 完了時のWaker
    waker: Option<Waker>,
}

impl NetVirtQueue {
    /// 新しいVirtQueueを作成
    /// 
    /// # Safety
    /// desc_table, avail_ring, used_ring は有効なDMA可能メモリを指している必要がある
    pub unsafe fn new(
        index: u16,
        size: u16,
        desc_table: *mut VringDesc,
        avail_ring: *mut VringAvail,
        used_ring: *mut VringUsed,
    ) -> Self {
        // ペンディングバッファ配列を初期化
        let mut pending = Vec::with_capacity(size as usize);
        pending.resize_with(size as usize, || None);
        
        Self {
            index,
            size,
            desc_table,
            avail_ring,
            used_ring,
            next_free_desc: AtomicU16::new(0),
            last_used_idx: AtomicU16::new(0),
            pending_wakers: Mutex::new(Vec::new()),
            pending_buffers: Mutex::new(pending),
        }
    }
    
    /// ディスクリプタを割り当て
    fn alloc_desc(&self) -> Option<u16> {
        let idx = self.next_free_desc.fetch_add(1, Ordering::AcqRel);
        if idx < self.size {
            Some(idx)
        } else {
            self.next_free_desc.fetch_sub(1, Ordering::AcqRel);
            None
        }
    }
    
    /// 送信バッファを追加
    pub fn add_tx_buffer(&self, header: &VirtioNetHeader, data: &[u8]) -> Result<u16, VirtioNetError> {
        let desc_idx = self.alloc_desc().ok_or(VirtioNetError::QueueFull)?;
        
        unsafe {
            // ディスクリプタを設定
            let desc = &mut *self.desc_table.add(desc_idx as usize);
            desc.addr = data.as_ptr() as u64;
            desc.len = (VirtioNetHeader::SIZE + data.len()) as u32;
            desc.flags = 0;
            desc.next = 0;
            
            // Available Ringに追加
            let avail = &mut *self.avail_ring;
            let avail_idx = avail.idx;
            avail.ring[(avail_idx % self.size) as usize] = desc_idx;
            
            // メモリバリア
            core::sync::atomic::fence(Ordering::Release);
            
            avail.idx = avail_idx.wrapping_add(1);
        }
        
        Ok(desc_idx)
    }
    
    /// 受信バッファを追加
    pub fn add_rx_buffer(&self, buffer: &mut [u8]) -> Result<u16, VirtioNetError> {
        let desc_idx = self.alloc_desc().ok_or(VirtioNetError::QueueFull)?;
        
        unsafe {
            // ディスクリプタを設定（書き込み可能）
            let desc = &mut *self.desc_table.add(desc_idx as usize);
            desc.addr = buffer.as_ptr() as u64;
            desc.len = buffer.len() as u32;
            desc.flags = VringDesc::VRING_DESC_F_WRITE;
            desc.next = 0;
            
            // Available Ringに追加
            let avail = &mut *self.avail_ring;
            let avail_idx = avail.idx;
            avail.ring[(avail_idx % self.size) as usize] = desc_idx;
            
            core::sync::atomic::fence(Ordering::Release);
            
            avail.idx = avail_idx.wrapping_add(1);
        }
        
        Ok(desc_idx)
    }
    
    /// 完了したバッファを処理
    pub fn process_used(&self) -> Vec<(u16, u32)> {
        let mut completed = Vec::new();
        
        unsafe {
            let used = &*self.used_ring;
            let mut last_idx = self.last_used_idx.load(Ordering::Acquire);
            
            while last_idx != used.idx {
                let elem = &used.ring[(last_idx % self.size) as usize];
                completed.push((elem.id as u16, elem.len));
                last_idx = last_idx.wrapping_add(1);
            }
            
            self.last_used_idx.store(last_idx, Ordering::Release);
        }
        
        // 完了したバッファのWakerを起動
        if !completed.is_empty() {
            let wakers: Vec<Waker> = self.pending_wakers.lock().drain(..).collect();
            for waker in wakers {
                waker.wake();
            }
        }
        
        completed
    }
    
    /// Wakerを登録
    pub fn register_waker(&self, waker: Waker) {
        self.pending_wakers.lock().push(waker);
    }
    
    /// ペンディングバッファがあるかチェック
    pub fn has_pending(&self) -> bool {
        unsafe {
            let used = &*self.used_ring;
            let last_idx = self.last_used_idx.load(Ordering::Acquire);
            last_idx != used.idx
        }
    }
}

// ============================================================================
// VirtIO Net Device
// ============================================================================

/// VirtIO ネットワークデバイス設定
#[derive(Debug, Clone)]
pub struct VirtioNetConfig {
    /// MACアドレス
    pub mac: [u8; 6],
    /// 最大キュー数
    pub max_queues: u16,
    /// MTU
    pub mtu: u16,
}

impl Default for VirtioNetConfig {
    fn default() -> Self {
        Self {
            mac: [0x52, 0x54, 0x00, 0x12, 0x34, 0x56], // QEMU default
            max_queues: 1,
            mtu: 1500,
        }
    }
}

/// VirtIO ネットワークデバイス
pub struct VirtioNetDevice {
    /// デバイスベースアドレス
    base_addr: usize,
    /// 設定
    config: VirtioNetConfig,
    /// 受信キュー
    rx_queue: Option<NetVirtQueue>,
    /// 送信キュー
    tx_queue: Option<NetVirtQueue>,
    /// 初期化済みフラグ
    initialized: AtomicBool,
    /// 統計: 送信パケット数
    tx_packets: AtomicU32,
    /// 統計: 受信パケット数
    rx_packets: AtomicU32,
    /// 統計: 送信バイト数
    tx_bytes: AtomicU32,
    /// 統計: 受信バイト数
    rx_bytes: AtomicU32,
}

impl VirtioNetDevice {
    /// 新しいデバイスを作成
    pub const fn new(base_addr: usize) -> Self {
        Self {
            base_addr,
            config: VirtioNetConfig {
                mac: [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
                max_queues: 1,
                mtu: 1500,
            },
            rx_queue: None,
            tx_queue: None,
            initialized: AtomicBool::new(false),
            tx_packets: AtomicU32::new(0),
            rx_packets: AtomicU32::new(0),
            tx_bytes: AtomicU32::new(0),
            rx_bytes: AtomicU32::new(0),
        }
    }
    
    /// デバイスを初期化
    pub fn init(&mut self) -> Result<(), VirtioNetError> {
        // VirtIOデバイスの初期化シーケンス
        // 1. デバイスリセット
        // 2. ACKNOWLEDGEビット設定
        // 3. DRIVERビット設定
        // 4. Feature negotiation
        // 5. FEATURES_OKビット設定
        // 6. キューの設定
        // 7. DRIVER_OKビット設定
        
        // TODO: 実際のMMIOレジスタ操作を実装
        
        self.initialized.store(true, Ordering::Release);
        Ok(())
    }
    
    /// パケットを送信（非同期）
    pub fn send_async(&self, data: &[u8]) -> SendFuture<'_> {
        SendFuture {
            device: self,
            data: data.as_ptr(),
            len: data.len(),
            submitted: false,
        }
    }
    
    /// パケットを受信（非同期）
    pub fn recv_async<'a>(&'a self, buffer: &'a mut [u8]) -> RecvFuture<'a> {
        RecvFuture {
            device: self,
            buffer,
            submitted: false,
        }
    }
    
    /// MACアドレスを取得
    pub fn mac_address(&self) -> [u8; 6] {
        self.config.mac
    }
    
    /// 割り込みハンドラ
    pub fn handle_interrupt(&self) {
        // RXキューを処理
        if let Some(ref rx_queue) = self.rx_queue {
            let completed = rx_queue.process_used();
            self.rx_packets.fetch_add(completed.len() as u32, Ordering::Relaxed);
        }
        
        // TXキューを処理
        if let Some(ref tx_queue) = self.tx_queue {
            let completed = tx_queue.process_used();
            self.tx_packets.fetch_add(completed.len() as u32, Ordering::Relaxed);
        }
        
        // 適応的ポーリングコントローラに通知
        super::polling::net_io_controller().notify_packet_processed(1);
    }
    
    /// 統計を取得
    pub fn stats(&self) -> VirtioNetStats {
        VirtioNetStats {
            tx_packets: self.tx_packets.load(Ordering::Relaxed),
            rx_packets: self.rx_packets.load(Ordering::Relaxed),
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
        }
    }
}

// ============================================================================
// Async Futures
// ============================================================================

/// 送信用Future
pub struct SendFuture<'a> {
    device: &'a VirtioNetDevice,
    data: *const u8,
    len: usize,
    submitted: bool,
}

impl<'a> Future for SendFuture<'a> {
    type Output = Result<usize, VirtioNetError>;
    
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.submitted {
            // 送信をキューに追加
            if let Some(ref tx_queue) = self.device.tx_queue {
                let header = VirtioNetHeader::new_tx();
                let data = unsafe { core::slice::from_raw_parts(self.data, self.len) };
                
                match tx_queue.add_tx_buffer(&header, data) {
                    Ok(_) => {
                        self.submitted = true;
                        tx_queue.register_waker(cx.waker().clone());
                        
                        // デバイスに通知
                        // TODO: virtio_notify()
                    }
                    Err(e) => return Poll::Ready(Err(e)),
                }
            } else {
                return Poll::Ready(Err(VirtioNetError::NotInitialized));
            }
        }
        
        // 完了を確認
        if let Some(ref tx_queue) = self.device.tx_queue {
            if tx_queue.has_pending() {
                Poll::Ready(Ok(self.len))
            } else {
                tx_queue.register_waker(cx.waker().clone());
                Poll::Pending
            }
        } else {
            Poll::Ready(Err(VirtioNetError::NotInitialized))
        }
    }
}

/// 受信用Future
pub struct RecvFuture<'a> {
    device: &'a VirtioNetDevice,
    buffer: &'a mut [u8],
    submitted: bool,
}

impl<'a> Future for RecvFuture<'a> {
    type Output = Result<usize, VirtioNetError>;
    
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.submitted {
            // 受信バッファをキューに追加
            if let Some(ref rx_queue) = self.device.rx_queue {
                match rx_queue.add_rx_buffer(self.buffer) {
                    Ok(_) => {
                        self.submitted = true;
                        rx_queue.register_waker(cx.waker().clone());
                    }
                    Err(e) => return Poll::Ready(Err(e)),
                }
            } else {
                return Poll::Ready(Err(VirtioNetError::NotInitialized));
            }
        }
        
        // 完了を確認
        if let Some(ref rx_queue) = self.device.rx_queue {
            let completed = rx_queue.process_used();
            if let Some((_, len)) = completed.first() {
                Poll::Ready(Ok(*len as usize))
            } else {
                rx_queue.register_waker(cx.waker().clone());
                Poll::Pending
            }
        } else {
            Poll::Ready(Err(VirtioNetError::NotInitialized))
        }
    }
}

// ============================================================================
// Error Types
// ============================================================================

/// VirtIO ネットワークエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VirtioNetError {
    /// デバイスが初期化されていない
    NotInitialized,
    /// キューが満杯
    QueueFull,
    /// バッファが不足
    BufferTooSmall,
    /// デバイスエラー
    DeviceError,
    /// タイムアウト
    Timeout,
}

impl core::fmt::Display for VirtioNetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VirtioNetError::NotInitialized => write!(f, "Device not initialized"),
            VirtioNetError::QueueFull => write!(f, "Queue is full"),
            VirtioNetError::BufferTooSmall => write!(f, "Buffer too small"),
            VirtioNetError::DeviceError => write!(f, "Device error"),
            VirtioNetError::Timeout => write!(f, "Operation timed out"),
        }
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// VirtIO ネットワーク統計
#[derive(Debug, Clone)]
pub struct VirtioNetStats {
    pub tx_packets: u32,
    pub rx_packets: u32,
    pub tx_bytes: u32,
    pub rx_bytes: u32,
}

// ============================================================================
// Global Device Instance
// ============================================================================

static VIRTIO_NET_DEVICE: Mutex<Option<VirtioNetDevice>> = Mutex::new(None);

/// VirtIO ネットワークデバイスを初期化
pub fn init_virtio_net(base_addr: usize) -> Result<(), VirtioNetError> {
    let mut device = VirtioNetDevice::new(base_addr);
    device.init()?;
    *VIRTIO_NET_DEVICE.lock() = Some(device);
    Ok(())
}

/// VirtIO ネットワークデバイスにアクセス
pub fn with_virtio_net<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&VirtioNetDevice) -> R,
{
    VIRTIO_NET_DEVICE.lock().as_ref().map(f)
}

/// 割り込みハンドラ
pub fn handle_virtio_net_interrupt() {
    if let Some(ref device) = *VIRTIO_NET_DEVICE.lock() {
        device.handle_interrupt();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_virtio_net_header() {
        let header = VirtioNetHeader::new_tx();
        assert_eq!(header.flags, 0);
        assert_eq!(VirtioNetHeader::SIZE, 12);
    }
}
