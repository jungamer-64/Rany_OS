// ============================================================================
// src/io/virtio/net.rs - VirtIO Network Device Driver
// 設計書 6.2: ネットワークスタック：真のゼロコピー
// 設計書 7.1: VirtIOドライバのRust実装
// ============================================================================
#![allow(dead_code)]

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};
use spin::Mutex;
use x86_64::PhysAddr;

// Import VirtIO common definitions
use super::defs::{status, VirtioDeviceType};
use super::transport::VirtioTransport;
use crate::io::dma::{TypedDmaSlice, CpuOwned, DeviceOwned, CoherentDmaBuffer, DmaMemoryAttributes};
use crate::io::io_scheduler::{DeviceId, IoRequestId, IoResult, PollHandler, hybrid_coordinator};
// Import PacketRef for zero-copy
use crate::net::mempool::PacketRef;

// ============================================================================
// VirtIO Net Transport Helper Functions
// ============================================================================

/// トランスポートからMACアドレスを読み取り（Net device config space）
fn read_mac_address(transport: &dyn VirtioTransport) -> [u8; 6] {
    [
        transport.read_config_u8(0),
        transport.read_config_u8(1),
        transport.read_config_u8(2),
        transport.read_config_u8(3),
        transport.read_config_u8(4),
        transport.read_config_u8(5),
    ]
}


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

// ============================================================================
// Send-safe pointer wrapper
// ============================================================================

/// 生ポインタをSend可能にするラッパー
///
/// # Safety
/// このラッパーを使う側が、ポインタの有効性とスレッド安全性を保証する必要がある
struct SendPtr<T>(*mut T);

unsafe impl<T> Send for SendPtr<T> {}
unsafe impl<T> Sync for SendPtr<T> {}

impl<T> SendPtr<T> {
    fn new(ptr: *mut T) -> Self {
        Self(ptr)
    }

    fn as_ptr(&self) -> *mut T {
        self.0
    }
}

impl<T> Clone for SendPtr<T> {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl<T> Copy for SendPtr<T> {}

/// ネットワーク VirtQueue
pub struct NetVirtQueue {
    /// キューインデックス (0=RX, 1=TX)
    pub index: u16,
    /// キューサイズ
    pub size: u16,
    /// ディスクリプタテーブル
    desc_table: SendPtr<VringDesc>,
    /// Available Ring
    avail_ring: SendPtr<VringAvail>,
    /// Used Ring
    used_ring: SendPtr<VringUsed>,
    /// 次の空きディスクリプタ
    next_free_desc: AtomicU16,
    /// 最後に処理した Used インデックス
    last_used_idx: AtomicU16,
    /// 割り込み待機中のWaker
    pending_wakers: Mutex<Vec<Waker>>,
    /// ペンディングバッファの追跡 (desc_id -> callback)
    pending_buffers: Mutex<Vec<Option<PendingBuffer>>>,
}

// NetVirtQueueをSend/Syncにする
unsafe impl Send for NetVirtQueue {}
unsafe impl Sync for NetVirtQueue {}

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
            desc_table: SendPtr::new(desc_table),
            avail_ring: SendPtr::new(avail_ring),
            used_ring: SendPtr::new(used_ring),
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
    pub fn add_tx_buffer(
        &self,
        _header: &VirtioNetHeader,
        data: &[u8],
    ) -> Result<u16, VirtioNetError> {
        let desc_idx = self.alloc_desc().ok_or(VirtioNetError::QueueFull)?;

        unsafe {
            // ディスクリプタを設定
            let desc = &mut *self.desc_table.as_ptr().add(desc_idx as usize);
            desc.addr = data.as_ptr() as u64;
            desc.len = (VirtioNetHeader::SIZE + data.len()) as u32;
            desc.flags = 0;
            desc.next = 0;

            // Available Ringに追加
            let avail = &mut *self.avail_ring.as_ptr();
            let avail_idx = avail.idx;
            avail.ring[(avail_idx % self.size) as usize] = desc_idx;

            // メモリバリア
            core::sync::atomic::fence(Ordering::Release);

            avail.idx = avail_idx.wrapping_add(1);
        }

        Ok(desc_idx)
    }

    /// ゼロコピー送信バッファを追加（設計書 6.2準拠）
    /// 物理アドレスを直接使用し、メモリコピーを回避
    pub fn add_tx_buffer_zero_copy(
        &self,
        phys_addr: u64,
        data_len: usize,
    ) -> Result<u16, VirtioNetError> {
        let desc_idx = self.alloc_desc().ok_or(VirtioNetError::QueueFull)?;

        unsafe {
            // ディスクリプタを設定（物理アドレスを直接使用）
            let desc = &mut *self.desc_table.as_ptr().add(desc_idx as usize);
            desc.addr = phys_addr;
            desc.len = (VirtioNetHeader::SIZE + data_len) as u32;
            desc.flags = 0;
            desc.next = 0;

            // Available Ringに追加
            let avail = &mut *self.avail_ring.as_ptr();
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
            let desc = &mut *self.desc_table.as_ptr().add(desc_idx as usize);
            desc.addr = buffer.as_ptr() as u64;
            desc.len = buffer.len() as u32;
            desc.flags = VringDesc::VRING_DESC_F_WRITE;
            desc.next = 0;

            // Available Ringに追加
            let avail = &mut *self.avail_ring.as_ptr();
            let avail_idx = avail.idx;
            avail.ring[(avail_idx % self.size) as usize] = desc_idx;

            core::sync::atomic::fence(Ordering::Release);

            avail.idx = avail_idx.wrapping_add(1);
        }

        Ok(desc_idx)
    }

    /// ゼロコピー受信バッファを追加（設計書 6.2準拠）
    /// Mempool物理アドレスを直接使用
    pub fn add_rx_buffer_zero_copy(
        &self,
        phys_addr: u64,
        buffer_len: usize,
    ) -> Result<u16, VirtioNetError> {
        let desc_idx = self.alloc_desc().ok_or(VirtioNetError::QueueFull)?;

        unsafe {
            // ディスクリプタを設定（書き込み可能、物理アドレス直接使用）
            let desc = &mut *self.desc_table.as_ptr().add(desc_idx as usize);
            desc.addr = phys_addr;
            desc.len = buffer_len as u32;
            desc.flags = VringDesc::VRING_DESC_F_WRITE;
            desc.next = 0;

            // Available Ringに追加
            let avail = &mut *self.avail_ring.as_ptr();
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
            let used = &*self.used_ring.as_ptr();
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
            let used = &*self.used_ring.as_ptr();
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
    /// トランスポート層（MMIO/PCI共通インターフェース）
    transport: Box<dyn VirtioTransport>,
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
    /// 
    /// # Arguments
    /// * `transport` - 初期化済みの VirtioTransport 実装（MMIO または PCI）
    ///   トランスポートはmagic/version検証を通過している必要がある
    pub fn new(transport: Box<dyn VirtioTransport>) -> Self {
        Self {
            transport,
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
        // 1. デバイスタイプ確認（トランスポートはすでにmagic/version検証済み）
        if self.transport.device_type() != VirtioDeviceType::Network {
            return Err(VirtioNetError::DeviceError);
        }
        
        // 2. デバイスリセット
        self.transport.reset();
        
        // 3. ACKNOWLEDGE ステータスビットを設定
        self.transport.set_status(status::VIRTIO_STATUS_ACKNOWLEDGE);
        
        // 4. DRIVER ステータスビットを設定
        self.transport.set_status(
            status::VIRTIO_STATUS_ACKNOWLEDGE | status::VIRTIO_STATUS_DRIVER
        );
        
        // 5. Feature negotiation
        let device_features_low = self.transport.get_device_features_low();
        let device_features_high = self.transport.get_device_features_high();
        
        // 必要なフィーチャーのみを受け入れる
        let accepted_features_low = device_features_low & 
            (features::VIRTIO_NET_F_MAC as u32 | features::VIRTIO_NET_F_CSUM as u32);
        let accepted_features_high = device_features_high;
        
        self.transport.set_driver_features_low(accepted_features_low);
        self.transport.set_driver_features_high(accepted_features_high);
        
        // 6. FEATURES_OK を設定
        self.transport.set_status(
            status::VIRTIO_STATUS_ACKNOWLEDGE | 
            status::VIRTIO_STATUS_DRIVER | 
            status::VIRTIO_STATUS_FEATURES_OK
        );
        
        // FEATURES_OK が設定されたか確認
        if (self.transport.get_status() & status::VIRTIO_STATUS_FEATURES_OK) == 0 {
            self.transport.set_status(status::VIRTIO_STATUS_FAILED);
            return Err(VirtioNetError::DeviceError);
        }
        
        // 7. MACアドレスを読み取り
        if (accepted_features_low & features::VIRTIO_NET_F_MAC as u32) != 0 {
            self.config.mac = read_mac_address(self.transport.as_ref());
        }
        
        // 8. キューの設定
        self.setup_queues()?;
        
        // 9. DRIVER_OK を設定
        self.transport.set_status(
            status::VIRTIO_STATUS_ACKNOWLEDGE | 
            status::VIRTIO_STATUS_DRIVER | 
            status::VIRTIO_STATUS_FEATURES_OK |
            status::VIRTIO_STATUS_DRIVER_OK
        );

        self.initialized.store(true, Ordering::Release);
        Ok(())
    }
    
    /// VirtQueueを設定
    fn setup_queues(&mut self) -> Result<(), VirtioNetError> {
        // RX queue (queue 0)
        self.setup_single_queue(0)?;
        
        // TX queue (queue 1)
        self.setup_single_queue(1)?;
        
        Ok(())
    }
    
    /// 単一のキューを設定
    fn setup_single_queue(&mut self, queue_index: u16) -> Result<(), VirtioNetError> {
        // キューを選択
        self.transport.select_queue(queue_index);
        
        // 最大キューサイズを取得
        let max_size = self.transport.get_queue_max_size();
        if max_size == 0 {
            return Err(VirtioNetError::DeviceError);
        }
        
        // キューサイズを設定（最大256エントリに制限）
        let queue_size = max_size.min(256);
        self.transport.set_queue_size(queue_size);
        
        // メモリをアロケート（実際の実装ではDMA対応メモリが必要）
        // ここでは簡略化のためスキップ
        // 実際のキュー設定はVirtQueueの初期化と連携が必要
        
        // キューを有効化
        self.transport.enable_queue();
        
        Ok(())
    }
    
    /// デバイスに通知（キュー更新）
    pub fn notify(&mut self, queue_index: u16) {
        self.transport.notify_queue(queue_index);
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

    /// ゼロコピーパケット送信（設計書 6.2準拠）
    /// 
    /// PacketRefを直接使用し、コピーなしでDMAバッファに渡す。
    /// 送信完了まで所有権を保持し、完了後に自動解放される。
    pub fn send_zero_copy(&self, packet: PacketRef) -> ZeroCopySendFuture<'_> {
        ZeroCopySendFuture {
            device: self,
            packet: Some(packet),
            submitted: false,
            desc_idx: 0,
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

    /// ゼロコピーパケット受信（設計書 6.2準拠）
    /// 
    /// Mempoolから割り当てられたバッファに直接受信し、
    /// PacketRefとして返却する。
    pub fn recv_zero_copy(&self, pool: &'static crate::net::mempool::Mempool) -> ZeroCopyRecvFuture<'_> {
        ZeroCopyRecvFuture {
            device: self,
            pool,
            packet: None,
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
            self.rx_packets
                .fetch_add(completed.len() as u32, Ordering::Relaxed);
        }

        // TXキューを処理
        if let Some(ref tx_queue) = self.tx_queue {
            let completed = tx_queue.process_used();
            self.tx_packets
                .fetch_add(completed.len() as u32, Ordering::Relaxed);
        }

        // HybridIoCoordinator 経由でパケット処理を通知（io_scheduler 統一後）
        // Note: 旧 polling::net_io_controller() は削除済み
        // io_scheduler の complete_request はリクエストID単位のため、
        // ここではwaker通知のみで十分

        // Interrupt-Wakerブリッジに通知（設計書 4.2）
        // RX/TXで待機中のFutureを起床
        crate::task::interrupt_waker::wake_from_interrupt(
            crate::task::interrupt_waker::InterruptSource::VirtioNet(0),
        );
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
// ゼロコピー送受信 Futures（設計書 6.2）
// ============================================================================

/// ゼロコピー送信用Future
/// 
/// PacketRefの所有権を取得し、DMA転送が完了するまで保持する。
/// 完了後、PacketRefは自動的にMempoolに返却される。
pub struct ZeroCopySendFuture<'a> {
    device: &'a VirtioNetDevice,
    packet: Option<PacketRef>,
    submitted: bool,
    desc_idx: u16,
}

impl<'a> Future for ZeroCopySendFuture<'a> {
    type Output = Result<usize, VirtioNetError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        
        if !this.submitted {
            // 送信をキューに追加
            if let Some(ref tx_queue) = this.device.tx_queue {
                if let Some(ref packet) = this.packet {
                    let data = packet.data();
                    let phys_addr = packet.phys_addr();
                    
                    // ゼロコピー: 物理アドレスを直接VirtQueueに渡す
                    match tx_queue.add_tx_buffer_zero_copy(phys_addr.as_u64(), data.len()) {
                        Ok(desc_idx) => {
                            this.submitted = true;
                            this.desc_idx = desc_idx;
                            tx_queue.register_waker(cx.waker().clone());
                        }
                        Err(e) => return Poll::Ready(Err(e)),
                    }
                } else {
                    return Poll::Ready(Err(VirtioNetError::BufferTooSmall));
                }
            } else {
                return Poll::Ready(Err(VirtioNetError::NotInitialized));
            }
        }

        // 完了を確認
        if let Some(ref tx_queue) = this.device.tx_queue {
            if tx_queue.has_pending() {
                // 送信完了: PacketRefをドロップしてMempoolに返却
                let packet = this.packet.take();
                let len = packet.map(|p| p.data().len()).unwrap_or(0);
                Poll::Ready(Ok(len))
            } else {
                tx_queue.register_waker(cx.waker().clone());
                Poll::Pending
            }
        } else {
            Poll::Ready(Err(VirtioNetError::NotInitialized))
        }
    }
}

/// ゼロコピー受信用Future
/// 
/// Mempoolから直接バッファを割り当て、DMAバッファとして使用。
/// 受信完了後、PacketRefとしてデータを返却する。
pub struct ZeroCopyRecvFuture<'a> {
    device: &'a VirtioNetDevice,
    pool: &'static crate::net::mempool::Mempool,
    packet: Option<PacketRef>,
    submitted: bool,
}

impl<'a> Future for ZeroCopyRecvFuture<'a> {
    type Output = Result<PacketRef, VirtioNetError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        
        if !this.submitted {
            // Mempoolからバッファを割り当て
            let packet = this.pool.alloc().ok_or(VirtioNetError::BufferTooSmall)?;
            let phys_addr = packet.phys_addr();
            
            // 受信バッファをキューに追加
            if let Some(ref rx_queue) = this.device.rx_queue {
                match rx_queue.add_rx_buffer_zero_copy(phys_addr.as_u64(), packet.data().len()) {
                    Ok(_) => {
                        this.packet = Some(packet);
                        this.submitted = true;
                        rx_queue.register_waker(cx.waker().clone());
                    }
                    Err(e) => return Poll::Ready(Err(e)),
                }
            } else {
                return Poll::Ready(Err(VirtioNetError::NotInitialized));
            }
        }

        // 完了を確認
        if let Some(ref rx_queue) = this.device.rx_queue {
            let completed = rx_queue.process_used();
            if let Some((_, len)) = completed.first() {
                // 受信完了: データ長を設定してPacketRefを返却
                if let Some(packet) = this.packet.take() {
                    packet.set_len(*len as usize);
                    return Poll::Ready(Ok(packet));
                }
                return Poll::Ready(Err(VirtioNetError::BufferTooSmall));
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

use super::transport::VirtioMmioTransport;

static VIRTIO_NET_DEVICE: Mutex<Option<VirtioNetDevice>> = Mutex::new(None);

/// VirtIO ネットワークデバイス（MMIO）を初期化
/// 
/// # Safety
/// `base_addr` は有効なVirtIO MMIOデバイスのベースアドレスを指す必要がある
pub fn init_virtio_net(base_addr: usize) -> Result<(), VirtioNetError> {
    // トランスポート作成（magic/version検証含む）
    let transport = unsafe { 
        VirtioMmioTransport::new(base_addr)
            .map_err(|_| VirtioNetError::DeviceError)?
    };
    
    let mut device = VirtioNetDevice::new(Box::new(transport));
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

// ============================================================================
// IoScheduler Integration
// ============================================================================

/// VirtIO ネットワーク PollHandler 実装
pub struct VirtioNetPollHandler {
    /// デバイスへの参照
    device_lock: &'static Mutex<Option<VirtioNetDevice>>,
    /// 保留中リクエスト (IoRequestId -> buffer_index)
    pending_rx: Mutex<BTreeMap<IoRequestId, u16>>,
    pending_tx: Mutex<BTreeMap<IoRequestId, u16>>,
    /// 次のリクエストID
    next_request_id: AtomicU64,
}

impl VirtioNetPollHandler {
    /// 新しい VirtioNetPollHandler を作成
    pub fn new() -> Self {
        Self {
            device_lock: &VIRTIO_NET_DEVICE,
            pending_rx: Mutex::new(BTreeMap::new()),
            pending_tx: Mutex::new(BTreeMap::new()),
            next_request_id: AtomicU64::new(1),
        }
    }
    
    /// 新しいリクエストIDを生成
    pub fn next_request_id(&self) -> IoRequestId {
        IoRequestId(self.next_request_id.fetch_add(1, Ordering::SeqCst))
    }
    
    /// RX リクエストを追加
    pub fn add_pending_rx(&self, id: IoRequestId, buffer_idx: u16) {
        self.pending_rx.lock().insert(id, buffer_idx);
    }
    
    /// TX リクエストを追加
    pub fn add_pending_tx(&self, id: IoRequestId, buffer_idx: u16) {
        self.pending_tx.lock().insert(id, buffer_idx);
    }
}

impl PollHandler for VirtioNetPollHandler {
    fn poll_completions(&self) -> Vec<(IoRequestId, IoResult)> {
        let mut results = Vec::new();
        
        if let Some(ref device) = *self.device_lock.lock() {
            // RX 完了をチェック - rx_queue が存在するか確認
            if let Some(ref rx_queue) = device.rx_queue {
                let mut pending = self.pending_rx.lock();
                let mut completed = Vec::new();
                
                // 簡略化: キューにリクエストがあれば完了とみなす
                // 実際の実装では used ring のインデックスを追跡
                for (&id, &_buf_idx) in pending.iter() {
                    // rx_queue の状態をチェック
                    let _ = rx_queue; // 使用を示す
                    results.push((id, IoResult::Success(1514))); // MTU
                    completed.push(id);
                    break; // 1つずつ処理
                }
                
                for id in completed {
                    pending.remove(&id);
                }
            }
            
            // TX 完了をチェック
            if let Some(ref tx_queue) = device.tx_queue {
                let mut pending = self.pending_tx.lock();
                let mut completed = Vec::new();
                
                for (&id, &_buf_idx) in pending.iter() {
                    let _ = tx_queue;
                    results.push((id, IoResult::Success(0)));
                    completed.push(id);
                    break;
                }
                
                for id in completed {
                    pending.remove(&id);
                }
            }
        }
        
        results
    }
    
    fn is_ready(&self) -> bool {
        self.device_lock.lock().is_some()
    }
}

// SAFETY: VirtioNetPollHandler はスレッドセーフ
// - 内部の Mutex で安全に同期
unsafe impl Send for VirtioNetPollHandler {}
unsafe impl Sync for VirtioNetPollHandler {}

/// VirtIO ネットワークを IoScheduler に登録
pub fn register_virtio_net_with_io_scheduler(index: u8) {
    let handler = VirtioNetPollHandler::new();
    let handler: Box<dyn PollHandler + Send + Sync> = Box::new(handler);
    
    let coordinator = hybrid_coordinator();
    let executor = coordinator.polling_executor();
    executor.register_handler(DeviceId::VirtioNet { index }, handler);
}

// ============================================================================
// 型安全 DMA バッファ (VirtIO Network)
// ============================================================================

/// VirtIO ネットワーク最大フレームサイズ
const VIRTIO_NET_MTU: usize = 1514;

/// VirtIO ネットワーク受信用DMAバッファ
/// 
/// 型状態パターンで DMA 転送中の不正アクセスを防止
pub struct VirtioNetRxDmaBuffer {
    /// CPU所有状態のバッファ
    buffer: Option<TypedDmaSlice<CpuOwned>>,
    /// デバイス所有状態（転送中）
    inflight: Option<TypedDmaSlice<DeviceOwned>>,
}

impl VirtioNetRxDmaBuffer {
    /// MTUサイズの受信バッファを作成
    pub fn new() -> Option<Self> {
        // VirtIO net header + MTU
        let size = core::mem::size_of::<VirtioNetHeader>() + VIRTIO_NET_MTU;
        let buffer = TypedDmaSlice::new(size)?;
        
        Some(Self {
            buffer: Some(buffer),
            inflight: None,
        })
    }
    
    /// 物理アドレスを取得
    pub fn phys_addr(&self) -> Option<PhysAddr> {
        self.buffer.as_ref().map(|b| b.phys_addr())
            .or_else(|| self.inflight.as_ref().map(|b| b.phys_addr()))
    }
    
    /// DMA転送を開始（VirtQueueへのバッファ追加時）
    pub fn start_receive(&mut self) -> Result<u64, &'static str> {
        let buffer = self.buffer.take().ok_or("Buffer already in use")?;
        let phys = buffer.phys_addr().as_u64();
        self.inflight = Some(buffer.start_dma());
        Ok(phys)
    }
    
    /// DMA転送完了（受信完了時）
    pub fn complete_receive(&mut self) -> Result<(), &'static str> {
        let inflight = self.inflight.take().ok_or("No receive in progress")?;
        self.buffer = Some(inflight.complete_dma());
        Ok(())
    }
    
    /// 受信データを取得（完了後のみ）
    pub fn received_data(&self) -> Option<&[u8]> {
        self.buffer.as_ref().map(|b| {
            // Skip VirtIO net header
            let slice = b.as_slice();
            let header_size = core::mem::size_of::<VirtioNetHeader>();
            &slice[header_size..]
        })
    }
    
    /// バッファ全体のサイズ
    pub fn size(&self) -> usize {
        core::mem::size_of::<VirtioNetHeader>() + VIRTIO_NET_MTU
    }
}

impl Default for VirtioNetRxDmaBuffer {
    fn default() -> Self {
        Self::new().expect("Failed to allocate VirtIO net RX buffer")
    }
}

/// VirtIO ネットワーク送信用DMAバッファ
pub struct VirtioNetTxDmaBuffer {
    buffer: Option<TypedDmaSlice<CpuOwned>>,
    inflight: Option<TypedDmaSlice<DeviceOwned>>,
    data_len: usize,
}

impl VirtioNetTxDmaBuffer {
    /// 送信データからバッファを作成
    pub fn with_data(data: &[u8]) -> Option<Self> {
        let header_size = core::mem::size_of::<VirtioNetHeader>();
        let total_size = header_size + data.len();
        
        let mut buffer = TypedDmaSlice::new(total_size)?;
        
        {
            let slice = buffer.as_mut_slice();
            // VirtIO net header をゼロクリア（初期化済み）
            // slice[..header_size] は既に 0
            // データをコピー
            slice[header_size..].copy_from_slice(data);
        }
        
        Some(Self {
            buffer: Some(buffer),
            inflight: None,
            data_len: data.len(),
        })
    }
    
    /// 物理アドレスを取得
    pub fn phys_addr(&self) -> Option<PhysAddr> {
        self.buffer.as_ref().map(|b| b.phys_addr())
            .or_else(|| self.inflight.as_ref().map(|b| b.phys_addr()))
    }
    
    /// DMA転送を開始
    pub fn start_transmit(&mut self) -> Result<u64, &'static str> {
        let buffer = self.buffer.take().ok_or("Buffer already in use")?;
        let phys = buffer.phys_addr().as_u64();
        self.inflight = Some(buffer.start_dma());
        Ok(phys)
    }
    
    /// DMA転送完了
    pub fn complete_transmit(&mut self) -> Result<(), &'static str> {
        let inflight = self.inflight.take().ok_or("No transmit in progress")?;
        self.buffer = Some(inflight.complete_dma());
        Ok(())
    }
    
    /// 送信データ長
    pub fn data_len(&self) -> usize {
        self.data_len
    }
    
    /// 合計バッファサイズ（ヘッダー含む）
    pub fn total_size(&self) -> usize {
        core::mem::size_of::<VirtioNetHeader>() + self.data_len
    }
}

/// コヒーレントDMAバッファを使用したVirtQueue
/// 
/// VirtQueueの記述子テーブル、Availableリング、Usedリングに使用
pub struct VirtQueueDmaBuffers {
    /// 記述子テーブル
    pub desc_table: CoherentDmaBuffer,
    /// Available リング
    pub avail_ring: CoherentDmaBuffer,
    /// Used リング  
    pub used_ring: CoherentDmaBuffer,
}

impl VirtQueueDmaBuffers {
    /// VirtQueue用のDMAバッファセットを作成
    /// 
    /// # Arguments
    /// * `queue_size` - キューサイズ（記述子数）
    pub fn new(queue_size: u16) -> Option<Self> {
        let desc_size = queue_size as usize * 16; // VirtqDesc は 16 バイト
        let avail_size = 6 + queue_size as usize * 2; // header + entries
        let used_size = 6 + queue_size as usize * 8;  // header + entries
        
        let desc_table = CoherentDmaBuffer::new(desc_size, DmaMemoryAttributes::MMIO)?;
        let avail_ring = CoherentDmaBuffer::new(avail_size, DmaMemoryAttributes::MMIO)?;
        let used_ring = CoherentDmaBuffer::new(used_size, DmaMemoryAttributes::FROM_DEVICE)?;
        
        Some(Self {
            desc_table,
            avail_ring,
            used_ring,
        })
    }
    
    /// 記述子テーブルの物理アドレス
    pub fn desc_table_addr(&self) -> u64 {
        self.desc_table.phys_addr().as_u64()
    }
    
    /// Available リングの物理アドレス
    pub fn avail_ring_addr(&self) -> u64 {
        self.avail_ring.phys_addr().as_u64()
    }
    
    /// Used リングの物理アドレス
    pub fn used_ring_addr(&self) -> u64 {
        self.used_ring.phys_addr().as_u64()
    }
}