// ============================================================================
// src/io/virtio/net.rs - VirtIO Network Device Driver
// 設計書 6.2: ネットワークスタック：真のゼロコピー
// 設計書 7.1: VirtIOドライバのRust実装
// ============================================================================
#![allow(dead_code)]

use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering};
use core::task::{Context, Poll, Waker};
use spin::Mutex;

// Import VirtIO common definitions
use super::defs::{mmio_regs, status, VIRTIO_MMIO_MAGIC, VirtioDeviceType};

// ============================================================================
// MMIO Access Abstraction
// ============================================================================

/// VirtIO MMIO アクセサ
/// 
/// VirtIO MMIO トランスポートへの安全なアクセスを提供する。
pub struct VirtioMmioAccess {
    /// MMIOベースアドレス
    base: usize,
}

impl VirtioMmioAccess {
    /// 新しいMMIOアクセサを作成
    pub const fn new(base: usize) -> Self {
        Self { base }
    }
    
    /// 32ビットレジスタを読み取り
    #[inline]
    pub fn read32(&self, offset: usize) -> u32 {
        unsafe {
            core::ptr::read_volatile((self.base + offset) as *const u32)
        }
    }
    
    /// 32ビットレジスタに書き込み
    #[inline]
    pub fn write32(&self, offset: usize, value: u32) {
        unsafe {
            core::ptr::write_volatile((self.base + offset) as *mut u32, value);
        }
    }
    
    /// Magic valueを検証
    pub fn verify_magic(&self) -> bool {
        self.read32(mmio_regs::MAGIC_VALUE) == VIRTIO_MMIO_MAGIC
    }
    
    /// バージョンを取得
    pub fn version(&self) -> u32 {
        self.read32(mmio_regs::VERSION)
    }
    
    /// デバイスIDを取得
    pub fn device_id(&self) -> VirtioDeviceType {
        VirtioDeviceType::from(self.read32(mmio_regs::DEVICE_ID))
    }
    
    /// ベンダーIDを取得
    pub fn vendor_id(&self) -> u32 {
        self.read32(mmio_regs::VENDOR_ID)
    }
    
    /// デバイスフィーチャーを取得
    pub fn device_features(&self, selector: u32) -> u32 {
        self.write32(mmio_regs::DEVICE_FEATURES_SEL, selector);
        self.read32(mmio_regs::DEVICE_FEATURES)
    }
    
    /// ドライバフィーチャーを設定
    pub fn set_driver_features(&self, selector: u32, features: u32) {
        self.write32(mmio_regs::DRIVER_FEATURES_SEL, selector);
        self.write32(mmio_regs::DRIVER_FEATURES, features);
    }
    
    /// ステータスを取得
    pub fn status(&self) -> u8 {
        self.read32(mmio_regs::STATUS) as u8
    }
    
    /// ステータスを設定
    pub fn set_status(&self, status: u8) {
        self.write32(mmio_regs::STATUS, status as u32);
    }
    
    /// デバイスをリセット
    pub fn reset(&self) {
        self.set_status(status::VIRTIO_STATUS_RESET);
    }
    
    /// キューを選択
    pub fn select_queue(&self, index: u16) {
        self.write32(mmio_regs::QUEUE_SEL, index as u32);
    }
    
    /// 選択されたキューの最大サイズを取得
    pub fn queue_max_size(&self) -> u16 {
        self.read32(mmio_regs::QUEUE_NUM_MAX) as u16
    }
    
    /// キューサイズを設定
    pub fn set_queue_size(&self, size: u16) {
        self.write32(mmio_regs::QUEUE_NUM, size as u32);
    }
    
    /// キューを有効化
    pub fn enable_queue(&self) {
        self.write32(mmio_regs::QUEUE_READY, 1);
    }
    
    /// キューを無効化
    pub fn disable_queue(&self) {
        self.write32(mmio_regs::QUEUE_READY, 0);
    }
    
    /// キューにディスクリプタテーブルアドレスを設定
    pub fn set_queue_desc(&self, addr: u64) {
        self.write32(mmio_regs::QUEUE_DESC_LOW, addr as u32);
        self.write32(mmio_regs::QUEUE_DESC_HIGH, (addr >> 32) as u32);
    }
    
    /// キューにAvailリングアドレスを設定
    pub fn set_queue_avail(&self, addr: u64) {
        self.write32(mmio_regs::QUEUE_AVAIL_LOW, addr as u32);
        self.write32(mmio_regs::QUEUE_AVAIL_HIGH, (addr >> 32) as u32);
    }
    
    /// キューにUsedリングアドレスを設定
    pub fn set_queue_used(&self, addr: u64) {
        self.write32(mmio_regs::QUEUE_USED_LOW, addr as u32);
        self.write32(mmio_regs::QUEUE_USED_HIGH, (addr >> 32) as u32);
    }
    
    /// キューに通知
    pub fn notify_queue(&self, queue_index: u16) {
        self.write32(mmio_regs::QUEUE_NOTIFY, queue_index as u32);
    }
    
    /// 割り込みステータスを取得
    pub fn interrupt_status(&self) -> u32 {
        self.read32(mmio_regs::INTERRUPT_STATUS)
    }
    
    /// 割り込みをACK
    pub fn interrupt_ack(&self, status: u32) {
        self.write32(mmio_regs::INTERRUPT_ACK, status);
    }
    
    /// コンフィグ空間から8ビット値を読み取り
    pub fn read_config8(&self, offset: usize) -> u8 {
        unsafe {
            core::ptr::read_volatile((self.base + mmio_regs::CONFIG + offset) as *const u8)
        }
    }
    
    /// コンフィグ空間から16ビット値を読み取り
    pub fn read_config16(&self, offset: usize) -> u16 {
        unsafe {
            core::ptr::read_volatile((self.base + mmio_regs::CONFIG + offset) as *const u16)
        }
    }
    
    /// コンフィグ空間から32ビット値を読み取り
    pub fn read_config32(&self, offset: usize) -> u32 {
        unsafe {
            core::ptr::read_volatile((self.base + mmio_regs::CONFIG + offset) as *const u32)
        }
    }
    
    /// MACアドレスを読み取り（Net device config space）
    pub fn read_mac_address(&self) -> [u8; 6] {
        [
            self.read_config8(0),
            self.read_config8(1),
            self.read_config8(2),
            self.read_config8(3),
            self.read_config8(4),
            self.read_config8(5),
        ]
    }
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
    /// デバイスベースアドレス
    base_addr: usize,
    /// MMIOアクセサ
    mmio: VirtioMmioAccess,
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
            mmio: VirtioMmioAccess::new(base_addr),
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
        // 1. Magic value検証
        if !self.mmio.verify_magic() {
            return Err(VirtioNetError::DeviceError);
        }
        
        // 2. バージョン確認 (version 2 = modern MMIO)
        let version = self.mmio.version();
        if version != 2 && version != 1 {
            return Err(VirtioNetError::DeviceError);
        }
        
        // 3. デバイスタイプ確認
        if self.mmio.device_id() != VirtioDeviceType::Network {
            return Err(VirtioNetError::DeviceError);
        }
        
        // 4. デバイスリセット
        self.mmio.reset();
        
        // 5. ACKNOWLEDGE ステータスビットを設定
        self.mmio.set_status(status::VIRTIO_STATUS_ACKNOWLEDGE);
        
        // 6. DRIVER ステータスビットを設定
        self.mmio.set_status(
            status::VIRTIO_STATUS_ACKNOWLEDGE | status::VIRTIO_STATUS_DRIVER
        );
        
        // 7. Feature negotiation
        let device_features_low = self.mmio.device_features(0);
        let device_features_high = self.mmio.device_features(1);
        
        // 必要なフィーチャーのみを受け入れる
        let accepted_features_low = device_features_low & 
            (features::VIRTIO_NET_F_MAC as u32 | features::VIRTIO_NET_F_CSUM as u32);
        let accepted_features_high = device_features_high;
        
        self.mmio.set_driver_features(0, accepted_features_low);
        self.mmio.set_driver_features(1, accepted_features_high);
        
        // 8. FEATURES_OK を設定
        self.mmio.set_status(
            status::VIRTIO_STATUS_ACKNOWLEDGE | 
            status::VIRTIO_STATUS_DRIVER | 
            status::VIRTIO_STATUS_FEATURES_OK
        );
        
        // FEATURES_OK が設定されたか確認
        if (self.mmio.status() & status::VIRTIO_STATUS_FEATURES_OK) == 0 {
            self.mmio.set_status(status::VIRTIO_STATUS_FAILED);
            return Err(VirtioNetError::DeviceError);
        }
        
        // 9. MACアドレスを読み取り
        if (accepted_features_low & features::VIRTIO_NET_F_MAC as u32) != 0 {
            self.config.mac = self.mmio.read_mac_address();
        }
        
        // 10. キューの設定
        self.setup_queues()?;
        
        // 11. DRIVER_OK を設定
        self.mmio.set_status(
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
        self.mmio.select_queue(queue_index);
        
        // 最大キューサイズを取得
        let max_size = self.mmio.queue_max_size();
        if max_size == 0 {
            return Err(VirtioNetError::DeviceError);
        }
        
        // キューサイズを設定（最大256エントリに制限）
        let queue_size = max_size.min(256);
        self.mmio.set_queue_size(queue_size);
        
        // メモリをアロケート（実際の実装ではDMA対応メモリが必要）
        // ここでは簡略化のためスキップ
        // 実際のキュー設定はVirtQueueの初期化と連携が必要
        
        // キューを有効化
        self.mmio.enable_queue();
        
        Ok(())
    }
    
    /// デバイスに通知（キュー更新）
    pub fn notify(&self, queue_index: u16) {
        self.mmio.notify_queue(queue_index);
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
            self.rx_packets
                .fetch_add(completed.len() as u32, Ordering::Relaxed);
        }

        // TXキューを処理
        if let Some(ref tx_queue) = self.tx_queue {
            let completed = tx_queue.process_used();
            self.tx_packets
                .fetch_add(completed.len() as u32, Ordering::Relaxed);
        }

        // 適応的ポーリングコントローラに通知
        crate::io::polling::net_io_controller().notify_packet_processed(1);

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
