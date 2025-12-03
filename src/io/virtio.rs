// ============================================================================
// src/io/virtio.rs - Complete Async VirtIO-Net Driver
// 設計書 6.2: NIC Driverのゼロコピーパケット処理
// ============================================================================
#![allow(dead_code)]

use alloc::collections::VecDeque;
use core::future::poll_fn;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::task::{Poll, Waker};
use spin::Mutex;
use x86_64::PhysAddr;

use crate::net::mempool::{PacketRef, alloc_packet};

// ============================================================================
// VirtIO Constants
// ============================================================================

/// VirtIOデバイスステータス
const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;
const VIRTIO_STATUS_DRIVER: u8 = 2;
const VIRTIO_STATUS_DRIVER_OK: u8 = 4;
const VIRTIO_STATUS_FEATURES_OK: u8 = 8;
const VIRTIO_STATUS_FAILED: u8 = 128;

/// VirtIO-netフィーチャービット
const VIRTIO_NET_F_MAC: u64 = 1 << 5; // デバイスはMACアドレスを持つ
const VIRTIO_NET_F_STATUS: u64 = 1 << 16; // リンクステータスを報告
const VIRTIO_NET_F_MRG_RXBUF: u64 = 1 << 15; // マージ受信バッファ
const VIRTIO_NET_F_CTRL_VQ: u64 = 1 << 17; // 制御virtqueue

/// Virtqueueインデックス
const VIRTQUEUE_RX: u16 = 0;
const VIRTQUEUE_TX: u16 = 1;
const VIRTQUEUE_CTRL: u16 = 2;

/// キューサイズ
const QUEUE_SIZE: u16 = 256;

// ============================================================================
// VirtIO Ring Structures
// ============================================================================

/// Virtqueueディスクリプタ
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VirtqDesc {
    /// ゲスト物理アドレス
    pub addr: u64,
    /// バッファ長
    pub len: u32,
    /// フラグ (NEXT, WRITE, INDIRECT)
    pub flags: u16,
    /// 次のディスクリプタインデックス
    pub next: u16,
}

impl VirtqDesc {
    pub const FLAG_NEXT: u16 = 1; // チェーンに続くディスクリプタあり
    pub const FLAG_WRITE: u16 = 2; // デバイスが書き込むバッファ
    pub const FLAG_INDIRECT: u16 = 4; // 間接ディスクリプタテーブル
}

/// Availableリング
#[repr(C)]
pub struct VirtqAvail {
    pub flags: u16,
    pub idx: u16,
    pub ring: [u16; QUEUE_SIZE as usize],
    pub used_event: u16,
}

/// Usedリングエントリ
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VirtqUsedElem {
    pub id: u32,
    pub len: u32,
}

/// Usedリング
#[repr(C)]
pub struct VirtqUsed {
    pub flags: u16,
    pub idx: u16,
    pub ring: [VirtqUsedElem; QUEUE_SIZE as usize],
    pub avail_event: u16,
}

// ============================================================================
// Virtqueue Management
// ============================================================================

/// Virtqueue
pub struct Virtqueue {
    /// キューインデックス
    index: u16,
    /// キューサイズ
    size: u16,
    /// ディスクリプタテーブル
    desc: NonNull<[VirtqDesc; QUEUE_SIZE as usize]>,
    /// Availableリング
    avail: NonNull<VirtqAvail>,
    /// Usedリング
    used: NonNull<VirtqUsed>,
    /// 次の空きディスクリプタ
    free_head: u16,
    /// 空きディスクリプタ数
    free_count: u16,
    /// 最後に処理したusedインデックス
    last_used_idx: u16,
    /// 保留中のバッファ（ゼロコピー用）
    pending_buffers: VecDeque<Option<PacketRef>>,
}

// SAFETY: VirtqueueはMutexで保護され、NonNullポインタはDMA領域への有効なポインタ
// デバイスとの同期はメモリバリアで行われる
unsafe impl Send for Virtqueue {}
unsafe impl Sync for Virtqueue {}

impl Virtqueue {
    /// 新しいVirtqueueを割り当て
    pub fn new(index: u16) -> Result<Self, &'static str> {
        // ディスクリプタテーブル、Avail、Usedリングを割り当て
        // 実際にはDMA可能な連続物理メモリが必要

        let desc_layout = core::alloc::Layout::array::<VirtqDesc>(QUEUE_SIZE as usize)
            .map_err(|_| "Layout error")?;
        let avail_layout = core::alloc::Layout::new::<VirtqAvail>();
        let used_layout = core::alloc::Layout::new::<VirtqUsed>();

        let desc_ptr = unsafe {
            alloc::alloc::alloc_zeroed(desc_layout) as *mut [VirtqDesc; QUEUE_SIZE as usize]
        };
        let avail_ptr = unsafe { alloc::alloc::alloc_zeroed(avail_layout) as *mut VirtqAvail };
        let used_ptr = unsafe { alloc::alloc::alloc_zeroed(used_layout) as *mut VirtqUsed };

        if desc_ptr.is_null() || avail_ptr.is_null() || used_ptr.is_null() {
            return Err("Failed to allocate virtqueue memory");
        }

        // ディスクリプタチェーンを初期化
        let desc = unsafe { NonNull::new_unchecked(desc_ptr) };
        unsafe {
            let desc_ref = desc.as_ref();
            for i in 0..(QUEUE_SIZE - 1) {
                (desc_ref.as_ptr() as *mut VirtqDesc)
                    .add(i as usize)
                    .write(VirtqDesc {
                        addr: 0,
                        len: 0,
                        flags: VirtqDesc::FLAG_NEXT,
                        next: i + 1,
                    });
            }
        }

        // 保留バッファを初期化
        let mut pending_buffers = VecDeque::with_capacity(QUEUE_SIZE as usize);
        for _ in 0..QUEUE_SIZE {
            pending_buffers.push_back(None);
        }

        Ok(Self {
            index,
            size: QUEUE_SIZE,
            desc,
            avail: unsafe { NonNull::new_unchecked(avail_ptr) },
            used: unsafe { NonNull::new_unchecked(used_ptr) },
            free_head: 0,
            free_count: QUEUE_SIZE,
            last_used_idx: 0,
            pending_buffers,
        })
    }

    /// ディスクリプタを割り当て
    fn alloc_desc(&mut self) -> Option<u16> {
        if self.free_count == 0 {
            return None;
        }

        let idx = self.free_head;
        let desc = unsafe { &(*self.desc.as_ptr())[idx as usize] };
        self.free_head = desc.next;
        self.free_count -= 1;

        Some(idx)
    }

    /// ディスクリプタを解放
    fn free_desc(&mut self, idx: u16) {
        let desc = unsafe { &mut (*self.desc.as_ptr())[idx as usize] };
        desc.next = self.free_head;
        desc.flags = VirtqDesc::FLAG_NEXT;
        self.free_head = idx;
        self.free_count += 1;
    }

    /// バッファをキューに追加（ゼロコピー送信用）
    pub fn add_buffer_tx(&mut self, packet: PacketRef) -> Result<u16, &'static str> {
        let desc_idx = self.alloc_desc().ok_or("No free descriptors")?;

        // ディスクリプタを設定
        let desc = unsafe { &mut (*self.desc.as_ptr())[desc_idx as usize] };
        desc.addr = packet.phys_addr().as_u64();
        desc.len = packet.data().len() as u32;
        desc.flags = 0; // デバイスは読み取りのみ

        // バッファを保存（完了時に解放）
        self.pending_buffers[desc_idx as usize] = Some(packet);

        // Availリングに追加
        unsafe {
            let avail = self.avail.as_mut();
            let avail_idx = avail.idx;
            avail.ring[(avail_idx % self.size) as usize] = desc_idx;

            // メモリバリア
            core::sync::atomic::fence(Ordering::Release);

            avail.idx = avail_idx.wrapping_add(1);
        }

        Ok(desc_idx)
    }

    /// バッファをキューに追加（ゼロコピー受信用）
    pub fn add_buffer_rx(&mut self, packet: PacketRef) -> Result<u16, &'static str> {
        let desc_idx = self.alloc_desc().ok_or("No free descriptors")?;

        // ディスクリプタを設定
        let desc = unsafe { &mut (*self.desc.as_ptr())[desc_idx as usize] };
        desc.addr = packet.phys_addr().as_u64();
        desc.len = packet.data().len() as u32;
        desc.flags = VirtqDesc::FLAG_WRITE; // デバイスが書き込む

        // バッファを保存
        self.pending_buffers[desc_idx as usize] = Some(packet);

        // Availリングに追加
        unsafe {
            let avail = self.avail.as_mut();
            let avail_idx = avail.idx;
            avail.ring[(avail_idx % self.size) as usize] = desc_idx;

            core::sync::atomic::fence(Ordering::Release);

            avail.idx = avail_idx.wrapping_add(1);
        }

        Ok(desc_idx)
    }

    /// 完了したバッファを取得
    pub fn pop_used(&mut self) -> Option<(u16, PacketRef, u32)> {
        core::sync::atomic::fence(Ordering::Acquire);

        let used_idx = unsafe { self.used.as_ref().idx };

        if self.last_used_idx == used_idx {
            return None;
        }

        let used_elem =
            unsafe { &self.used.as_ref().ring[(self.last_used_idx % self.size) as usize] };

        let desc_idx = used_elem.id as u16;
        let len = used_elem.len;

        self.last_used_idx = self.last_used_idx.wrapping_add(1);

        // バッファを取り出してディスクリプタを解放
        let packet = self.pending_buffers[desc_idx as usize].take()?;
        self.free_desc(desc_idx);

        Some((desc_idx, packet, len))
    }

    /// 物理アドレスを取得（デバイス設定用）
    pub fn desc_phys_addr(&self) -> PhysAddr {
        PhysAddr::new(self.desc.as_ptr() as u64)
    }

    pub fn avail_phys_addr(&self) -> PhysAddr {
        PhysAddr::new(self.avail.as_ptr() as u64)
    }

    pub fn used_phys_addr(&self) -> PhysAddr {
        PhysAddr::new(self.used.as_ptr() as u64)
    }
}

// ============================================================================
// VirtIO-Net Device
// ============================================================================

/// VirtIO-netデバイス設定
#[repr(C)]
pub struct VirtioNetConfig {
    pub mac: [u8; 6],
    pub status: u16,
    pub max_virtqueue_pairs: u16,
    pub mtu: u16,
}

/// VirtIO-netデバイス
pub struct VirtioNet {
    /// ベースアドレス（MMIO）
    base_addr: usize,
    /// MACアドレス
    mac: [u8; 6],
    /// 受信キュー
    rx_queue: Mutex<Virtqueue>,
    /// 送信キュー
    tx_queue: Mutex<Virtqueue>,
    /// 受信バッファキュー
    rx_buffers: Mutex<VecDeque<PacketRef>>,
    /// 統計
    stats: VirtioNetStats,
}

/// VirtIO-netデバイス統計
pub struct VirtioNetStats {
    pub rx_packets: AtomicU64,
    pub tx_packets: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub rx_errors: AtomicU64,
    pub tx_errors: AtomicU64,
}

impl VirtioNetStats {
    pub const fn new() -> Self {
        Self {
            rx_packets: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_errors: AtomicU64::new(0),
            tx_errors: AtomicU64::new(0),
        }
    }
}

impl VirtioNet {
    /// 新しいVirtIO-netデバイスを初期化
    pub fn new(base_addr: usize) -> Result<Self, &'static str> {
        let rx_queue = Virtqueue::new(VIRTQUEUE_RX)?;
        let tx_queue = Virtqueue::new(VIRTQUEUE_TX)?;

        let mut device = Self {
            base_addr,
            mac: [0; 6],
            rx_queue: Mutex::new(rx_queue),
            tx_queue: Mutex::new(tx_queue),
            rx_buffers: Mutex::new(VecDeque::new()),
            stats: VirtioNetStats::new(),
        };

        device.initialize()?;

        Ok(device)
    }

    /// デバイスを初期化
    fn initialize(&mut self) -> Result<(), &'static str> {
        // 1. デバイスリセット
        self.write_status(0);

        // 2. ACKNOWLEDGE
        self.write_status(VIRTIO_STATUS_ACKNOWLEDGE);

        // 3. DRIVER
        self.write_status(self.read_status() | VIRTIO_STATUS_DRIVER);

        // 4. フィーチャーネゴシエーション
        let features = self.read_features();
        let supported = VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS;
        self.write_features(features & supported);

        // 5. FEATURES_OK
        self.write_status(self.read_status() | VIRTIO_STATUS_FEATURES_OK);

        // フィーチャーが受け入れられたか確認
        if (self.read_status() & VIRTIO_STATUS_FEATURES_OK) == 0 {
            self.write_status(VIRTIO_STATUS_FAILED);
            return Err("Feature negotiation failed");
        }

        // 6. MACアドレスを読み取り
        self.read_mac()?;

        // 7. Virtqueueを設定
        self.setup_queues()?;

        // 8. 受信バッファを投入
        self.refill_rx_buffers()?;

        // 9. DRIVER_OK
        self.write_status(self.read_status() | VIRTIO_STATUS_DRIVER_OK);

        crate::log!(
            "[VIRTIO-NET] Initialized, MAC={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n",
            self.mac[0],
            self.mac[1],
            self.mac[2],
            self.mac[3],
            self.mac[4],
            self.mac[5]
        );

        Ok(())
    }

    /// ステータスレジスタを読み取り
    fn read_status(&self) -> u8 {
        // TODO: 実際のMMIO読み取り
        0
    }

    /// ステータスレジスタに書き込み
    fn write_status(&self, _status: u8) {
        // TODO: 実際のMMIO書き込み
    }

    /// フィーチャーを読み取り
    fn read_features(&self) -> u64 {
        // TODO: 実際のMMIO読み取り
        VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS
    }

    /// フィーチャーを書き込み
    fn write_features(&self, _features: u64) {
        // TODO: 実際のMMIO書き込み
    }

    /// MACアドレスを読み取り
    fn read_mac(&mut self) -> Result<(), &'static str> {
        // TODO: 実際のMMIO読み取り
        // ここではダミー値
        self.mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        Ok(())
    }

    /// Virtqueueを設定
    fn setup_queues(&self) -> Result<(), &'static str> {
        // TODO: デバイスにキューアドレスを通知
        Ok(())
    }

    /// 受信バッファを補充
    fn refill_rx_buffers(&self) -> Result<(), &'static str> {
        let mut rx_queue = self.rx_queue.lock();

        // キューサイズの半分までバッファを投入
        for _ in 0..(QUEUE_SIZE / 2) {
            if let Some(packet) = alloc_packet() {
                packet.set_len(2048); // 最大受信サイズ
                rx_queue.add_buffer_rx(packet)?;
            } else {
                break;
            }
        }

        // デバイスに通知
        self.notify_rx();

        Ok(())
    }

    /// デバイスに通知（RXキュー）
    fn notify_rx(&self) {
        // TODO: 実際のMMIO書き込み（キュー通知）
    }

    /// デバイスに通知（TXキュー）
    fn notify_tx(&self) {
        // TODO: 実際のMMIO書き込み（キュー通知）
    }

    /// パケットを送信（ゼロコピー）
    pub fn send_packet(&self, packet: PacketRef) -> Result<(), &'static str> {
        let mut tx_queue = self.tx_queue.lock();

        let len = packet.data().len();
        tx_queue.add_buffer_tx(packet)?;

        // デバイスに通知
        drop(tx_queue);
        self.notify_tx();

        self.stats.tx_packets.fetch_add(1, Ordering::Relaxed);
        self.stats.tx_bytes.fetch_add(len as u64, Ordering::Relaxed);

        Ok(())
    }

    /// 完了した送信を処理
    pub fn process_tx_completions(&self) {
        let mut tx_queue = self.tx_queue.lock();

        while let Some((_idx, _packet, _len)) = tx_queue.pop_used() {
            // PacketRefはdropされると自動的にプールに返却される
        }
    }

    /// 受信したパケットを取得（ゼロコピー）
    pub fn receive_packet(&self) -> Option<PacketRef> {
        let mut rx_queue = self.rx_queue.lock();

        if let Some((_idx, packet, len)) = rx_queue.pop_used() {
            // 受信したデータ長を設定
            packet.set_len(len as usize);

            self.stats.rx_packets.fetch_add(1, Ordering::Relaxed);
            self.stats.rx_bytes.fetch_add(len as u64, Ordering::Relaxed);

            // 新しいバッファを補充
            drop(rx_queue);
            let _ = self.refill_rx_buffers();

            return Some(packet);
        }

        None
    }

    /// MACアドレスを取得
    pub fn mac_address(&self) -> [u8; 6] {
        self.mac
    }

    /// 統計を取得
    pub fn get_stats(&self) -> (u64, u64, u64, u64) {
        (
            self.stats.rx_packets.load(Ordering::Relaxed),
            self.stats.tx_packets.load(Ordering::Relaxed),
            self.stats.rx_bytes.load(Ordering::Relaxed),
            self.stats.tx_bytes.load(Ordering::Relaxed),
        )
    }
}

// ============================================================================
// Async Interface
// ============================================================================

/// 割り込みハンドラとドライバをつなぐ共有ステート
pub struct VirtioSharedState {
    pub waker: Mutex<Option<Waker>>,
    pub ready: AtomicBool,
}

impl VirtioSharedState {
    pub const fn new() -> Self {
        Self {
            waker: Mutex::new(None),
            ready: AtomicBool::new(false),
        }
    }
}

/// グローバルなネットワークデバイスステート
static NET_DEVICE_STATE: VirtioSharedState = VirtioSharedState::new();

/// グローバルVirtIO-netデバイス
static VIRTIO_NET_DEVICE: Mutex<Option<VirtioNet>> = Mutex::new(None);

/// VirtIO-netデバイスを初期化
pub fn init_virtio_net(base_addr: usize) -> Result<(), &'static str> {
    let device = VirtioNet::new(base_addr)?;
    *VIRTIO_NET_DEVICE.lock() = Some(device);
    Ok(())
}

/// 割り込みハンドラ (ISR)
pub fn virtio_net_interrupt_handler() {
    // 1. 割り込み要因のクリア（ドライバ依存）
    // TODO: VirtIOレジスタからの読み取り処理

    // 2. フラグをセット
    NET_DEVICE_STATE.ready.store(true, Ordering::SeqCst);

    // 3. Wakerを起動
    if let Some(waker) = NET_DEVICE_STATE.waker.lock().take() {
        waker.wake_by_ref();
    }

    // 4. EOI送信
    // TODO: APIC/PICへのEOI送信処理
}

/// 非同期パケット受信関数（ゼロコピー）
/// 設計書 6.2: 所有権の連鎖
pub async fn async_receive_packet() -> Option<PacketRef> {
    poll_fn(|cx| {
        // 受信データをチェック
        let device_guard = VIRTIO_NET_DEVICE.lock();
        if let Some(device) = device_guard.as_ref() {
            if let Some(packet) = device.receive_packet() {
                return Poll::Ready(Some(packet));
            }
        }
        drop(device_guard);

        if NET_DEVICE_STATE.ready.load(Ordering::SeqCst) {
            NET_DEVICE_STATE.ready.store(false, Ordering::SeqCst);

            // もう一度チェック
            let device_guard = VIRTIO_NET_DEVICE.lock();
            if let Some(device) = device_guard.as_ref() {
                if let Some(packet) = device.receive_packet() {
                    return Poll::Ready(Some(packet));
                }
            }
        }

        // まだデータがないならWakerを登録
        let mut waker_guard = NET_DEVICE_STATE.waker.lock();
        *waker_guard = Some(cx.waker().clone());
        Poll::Pending
    })
    .await
}

/// 非同期パケット送信関数（ゼロコピー）
pub async fn async_send_packet(packet: PacketRef) -> Result<(), &'static str> {
    let device_guard = VIRTIO_NET_DEVICE.lock();
    if let Some(device) = device_guard.as_ref() {
        device.send_packet(packet)
    } else {
        Err("VirtIO-net device not initialized")
    }
}

/// パケットを送信（Vec<u8>からPacketRefを作成）
pub async fn async_send_data(data: &[u8]) -> Result<(), &'static str> {
    let mut packet = alloc_packet().ok_or("Failed to allocate packet buffer")?;

    let len = data.len().min(packet.data().len());
    packet.data_mut()[..len].copy_from_slice(&data[..len]);
    packet.set_len(len);

    async_send_packet(packet).await
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_virtqueue_desc_allocation() {
        let mut queue = Virtqueue::new(0).expect("Failed to create virtqueue");

        // ディスクリプタを割り当て
        let idx1 = queue.alloc_desc().expect("Should allocate descriptor");
        let idx2 = queue.alloc_desc().expect("Should allocate descriptor");
        assert_ne!(idx1, idx2);

        // 解放して再割り当て
        queue.free_desc(idx1);
        let idx3 = queue.alloc_desc().expect("Should allocate descriptor");
        assert_eq!(idx1, idx3); // 同じインデックスが再利用される
    }
}
