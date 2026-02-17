// ============================================================================
// src/io/usb/xhci/controller.rs - xHCI Host Controller
// ============================================================================
//!
//! xHCI ホストコントローラの実装。
//!
//! ## 機能
//! - コントローラ初期化とリセット
//! - コマンドリング/イベントリング管理
//! - ポート状態管理
//! - デバイス列挙

#![allow(dead_code)]

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::Waker;
use kernel_api::types::DmaBuffer;
use spin::Mutex;

use super::context::DeviceContext;
use super::event_handler::{
mod _split_1;
use _split_1::*;
    CommandCompletionEvent, EventHandler, PortStatusChangeEvent, ProcessedEvent, TransferEvent,
};
use super::trb::{CompletionCode, ErstEntry, Trb, TrbRing};
use super::{
    COMMAND_RING_SIZE, CONFIG, CRCR, DCBAAP, ERDP, ERSTBA, ERSTSZ, EVENT_RING_SIZE, IMAN, IR0,
    MAX_ENDPOINTS, MAX_SLOTS, PORT_REGISTER_SIZE, PORTSC_BASE, PORTSC_CCS, PORTSC_CHANGE_MASK,
    PORTSC_CSC, PORTSC_OCA, PORTSC_PEC, PORTSC_PED, PORTSC_PP, PORTSC_PR, PORTSC_PRC, USBCMD,
    USBCMD_HCRST, USBCMD_INTE, USBCMD_RUN, USBSTS, USBSTS_CNR, USBSTS_HCH,
};
use crate::{PortNumber, PortStatus, SlotId, UsbError, UsbResult, UsbSpeed};

// ============================================================================
// Register Offsets (from Capability Registers)
// ============================================================================

const CAPLENGTH: usize = 0x00;
const HCIVERSION: usize = 0x02;
const HCSPARAMS1: usize = 0x04;
const HCCPARAMS1: usize = 0x10;
const DBOFF: usize = 0x14;
const RTSOFF: usize = 0x18;

// ============================================================================
// DMA-backed Device Context
// ============================================================================

/// DMAバッファで裏付けされたデバイスコンテキスト
struct DmaDeviceContext {
    /// CPUアクセス用ポインタ
    ptr: *mut DeviceContext,
    /// デバイス可視アドレス (IOVA or physical)
    #[allow(dead_code)]
    device_addr: u64,
    /// DMAバッファ (所有権保持)
    _dma_buf: DmaBuffer,
}

// Safety: DmaBufferのSend性を保証
unsafe impl Send for DmaDeviceContext {}

impl DmaDeviceContext {
    /// CPU側からDeviceContextにアクセス
    fn context(&self) -> &DeviceContext {
        unsafe { &*self.ptr }
    }
}

// ============================================================================
// xHCI Controller
// ============================================================================

/// xHCIコントローラ
pub struct XhciController {
    /// ベースアドレス
    base_addr: u64,
    /// Capability Registers オフセット
    cap_offset: u64,
    /// Operational Registers オフセット
    op_offset: u64,
    /// Runtime Registers オフセット
    rt_offset: u64,
    /// Doorbell Registers オフセット
    db_offset: u64,
    /// 最大スロット数
    max_slots: u8,
    /// 最大ポート数
    max_ports: u8,
    /// ページサイズ
    page_size: u32,
    /// コマンドリング
    command_ring: Mutex<TrbRing>,
    /// イベントリング
    event_ring: Mutex<TrbRing>,
    /// ERST (CPU access pointer)
    erst_ptr: *mut ErstEntry,
    /// ERST device-visible address
    erst_device_addr: u64,
    /// ERST DMAバッファ (所有権保持)
    _erst_buf: Option<DmaBuffer>,
    /// DCBAA (CPU access pointer)
    dcbaa_ptr: *mut u64,
    /// DCBAA device-visible address
    dcbaa_device_addr: u64,
    /// DCBAA DMAバッファ (所有権保持)
    _dcbaa_buf: Option<DmaBuffer>,
    /// デバイスコンテキスト (DMA-backed)
    device_contexts: Mutex<Vec<Option<DmaDeviceContext>>>,
    /// 転送リング（スロット×エンドポイント）
    pub(crate) transfer_rings: Mutex<Vec<Vec<Option<Box<TrbRing>>>>>,
    /// コマンド完了待ち
    command_completions: Mutex<Vec<CommandCompletion>>,
    /// 転送完了待ち
    transfer_completions: Mutex<Vec<TransferCompletion>>,
    /// イベントハンドラ (ISR/Task共有)
    event_handler: Mutex<EventHandler>,
    /// 実行中フラグ
    running: AtomicBool,
}

// Safety: XhciControllerの生ポインタ(erst_ptr, dcbaa_ptr)はDMAバッファの寿命内で有効。
//         全ての可変状態はMutexで保護されている。
unsafe impl Send for XhciController {}
unsafe impl Sync for XhciController {}

/// コマンド完了情報
pub(crate) struct CommandCompletion {
    pub trb_addr: u64,
    pub completion_code: CompletionCode,
    pub slot_id: SlotId,
    pub waker: Option<Waker>,
    pub completed: bool,
}

/// コマンド完了結果
pub(crate) struct CommandCompletionResult {
    pub completion_code: CompletionCode,
    pub slot_id: SlotId,
}

/// 転送完了情報
pub(crate) struct TransferCompletion {
    /// TRBアドレス
    pub trb_addr: u64,
    /// スロットID
    pub slot_id: SlotId,
    /// エンドポイントID
    pub endpoint_id: u8,
    /// 完了コード
    pub completion_code: CompletionCode,
    /// 転送バイト数
    pub transferred: u32,
    /// Waker
    pub waker: Option<Waker>,
    /// 完了フラグ
    pub completed: bool,
}

/// 転送完了結果
pub(crate) struct TransferCompletionResult {
    pub completion_code: CompletionCode,
    pub transferred: u32,
}

impl XhciController {
    /// 新しいxHCIコントローラを作成
    pub fn new(base_addr: u64) -> UsbResult<Self> {
        // Capability Registers を読み取り
        let caplength = hal::mmio::mmio_read_u8((base_addr + CAPLENGTH as u64) as usize);
        let hciversion = hal::mmio::mmio_read_u16((base_addr + HCIVERSION as u64) as usize);
        let hcsparams1 = hal::mmio::mmio_read_u32((base_addr + HCSPARAMS1 as u64) as usize);
        let hccparams1 = hal::mmio::mmio_read_u32((base_addr + HCCPARAMS1 as u64) as usize);
        let dboff = hal::mmio::mmio_read_u32((base_addr + DBOFF as u64) as usize);
        let rtsoff = hal::mmio::mmio_read_u32((base_addr + RTSOFF as u64) as usize);

        let _ = hciversion;

        let max_slots = (hcsparams1 & 0xFF) as u8;
        let max_ports = ((hcsparams1 >> 24) & 0xFF) as u8;
        let _context_size_flag = (hccparams1 >> 2) & 1;

        let op_offset = base_addr + caplength as u64;
        let rt_offset = base_addr + (rtsoff & !0x1F) as u64;
        let db_offset = base_addr + (dboff & !0x03) as u64;

        // コマンドリングを作成
        let command_ring = TrbRing::new(COMMAND_RING_SIZE);

        // イベントリングを作成
        let event_ring = TrbRing::new(EVENT_RING_SIZE);

        // ERSTをDMAバッファで作成
        let erst_byte_size = core::mem::size_of::<ErstEntry>();
        let (erst_ptr, erst_device_addr, erst_buf) =
            match kernel_api::services::kernel().alloc_dma(erst_byte_size) {
                Ok(dma_buf) => {
                    let ptr = dma_buf.as_ptr() as *mut ErstEntry;
                    let dev_addr = dma_buf.device_address();
                    unsafe {
                        let entry = &mut *ptr;
                        entry.ring_segment_base = event_ring.physical_address();
                        entry.ring_segment_size = EVENT_RING_SIZE as u16;
                        entry.reserved = [0u8; 6];
                    }
                    (ptr, dev_addr, Some(dma_buf))
                }
                Err(_) => {
                    // Fallback: ヒープ割り当て
                    let mut erst = vec![ErstEntry::default(); 1].into_boxed_slice();
                    erst[0].ring_segment_base = event_ring.physical_address();
                    erst[0].ring_segment_size = EVENT_RING_SIZE as u16;
                    let ptr = erst.as_mut_ptr();
                    let addr = ptr as u64;
                    core::mem::forget(erst);
                    (ptr, addr, None)
                }
            };

        // DCBAAをDMAバッファで作成
        let dcbaa_entries = max_slots as usize + 1;
        let dcbaa_byte_size = dcbaa_entries * core::mem::size_of::<u64>();
        let (dcbaa_ptr, dcbaa_device_addr, dcbaa_buf) =
            match kernel_api::services::kernel().alloc_dma(dcbaa_byte_size) {
                Ok(dma_buf) => {
                    let ptr = dma_buf.as_ptr() as *mut u64;
                    let dev_addr = dma_buf.device_address();
                    unsafe { core::ptr::write_bytes(ptr, 0, dcbaa_entries); }
                    (ptr, dev_addr, Some(dma_buf))
                }
                Err(_) => {
                    // Fallback: ヒープ割り当て
                    let dcbaa = vec![0u64; dcbaa_entries].into_boxed_slice();
                    let ptr = dcbaa.as_ptr() as *mut u64;
                    let addr = ptr as u64;
                    core::mem::forget(dcbaa);
                    (ptr, addr, None)
                }
            };

        // Device contextsの初期化
        let device_contexts: Vec<Option<DmaDeviceContext>> =
            (0..MAX_SLOTS).map(|_| None).collect();
        // Transfer ringsの初期化
        let transfer_rings: Vec<Vec<Option<Box<TrbRing>>>> = (0..MAX_SLOTS)
            .map(|_| (0..MAX_ENDPOINTS).map(|_| None).collect())
            .collect();

        let controller = Self {
            base_addr,
            cap_offset: base_addr,
            op_offset,
            rt_offset,
            db_offset,
            max_slots,
            max_ports,
            page_size: 4096,
            command_ring: Mutex::new(command_ring),
            event_ring: Mutex::new(event_ring),
            erst_ptr,
            erst_device_addr,
            _erst_buf: erst_buf,
            dcbaa_ptr,
            dcbaa_device_addr,
            _dcbaa_buf: dcbaa_buf,
            device_contexts: Mutex::new(device_contexts),
            transfer_rings: Mutex::new(transfer_rings),
            command_completions: Mutex::new(Vec::new()),
            transfer_completions: Mutex::new(Vec::new()),
            event_handler: Mutex::new(EventHandler::new()),
            running: AtomicBool::new(false),
        };

        Ok(controller)
    }

    /// コントローラを初期化
    pub fn init(&mut self) -> UsbResult<()> {
        // コントローラを停止
        self.stop()?;

        // コントローラをリセット
        self.reset()?;

        // 最大スロット数を設定
        self.write_op(CONFIG, self.max_slots as u32);

        // DCBAAを設定 (デバイス可視アドレスで)
        self.write_op_64(DCBAAP, self.dcbaa_device_addr);

        // コマンドリングを設定
        let cmd_ring = self.command_ring.lock();
        let crcr_val = cmd_ring.physical_address() | 1; // RCS = 1
        drop(cmd_ring);
        self.write_op_64(CRCR, crcr_val);

        // イベントリングを設定
        let event_ring = self.event_ring.lock();

        // ERSTSZ
        self.write_runtime(ERSTSZ, 1);

        // ERDP
        self.write_runtime_64(ERDP, event_ring.physical_address());

        // ERSTBA (デバイス可視アドレスで)
        self.write_runtime_64(ERSTBA, self.erst_device_addr);
        drop(event_ring);

        // 割り込みを有効化
        self.write_runtime(IMAN, 0x3); // IP | IE

        // コントローラを開始
        self.start()?;

        Ok(())
    }

    /// コントローラを停止
    fn stop(&self) -> UsbResult<()> {
        let mut cmd = self.read_op(USBCMD);
        cmd &= !USBCMD_RUN;
        self.write_op(USBCMD, cmd);

        // HCHビットが1になるまで待機
        for _ in 0..100 {
            let status = self.read_op(USBSTS);
            if (status & USBSTS_HCH) != 0 {
                return Ok(());
            }
        }

        Err(UsbError::Timeout)
    }

    /// コントローラをリセット
    fn reset(&self) -> UsbResult<()> {
        let mut cmd = self.read_op(USBCMD);
        cmd |= USBCMD_HCRST;
        self.write_op(USBCMD, cmd);

        // HCRSTビットが0になるまで待機
        for _ in 0..100 {
            let cmd = self.read_op(USBCMD);
            if (cmd & USBCMD_HCRST) == 0 {
                // CNRビットも確認
                let status = self.read_op(USBSTS);
                if (status & USBSTS_CNR) == 0 {
                    return Ok(());
                }
            }
        }

        Err(UsbError::Timeout)
    }

    /// コントローラを開始
    fn start(&self) -> UsbResult<()> {
        let mut cmd = self.read_op(USBCMD);
        cmd |= USBCMD_RUN | USBCMD_INTE;
        self.write_op(USBCMD, cmd);

        // HCHビットが0になるまで待機
        for _ in 0..100 {
            let status = self.read_op(USBSTS);
            if (status & USBSTS_HCH) == 0 {
                self.running.store(true, Ordering::SeqCst);
                return Ok(());
            }
        }

        Err(UsbError::Timeout)
    }

    /// ポート状態を取得
    pub fn port_status(&self, port: PortNumber) -> PortStatus {
        let portsc = self.read_portsc(port);

        let speed = match (portsc >> 10) & 0x0F {
            1 => Some(UsbSpeed::Full),
            2 => Some(UsbSpeed::Low),
            3 => Some(UsbSpeed::High),
            4 => Some(UsbSpeed::Super),
            5 => Some(UsbSpeed::SuperPlus),
            _ => None,
        };

        PortStatus {
            connected: (portsc & PORTSC_CCS) != 0,
            enabled: (portsc & PORTSC_PED) != 0,
            suspended: false,
            overcurrent: (portsc & PORTSC_OCA) != 0,
            reset: (portsc & PORTSC_PR) != 0,
            powered: (portsc & PORTSC_PP) != 0,
            connect_change: (portsc & PORTSC_CSC) != 0,
            enable_change: (portsc & PORTSC_PEC) != 0,
            reset_change: (portsc & PORTSC_PRC) != 0,
            speed,
        }
    }

    /// ポートをリセット
    pub async fn reset_port(&self, port: PortNumber) -> UsbResult<UsbSpeed> {
        let offset = PORTSC_BASE + port.as_usize() * PORT_REGISTER_SIZE;

        // リセットを開始
        let portsc = self.read_op(offset);
        self.write_op(offset, (portsc & !PORTSC_CHANGE_MASK) | PORTSC_PR);

        // リセット完了を待機
        for _ in 0..100 {
            let portsc = self.read_op(offset);
            if (portsc & PORTSC_PRC) != 0 {
                // リセット完了、変更フラグをクリア
                self.write_op(offset, (portsc & !PORTSC_CHANGE_MASK) | PORTSC_PRC);

                let speed_code = ((portsc >> 10) & 0x0F) as u8;
                return UsbSpeed::from_code(speed_code)
                    .ok_or(UsbError::Other("Unknown speed".into()));
            }
        }

        Err(UsbError::Timeout)
    }

    /// ポートをサスペンド
    pub async fn suspend_port(&self, port: PortNumber) -> UsbResult<()> {
        let offset = PORTSC_BASE + port.as_usize() * PORT_REGISTER_SIZE;
        let portsc = self.read_op(offset);

        if (portsc & PORTSC_PED) == 0 {
            return Err(UsbError::Other("Port disabled".into()));
        }

        // U3 (Suspend) = 3
        let pls_u3 = 3;
        let new_portsc = (portsc & !PORTSC_CHANGE_MASK & !(0xF << 5)) | (pls_u3 << 5) | (1 << 16); // LWS=1
        self.write_op(offset, new_portsc);

        // 状態遷移待ち（必要に応じて）
        Ok(())
    }

    /// ポートをレジューム
    pub async fn resume_port(&self, port: PortNumber) -> UsbResult<()> {
        let offset = PORTSC_BASE + port.as_usize() * PORT_REGISTER_SIZE;
        let portsc = self.read_op(offset);

        // USB 2.0 vs 3.0 check
        // Speed is in bits 10-13.
        // 1=Full, 2=Low, 3=High (USB2)
        // 4=Super, 5=SuperPlus (USB3)
        let speed_val = (portsc >> 10) & 0xF;
        let is_usb3 = speed_val >= 4;

        let pls_resume = if is_usb3 {
            0 // U0
        } else {
            15 // Resume
        };

        let new_portsc =
            (portsc & !PORTSC_CHANGE_MASK & !(0xF << 5)) | (pls_resume << 5) | (1 << 16); // LWS=1
        self.write_op(offset, new_portsc);

        Ok(())
    }

    /// デバイスをサスペンド
    pub async fn suspend_device(&self, slot_id: SlotId) -> UsbResult<()> {
        let port = self.get_root_port_for_slot(slot_id).await?;
        self.suspend_port(port).await
    }

    /// デバイスをレジューム
    pub async fn resume_device(&self, slot_id: SlotId) -> UsbResult<()> {
        let port = self.get_root_port_for_slot(slot_id).await?;
        self.resume_port(port).await
    }

    /// スロットIDからルートハブポート番号を取得
    async fn get_root_port_for_slot(&self, slot_id: SlotId) -> UsbResult<PortNumber> {
        let device_contexts = self.device_contexts.lock();
        if let Some(ctx) = device_contexts
            .get(slot_id.as_usize())
            .and_then(|opt| opt.as_ref())
        {
            // latency_and_ports: Bits 16-23 is Root Hub Port Number
            let root_port_num = ((ctx.context().slot.latency_and_ports >> 16) & 0xFF) as u8;
            drop(device_contexts);

            if root_port_num == 0 {
                return Err(UsbError::InvalidDevice);
            }
            Ok(PortNumber(root_port_num))
        } else {
            Err(UsbError::InvalidDevice)
        }
    }

    /// スロットを有効化
    pub async fn enable_slot(&self) -> UsbResult<SlotId> {
        let trb = Trb::enable_slot(self.command_ring.lock().cycle_bit());
        let trb_addr = self.send_command(trb)?;

        let completion = self.wait_command_completion(trb_addr).await?;

        if completion.completion_code == CompletionCode::Success {
            Ok(completion.slot_id)
        } else {
            Err(UsbError::XhciError(alloc::format!(
                "Enable slot failed: {:?}",
                completion.completion_code
            )))
        }
    }

    /// コマンドを送信
    pub(crate) fn send_command(&self, trb: Trb) -> UsbResult<u64> {
        let mut ring = self.command_ring.lock();
        let addr = ring.enqueue(trb).ok_or(UsbError::NoResources)?;
        drop(ring);

        // ドアベルを鳴らす
        self.ring_doorbell(0, 0);

        Ok(addr)
    }

    /// コマンド完了を待機
    async fn wait_command_completion(&self, trb_addr: u64) -> UsbResult<CommandCompletionResult> {
        // 実際の実装では適切なasync待機を行う
        for _ in 0..1000 {
            self.process_events();
            self.process_pending_events();

            let mut completions = self.command_completions.lock();
            if let Some(pos) = completions
                .iter()
                .position(|c| c.trb_addr == trb_addr && c.completed)
            {
                let completion = completions.remove(pos);
                return Ok(CommandCompletionResult {
                    completion_code: completion.completion_code,
                    slot_id: completion.slot_id,
                });
            }
        }

        Err(UsbError::Timeout)
    }

    /// イベントを処理 (ISRから呼び出し)
    ///
    /// イベントリングからTRBを読み出し、キューに積む。
    /// 実際の処理は `process_pending_events` で行う。
    pub fn process_events(&self) {
        let mut event_ring = self.event_ring.lock();
        let expected_cycle = event_ring.cycle_bit;
        let mut event_handler = self.event_handler.lock();

        loop {
            let idx = event_ring.dequeue_index;
            let trb = hal::mmio::volatile_read::<Trb>(&event_ring.trbs()[idx] as *const Trb as usize);

            if trb.cycle_bit() != expected_cycle {
                break;
            }

            // TRBをパースしてキューに追加
            let event = EventHandler::parse_event(&trb);
            event_handler.handle_event(event);

            event_ring.dequeue_index = (idx + 1) % event_ring.len();
            if event_ring.dequeue_index == 0 {
                // サイクルビットを反転
                event_ring.cycle_bit = !event_ring.cycle_bit;
            }
        }

        // ERDPを更新
        let dequeue_ptr = event_ring.phys_addr + (event_ring.dequeue_index * 16) as u64;
        drop(event_ring);
        self.write_runtime_64(ERDP, dequeue_ptr | 0x8); // EHB
    }

    /// 保留中のイベントを処理 (タスク/ポーリングループから呼び出し)
    pub fn process_pending_events(&self) {
        let mut event_handler = self.event_handler.lock();
        while let Some(event) = event_handler.pop_pending_event() {
            drop(event_handler); // ハンドラロックを一旦解放（コールバック内でのロック競合回避）

            match event {
                ProcessedEvent::CommandCompletion(evt) => {
                    self.handle_command_completion(&evt);
                }
                ProcessedEvent::Transfer(evt) => {
                    self.handle_transfer_completion(&evt);
                }
                ProcessedEvent::PortStatusChange(evt) => {
                    self.handle_port_status_change(&evt);
                }
                _ => {}
            }

            event_handler = self.event_handler.lock(); // ロック再取得
        }
    }

    /// コマンド完了イベントを処理
    fn handle_command_completion(&self, event: &CommandCompletionEvent) {
        let trb_addr = event.trb_address;

        let mut completions = self.command_completions.lock();
        for completion in completions.iter_mut() {
            if completion.trb_addr == trb_addr {
                completion.completion_code = event.completion_code;
                completion.slot_id = event.slot_id;
                completion.completed = true;
                if let Some(waker) = completion.waker.take() {
                    waker.wake();
                }
                return;
            }
        }

        // 新しい完了を追加
        completions.push(CommandCompletion {
            trb_addr,
            completion_code: event.completion_code,
            slot_id: event.slot_id,
            waker: None,
            completed: true,
        });
    }

    /// 転送完了イベントを処理
    fn handle_transfer_completion(&self, event: &TransferEvent) {
        let transferred = event.transfer_length; // TODO: Check calculation

        let mut completions = self.transfer_completions.lock();
        for completion in completions.iter_mut() {
            // スロットとエンドポイントでマッチング
            if completion.slot_id == event.slot_id
                && completion.endpoint_id == event.endpoint_id
                && !completion.completed
            {
                completion.completion_code = event.completion_code;
                completion.transferred = transferred; // 簡易実装。実際はResidualからの計算が必要かも
                completion.completed = true;
                if let Some(waker) = completion.waker.take() {
                    waker.wake();
                }
                return;
            }
        }

        // 未登録の転送完了は新規追加
        completions.push(TransferCompletion {
            trb_addr: event.trb_pointer,
            slot_id: event.slot_id,
            endpoint_id: event.endpoint_id,
            completion_code: event.completion_code,
            transferred,
            waker: None,
            completed: true,
        });
    }

    /// ポート状態変更イベントを処理
    fn handle_port_status_change(&self, event: &PortStatusChangeEvent) {
        let _port_id = event.port_id;
        // ポート状態変更の処理は別途実装
    }

    /// ドアベルを鳴らす
    pub(crate) fn ring_doorbell(&self, slot_id: u8, target: u8) {
        let offset = self.db_offset + (slot_id as u64) * 4;
        hal::mmio::mmio_write_u32(offset as usize, target as u32);
    }

    // レジスタアクセスヘルパー
    fn read_op(&self, offset: usize) -> u32 {
        hal::mmio::mmio_read_u32((self.op_offset + offset as u64) as usize)
    }

    fn write_op(&self, offset: usize, value: u32) {
        hal::mmio::mmio_write_u32((self.op_offset + offset as u64) as usize, value)
    }

    fn write_op_64(&self, offset: usize, value: u64) {
        hal::mmio::mmio_write_u64((self.op_offset + offset as u64) as usize, value)
    }

    fn read_portsc(&self, port: PortNumber) -> u32 {
        let offset = PORTSC_BASE + port.as_usize() * PORT_REGISTER_SIZE;
        self.read_op(offset)
    }

    fn read_runtime(&self, offset: usize) -> u32 {
        hal::mmio::mmio_read_u32((self.rt_offset + IR0 as u64 + offset as u64) as usize)
    }
}
