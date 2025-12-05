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
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::Waker;
use spin::Mutex;

use super::context::DeviceContext;
use super::trb::{CompletionCode, ErstEntry, Trb, TrbRing, TrbType};
use super::{
    COMMAND_RING_SIZE, CONFIG, CRCR, DCBAAP, ERDP, ERSTBA, ERSTSZ, EVENT_RING_SIZE, IMAN,
    IR0, MAX_ENDPOINTS, MAX_SLOTS, PAGESIZE, PORTSC_BASE, PORTSC_CCS, PORTSC_CHANGE_MASK,
    PORTSC_CSC, PORTSC_OCA, PORTSC_PEC, PORTSC_PED, PORTSC_PP, PORTSC_PR, PORTSC_PRC,
    PORT_REGISTER_SIZE, USBCMD, USBCMD_HCRST, USBCMD_INTE, USBCMD_RUN, USBSTS, USBSTS_CNR,
    USBSTS_HCH,
};
use crate::io::usb::{PortNumber, PortStatus, SlotId, UsbError, UsbResult, UsbSpeed};

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
    /// イベントリングセグメントテーブル
    erst: Box<[ErstEntry]>,
    /// DCBAA
    dcbaa: Box<[u64]>,
    /// デバイスコンテキスト
    device_contexts: Mutex<Vec<Option<Box<DeviceContext>>>>,
    /// 転送リング（スロット×エンドポイント）
    pub(crate) transfer_rings: Mutex<Vec<Vec<Option<Box<TrbRing>>>>>,
    /// コマンド完了待ち
    command_completions: Mutex<Vec<CommandCompletion>>,
    /// 転送完了待ち
    transfer_completions: Mutex<Vec<TransferCompletion>>,
    /// 実行中フラグ
    running: AtomicBool,
}

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
        let caplength = unsafe { ptr::read_volatile((base_addr + CAPLENGTH as u64) as *const u8) };
        let hciversion =
            unsafe { ptr::read_volatile((base_addr + HCIVERSION as u64) as *const u16) };
        let hcsparams1 =
            unsafe { ptr::read_volatile((base_addr + HCSPARAMS1 as u64) as *const u32) };
        let hccparams1 =
            unsafe { ptr::read_volatile((base_addr + HCCPARAMS1 as u64) as *const u32) };
        let dboff = unsafe { ptr::read_volatile((base_addr + DBOFF as u64) as *const u32) };
        let rtsoff = unsafe { ptr::read_volatile((base_addr + RTSOFF as u64) as *const u32) };

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

        // ERSTを作成
        let mut erst = vec![ErstEntry::default(); 1].into_boxed_slice();
        erst[0].ring_segment_base = event_ring.physical_address();
        erst[0].ring_segment_size = EVENT_RING_SIZE as u16;

        // DCBAAを作成
        let dcbaa = vec![0u64; max_slots as usize + 1].into_boxed_slice();

        // Device contextsの初期化
        let device_contexts: Vec<Option<Box<DeviceContext>>> =
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
            erst,
            dcbaa,
            device_contexts: Mutex::new(device_contexts),
            transfer_rings: Mutex::new(transfer_rings),
            command_completions: Mutex::new(Vec::new()),
            transfer_completions: Mutex::new(Vec::new()),
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

        // DCBAAを設定
        let dcbaa_addr = self.dcbaa.as_ptr() as u64;
        self.write_op_64(DCBAAP, dcbaa_addr);

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

        // ERSTBA
        let erst_addr = self.erst.as_ptr() as u64;
        self.write_runtime_64(ERSTBA, erst_addr);
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

    /// イベントを処理
    pub fn process_events(&self) {
        let mut event_ring = self.event_ring.lock();
        let expected_cycle = event_ring.cycle_bit;

        loop {
            let idx = event_ring.dequeue_index;
            let trb = unsafe { ptr::read_volatile(&event_ring.trbs[idx] as *const Trb) };

            if trb.cycle_bit() != expected_cycle {
                break;
            }

            // イベントを処理
            match TrbType::from_u8(trb.trb_type()) {
                Some(TrbType::CommandCompletion) => {
                    self.handle_command_completion(&trb);
                }
                Some(TrbType::Transfer) => {
                    self.handle_transfer_completion(&trb);
                }
                Some(TrbType::PortStatusChange) => {
                    self.handle_port_status_change(&trb);
                }
                _ => {}
            }

            event_ring.dequeue_index = (idx + 1) % event_ring.trbs.len();
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

    /// コマンド完了イベントを処理
    fn handle_command_completion(&self, trb: &Trb) {
        let completion_code = CompletionCode::from_u8(((trb.status >> 24) & 0xFF) as u8);
        let slot_id = SlotId(((trb.control >> 24) & 0xFF) as u8);
        let trb_addr = trb.parameter & !0xF;

        let mut completions = self.command_completions.lock();
        for completion in completions.iter_mut() {
            if completion.trb_addr == trb_addr {
                completion.completion_code = completion_code;
                completion.slot_id = slot_id;
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
            completion_code,
            slot_id,
            waker: None,
            completed: true,
        });
    }

    /// 転送完了イベントを処理
    fn handle_transfer_completion(&self, trb: &Trb) {
        let completion_code = CompletionCode::from_u8(((trb.status >> 24) & 0xFF) as u8);
        let slot_id = SlotId(((trb.control >> 24) & 0xFF) as u8);
        let endpoint_id = ((trb.control >> 16) & 0x1F) as u8;
        let trb_addr = trb.parameter;
        let transferred = trb.status & 0xFFFFFF; // Transfer Length

        let mut completions = self.transfer_completions.lock();
        for completion in completions.iter_mut() {
            // スロットとエンドポイントでマッチング（TRBアドレスも考慮可能）
            if completion.slot_id == slot_id 
                && completion.endpoint_id == endpoint_id 
                && !completion.completed 
            {
                completion.completion_code = completion_code;
                completion.transferred = transferred;
                completion.completed = true;
                if let Some(waker) = completion.waker.take() {
                    waker.wake();
                }
                return;
            }
        }

        // 未登録の転送完了は新規追加（コールバックがない場合）
        completions.push(TransferCompletion {
            trb_addr,
            slot_id,
            endpoint_id,
            completion_code,
            transferred,
            waker: None,
            completed: true,
        });
    }

    /// ポート状態変更イベントを処理
    fn handle_port_status_change(&self, trb: &Trb) {
        let _port_id = ((trb.parameter >> 24) & 0xFF) as u8;
        // ポート状態変更の処理は別途実装
    }

    /// ドアベルを鳴らす
    pub(crate) fn ring_doorbell(&self, slot_id: u8, target: u8) {
        let offset = self.db_offset + (slot_id as u64) * 4;
        unsafe {
            ptr::write_volatile(offset as *mut u32, target as u32);
        }
    }

    // レジスタアクセスヘルパー
    fn read_op(&self, offset: usize) -> u32 {
        unsafe { ptr::read_volatile((self.op_offset + offset as u64) as *const u32) }
    }

    fn write_op(&self, offset: usize, value: u32) {
        unsafe { ptr::write_volatile((self.op_offset + offset as u64) as *mut u32, value) }
    }

    fn write_op_64(&self, offset: usize, value: u64) {
        unsafe { ptr::write_volatile((self.op_offset + offset as u64) as *mut u64, value) }
    }

    fn read_portsc(&self, port: PortNumber) -> u32 {
        let offset = PORTSC_BASE + port.as_usize() * PORT_REGISTER_SIZE;
        self.read_op(offset)
    }

    fn read_runtime(&self, offset: usize) -> u32 {
        unsafe { ptr::read_volatile((self.rt_offset + IR0 as u64 + offset as u64) as *const u32) }
    }

    fn write_runtime(&self, offset: usize, value: u32) {
        unsafe {
            ptr::write_volatile(
                (self.rt_offset + IR0 as u64 + offset as u64) as *mut u32,
                value,
            )
        }
    }

    fn write_runtime_64(&self, offset: usize, value: u64) {
        unsafe {
            ptr::write_volatile(
                (self.rt_offset + IR0 as u64 + offset as u64) as *mut u64,
                value,
            )
        }
    }

    /// ポート数を取得
    pub fn port_count(&self) -> u8 {
        self.max_ports
    }

    /// 転送完了待ちを登録
    pub(crate) fn register_transfer_wait(
        &self, 
        slot_id: SlotId, 
        endpoint_id: u8,
        waker: Waker,
    ) {
        let mut completions = self.transfer_completions.lock();
        completions.push(TransferCompletion {
            trb_addr: 0, // TRBアドレスは後で設定可能
            slot_id,
            endpoint_id,
            completion_code: CompletionCode::Invalid,
            transferred: 0,
            waker: Some(waker),
            completed: false,
        });
    }

    /// 転送完了を確認
    pub(crate) fn check_transfer_completion(
        &self,
        slot_id: SlotId,
        endpoint_id: u8,
    ) -> Option<TransferCompletionResult> {
        let mut completions = self.transfer_completions.lock();
        if let Some(pos) = completions.iter().position(|c| {
            c.slot_id == slot_id && c.endpoint_id == endpoint_id && c.completed
        }) {
            let completion = completions.remove(pos);
            return Some(TransferCompletionResult {
                completion_code: completion.completion_code,
                transferred: completion.transferred,
            });
        }
        None
    }

    /// 転送完了待ちをキャンセル
    pub(crate) fn cancel_transfer_wait(&self, slot_id: SlotId, endpoint_id: u8) {
        let mut completions = self.transfer_completions.lock();
        completions.retain(|c| !(c.slot_id == slot_id && c.endpoint_id == endpoint_id && !c.completed));
    }
}
