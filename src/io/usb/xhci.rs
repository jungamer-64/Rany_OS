// ============================================================================
// src/io/usb/xhci.rs - xHCI Host Controller Driver
// ============================================================================
//!
//! # xHCI (eXtensible Host Controller Interface) ドライバ
//!
//! USB 3.x ホストコントローラドライバ。
//!
//! ## アーキテクチャ
//! - レジスタ操作による直接制御
//! - TRB (Transfer Request Block) ベースのコマンド/転送
//! - イベントリングによる非同期完了通知
//!
//! ## メモリ構造
//! - DCBAA (Device Context Base Address Array)
//! - Transfer Ring per endpoint
//! - Command Ring
//! - Event Ring
//!
//! ## 型安全性
//! - TRB の型レベル表現
//! - Volatile 型によるレジスタアクセス

#![allow(dead_code)]

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use core::task::{Context, Poll, Waker};
use spin::Mutex;

use super::{
    DeviceAddress, EndpointAddress, PortNumber, PortStatus, SetupPacket, SlotId,
    TransferDirection, TransferStatus, TransferType, UsbDevice, UsbError, UsbResult, UsbSpeed,
};
use super::descriptor::{DeviceDescriptor, parse_configuration, ParsedConfiguration};

// ============================================================================
// xHCI Constants
// ============================================================================

/// 最大スロット数
const MAX_SLOTS: usize = 256;
/// 最大ポート数
const MAX_PORTS: usize = 256;
/// 最大エンドポイント数（スロットあたり）
const MAX_ENDPOINTS: usize = 31;
/// コマンドリングサイズ
const COMMAND_RING_SIZE: usize = 256;
/// イベントリングサイズ
const EVENT_RING_SIZE: usize = 256;
/// 転送リングサイズ
const TRANSFER_RING_SIZE: usize = 256;

// ============================================================================
// xHCI Register Offsets (Capability)
// ============================================================================

/// Capability Register Length
const CAPLENGTH: usize = 0x00;
/// Host Controller Interface Version
const HCIVERSION: usize = 0x02;
/// Structural Parameters 1
const HCSPARAMS1: usize = 0x04;
/// Structural Parameters 2
const HCSPARAMS2: usize = 0x08;
/// Structural Parameters 3
const HCSPARAMS3: usize = 0x0C;
/// Capability Parameters 1
const HCCPARAMS1: usize = 0x10;
/// Doorbell Offset
const DBOFF: usize = 0x14;
/// Runtime Register Space Offset
const RTSOFF: usize = 0x18;
/// Capability Parameters 2
const HCCPARAMS2: usize = 0x1C;

// ============================================================================
// xHCI Register Offsets (Operational)
// ============================================================================

/// USB Command
const USBCMD: usize = 0x00;
/// USB Status
const USBSTS: usize = 0x04;
/// Page Size
const PAGESIZE: usize = 0x08;
/// Device Notification Control
const DNCTRL: usize = 0x14;
/// Command Ring Control
const CRCR: usize = 0x18;
/// Device Context Base Address Array Pointer
const DCBAAP: usize = 0x30;
/// Configure
const CONFIG: usize = 0x38;
/// Port Register Set (port 1 at offset 0x400)
const PORTSC_BASE: usize = 0x400;
const PORT_REGISTER_SIZE: usize = 0x10;

// ============================================================================
// xHCI Register Offsets (Runtime)
// ============================================================================

/// Microframe Index
const MFINDEX: usize = 0x00;
/// Interrupter Register Set Base
const IR0: usize = 0x20;
/// Interrupter Management
const IMAN: usize = 0x00;
/// Interrupter Moderation
const IMOD: usize = 0x04;
/// Event Ring Segment Table Size
const ERSTSZ: usize = 0x08;
/// Event Ring Segment Table Base Address
const ERSTBA: usize = 0x10;
/// Event Ring Dequeue Pointer
const ERDP: usize = 0x18;

// ============================================================================
// USBCMD Bits
// ============================================================================

const USBCMD_RUN: u32 = 1 << 0;
const USBCMD_HCRST: u32 = 1 << 1;
const USBCMD_INTE: u32 = 1 << 2;
const USBCMD_HSEE: u32 = 1 << 3;

// ============================================================================
// USBSTS Bits
// ============================================================================

const USBSTS_HCH: u32 = 1 << 0;  // Host Controller Halted
const USBSTS_HSE: u32 = 1 << 2;  // Host System Error
const USBSTS_EINT: u32 = 1 << 3; // Event Interrupt
const USBSTS_PCD: u32 = 1 << 4;  // Port Change Detect
const USBSTS_CNR: u32 = 1 << 11; // Controller Not Ready

// ============================================================================
// PORTSC Bits
// ============================================================================

const PORTSC_CCS: u32 = 1 << 0;   // Current Connect Status
const PORTSC_PED: u32 = 1 << 1;   // Port Enabled/Disabled
const PORTSC_OCA: u32 = 1 << 3;   // Over-current Active
const PORTSC_PR: u32 = 1 << 4;    // Port Reset
const PORTSC_PP: u32 = 1 << 9;    // Port Power
const PORTSC_CSC: u32 = 1 << 17;  // Connect Status Change
const PORTSC_PEC: u32 = 1 << 18;  // Port Enabled/Disabled Change
const PORTSC_WRC: u32 = 1 << 19;  // Warm Port Reset Change
const PORTSC_PRC: u32 = 1 << 21;  // Port Reset Change
const PORTSC_PLC: u32 = 1 << 22;  // Port Link State Change
const PORTSC_CEC: u32 = 1 << 23;  // Port Config Error Change
const PORTSC_CHANGE_MASK: u32 = PORTSC_CSC | PORTSC_PEC | PORTSC_WRC | PORTSC_PRC | PORTSC_PLC | PORTSC_CEC;

// ============================================================================
// TRB Types
// ============================================================================

/// TRBタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TrbType {
    Normal = 1,
    SetupStage = 2,
    DataStage = 3,
    StatusStage = 4,
    Isoch = 5,
    Link = 6,
    EventData = 7,
    NoOp = 8,
    EnableSlot = 9,
    DisableSlot = 10,
    AddressDevice = 11,
    ConfigureEndpoint = 12,
    EvaluateContext = 13,
    ResetEndpoint = 14,
    StopEndpoint = 15,
    SetTrDequeuePointer = 16,
    ResetDevice = 17,
    ForceEvent = 18,
    NegotiateBandwidth = 19,
    SetLatencyToleranceValue = 20,
    GetPortBandwidth = 21,
    ForceHeader = 22,
    NoOpCommand = 23,
    GetExtendedProperty = 24,
    SetExtendedProperty = 25,
    // Event TRBs
    Transfer = 32,
    CommandCompletion = 33,
    PortStatusChange = 34,
    BandwidthRequest = 35,
    Doorbell = 36,
    HostController = 37,
    DeviceNotification = 38,
    MfindexWrap = 39,
}

/// TRB完了コード
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CompletionCode {
    Invalid = 0,
    Success = 1,
    DataBufferError = 2,
    BabbleDetected = 3,
    UsbTransactionError = 4,
    TrbError = 5,
    StallError = 6,
    ResourceError = 7,
    BandwidthError = 8,
    NoSlotsAvailable = 9,
    InvalidStreamType = 10,
    SlotNotEnabled = 11,
    EndpointNotEnabled = 12,
    ShortPacket = 13,
    RingUnderrun = 14,
    RingOverrun = 15,
    VfEventRingFull = 16,
    ParameterError = 17,
    BandwidthOverrun = 18,
    ContextStateError = 19,
    NoPingResponse = 20,
    EventRingFull = 21,
    IncompatibleDevice = 22,
    MissedService = 23,
    CommandRingStopped = 24,
    CommandAborted = 25,
    Stopped = 26,
    StoppedLengthInvalid = 27,
    StoppedShortPacket = 28,
    MaxExitLatencyTooLarge = 29,
    IsochBufferOverrun = 31,
    EventLost = 32,
    Undefined = 33,
    InvalidStreamId = 34,
    SecondaryBandwidth = 35,
    SplitTransaction = 36,
}

impl CompletionCode {
    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => CompletionCode::Invalid,
            1 => CompletionCode::Success,
            2 => CompletionCode::DataBufferError,
            3 => CompletionCode::BabbleDetected,
            4 => CompletionCode::UsbTransactionError,
            5 => CompletionCode::TrbError,
            6 => CompletionCode::StallError,
            7 => CompletionCode::ResourceError,
            8 => CompletionCode::BandwidthError,
            9 => CompletionCode::NoSlotsAvailable,
            13 => CompletionCode::ShortPacket,
            19 => CompletionCode::ContextStateError,
            24 => CompletionCode::CommandRingStopped,
            25 => CompletionCode::CommandAborted,
            26 => CompletionCode::Stopped,
            _ => CompletionCode::Undefined,
        }
    }

    pub fn to_transfer_status(&self) -> TransferStatus {
        match self {
            CompletionCode::Success => TransferStatus::Success,
            CompletionCode::StallError => TransferStatus::Stalled,
            CompletionCode::DataBufferError => TransferStatus::BufferError,
            CompletionCode::BabbleDetected => TransferStatus::BabbleError,
            CompletionCode::UsbTransactionError => TransferStatus::TransactionError,
            CompletionCode::TrbError => TransferStatus::TrbError,
            CompletionCode::ShortPacket => TransferStatus::ShortPacket,
            _ => TransferStatus::Error(*self as u8),
        }
    }
}

// ============================================================================
// TRB Structure
// ============================================================================

/// Transfer Request Block (16バイト)
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default)]
pub struct Trb {
    /// Parameter (depends on TRB type)
    pub parameter: u64,
    /// Status
    pub status: u32,
    /// Control
    pub control: u32,
}

impl Trb {
    /// TRBタイプを取得
    pub fn trb_type(&self) -> u8 {
        ((self.control >> 10) & 0x3F) as u8
    }

    /// サイクルビットを取得
    pub fn cycle_bit(&self) -> bool {
        (self.control & 1) != 0
    }

    /// サイクルビットを設定
    pub fn set_cycle_bit(&mut self, cycle: bool) {
        if cycle {
            self.control |= 1;
        } else {
            self.control &= !1;
        }
    }

    /// Normalトランスファー TRB を作成
    pub fn normal(data_ptr: u64, length: u32, cycle: bool) -> Self {
        Self {
            parameter: data_ptr,
            status: length & 0x1FFFF,
            control: ((TrbType::Normal as u32) << 10) | (1 << 5) | if cycle { 1 } else { 0 },
        }
    }

    /// Setup Stage TRB を作成
    pub fn setup_stage(setup: &SetupPacket, transfer_type: u8, cycle: bool) -> Self {
        let setup_bytes = unsafe {
            core::slice::from_raw_parts(
                setup as *const _ as *const u8,
                8,
            )
        };
        let parameter = u64::from_le_bytes([
            setup_bytes[0], setup_bytes[1], setup_bytes[2], setup_bytes[3],
            setup_bytes[4], setup_bytes[5], setup_bytes[6], setup_bytes[7],
        ]);

        Self {
            parameter,
            status: 8, // Transfer length = 8
            control: ((TrbType::SetupStage as u32) << 10) 
                   | ((transfer_type as u32) << 16) 
                   | (1 << 6)  // IDT
                   | if cycle { 1 } else { 0 },
        }
    }

    /// Data Stage TRB を作成
    pub fn data_stage(data_ptr: u64, length: u32, dir_in: bool, cycle: bool) -> Self {
        Self {
            parameter: data_ptr,
            status: length & 0x1FFFF,
            control: ((TrbType::DataStage as u32) << 10)
                   | ((dir_in as u32) << 16)
                   | (1 << 5)  // IOC
                   | if cycle { 1 } else { 0 },
        }
    }

    /// Status Stage TRB を作成
    pub fn status_stage(dir_in: bool, cycle: bool) -> Self {
        Self {
            parameter: 0,
            status: 0,
            control: ((TrbType::StatusStage as u32) << 10)
                   | ((dir_in as u32) << 16)
                   | (1 << 5)  // IOC
                   | if cycle { 1 } else { 0 },
        }
    }

    /// Link TRB を作成
    pub fn link(next_ring: u64, toggle_cycle: bool, cycle: bool) -> Self {
        Self {
            parameter: next_ring,
            status: 0,
            control: ((TrbType::Link as u32) << 10)
                   | ((toggle_cycle as u32) << 1)
                   | if cycle { 1 } else { 0 },
        }
    }

    /// Enable Slot コマンドTRB を作成
    pub fn enable_slot(cycle: bool) -> Self {
        Self {
            parameter: 0,
            status: 0,
            control: ((TrbType::EnableSlot as u32) << 10) | if cycle { 1 } else { 0 },
        }
    }

    /// Disable Slot コマンドTRB を作成
    pub fn disable_slot(slot_id: SlotId, cycle: bool) -> Self {
        Self {
            parameter: 0,
            status: 0,
            control: ((TrbType::DisableSlot as u32) << 10)
                   | ((slot_id.as_u8() as u32) << 24)
                   | if cycle { 1 } else { 0 },
        }
    }

    /// Address Device コマンドTRB を作成
    pub fn address_device(input_context_ptr: u64, slot_id: SlotId, bsr: bool, cycle: bool) -> Self {
        Self {
            parameter: input_context_ptr,
            status: 0,
            control: ((TrbType::AddressDevice as u32) << 10)
                   | ((slot_id.as_u8() as u32) << 24)
                   | ((bsr as u32) << 9)
                   | if cycle { 1 } else { 0 },
        }
    }

    /// Configure Endpoint コマンドTRB を作成
    pub fn configure_endpoint(input_context_ptr: u64, slot_id: SlotId, cycle: bool) -> Self {
        Self {
            parameter: input_context_ptr,
            status: 0,
            control: ((TrbType::ConfigureEndpoint as u32) << 10)
                   | ((slot_id.as_u8() as u32) << 24)
                   | if cycle { 1 } else { 0 },
        }
    }

    /// Reset Endpoint コマンドTRB を作成
    pub fn reset_endpoint(slot_id: SlotId, dci: u8, cycle: bool) -> Self {
        Self {
            parameter: 0,
            status: 0,
            control: ((TrbType::ResetEndpoint as u32) << 10)
                   | ((slot_id.as_u8() as u32) << 24)
                   | ((dci as u32) << 16)
                   | if cycle { 1 } else { 0 },
        }
    }

    /// NoOp コマンドTRB を作成
    pub fn noop_command(cycle: bool) -> Self {
        Self {
            parameter: 0,
            status: 0,
            control: ((TrbType::NoOpCommand as u32) << 10) | if cycle { 1 } else { 0 },
        }
    }
}

// ============================================================================
// Ring Buffer
// ============================================================================

/// TRBリングバッファ
pub struct TrbRing {
    /// リングバッファ
    trbs: Box<[Trb]>,
    /// 現在のエンキュー位置
    enqueue_index: usize,
    /// 現在のデキュー位置
    dequeue_index: usize,
    /// サイクルビット状態
    cycle_bit: bool,
    /// リング物理アドレス
    phys_addr: u64,
}

impl TrbRing {
    /// 新しいリングを作成
    pub fn new(size: usize) -> Self {
        let mut trbs = vec![Trb::default(); size].into_boxed_slice();
        
        // 物理アドレスを取得（実際の実装ではメモリマネージャを使用）
        let phys_addr = trbs.as_ptr() as u64;

        // 最後にリンクTRBを設定
        let last_idx = size - 1;
        trbs[last_idx] = Trb::link(phys_addr, true, false);

        Self {
            trbs,
            enqueue_index: 0,
            dequeue_index: 0,
            cycle_bit: true,
            phys_addr,
        }
    }

    /// TRBをエンキュー
    pub fn enqueue(&mut self, mut trb: Trb) -> Option<u64> {
        let idx = self.enqueue_index;

        // リンクTRBをスキップ
        if self.trbs[idx].trb_type() == TrbType::Link as u8 {
            // リンクTRBのサイクルビットを更新
            self.trbs[idx].set_cycle_bit(self.cycle_bit);
            self.cycle_bit = !self.cycle_bit;
            self.enqueue_index = 0;
            return self.enqueue(trb);
        }

        trb.set_cycle_bit(self.cycle_bit);
        self.trbs[idx] = trb;

        let trb_addr = self.phys_addr + (idx * 16) as u64;
        self.enqueue_index = idx + 1;

        Some(trb_addr)
    }

    /// 現在のエンキューポインタを取得
    pub fn enqueue_ptr(&self) -> u64 {
        self.phys_addr + (self.enqueue_index * 16) as u64
    }

    /// リングの物理アドレスを取得
    pub fn physical_address(&self) -> u64 {
        self.phys_addr
    }

    /// 現在のサイクルビットを取得
    pub fn cycle_bit(&self) -> bool {
        self.cycle_bit
    }
}

// ============================================================================
// Event Ring Segment Table Entry
// ============================================================================

/// イベントリングセグメントテーブルエントリ
#[repr(C, align(64))]
#[derive(Clone, Copy, Debug, Default)]
pub struct ErstEntry {
    /// リングセグメントベースアドレス
    pub ring_segment_base: u64,
    /// リングセグメントサイズ
    pub ring_segment_size: u16,
    /// 予約
    pub reserved: [u8; 6],
}

// ============================================================================
// Device Context
// ============================================================================

/// スロットコンテキスト (32バイト)
#[repr(C, align(32))]
#[derive(Clone, Copy, Debug, Default)]
pub struct SlotContext {
    /// ルートハブポート番号、速度など
    pub route_string_and_speed: u32,
    /// 最大終了レイテンシなど
    pub latency_and_ports: u32,
    /// 親ハブスロットID、TTポート番号
    pub tt_info: u32,
    /// デバイス状態、デバイスアドレス
    pub state_and_address: u32,
    /// 予約
    pub reserved: [u32; 4],
}

impl SlotContext {
    /// スロット状態を取得
    pub fn slot_state(&self) -> u8 {
        ((self.state_and_address >> 27) & 0x1F) as u8
    }

    /// デバイスアドレスを取得
    pub fn device_address(&self) -> u8 {
        (self.state_and_address & 0xFF) as u8
    }

    /// 設定
    pub fn set_context(
        &mut self,
        speed: UsbSpeed,
        route_string: u32,
        root_port: u8,
        context_entries: u8,
    ) {
        self.route_string_and_speed = (route_string & 0xFFFFF)
            | ((speed.to_slot_speed() as u32) << 20)
            | ((context_entries as u32) << 27);
        
        self.latency_and_ports = (root_port as u32) << 16;
    }
}

/// エンドポイントコンテキスト (32バイト)
#[repr(C, align(32))]
#[derive(Clone, Copy, Debug, Default)]
pub struct EndpointContext {
    /// エンドポイント状態、タイプなど
    pub ep_state_and_type: u32,
    /// 最大パケットサイズ、バーストサイズなど
    pub max_packet_and_burst: u32,
    /// TRデキューポインタ
    pub tr_dequeue_ptr: u64,
    /// 平均TRB長など
    pub average_trb_length: u32,
    /// 予約
    pub reserved: [u32; 3],
}

impl EndpointContext {
    /// 設定
    pub fn set_context(
        &mut self,
        ep_type: u8,
        max_packet_size: u16,
        max_burst_size: u8,
        tr_dequeue_ptr: u64,
        interval: u8,
        error_count: u8,
    ) {
        self.ep_state_and_type = ((ep_type as u32) << 3)
            | ((error_count as u32) << 1)
            | ((interval as u32) << 16);

        self.max_packet_and_burst = (max_packet_size as u32)
            | ((max_burst_size as u32) << 8);

        // DCS (Dequeue Cycle State) = 1
        self.tr_dequeue_ptr = tr_dequeue_ptr | 1;

        self.average_trb_length = 8; // デフォルト値
    }
}

/// デバイスコンテキスト
#[repr(C, align(64))]
pub struct DeviceContext {
    pub slot: SlotContext,
    pub endpoints: [EndpointContext; 31],
}

/// 入力コンテキスト
#[repr(C, align(64))]
pub struct InputContext {
    /// 入力コントロールコンテキスト
    pub input_control: InputControlContext,
    /// スロットコンテキスト
    pub slot: SlotContext,
    /// エンドポイントコンテキスト
    pub endpoints: [EndpointContext; 31],
}

/// 入力コントロールコンテキスト
#[repr(C, align(32))]
#[derive(Clone, Copy, Debug, Default)]
pub struct InputControlContext {
    /// ドロップコンテキストフラグ
    pub drop_flags: u32,
    /// 追加コンテキストフラグ
    pub add_flags: u32,
    /// 予約
    pub reserved: [u32; 6],
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
    /// イベントリングセグメントテーブル
    erst: Box<[ErstEntry]>,
    /// DCBAA
    dcbaa: Box<[u64]>,
    /// デバイスコンテキスト
    device_contexts: Mutex<Vec<Option<Box<DeviceContext>>>>,
    /// 転送リング（スロット×エンドポイント）
    transfer_rings: Mutex<Vec<Vec<Option<Box<TrbRing>>>>>,
    /// コマンド完了待ち
    command_completions: Mutex<Vec<CommandCompletion>>,
    /// 実行中フラグ
    running: AtomicBool,
}

/// コマンド完了情報
struct CommandCompletion {
    trb_addr: u64,
    completion_code: CompletionCode,
    slot_id: SlotId,
    waker: Option<Waker>,
    completed: bool,
}

impl XhciController {
    /// 新しいxHCIコントローラを作成
    pub fn new(base_addr: u64) -> UsbResult<Self> {
        // Capability Registers を読み取り
        let caplength = unsafe { ptr::read_volatile((base_addr + CAPLENGTH as u64) as *const u8) };
        let hciversion = unsafe { ptr::read_volatile((base_addr + HCIVERSION as u64) as *const u16) };
        let hcsparams1 = unsafe { ptr::read_volatile((base_addr + HCSPARAMS1 as u64) as *const u32) };
        let hccparams1 = unsafe { ptr::read_volatile((base_addr + HCCPARAMS1 as u64) as *const u32) };
        let dboff = unsafe { ptr::read_volatile((base_addr + DBOFF as u64) as *const u32) };
        let rtsoff = unsafe { ptr::read_volatile((base_addr + RTSOFF as u64) as *const u32) };

        // log::info!("xHCI version: {:#06x}", hciversion);
        let _ = hciversion;

        let max_slots = (hcsparams1 & 0xFF) as u8;
        let max_ports = ((hcsparams1 >> 24) & 0xFF) as u8;
        let _context_size_flag = (hccparams1 >> 2) & 1;

        // log::info!("xHCI: {} slots, {} ports, context_size_64={}", 
        //            max_slots, max_ports, context_size_flag);

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
        let device_contexts: Vec<Option<Box<DeviceContext>>> = (0..MAX_SLOTS).map(|_| None).collect();
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

        // log::info!("xHCI controller initialized successfully");

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
            // 実際の実装ではスリープを入れる
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
            // 実際の実装ではスリープを入れる
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

        // リセット完了を待機（実際の実装ではasync待機）
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
                "Enable slot failed: {:?}", completion.completion_code
            )))
        }
    }

    /// コマンドを送信
    fn send_command(&self, trb: Trb) -> UsbResult<u64> {
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
            if let Some(pos) = completions.iter().position(|c| c.trb_addr == trb_addr && c.completed) {
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
        let expected_cycle = event_ring.cycle_bit();
        
        loop {
            let idx = event_ring.dequeue_index;
            let trb = unsafe {
                ptr::read_volatile(&event_ring.trbs[idx] as *const Trb)
            };

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
                _ => {
                    // log::debug!("Unknown event TRB type: {}", trb.trb_type());
                }
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
        let _completion_code = CompletionCode::from_u8(((trb.status >> 24) & 0xFF) as u8);
        let _slot_id = SlotId(((trb.control >> 24) & 0xFF) as u8);
        let _endpoint_id = ((trb.control >> 16) & 0x1F) as u8;
        // 転送完了の処理は別途実装
    }

    /// ポート状態変更イベントを処理
    fn handle_port_status_change(&self, trb: &Trb) {
        let _port_id = ((trb.parameter >> 24) & 0xFF) as u8;
        // log::info!("Port {} status changed", port_id);
        // ポート状態変更の処理は別途実装
    }

    /// ドアベルを鳴らす
    fn ring_doorbell(&self, slot_id: u8, target: u8) {
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
        unsafe { ptr::write_volatile((self.rt_offset + IR0 as u64 + offset as u64) as *mut u32, value) }
    }

    fn write_runtime_64(&self, offset: usize, value: u64) {
        unsafe { ptr::write_volatile((self.rt_offset + IR0 as u64 + offset as u64) as *mut u64, value) }
    }

    /// ポート数を取得
    pub fn port_count(&self) -> u8 {
        self.max_ports
    }
}

impl TrbType {
    fn from_u8(val: u8) -> Option<Self> {
        match val {
            1 => Some(TrbType::Normal),
            2 => Some(TrbType::SetupStage),
            3 => Some(TrbType::DataStage),
            4 => Some(TrbType::StatusStage),
            5 => Some(TrbType::Isoch),
            6 => Some(TrbType::Link),
            7 => Some(TrbType::EventData),
            8 => Some(TrbType::NoOp),
            9 => Some(TrbType::EnableSlot),
            10 => Some(TrbType::DisableSlot),
            11 => Some(TrbType::AddressDevice),
            12 => Some(TrbType::ConfigureEndpoint),
            13 => Some(TrbType::EvaluateContext),
            14 => Some(TrbType::ResetEndpoint),
            15 => Some(TrbType::StopEndpoint),
            16 => Some(TrbType::SetTrDequeuePointer),
            17 => Some(TrbType::ResetDevice),
            23 => Some(TrbType::NoOpCommand),
            32 => Some(TrbType::Transfer),
            33 => Some(TrbType::CommandCompletion),
            34 => Some(TrbType::PortStatusChange),
            37 => Some(TrbType::HostController),
            _ => None,
        }
    }
}

/// コマンド完了結果
struct CommandCompletionResult {
    completion_code: CompletionCode,
    slot_id: SlotId,
}

// ============================================================================
// USB Device Implementation for xHCI
// ============================================================================

/// xHCI経由のUSBデバイス
pub struct XhciDevice {
    /// コントローラ参照
    controller: Arc<XhciController>,
    /// スロットID
    slot_id: SlotId,
    /// デバイスアドレス
    address: DeviceAddress,
    /// デバイスディスクリプタ
    device_descriptor: DeviceDescriptor,
    /// 現在のコンフィグレーション
    configuration: Option<ParsedConfiguration>,
    /// USB速度
    speed: UsbSpeed,
}

impl UsbDevice for XhciDevice {
    fn address(&self) -> DeviceAddress {
        self.address
    }

    fn vendor_id(&self) -> u16 {
        self.device_descriptor.id_vendor
    }

    fn product_id(&self) -> u16 {
        self.device_descriptor.id_product
    }

    fn device_class(&self) -> u8 {
        self.device_descriptor.b_device_class
    }

    fn device_subclass(&self) -> u8 {
        self.device_descriptor.b_device_sub_class
    }

    fn device_protocol(&self) -> u8 {
        self.device_descriptor.b_device_protocol
    }

    fn speed(&self) -> UsbSpeed {
        self.speed
    }

    fn control_transfer(
        &self,
        _setup: &SetupPacket,
        _data: Option<&mut [u8]>,
    ) -> Pin<Box<dyn Future<Output = UsbResult<usize>> + Send + '_>> {
        Box::pin(async move {
            // 実装は省略（実際にはTRBを構築して転送）
            Ok(0)
        })
    }

    fn bulk_in(
        &self,
        _endpoint: EndpointAddress,
        _buffer: &mut [u8],
    ) -> Pin<Box<dyn Future<Output = UsbResult<usize>> + Send + '_>> {
        Box::pin(async move {
            Ok(0)
        })
    }

    fn bulk_out(
        &self,
        _endpoint: EndpointAddress,
        _data: &[u8],
    ) -> Pin<Box<dyn Future<Output = UsbResult<usize>> + Send + '_>> {
        Box::pin(async move {
            Ok(0)
        })
    }

    fn interrupt_in(
        &self,
        _endpoint: EndpointAddress,
        _buffer: &mut [u8],
    ) -> Pin<Box<dyn Future<Output = UsbResult<usize>> + Send + '_>> {
        Box::pin(async move {
            Ok(0)
        })
    }

    fn interrupt_out(
        &self,
        _endpoint: EndpointAddress,
        _data: &[u8],
    ) -> Pin<Box<dyn Future<Output = UsbResult<usize>> + Send + '_>> {
        Box::pin(async move {
            Ok(0)
        })
    }
}

// ============================================================================
// xHCI Initialization from PCI
// ============================================================================

/// PCIデバイスからxHCIを初期化
pub fn init_from_pci(base_addr: u64) -> UsbResult<Arc<XhciController>> {
    let mut controller = XhciController::new(base_addr)?;
    controller.init()?;

    let controller = Arc::new(controller);

    // ポートをスキャン
    for port in 0..controller.port_count() {
        let status = controller.port_status(PortNumber(port));
        if status.connected {
            // log::info!("USB device connected on port {}: speed={:?}", port, status.speed);
            let _ = status.speed; // suppress unused warning
        }
    }

    Ok(controller)
}
