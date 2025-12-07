// ============================================================================
// src/io/usb/xhci/trb.rs - TRB (Transfer Request Block) Definitions
// ============================================================================
//!
//! TRB (Transfer Request Block) 関連の型定義と操作。
//!
//! ## 概要
//! xHCIはTRBベースのコマンド/転送メカニズムを使用。
//! - Command TRB: ホストからコントローラへのコマンド
//! - Transfer TRB: データ転送要求
//! - Event TRB: コントローラからホストへの通知

#![allow(dead_code)]

use alloc::boxed::Box;
use alloc::vec;

use crate::io::usb::{SetupPacket, SlotId, TransferStatus};

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

impl TrbType {
    pub fn from_u8(val: u8) -> Option<Self> {
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

// ============================================================================
// Completion Code
// ============================================================================

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
        let setup_bytes = unsafe { core::slice::from_raw_parts(setup as *const _ as *const u8, 8) };
        let parameter = u64::from_le_bytes([
            setup_bytes[0],
            setup_bytes[1],
            setup_bytes[2],
            setup_bytes[3],
            setup_bytes[4],
            setup_bytes[5],
            setup_bytes[6],
            setup_bytes[7],
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
    pub(crate) trbs: Box<[Trb]>,
    /// 現在のエンキュー位置
    pub(crate) enqueue_index: usize,
    /// 現在のデキュー位置
    pub(crate) dequeue_index: usize,
    /// サイクルビット状態
    pub(crate) cycle_bit: bool,
    /// リング物理アドレス
    pub(crate) phys_addr: u64,
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
