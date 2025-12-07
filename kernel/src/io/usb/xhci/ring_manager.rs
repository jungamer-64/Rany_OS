// ============================================================================
// src/io/usb/xhci/ring_manager.rs - xHCI Ring Management
// ============================================================================
//!
//! # xHCI リング管理
//!
//! コマンドリング、イベントリング、転送リングの管理を担当。
//! TRBのエンキュー/デキュー、サイクルビット管理を行う。

#![allow(dead_code)]

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use spin::Mutex;

use super::trb::{Trb, TrbRing, TrbType, CompletionCode, ErstEntry};

// ============================================================================
// Constants
// ============================================================================

/// コマンドリングサイズ
pub const COMMAND_RING_SIZE: usize = 256;

/// イベントリングサイズ
pub const EVENT_RING_SIZE: usize = 256;

/// 転送リングサイズ
pub const TRANSFER_RING_SIZE: usize = 256;

/// 最大同時実行コマンド数
pub const MAX_PENDING_COMMANDS: usize = 32;

// ============================================================================
// Ring Types
// ============================================================================

/// リングタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RingType {
    /// コマンドリング（ホスト→コントローラ）
    Command,
    /// イベントリング（コントローラ→ホスト）
    Event,
    /// 転送リング（エンドポイントごと）
    Transfer,
}

// ============================================================================
// Ring Manager
// ============================================================================

/// xHCI リングマネージャ
///
/// コマンド/イベント/転送リングの統一的な管理を提供
pub struct XhciRingManager {
    /// コマンドリング
    command_ring: Mutex<ManagedRing>,
    /// イベントリング
    event_ring: Mutex<ManagedRing>,
    /// イベントリングセグメントテーブル
    erst: Box<[ErstEntry]>,
    /// 転送リング（スロット×エンドポイント）
    transfer_rings: Mutex<Vec<Vec<Option<Box<ManagedRing>>>>>,
    /// 最大スロット数
    max_slots: u8,
    /// 最大エンドポイント数（スロットあたり）
    max_endpoints: u8,
}

/// 管理対象リング
pub struct ManagedRing {
    /// 基本のTRBリング
    ring: TrbRing,
    /// リングタイプ
    ring_type: RingType,
    /// エンキューインデックス
    enqueue_index: u16,
    /// デキューインデックス
    dequeue_index: u16,
    /// 現在のサイクルビット
    cycle_bit: bool,
    /// リングサイズ
    size: u16,
}

impl ManagedRing {
    /// 新しい管理対象リングを作成
    pub fn new(size: usize, ring_type: RingType) -> Self {
        Self {
            ring: TrbRing::new(size),
            ring_type,
            enqueue_index: 0,
            dequeue_index: 0,
            cycle_bit: true,
            size: size as u16,
        }
    }
    
    /// 物理アドレスを取得
    pub fn physical_address(&self) -> u64 {
        self.ring.physical_address()
    }
    
    /// TRBをエンキュー
    pub fn enqueue(&mut self, trb: Trb) -> Option<u64> {
        // リンクTRBをチェック
        if self.enqueue_index >= self.size - 1 {
            // リンクTRBを設定してラップアラウンド
            self.set_link_trb();
            self.enqueue_index = 0;
            self.cycle_bit = !self.cycle_bit;
        }
        
        // TRBを書き込み
        let trb_addr = self.ring.physical_address() + (self.enqueue_index as u64) * 16;
        
        unsafe {
            let trb_ptr = trb_addr as *mut Trb;
            let mut trb_with_cycle = trb;
            
            // サイクルビットを設定
            if self.cycle_bit {
                trb_with_cycle.control |= 1; // Cycle bit
            } else {
                trb_with_cycle.control &= !1;
            }
            
            ptr::write_volatile(trb_ptr, trb_with_cycle);
        }
        
        let result_addr = trb_addr;
        self.enqueue_index += 1;
        
        Some(result_addr)
    }
    
    /// TRBをデキュー（イベントリング用）
    pub fn dequeue(&mut self) -> Option<Trb> {
        let trb_addr = self.ring.physical_address() + (self.dequeue_index as u64) * 16;
        
        let trb = unsafe {
            let trb_ptr = trb_addr as *const Trb;
            ptr::read_volatile(trb_ptr)
        };
        
        // サイクルビットをチェック
        let trb_cycle = (trb.control & 1) != 0;
        if trb_cycle != self.cycle_bit {
            return None; // まだ処理されていない
        }
        
        self.dequeue_index += 1;
        if self.dequeue_index >= self.size {
            self.dequeue_index = 0;
            self.cycle_bit = !self.cycle_bit;
        }
        
        Some(trb)
    }
    
    /// リンクTRBを設定
    fn set_link_trb(&mut self) {
        let link_trb = Trb {
            parameter: self.ring.physical_address(),
            status: 0,
            control: (TrbType::Link as u32) << 10 | if self.cycle_bit { 1 } else { 0 } | (1 << 1), // Toggle Cycle
        };
        
        let link_addr = self.ring.physical_address() + ((self.size - 1) as u64) * 16;
        unsafe {
            let trb_ptr = link_addr as *mut Trb;
            ptr::write_volatile(trb_ptr, link_trb);
        }
    }
    
    /// リングが空かどうか
    pub fn is_empty(&self) -> bool {
        self.enqueue_index == self.dequeue_index
    }
    
    /// リングがフルかどうか
    pub fn is_full(&self) -> bool {
        let next = (self.enqueue_index + 1) % self.size;
        next == self.dequeue_index
    }
    
    /// 現在のデキューポインタを取得
    pub fn dequeue_pointer(&self) -> u64 {
        self.ring.physical_address() + (self.dequeue_index as u64) * 16
    }
    
    /// 現在のエンキューポインタを取得
    pub fn enqueue_pointer(&self) -> u64 {
        self.ring.physical_address() + (self.enqueue_index as u64) * 16
    }
    
    /// サイクルビットを取得
    pub fn cycle_bit(&self) -> bool {
        self.cycle_bit
    }
}

impl XhciRingManager {
    /// 新しいリングマネージャを作成
    pub fn new(max_slots: u8, max_endpoints: u8) -> Self {
        // コマンドリングを作成
        let command_ring = ManagedRing::new(COMMAND_RING_SIZE, RingType::Command);
        
        // イベントリングを作成
        let event_ring = ManagedRing::new(EVENT_RING_SIZE, RingType::Event);
        
        // ERSTを作成
        let mut erst = vec![ErstEntry::default(); 1].into_boxed_slice();
        erst[0].ring_segment_base = event_ring.physical_address();
        erst[0].ring_segment_size = EVENT_RING_SIZE as u16;
        
        // 転送リングの初期化（遅延割り当て）
        let transfer_rings: Vec<Vec<Option<Box<ManagedRing>>>> = (0..max_slots as usize)
            .map(|_| (0..max_endpoints as usize).map(|_| None).collect())
            .collect();
        
        Self {
            command_ring: Mutex::new(command_ring),
            event_ring: Mutex::new(event_ring),
            erst,
            transfer_rings: Mutex::new(transfer_rings),
            max_slots,
            max_endpoints,
        }
    }
    
    // ========================================================================
    // コマンドリング操作
    // ========================================================================
    
    /// コマンドリングの物理アドレスを取得
    pub fn command_ring_address(&self) -> u64 {
        self.command_ring.lock().physical_address()
    }
    
    /// コマンドリングのサイクルビットを取得
    pub fn command_ring_cycle(&self) -> bool {
        self.command_ring.lock().cycle_bit()
    }
    
    /// コマンドTRBをエンキュー
    pub fn enqueue_command(&self, trb: Trb) -> Option<u64> {
        self.command_ring.lock().enqueue(trb)
    }
    
    // ========================================================================
    // イベントリング操作
    // ========================================================================
    
    /// イベントリングの物理アドレスを取得
    pub fn event_ring_address(&self) -> u64 {
        self.event_ring.lock().physical_address()
    }
    
    /// ERSTの物理アドレスを取得
    pub fn erst_address(&self) -> u64 {
        self.erst.as_ptr() as u64
    }
    
    /// ERSTのサイズを取得
    pub fn erst_size(&self) -> u32 {
        self.erst.len() as u32
    }
    
    /// イベントTRBをデキュー
    pub fn dequeue_event(&self) -> Option<Trb> {
        self.event_ring.lock().dequeue()
    }
    
    /// イベントリングのデキューポインタを取得
    pub fn event_dequeue_pointer(&self) -> u64 {
        self.event_ring.lock().dequeue_pointer()
    }
    
    // ========================================================================
    // 転送リング操作
    // ========================================================================
    
    /// 転送リングを作成
    pub fn create_transfer_ring(&self, slot_id: u8, endpoint_id: u8) -> Option<u64> {
        if slot_id == 0 || slot_id > self.max_slots || endpoint_id >= self.max_endpoints {
            return None;
        }
        
        let slot_index = (slot_id - 1) as usize;
        let ep_index = endpoint_id as usize;
        
        let mut rings = self.transfer_rings.lock();
        
        if rings[slot_index][ep_index].is_some() {
            // 既存のリングの物理アドレスを返す
            return rings[slot_index][ep_index].as_ref().map(|r| r.physical_address());
        }
        
        // 新しい転送リングを作成
        let ring = Box::new(ManagedRing::new(TRANSFER_RING_SIZE, RingType::Transfer));
        let addr = ring.physical_address();
        rings[slot_index][ep_index] = Some(ring);
        
        Some(addr)
    }
    
    /// 転送リングを取得
    pub fn get_transfer_ring(&self, slot_id: u8, endpoint_id: u8) -> Option<u64> {
        if slot_id == 0 || slot_id > self.max_slots || endpoint_id >= self.max_endpoints {
            return None;
        }
        
        let slot_index = (slot_id - 1) as usize;
        let ep_index = endpoint_id as usize;
        
        self.transfer_rings.lock()[slot_index][ep_index]
            .as_ref()
            .map(|r| r.physical_address())
    }
    
    /// 転送TRBをエンキュー
    pub fn enqueue_transfer(&self, slot_id: u8, endpoint_id: u8, trb: Trb) -> Option<u64> {
        if slot_id == 0 || slot_id > self.max_slots || endpoint_id >= self.max_endpoints {
            return None;
        }
        
        let slot_index = (slot_id - 1) as usize;
        let ep_index = endpoint_id as usize;
        
        let mut rings = self.transfer_rings.lock();
        
        if let Some(ref mut ring) = rings[slot_index][ep_index] {
            ring.enqueue(trb)
        } else {
            None
        }
    }
    
    /// 転送リングを解放
    pub fn free_transfer_ring(&self, slot_id: u8, endpoint_id: u8) {
        if slot_id == 0 || slot_id > self.max_slots || endpoint_id >= self.max_endpoints {
            return;
        }
        
        let slot_index = (slot_id - 1) as usize;
        let ep_index = endpoint_id as usize;
        
        self.transfer_rings.lock()[slot_index][ep_index] = None;
    }
    
    /// スロットの全転送リングを解放
    pub fn free_slot_rings(&self, slot_id: u8) {
        if slot_id == 0 || slot_id > self.max_slots {
            return;
        }
        
        let slot_index = (slot_id - 1) as usize;
        let mut rings = self.transfer_rings.lock();
        
        for ep_index in 0..self.max_endpoints as usize {
            rings[slot_index][ep_index] = None;
        }
    }
}

// ============================================================================
// Command Builder
// ============================================================================

/// コマンドTRBビルダー
pub struct CommandBuilder;

impl CommandBuilder {
    /// No Op コマンドを作成
    pub fn noop() -> Trb {
        Trb {
            parameter: 0,
            status: 0,
            control: (TrbType::NoOpCommand as u32) << 10,
        }
    }
    
    /// Enable Slot コマンドを作成
    pub fn enable_slot() -> Trb {
        Trb {
            parameter: 0,
            status: 0,
            control: (TrbType::EnableSlot as u32) << 10,
        }
    }
    
    /// Disable Slot コマンドを作成
    pub fn disable_slot(slot_id: u8) -> Trb {
        Trb {
            parameter: 0,
            status: 0,
            control: (TrbType::DisableSlot as u32) << 10 | ((slot_id as u32) << 24),
        }
    }
    
    /// Address Device コマンドを作成
    pub fn address_device(slot_id: u8, input_context_addr: u64, bsr: bool) -> Trb {
        let mut control = (TrbType::AddressDevice as u32) << 10 | ((slot_id as u32) << 24);
        if bsr {
            control |= 1 << 9; // Block Set Address Request
        }
        Trb {
            parameter: input_context_addr,
            status: 0,
            control,
        }
    }
    
    /// Configure Endpoint コマンドを作成
    pub fn configure_endpoint(slot_id: u8, input_context_addr: u64, deconfigure: bool) -> Trb {
        let mut control = (TrbType::ConfigureEndpoint as u32) << 10 | ((slot_id as u32) << 24);
        if deconfigure {
            control |= 1 << 9; // Deconfigure
        }
        Trb {
            parameter: input_context_addr,
            status: 0,
            control,
        }
    }
    
    /// Evaluate Context コマンドを作成
    pub fn evaluate_context(slot_id: u8, input_context_addr: u64) -> Trb {
        Trb {
            parameter: input_context_addr,
            status: 0,
            control: (TrbType::EvaluateContext as u32) << 10 | ((slot_id as u32) << 24),
        }
    }
    
    /// Reset Endpoint コマンドを作成
    pub fn reset_endpoint(slot_id: u8, endpoint_id: u8, tsp: bool) -> Trb {
        let mut control = (TrbType::ResetEndpoint as u32) << 10 
            | ((slot_id as u32) << 24)
            | ((endpoint_id as u32) << 16);
        if tsp {
            control |= 1 << 9; // Transfer State Preserve
        }
        Trb {
            parameter: 0,
            status: 0,
            control,
        }
    }
    
    /// Stop Endpoint コマンドを作成
    pub fn stop_endpoint(slot_id: u8, endpoint_id: u8, suspend: bool) -> Trb {
        let mut control = (TrbType::StopEndpoint as u32) << 10 
            | ((slot_id as u32) << 24)
            | ((endpoint_id as u32) << 16);
        if suspend {
            control |= 1 << 23; // Suspend
        }
        Trb {
            parameter: 0,
            status: 0,
            control,
        }
    }
    
    /// Set TR Dequeue Pointer コマンドを作成
    pub fn set_tr_dequeue_pointer(slot_id: u8, endpoint_id: u8, dequeue_ptr: u64, dcs: bool) -> Trb {
        let param = dequeue_ptr | if dcs { 1 } else { 0 };
        Trb {
            parameter: param,
            status: 0,
            control: (TrbType::SetTrDequeuePointer as u32) << 10 
                | ((slot_id as u32) << 24)
                | ((endpoint_id as u32) << 16),
        }
    }
    
    /// Reset Device コマンドを作成
    pub fn reset_device(slot_id: u8) -> Trb {
        Trb {
            parameter: 0,
            status: 0,
            control: (TrbType::ResetDevice as u32) << 10 | ((slot_id as u32) << 24),
        }
    }
}

// ============================================================================
// Transfer TRB Builder
// ============================================================================

/// 転送TRBビルダー
pub struct TransferBuilder;

impl TransferBuilder {
    /// Normal TRBを作成
    pub fn normal(data_addr: u64, length: u32, ioc: bool, chain: bool) -> Trb {
        let mut control = (TrbType::Normal as u32) << 10;
        if ioc {
            control |= 1 << 5; // Interrupt on Completion
        }
        if chain {
            control |= 1 << 4; // Chain bit
        }
        Trb {
            parameter: data_addr,
            status: length & 0x1FFFF, // TRB Transfer Length (17 bits)
            control,
        }
    }
    
    /// Setup Stage TRBを作成
    pub fn setup_stage(request_type: u8, request: u8, value: u16, index: u16, length: u16, trt: u8) -> Trb {
        let param = (request_type as u64)
            | ((request as u64) << 8)
            | ((value as u64) << 16)
            | ((index as u64) << 32)
            | ((length as u64) << 48);
        
        Trb {
            parameter: param,
            status: 8, // Transfer Length = 8 (setup packet size)
            control: (TrbType::SetupStage as u32) << 10 
                | ((trt as u32) << 16) // Transfer Type
                | (1 << 6), // Immediate Data
        }
    }
    
    /// Data Stage TRBを作成
    pub fn data_stage(data_addr: u64, length: u32, direction_in: bool, ioc: bool) -> Trb {
        let mut control = (TrbType::DataStage as u32) << 10;
        if direction_in {
            control |= 1 << 16; // Direction = IN
        }
        if ioc {
            control |= 1 << 5; // Interrupt on Completion
        }
        Trb {
            parameter: data_addr,
            status: length & 0x1FFFF,
            control,
        }
    }
    
    /// Status Stage TRBを作成
    pub fn status_stage(direction_in: bool, ioc: bool) -> Trb {
        let mut control = (TrbType::StatusStage as u32) << 10;
        if direction_in {
            control |= 1 << 16; // Direction = IN
        }
        if ioc {
            control |= 1 << 5; // Interrupt on Completion
        }
        Trb {
            parameter: 0,
            status: 0,
            control,
        }
    }
    
    /// Isoch TRBを作成
    pub fn isoch(data_addr: u64, length: u32, frame_id: u16, sia: bool, ioc: bool) -> Trb {
        let mut control = (TrbType::Isoch as u32) << 10 | ((frame_id as u32) << 20);
        if sia {
            control |= 1 << 31; // Start Isoch ASAP
        }
        if ioc {
            control |= 1 << 5;
        }
        Trb {
            parameter: data_addr,
            status: length & 0x1FFFF,
            control,
        }
    }
    
    /// Event Data TRBを作成
    pub fn event_data(data: u64, ioc: bool) -> Trb {
        let mut control = (TrbType::EventData as u32) << 10;
        if ioc {
            control |= 1 << 5;
        }
        Trb {
            parameter: data,
            status: 0,
            control,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_command_builder() {
        let noop = CommandBuilder::noop();
        assert_eq!((noop.control >> 10) & 0x3F, TrbType::NoOpCommand as u32);
        
        let enable = CommandBuilder::enable_slot();
        assert_eq!((enable.control >> 10) & 0x3F, TrbType::EnableSlot as u32);
    }
    
    #[test]
    fn test_transfer_builder() {
        let setup = TransferBuilder::setup_stage(0x80, 0x06, 0x0100, 0, 18, 3);
        assert_eq!((setup.control >> 10) & 0x3F, TrbType::SetupStage as u32);
    }
}
