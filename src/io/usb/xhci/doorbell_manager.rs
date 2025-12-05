// ============================================================================
// src/io/usb/xhci/doorbell_manager.rs - xHCI Doorbell Management
// ============================================================================
//!
//! # xHCI ドアベル管理
//!
//! ドアベルレジスタへのアクセスを管理し、コマンドリングや
//! 転送リングへの通知を行う。

#![allow(dead_code)]

use core::sync::atomic::{AtomicU32, Ordering};

// ============================================================================
// Doorbell Register Layout
// ============================================================================

/// ドアベルレジスタサイズ（バイト）
pub const DOORBELL_SIZE: usize = 4;

/// ホストコントローラ用ドアベル（スロット0）
pub const DOORBELL_HOST_CONTROLLER: u8 = 0;

/// コマンドリング用のドアベルターゲット値
pub const DB_TARGET_COMMAND: u8 = 0;

/// 制御エンドポイント用のドアベルターゲット値
pub const DB_TARGET_CONTROL_EP0: u8 = 1;

// ============================================================================
// Doorbell Target
// ============================================================================

/// ドアベルターゲット
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoorbellTarget {
    /// コマンドリング（スロット0専用）
    CommandRing,
    /// 制御エンドポイント0
    ControlEndpoint0,
    /// アウトエンドポイント
    OutEndpoint(u8),
    /// インエンドポイント
    InEndpoint(u8),
}

impl DoorbellTarget {
    /// ターゲット値を計算（ドアベルレジスタ用）
    pub fn target_value(&self) -> u8 {
        match self {
            Self::CommandRing => 0,
            Self::ControlEndpoint0 => 1,
            // OUT EP n -> DCI = 2n
            // IN EP n -> DCI = 2n + 1
            Self::OutEndpoint(ep) => *ep * 2,
            Self::InEndpoint(ep) => *ep * 2 + 1,
        }
    }
    
    /// エンドポイント番号からターゲットを作成
    pub fn from_endpoint(endpoint_addr: u8) -> Self {
        if endpoint_addr == 0 {
            Self::ControlEndpoint0
        } else if endpoint_addr & 0x80 != 0 {
            // IN endpoint
            Self::InEndpoint(endpoint_addr & 0x7F)
        } else {
            // OUT endpoint
            Self::OutEndpoint(endpoint_addr)
        }
    }
}

// ============================================================================
// Stream ID
// ============================================================================

/// ストリームID（Bulk Streams用）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StreamId(pub u16);

impl StreamId {
    /// プライマリストリーム（ストリーム非使用）
    pub const PRIMARY: Self = Self(0);
    
    /// ストリームIDを作成
    pub fn new(id: u16) -> Self {
        Self(id)
    }
    
    /// 値を取得
    pub fn value(&self) -> u16 {
        self.0
    }
}

// ============================================================================
// Doorbell Manager
// ============================================================================

/// xHCI ドアベルマネージャ
pub struct XhciDoorbellManager {
    /// ドアベルレジスタのベースアドレス
    doorbell_base: u64,
    /// 最大スロット数
    max_slots: u8,
    /// ドアベル発行カウンタ（デバッグ用）
    ring_count: AtomicU32,
}

impl XhciDoorbellManager {
    /// 新しいドアベルマネージャを作成
    ///
    /// # Arguments
    /// * `doorbell_base` - ドアベルアレイのベースアドレス
    /// * `max_slots` - 最大デバイススロット数
    pub fn new(doorbell_base: u64, max_slots: u8) -> Self {
        Self {
            doorbell_base,
            max_slots,
            ring_count: AtomicU32::new(0),
        }
    }
    
    // ========================================================================
    // ドアベルアドレス計算
    // ========================================================================
    
    /// スロットのドアベルレジスタアドレスを計算
    fn doorbell_address(&self, slot_id: u8) -> u64 {
        self.doorbell_base + (slot_id as u64) * DOORBELL_SIZE as u64
    }
    
    // ========================================================================
    // ドアベル発行
    // ========================================================================
    
    /// ドアベルを鳴らす（汎用）
    fn ring_doorbell(&self, slot_id: u8, target: u8, stream_id: u16) {
        let addr = self.doorbell_address(slot_id);
        let value = (target as u32) | ((stream_id as u32) << 16);
        
        unsafe {
            let ptr = addr as *mut u32;
            core::ptr::write_volatile(ptr, value);
        }
        
        self.ring_count.fetch_add(1, Ordering::Relaxed);
    }
    
    /// コマンドリングのドアベルを鳴らす
    ///
    /// コマンドをエンキューした後に呼び出す
    pub fn ring_command(&self) {
        self.ring_doorbell(DOORBELL_HOST_CONTROLLER, DB_TARGET_COMMAND, 0);
    }
    
    /// 転送リングのドアベルを鳴らす
    ///
    /// # Arguments
    /// * `slot_id` - デバイススロットID (1-based)
    /// * `target` - ドアベルターゲット
    pub fn ring_transfer(&self, slot_id: u8, target: DoorbellTarget) {
        if slot_id == 0 || slot_id > self.max_slots {
            return;
        }
        self.ring_doorbell(slot_id, target.target_value(), 0);
    }
    
    /// 転送リングのドアベルを鳴らす（ストリームID付き）
    ///
    /// # Arguments
    /// * `slot_id` - デバイススロットID (1-based)
    /// * `target` - ドアベルターゲット
    /// * `stream_id` - ストリームID（Bulk Streams使用時）
    pub fn ring_transfer_stream(&self, slot_id: u8, target: DoorbellTarget, stream_id: StreamId) {
        if slot_id == 0 || slot_id > self.max_slots {
            return;
        }
        self.ring_doorbell(slot_id, target.target_value(), stream_id.value());
    }
    
    /// エンドポイントアドレスでドアベルを鳴らす
    ///
    /// # Arguments
    /// * `slot_id` - デバイススロットID (1-based)
    /// * `endpoint_addr` - エンドポイントアドレス (0x00-0x0F: OUT, 0x80-0x8F: IN)
    pub fn ring_endpoint(&self, slot_id: u8, endpoint_addr: u8) {
        let target = DoorbellTarget::from_endpoint(endpoint_addr);
        self.ring_transfer(slot_id, target);
    }
    
    // ========================================================================
    // 便利メソッド
    // ========================================================================
    
    /// 制御転送を開始
    pub fn ring_control(&self, slot_id: u8) {
        self.ring_transfer(slot_id, DoorbellTarget::ControlEndpoint0);
    }
    
    /// バルクIN転送を開始
    pub fn ring_bulk_in(&self, slot_id: u8, endpoint_num: u8) {
        self.ring_transfer(slot_id, DoorbellTarget::InEndpoint(endpoint_num));
    }
    
    /// バルクOUT転送を開始
    pub fn ring_bulk_out(&self, slot_id: u8, endpoint_num: u8) {
        self.ring_transfer(slot_id, DoorbellTarget::OutEndpoint(endpoint_num));
    }
    
    /// インタラプトIN転送を開始
    pub fn ring_interrupt_in(&self, slot_id: u8, endpoint_num: u8) {
        self.ring_transfer(slot_id, DoorbellTarget::InEndpoint(endpoint_num));
    }
    
    /// アイソクロナス転送を開始
    pub fn ring_isoch(&self, slot_id: u8, endpoint_num: u8, direction_in: bool) {
        if direction_in {
            self.ring_transfer(slot_id, DoorbellTarget::InEndpoint(endpoint_num));
        } else {
            self.ring_transfer(slot_id, DoorbellTarget::OutEndpoint(endpoint_num));
        }
    }
    
    // ========================================================================
    // 統計
    // ========================================================================
    
    /// 総ドアベル発行回数を取得
    pub fn total_rings(&self) -> u32 {
        self.ring_count.load(Ordering::Relaxed)
    }
    
    /// カウンタをリセット
    pub fn reset_counter(&self) {
        self.ring_count.store(0, Ordering::Relaxed);
    }
}

// ============================================================================
// Doorbell Builder (for batch operations)
// ============================================================================

/// ドアベル操作のバッチビルダー
pub struct DoorbellBatch {
    operations: [(u8, u8, u16); 16],
    count: usize,
}

impl DoorbellBatch {
    /// 新しいバッチを作成
    pub fn new() -> Self {
        Self {
            operations: [(0, 0, 0); 16],
            count: 0,
        }
    }
    
    /// 操作を追加
    pub fn add(&mut self, slot_id: u8, target: DoorbellTarget) -> &mut Self {
        if self.count < 16 {
            self.operations[self.count] = (slot_id, target.target_value(), 0);
            self.count += 1;
        }
        self
    }
    
    /// ストリーム付き操作を追加
    pub fn add_with_stream(&mut self, slot_id: u8, target: DoorbellTarget, stream_id: StreamId) -> &mut Self {
        if self.count < 16 {
            self.operations[self.count] = (slot_id, target.target_value(), stream_id.value());
            self.count += 1;
        }
        self
    }
    
    /// バッチを実行
    pub fn execute(&self, manager: &XhciDoorbellManager) {
        for i in 0..self.count {
            let (slot_id, target, stream_id) = self.operations[i];
            manager.ring_doorbell(slot_id, target, stream_id);
        }
    }
    
    /// バッチをクリア
    pub fn clear(&mut self) {
        self.count = 0;
    }
    
    /// 操作数を取得
    pub fn len(&self) -> usize {
        self.count
    }
    
    /// バッチが空かどうか
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for DoorbellBatch {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Doorbell Coordinator
// ============================================================================

/// 複数デバイスのドアベル調整
pub struct DoorbellCoordinator {
    manager: XhciDoorbellManager,
    /// 最後にドアベルを鳴らした時刻（ticks）
    last_ring_time: AtomicU32,
    /// 最小ドアベル間隔（ticks）
    min_interval: u32,
}

impl DoorbellCoordinator {
    /// 新しいコーディネータを作成
    pub fn new(doorbell_base: u64, max_slots: u8) -> Self {
        Self {
            manager: XhciDoorbellManager::new(doorbell_base, max_slots),
            last_ring_time: AtomicU32::new(0),
            min_interval: 1, // 最小1tick間隔
        }
    }
    
    /// 内部マネージャへの参照を取得
    pub fn manager(&self) -> &XhciDoorbellManager {
        &self.manager
    }
    
    /// レート制限付きでドアベルを鳴らす
    pub fn ring_with_rate_limit(&self, slot_id: u8, target: DoorbellTarget) {
        // 簡易的なレート制限（実際はRTCやTSCを使用）
        let _last = self.last_ring_time.load(Ordering::Relaxed);
        // レート制限ロジック（省略）
        
        self.manager.ring_transfer(slot_id, target);
        self.last_ring_time.fetch_add(1, Ordering::Relaxed);
    }
    
    /// コマンドリングを鳴らす
    pub fn ring_command(&self) {
        self.manager.ring_command();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_doorbell_target() {
        assert_eq!(DoorbellTarget::CommandRing.target_value(), 0);
        assert_eq!(DoorbellTarget::ControlEndpoint0.target_value(), 1);
        assert_eq!(DoorbellTarget::OutEndpoint(1).target_value(), 2);
        assert_eq!(DoorbellTarget::InEndpoint(1).target_value(), 3);
        assert_eq!(DoorbellTarget::OutEndpoint(2).target_value(), 4);
        assert_eq!(DoorbellTarget::InEndpoint(2).target_value(), 5);
    }
    
    #[test]
    fn test_doorbell_from_endpoint() {
        assert_eq!(DoorbellTarget::from_endpoint(0), DoorbellTarget::ControlEndpoint0);
        assert_eq!(DoorbellTarget::from_endpoint(1), DoorbellTarget::OutEndpoint(1));
        assert_eq!(DoorbellTarget::from_endpoint(0x81), DoorbellTarget::InEndpoint(1));
        assert_eq!(DoorbellTarget::from_endpoint(0x82), DoorbellTarget::InEndpoint(2));
    }
    
    #[test]
    fn test_doorbell_batch() {
        let mut batch = DoorbellBatch::new();
        batch
            .add(1, DoorbellTarget::ControlEndpoint0)
            .add(2, DoorbellTarget::InEndpoint(1));
        
        assert_eq!(batch.len(), 2);
        assert!(!batch.is_empty());
        
        batch.clear();
        assert!(batch.is_empty());
    }
}
