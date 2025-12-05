// ============================================================================
// src/io/interrupt_manager.rs - Unified Interrupt Management
// ============================================================================
//!
//! # 統一割り込みマネージャ
//!
//! システム全体で一意な割り込みベクタ割り当てを管理。
//! PCI MSI/MSI-X、IO-APIC、レガシー割り込みを統一的に扱う。
//!
//! ## 設計原則
//! - ベクタ衝突の防止
//! - 動的なベクタ割り当て/解放
//! - 割り込みルーティングの一元管理
//! - アフィニティ設定のサポート

#![allow(dead_code)]

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use spin::{Mutex, RwLock};

// ============================================================================
// Constants
// ============================================================================

/// システム予約ベクタ（例外ハンドラ用）
const RESERVED_VECTORS_START: u8 = 0;
const RESERVED_VECTORS_END: u8 = 31;

/// ユーザー割り込みベクタ範囲
const USER_VECTORS_START: u8 = 32;
const USER_VECTORS_END: u8 = 254;

/// Spurious interrupt vector
const SPURIOUS_VECTOR: u8 = 255;

/// MSI/MSI-X用ベクタ範囲
const MSI_VECTORS_START: u8 = 48;
const MSI_VECTORS_END: u8 = 223;

/// レガシー割り込み用ベクタ範囲
const LEGACY_VECTORS_START: u8 = 32;
const LEGACY_VECTORS_END: u8 = 47;

/// APIC Timer vector
const APIC_TIMER_VECTOR: u8 = 240;

/// IPI vectors
const IPI_VECTOR_BASE: u8 = 241;

// ============================================================================
// Interrupt Source Types
// ============================================================================

/// 割り込みソースの種類
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptSourceType {
    /// レガシーIOAPIC割り込み
    LegacyIoApic { gsi: u32 },
    /// MSI (Message Signaled Interrupt)
    Msi { device_bdf: u32 },
    /// MSI-X
    MsiX { device_bdf: u32, table_index: u16 },
    /// Local APICタイマー
    ApicTimer,
    /// IPI (Inter-Processor Interrupt)
    Ipi,
    /// カスタム
    Custom { name: &'static str },
}

/// 割り込み配送モード
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryMode {
    /// Fixed - 特定のCPUに配送
    Fixed,
    /// Lowest Priority - 最も優先度の低いCPUに配送
    LowestPriority,
    /// SMI
    Smi,
    /// NMI
    Nmi,
    /// INIT
    Init,
    /// ExtINT
    ExtInt,
}

impl DeliveryMode {
    pub fn to_bits(&self) -> u8 {
        match self {
            DeliveryMode::Fixed => 0b000,
            DeliveryMode::LowestPriority => 0b001,
            DeliveryMode::Smi => 0b010,
            DeliveryMode::Nmi => 0b100,
            DeliveryMode::Init => 0b101,
            DeliveryMode::ExtInt => 0b111,
        }
    }
}

/// トリガーモード
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriggerMode {
    Edge,
    Level,
}

/// 極性
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Polarity {
    ActiveHigh,
    ActiveLow,
}

// ============================================================================
// Interrupt Configuration
// ============================================================================

/// 割り込み設定
#[derive(Debug, Clone)]
pub struct InterruptConfig {
    /// ベクタ番号
    pub vector: u8,
    /// 配送先CPUのAPIC ID（Noneの場合はブロードキャスト）
    pub target_apic_id: Option<u8>,
    /// 配送モード
    pub delivery_mode: DeliveryMode,
    /// トリガーモード
    pub trigger_mode: TriggerMode,
    /// 極性
    pub polarity: Polarity,
    /// マスク状態
    pub masked: bool,
}

impl Default for InterruptConfig {
    fn default() -> Self {
        Self {
            vector: 0,
            target_apic_id: None,
            delivery_mode: DeliveryMode::Fixed,
            trigger_mode: TriggerMode::Edge,
            polarity: Polarity::ActiveHigh,
            masked: true,
        }
    }
}

impl InterruptConfig {
    /// MSI用のメッセージアドレスを生成
    pub fn msi_address(&self) -> u64 {
        const MSI_ADDRESS_BASE: u64 = 0xFEE00000;
        let apic_id = self.target_apic_id.unwrap_or(0) as u64;
        MSI_ADDRESS_BASE | (apic_id << 12)
    }
    
    /// MSI用のメッセージデータを生成
    pub fn msi_data(&self) -> u32 {
        let mut data = self.vector as u32;
        data |= (self.delivery_mode.to_bits() as u32) << 8;
        if self.trigger_mode == TriggerMode::Level {
            data |= 1 << 15; // Level trigger
            data |= 1 << 14; // Assert
        }
        data
    }
    
    /// IO-APIC用のリダイレクションエントリを生成
    pub fn ioapic_entry(&self) -> u64 {
        let mut entry = self.vector as u64;
        entry |= (self.delivery_mode.to_bits() as u64) << 8;
        
        if self.polarity == Polarity::ActiveLow {
            entry |= 1 << 13;
        }
        if self.trigger_mode == TriggerMode::Level {
            entry |= 1 << 15;
        }
        if self.masked {
            entry |= 1 << 16;
        }
        
        // Destination APIC ID
        let apic_id = self.target_apic_id.unwrap_or(0) as u64;
        entry |= apic_id << 56;
        
        entry
    }
}

// ============================================================================
// Interrupt Allocation
// ============================================================================

/// 割り込み割り当て情報
#[derive(Debug, Clone)]
pub struct InterruptAllocation {
    /// ベクタ番号
    pub vector: u8,
    /// 割り込みソース
    pub source: InterruptSourceType,
    /// 設定
    pub config: InterruptConfig,
    /// ハンドラ名（デバッグ用）
    pub handler_name: String,
}

/// ベクタ割り当て結果
pub struct VectorAllocation {
    /// 割り当てられたベクタ
    pub vector: u8,
    /// 設定済みの設定
    pub config: InterruptConfig,
}

impl VectorAllocation {
    /// ベクタ番号を取得
    pub fn vector(&self) -> u8 {
        self.vector
    }
}

// ============================================================================
// Interrupt Manager
// ============================================================================

/// 割り込みマネージャ
pub struct InterruptManager {
    /// 割り当て済みベクタ（ビットマップ）
    /// ベクタ 0-63
    allocated_vectors_0: AtomicU64,
    /// ベクタ 64-127
    allocated_vectors_1: AtomicU64,
    /// ベクタ 128-191
    allocated_vectors_2: AtomicU64,
    /// ベクタ 192-255
    allocated_vectors_3: AtomicU64,
    /// 割り当て情報
    allocations: RwLock<BTreeMap<u8, InterruptAllocation>>,
    /// GSI → ベクタ マッピング
    gsi_to_vector: RwLock<BTreeMap<u32, u8>>,
    /// 統計
    stats: InterruptStats,
}

/// 割り込み統計
pub struct InterruptStats {
    /// 割り込み発生回数（ベクタ別）
    pub counts: [AtomicU64; 256],
    /// 総割り込み数
    pub total_count: AtomicU64,
}

impl InterruptStats {
    const fn new() -> Self {
        const ZERO: AtomicU64 = AtomicU64::new(0);
        Self {
            counts: [ZERO; 256],
            total_count: AtomicU64::new(0),
        }
    }
    
    /// 割り込み発生を記録
    pub fn record(&self, vector: u8) {
        self.counts[vector as usize].fetch_add(1, Ordering::Relaxed);
        self.total_count.fetch_add(1, Ordering::Relaxed);
    }
    
    /// ベクタの割り込み回数を取得
    pub fn get_count(&self, vector: u8) -> u64 {
        self.counts[vector as usize].load(Ordering::Relaxed)
    }
}

/// 割り込みマネージャのエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptError {
    /// ベクタが使用可能なものがない
    NoAvailableVector,
    /// ベクタが既に使用中
    VectorInUse,
    /// 無効なベクタ
    InvalidVector,
    /// 無効なGSI
    InvalidGsi,
    /// ハードウェアエラー
    HardwareError,
}

impl InterruptManager {
    /// 新しい割り込みマネージャを作成
    pub const fn new() -> Self {
        Self {
            // 予約済みベクタ（0-31）をマーク
            allocated_vectors_0: AtomicU64::new(0xFFFFFFFF),
            allocated_vectors_1: AtomicU64::new(0),
            allocated_vectors_2: AtomicU64::new(0),
            // Spurious vector (255) とシステム用ベクタを予約
            allocated_vectors_3: AtomicU64::new(0x8000_0000_0000_0000),
            allocations: RwLock::new(BTreeMap::new()),
            gsi_to_vector: RwLock::new(BTreeMap::new()),
            stats: InterruptStats::new(),
        }
    }
    
    /// 初期化
    pub fn init(&self) {
        // システム予約ベクタをマーク
        // APIC Timer
        self.mark_vector_used(APIC_TIMER_VECTOR);
        // IPIs
        for i in 0..8 {
            self.mark_vector_used(IPI_VECTOR_BASE + i);
        }
    }
    
    /// ベクタを使用中としてマーク
    fn mark_vector_used(&self, vector: u8) {
        let (bitmap, bit) = self.vector_to_bitmap(vector);
        bitmap.fetch_or(1u64 << bit, Ordering::AcqRel);
    }
    
    /// ベクタを空きとしてマーク
    fn mark_vector_free(&self, vector: u8) {
        let (bitmap, bit) = self.vector_to_bitmap(vector);
        bitmap.fetch_and(!(1u64 << bit), Ordering::AcqRel);
    }
    
    /// ベクタが空いているか確認
    fn is_vector_free(&self, vector: u8) -> bool {
        let (bitmap, bit) = self.vector_to_bitmap(vector);
        (bitmap.load(Ordering::Acquire) & (1u64 << bit)) == 0
    }
    
    /// ベクタをビットマップ位置に変換
    fn vector_to_bitmap(&self, vector: u8) -> (&AtomicU64, u8) {
        match vector {
            0..=63 => (&self.allocated_vectors_0, vector),
            64..=127 => (&self.allocated_vectors_1, vector - 64),
            128..=191 => (&self.allocated_vectors_2, vector - 128),
            _ => (&self.allocated_vectors_3, vector - 192),
        }
    }
    
    /// MSI/MSI-X用のベクタを割り当て
    pub fn allocate_msi_vector(
        &self,
        device_bdf: u32,
        handler_name: String,
        target_apic_id: Option<u8>,
    ) -> Result<VectorAllocation, InterruptError> {
        // MSI範囲から空きベクタを探す
        for vector in MSI_VECTORS_START..=MSI_VECTORS_END {
            if self.try_allocate_vector(vector) {
                let config = InterruptConfig {
                    vector,
                    target_apic_id,
                    delivery_mode: DeliveryMode::Fixed,
                    trigger_mode: TriggerMode::Edge,
                    polarity: Polarity::ActiveHigh,
                    masked: false,
                };
                
                let allocation = InterruptAllocation {
                    vector,
                    source: InterruptSourceType::Msi { device_bdf },
                    config: config.clone(),
                    handler_name,
                };
                
                self.allocations.write().insert(vector, allocation);
                
                return Ok(VectorAllocation { vector, config });
            }
        }
        
        Err(InterruptError::NoAvailableVector)
    }
    
    /// MSI-X用の複数ベクタを割り当て
    pub fn allocate_msix_vectors(
        &self,
        device_bdf: u32,
        count: u16,
        handler_name: String,
        target_apic_id: Option<u8>,
    ) -> Result<Vec<VectorAllocation>, InterruptError> {
        let mut allocations = Vec::with_capacity(count as usize);
        
        for i in 0..count {
            match self.allocate_msi_vector(device_bdf, handler_name.clone(), target_apic_id) {
                Ok(mut alloc) => {
                    // MSI-Xとして記録
                    if let Some(allocation) = self.allocations.write().get_mut(&alloc.vector) {
                        allocation.source = InterruptSourceType::MsiX {
                            device_bdf,
                            table_index: i,
                        };
                    }
                    allocations.push(alloc);
                }
                Err(e) => {
                    // 割り当て済みのものを解放
                    for alloc in allocations {
                        self.free_vector(alloc.vector);
                    }
                    return Err(e);
                }
            }
        }
        
        Ok(allocations)
    }
    
    /// IO-APIC (GSI) 用のベクタを割り当て
    pub fn allocate_gsi_vector(
        &self,
        gsi: u32,
        handler_name: String,
        trigger_mode: TriggerMode,
        polarity: Polarity,
    ) -> Result<VectorAllocation, InterruptError> {
        // 既存のマッピングを確認
        if let Some(&vector) = self.gsi_to_vector.read().get(&gsi) {
            let config = self.allocations.read()
                .get(&vector)
                .map(|a| a.config.clone())
                .unwrap_or_default();
            return Ok(VectorAllocation { vector, config });
        }
        
        // レガシー範囲から割り当て
        let vector = if gsi < 16 {
            // IRQ 0-15 は固定マッピング
            LEGACY_VECTORS_START + gsi as u8
        } else {
            // その他のGSIは動的割り当て
            self.find_free_vector(LEGACY_VECTORS_START, USER_VECTORS_END)?
        };
        
        if !self.try_allocate_vector(vector) {
            return Err(InterruptError::VectorInUse);
        }
        
        let config = InterruptConfig {
            vector,
            target_apic_id: Some(0), // BSP
            delivery_mode: DeliveryMode::Fixed,
            trigger_mode,
            polarity,
            masked: true,
        };
        
        let allocation = InterruptAllocation {
            vector,
            source: InterruptSourceType::LegacyIoApic { gsi },
            config: config.clone(),
            handler_name,
        };
        
        self.allocations.write().insert(vector, allocation);
        self.gsi_to_vector.write().insert(gsi, vector);
        
        Ok(VectorAllocation { vector, config })
    }
    
    /// 空きベクタを探す
    fn find_free_vector(&self, start: u8, end: u8) -> Result<u8, InterruptError> {
        for vector in start..=end {
            if self.is_vector_free(vector) {
                return Ok(vector);
            }
        }
        Err(InterruptError::NoAvailableVector)
    }
    
    /// ベクタの割り当てを試みる
    fn try_allocate_vector(&self, vector: u8) -> bool {
        let (bitmap, bit) = self.vector_to_bitmap(vector);
        let mask = 1u64 << bit;
        
        loop {
            let current = bitmap.load(Ordering::Acquire);
            if (current & mask) != 0 {
                return false; // 既に使用中
            }
            
            match bitmap.compare_exchange(
                current,
                current | mask,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(_) => continue, // リトライ
            }
        }
    }
    
    /// ベクタを解放
    pub fn free_vector(&self, vector: u8) {
        self.mark_vector_free(vector);
        self.allocations.write().remove(&vector);
        
        // GSIマッピングも削除
        self.gsi_to_vector.write().retain(|_, &mut v| v != vector);
    }
    
    /// ベクタの設定を取得
    pub fn get_config(&self, vector: u8) -> Option<InterruptConfig> {
        self.allocations.read().get(&vector).map(|a| a.config.clone())
    }
    
    /// ベクタの設定を更新
    pub fn update_config(&self, vector: u8, config: InterruptConfig) -> Result<(), InterruptError> {
        if let Some(allocation) = self.allocations.write().get_mut(&vector) {
            allocation.config = config;
            Ok(())
        } else {
            Err(InterruptError::InvalidVector)
        }
    }
    
    /// 割り込み発生を記録
    pub fn record_interrupt(&self, vector: u8) {
        self.stats.record(vector);
    }
    
    /// 統計を取得
    pub fn stats(&self) -> &InterruptStats {
        &self.stats
    }
    
    /// 割り当て情報を取得
    pub fn get_allocation(&self, vector: u8) -> Option<InterruptAllocation> {
        self.allocations.read().get(&vector).cloned()
    }
    
    /// 全ての割り当てを列挙
    pub fn list_allocations(&self) -> Vec<InterruptAllocation> {
        self.allocations.read().values().cloned().collect()
    }
}

// ============================================================================
// Global Instance
// ============================================================================

static INTERRUPT_MANAGER: InterruptManager = InterruptManager::new();

/// グローバル割り込みマネージャを初期化
pub fn init() {
    INTERRUPT_MANAGER.init();
}

/// グローバル割り込みマネージャを取得
pub fn interrupt_manager() -> &'static InterruptManager {
    &INTERRUPT_MANAGER
}

/// MSIベクタを割り当て
pub fn allocate_msi(
    device_bdf: u32,
    handler_name: &str,
    target_apic_id: Option<u8>,
) -> Result<VectorAllocation, InterruptError> {
    INTERRUPT_MANAGER.allocate_msi_vector(
        device_bdf,
        alloc::string::ToString::to_string(handler_name),
        target_apic_id,
    )
}

/// MSI-Xベクタを割り当て
pub fn allocate_msix(
    device_bdf: u32,
    count: u16,
    handler_name: &str,
    target_apic_id: Option<u8>,
) -> Result<Vec<VectorAllocation>, InterruptError> {
    INTERRUPT_MANAGER.allocate_msix_vectors(
        device_bdf,
        count,
        alloc::string::ToString::to_string(handler_name),
        target_apic_id,
    )
}

/// GSIベクタを割り当て
pub fn allocate_gsi(
    gsi: u32,
    handler_name: &str,
    trigger_mode: TriggerMode,
    polarity: Polarity,
) -> Result<VectorAllocation, InterruptError> {
    INTERRUPT_MANAGER.allocate_gsi_vector(
        gsi,
        alloc::string::ToString::to_string(handler_name),
        trigger_mode,
        polarity,
    )
}

/// ベクタを解放
pub fn free_vector(vector: u8) {
    INTERRUPT_MANAGER.free_vector(vector);
}

/// 割り込み発生を記録
pub fn record_interrupt(vector: u8) {
    INTERRUPT_MANAGER.record_interrupt(vector);
}

// ============================================================================
// Integration with APIC
// ============================================================================

/// IO-APICに割り込みを設定
pub fn configure_ioapic_interrupt(
    gsi: u32,
    config: &InterruptConfig,
) -> Result<(), InterruptError> {
    // IO-APICのリダイレクションテーブルに書き込み
    let entry = config.ioapic_entry();
    
    // crate::io::apic モジュールの関数を呼び出す
    // （実際の実装はapic.rsに追加する必要がある）
    
    // 簡易実装: グローバルIO-APICインスタンスを使用
    // unsafe {
    //     crate::io::apic::set_ioapic_entry(gsi, entry);
    // }
    
    Ok(())
}

/// 割り込みをマスク
pub fn mask_interrupt(vector: u8) -> Result<(), InterruptError> {
    if let Some(allocation) = INTERRUPT_MANAGER.allocations.write().get_mut(&vector) {
        allocation.config.masked = true;
        
        match allocation.source {
            InterruptSourceType::LegacyIoApic { gsi } => {
                configure_ioapic_interrupt(gsi, &allocation.config)?;
            }
            InterruptSourceType::Msi { .. } | InterruptSourceType::MsiX { .. } => {
                // MSI/MSI-Xはデバイス側でマスク
            }
            _ => {}
        }
        
        Ok(())
    } else {
        Err(InterruptError::InvalidVector)
    }
}

/// 割り込みをアンマスク
pub fn unmask_interrupt(vector: u8) -> Result<(), InterruptError> {
    if let Some(allocation) = INTERRUPT_MANAGER.allocations.write().get_mut(&vector) {
        allocation.config.masked = false;
        
        match allocation.source {
            InterruptSourceType::LegacyIoApic { gsi } => {
                configure_ioapic_interrupt(gsi, &allocation.config)?;
            }
            InterruptSourceType::Msi { .. } | InterruptSourceType::MsiX { .. } => {
                // MSI/MSI-Xはデバイス側でアンマスク
            }
            _ => {}
        }
        
        Ok(())
    } else {
        Err(InterruptError::InvalidVector)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_msi_allocation() {
        let manager = InterruptManager::new();
        manager.init();
        
        let result = manager.allocate_msi_vector(
            0x0100, // BDF
            "test_device".into(),
            Some(0),
        );
        
        assert!(result.is_ok());
        let alloc = result.unwrap();
        assert!(alloc.vector >= MSI_VECTORS_START);
        assert!(alloc.vector <= MSI_VECTORS_END);
    }
    
    #[test]
    fn test_gsi_allocation() {
        let manager = InterruptManager::new();
        manager.init();
        
        let result = manager.allocate_gsi_vector(
            1, // IRQ 1 (keyboard)
            "keyboard".into(),
            TriggerMode::Edge,
            Polarity::ActiveHigh,
        );
        
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_vector_free() {
        let manager = InterruptManager::new();
        manager.init();
        
        let alloc = manager.allocate_msi_vector(
            0x0100,
            "test".into(),
            None,
        ).unwrap();
        
        let vector = alloc.vector;
        manager.free_vector(vector);
        
        // 同じベクタを再割り当てできるはず
        let alloc2 = manager.allocate_msi_vector(
            0x0200,
            "test2".into(),
            None,
        ).unwrap();
        
        // 空いているベクタが割り当てられる
        assert!(alloc2.vector >= MSI_VECTORS_START);
    }
}
