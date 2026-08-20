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
use crate::sync::IrqMutex;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use once_cell::race::OnceBox;
use spin::{Mutex, RwLock};
use x86_64::structures::idt::InterruptStackFrame;

// ============================================================================
// Constants
// ============================================================================

/// システム予約ベクタ（例外ハンドラ用）
mod mask_ops;
pub use mask_ops::*;

/// ユーザー割り込みベクタ範囲
const USER_VECTORS_END: u8 = 254;

/// MSI/MSI-X用ベクタ範囲
pub const NVME_VECTOR: u8 = 48; // NVMe専用ベクタ (0x30)
pub const MSI_VECTORS_START: u8 = 0x60;
pub const MSI_VECTORS_END: u8 = 0x6F;

/// レガシー割り込み用ベクタ範囲
const LEGACY_VECTORS_START: u8 = 32;

/// APIC Timer vector
///
/// 0xF0 is reserved for executor wake IPIs and 0xF1..=0xF8 are reserved for
/// TLB/IPI traffic, so the LAPIC runtime timer uses 0xEF.
const APIC_TIMER_VECTOR: u8 = 0xEF;

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
    /// MSI (Message-based Interrupt)
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
    /// Validated physical APIC destination.
    pub target_apic_id: crate::cpu::ApicId,
    /// 配送モード
    pub delivery_mode: DeliveryMode,
    /// トリガーモード
    pub trigger_mode: TriggerMode,
    /// 極性
    pub polarity: Polarity,
    /// マスク状態
    pub masked: bool,
    /// Interrupt Remapping Handle (if used)
    pub ir_handle: Option<u16>,
}

impl InterruptConfig {
    /// MSI用のメッセージアドレスを生成
    pub fn msi_address(&self) -> Result<u64, InterruptError> {
        if let Some(handle) = self.ir_handle {
            Ok(crate::io::iommu::api::get_remap_msi_message(handle).0)
        } else {
            const MSI_ADDRESS_BASE: u64 = 0xFEE00000;
            let apic_id = u8::try_from(self.target_apic_id.as_u32()).map_err(|_| {
                InterruptError::DestinationRequiresInterruptRemapping(self.target_apic_id)
            })?;
            Ok(MSI_ADDRESS_BASE | (u64::from(apic_id) << 12))
        }
    }

    /// MSI用のメッセージデータを生成
    pub fn msi_data(&self) -> u32 {
        if let Some(handle) = self.ir_handle {
            crate::io::iommu::api::get_remap_msi_message(handle).1
        } else {
            let mut data = self.vector as u32;
            data |= (self.delivery_mode.to_bits() as u32) << 8;
            if self.trigger_mode == TriggerMode::Level {
                data |= 1 << 15; // Level trigger
                data |= 1 << 14; // Assert
            }
            data
        }
    }

    /// IO-APIC用のリダイレクションエントリを生成
    pub fn ioapic_entry(&self) -> Result<crate::drivers::apic::RedirectionEntry, InterruptError> {
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

        let destination = crate::drivers::apic::IoApicDestination::try_from(
            crate::drivers::apic::ApicDestination::new(self.target_apic_id.as_u32()),
        )
        .map_err(InterruptError::IoApic)?;
        Ok(crate::drivers::apic::RedirectionEntry::from_raw(entry).destination(destination))
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
    /// Serializes destination validation/allocation against CPU drain.
    route_allocation_gate: Mutex<()>,
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
    /// CPU topology cannot provide the requested online destination.
    CpuNotOnline(crate::cpu::CpuId),
    /// Direct MSI delivery cannot represent this destination without an IOMMU
    /// interrupt-remapping entry.
    DestinationRequiresInterruptRemapping(crate::cpu::ApicId),
    /// Typed I/O APIC backend failure.
    IoApic(crate::drivers::apic::IoApicError),
    /// Typed local APIC backend failure.
    LocalApic(crate::drivers::apic::LocalApicError),
}

impl InterruptManager {
    /// 新しい割り込みマネージャを作成
    pub const fn new() -> Self {
        Self {
            route_allocation_gate: Mutex::new(()),
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
        target_cpu: crate::cpu::CpuId,
    ) -> Result<VectorAllocation, InterruptError> {
        let _route_allocation = self.route_allocation_gate.lock();
        let target_apic_id = online_apic_id(target_cpu)?;
        // MSI範囲から空きベクタを探す
        for vector in MSI_VECTORS_START..=MSI_VECTORS_END {
            if self.try_allocate_vector(vector) {
                let mut config = InterruptConfig {
                    vector,
                    target_apic_id,
                    delivery_mode: DeliveryMode::Fixed,
                    trigger_mode: TriggerMode::Edge,
                    polarity: Polarity::ActiveHigh,
                    masked: false,
                    ir_handle: None,
                };

                // Try Interrupt Remapping
                // Extract BDF (assuming segment 0)
                let bus = ((device_bdf >> 8) & 0xFF) as u8;
                let dev = ((device_bdf >> 3) & 0x1F) as u8;
                let func = (device_bdf & 0x7) as u8;
                let dest_id = target_apic_id.as_u32();

                match crate::io::iommu::api::map_interrupt(
                    0, bus, dev, func, vector, dest_id, false,
                ) {
                    Ok(handle) => config.ir_handle = Some(handle),
                    Err(_) if u8::try_from(dest_id).is_ok() => {}
                    Err(_) => {
                        self.mark_vector_free(vector);
                        return Err(InterruptError::DestinationRequiresInterruptRemapping(
                            target_apic_id,
                        ));
                    }
                }

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
        target_cpu: crate::cpu::CpuId,
    ) -> Result<Vec<VectorAllocation>, InterruptError> {
        let mut allocations = Vec::with_capacity(count as usize);

        for i in 0..count {
            match self.allocate_msi_vector(device_bdf, handler_name.clone(), target_cpu) {
                Ok(alloc) => {
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
        let target_apic_id = online_apic_id(crate::cpu::CpuId::BOOTSTRAP)?;
        // 既存のマッピングを確認
        if let Some(&vector) = self.gsi_to_vector.read().get(&gsi) {
            let config = self
                .allocations
                .read()
                .get(&vector)
                .map(|a| a.config.clone())
                .ok_or(InterruptError::InvalidVector)?;
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
            target_apic_id,
            delivery_mode: DeliveryMode::Fixed,
            trigger_mode,
            polarity,
            masked: true,
            ir_handle: None,
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
        self.allocations
            .read()
            .get(&vector)
            .map(|a| a.config.clone())
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

    /// Returns interrupt routes which cannot survive removal of `apic_id`.
    ///
    /// MSI/MSI-X and I/O APIC programming are device-visible state. Until a
    /// route-specific reprogramming operation exists, changing only the cached
    /// `InterruptConfig` would leave hardware targeting the parked CPU.
    pub(crate) fn cpu_offline_blockers(
        &self,
        apic_id: crate::cpu::ApicId,
    ) -> alloc::sync::Arc<[crate::cpu::CpuBlocker]> {
        let _route_allocation = self.route_allocation_gate.lock();
        self.allocations
            .read()
            .values()
            .filter(|allocation| allocation.config.target_apic_id == apic_id)
            .map(|allocation| crate::cpu::CpuBlocker::IrqRoute {
                vector: allocation.vector,
            })
            .collect::<Vec<_>>()
            .into()
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

pub(crate) fn cpu_offline_blockers(
    apic_id: crate::cpu::ApicId,
) -> alloc::sync::Arc<[crate::cpu::CpuBlocker]> {
    INTERRUPT_MANAGER.cpu_offline_blockers(apic_id)
}

/// MSIベクタを割り当て
pub fn allocate_msi(
    device_bdf: u32,
    handler_name: &str,
    target_cpu: crate::cpu::CpuId,
) -> Result<VectorAllocation, InterruptError> {
    INTERRUPT_MANAGER.allocate_msi_vector(
        device_bdf,
        alloc::string::ToString::to_string(handler_name),
        target_cpu,
    )
}

/// MSI-Xベクタを割り当て
pub fn allocate_msix(
    device_bdf: u32,
    count: u16,
    handler_name: &str,
    target_cpu: crate::cpu::CpuId,
) -> Result<Vec<VectorAllocation>, InterruptError> {
    INTERRUPT_MANAGER.allocate_msix_vectors(
        device_bdf,
        count,
        alloc::string::ToString::to_string(handler_name),
        target_cpu,
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
    let entry = config.ioapic_entry()?;
    crate::drivers::apic::io_apics()
        .map_err(InterruptError::IoApic)?
        .write_gsi(gsi, entry)
        .map_err(InterruptError::IoApic)
}

/// Local APICにEOIを送信
///
/// 割り込みハンドラの最後で呼び出してください
#[inline]
pub fn send_eoi() {
    crate::cpu::send_eoi_current_cpu()
        .unwrap_or_else(|error| panic!("local APIC EOI failed: {error:?}"));
}

/// 現在のCPUのAPIC IDを取得
pub fn current_apic_id() -> Result<crate::cpu::ApicId, InterruptError> {
    crate::cpu::current_apic_id().map_err(|error| match error {
        crate::cpu::CpuIpiError::LocalApic(error) => InterruptError::LocalApic(error),
        crate::cpu::CpuIpiError::CpuNotPresent(cpu) => InterruptError::CpuNotOnline(cpu),
        crate::cpu::CpuIpiError::CpuStateIneligible { cpu_id, .. } => {
            InterruptError::CpuNotOnline(cpu_id)
        }
    })
}

fn online_apic_id(cpu_id: crate::cpu::CpuId) -> Result<crate::cpu::ApicId, InterruptError> {
    let snapshot = crate::cpu::snapshot();
    let slot = snapshot
        .slot(cpu_id)
        .ok_or(InterruptError::CpuNotOnline(cpu_id))?;
    if !slot.state.is_schedulable() {
        return Err(InterruptError::CpuNotOnline(cpu_id));
    }
    Ok(slot.firmware.apic_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn direct_config(destination: u32) -> InterruptConfig {
        InterruptConfig {
            vector: 0x60,
            target_apic_id: crate::cpu::ApicId::new(destination),
            delivery_mode: DeliveryMode::Fixed,
            trigger_mode: TriggerMode::Edge,
            polarity: Polarity::ActiveHigh,
            masked: false,
            ir_handle: None,
        }
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn direct_msi_rejects_destination_wider_than_xapic() {
        assert_eq!(
            direct_config(0xff).msi_address(),
            Ok(0xfee0_0000 | (0xff << 12))
        );
        assert_eq!(
            direct_config(0x100).msi_address(),
            Err(InterruptError::DestinationRequiresInterruptRemapping(
                crate::cpu::ApicId::new(0x100)
            ))
        );
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn cpu_offline_reports_each_hardware_route_to_the_target_apic() {
        let manager = InterruptManager::new();
        let target = crate::cpu::ApicId::new(7);
        manager.allocations.write().insert(
            0x60,
            InterruptAllocation {
                vector: 0x60,
                source: InterruptSourceType::Msi { device_bdf: 0 },
                config: direct_config(target.as_u32()),
                handler_name: String::from("test route"),
            },
        );

        assert_eq!(
            manager.cpu_offline_blockers(target).as_ref(),
            [crate::cpu::CpuBlocker::IrqRoute { vector: 0x60 }]
        );
        assert!(
            manager
                .cpu_offline_blockers(crate::cpu::ApicId::new(8))
                .is_empty()
        );
    }
}
