//! AHCI (Advanced Host Controller Interface) ドライバ
//!
//! SATAデバイスを制御するためのAHCIコントローラドライバ
//!
//! # モジュール構成
//!
//! - `types` - 型安全なID、定数、エラー型 (from ahci_driver)
//! - `fis` - FIS (Frame Information Structure) 関連 (from ahci_driver)
//! - `command` - コマンドヘッダ、PRD、コマンドテーブル (from ahci_driver)
//! - `identify` - ATA IDENTIFY データ構造体 (from ahci_driver)
//! - `port` - AHCIポート実装 (kernel local)
//! - `controller` - AHCIコントローラ実装 (kernel local)
//! - `poll_handler` - IoScheduler統合 (kernel local)
//! - `dma_buffer` - DMA安全バッファ (kernel local)

// Local modules (kernel implementation)
// pub mod controller; // Migrated to ahci_driver
pub mod dma_buffer;
pub mod poll_handler;
// pub mod port; // Migrated to ahci_driver

// Re-export modules from ahci_driver
pub use ahci_driver::command;
pub use ahci_driver::controller;
pub use ahci_driver::fis;
pub use ahci_driver::identify;
pub use ahci_driver::port;
pub use ahci_driver::types;

pub use crate::sync::PoisonLock;
pub use alloc::sync::Arc;

// Re-export types from ahci_driver for convenience
pub use command::{CommandHeader, CommandTable, PhysicalRegionDescriptor, ReceivedFis};
pub use fis::{
    ATA_CMD_FLUSH_CACHE, ATA_CMD_FLUSH_CACHE_EXT, ATA_CMD_IDENTIFY, ATA_CMD_READ_DMA_EXT,
    ATA_CMD_WRITE_DMA_EXT, FisRegH2D, FisType,
};
pub use identify::IdentifyData;
pub use types::{
    AhciError,
    AhciResult,
    DeviceType,
    // レジスタ定数
    GHC_AE,
    GHC_CAP,
    GHC_GHC,
    GHC_HR,
    GHC_IE,
    GHC_IS,
    GHC_PI,
    GHC_VS,
    Lba,
    PORT_BASE,
    PORT_SIZE,
    PX_CI,
    PX_CLB,
    PX_CLBU,
    PX_CMD,
    PX_CMD_CR,
    PX_CMD_FR,
    PX_CMD_FRE,
    PX_CMD_ST,
    PX_FB,
    PX_FBU,
    PX_IE,
    PX_IS,
    PX_IS_DHRS,
    PX_IS_DSS,
    PX_IS_PSS,
    PX_IS_SDBS,
    PX_IS_TFES,
    PX_SACT,
    PX_SCTL,
    PX_SERR,
    PX_SIG,
    PX_SSTS,
    PX_TFD,
    PortNumber,
    SECTOR_SIZE,
    SectorCount,
    SlotNumber,
};

// Re-export types from local modules
pub use controller::AhciController;
pub use dma_buffer::{AhciDmaReadBuffer, AhciDmaWriteBuffer, AhciIdentifyBuffer};
pub use poll_handler::{AhciPollHandler, register_ahci_with_io_scheduler};
pub use port::AhciPort;

pub fn init_from_pci(
    base_virt: u64,
    device_id: crate::io::iommu::types::DeviceId,
) -> AhciResult<Arc<PoisonLock<AhciController>>> {
    let packed_id = kernel_api::abi::driver::PackedPciLocation::new(
        device_id.segment,
        device_id.bus,
        device_id.device,
        device_id.function,
    );
    let controller = AhciController::new(base_virt, packed_id)?;
    let arc = Arc::new(PoisonLock::new(controller));
    Ok(arc)
}
