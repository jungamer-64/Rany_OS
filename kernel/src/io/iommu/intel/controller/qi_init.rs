// ============================================================================
// kernel/src/io/iommu/intel/controller/qi_init.rs
// ============================================================================

//! Queued Invalidation Initialization Methods
//!
//! This module contains QI initialization and control methods for `IommuController` via `QIManager` trait.

use core::sync::atomic::Ordering;

use super::IommuController;
use super::init::CapabilityManager;
use super::utils::IommuUtils;
use crate::io::iommu::types::IommuError;
use crate::io::iommu::intel::qi::InvalidationQueue;
use crate::io::iommu::intel::registers::{gcmd_bits, gsts_bits, regs};

pub trait QIManager {
    /// Initialize the Invalidation Queue
    fn init_queued_invalidation(&mut self, size_log2: u8) -> Result<(), IommuError>;
    /// Enable Queued Invalidation
    unsafe fn enable_queued_invalidation(&self) -> Result<(), IommuError>;
    /// Disable Queued Invalidation
    unsafe fn disable_queued_invalidation(&self) -> Result<(), IommuError>;
}

impl QIManager for IommuController {
    fn init_queued_invalidation(&mut self, size_log2: u8) -> Result<(), IommuError> {
        #[cfg(test)]
        log::info!(
            "[test][IOMMU] init_queued_invalidation enter: size_log2={}",
            size_log2
        );

        if !self.supports_queued_invalidation() {
            #[cfg(test)]
            log::info!("[test][IOMMU] QI not supported");
            return Err(IommuError::NotSupported);
        }

        #[cfg(test)]
        log::info!(
            "[test][IOMMU] invalidation_queue.is_locked() before lock = {}",
            self.invalidation_queue.is_locked()
        );

        let guard = match self.invalidation_queue.lock() {
            Ok(g) => {
                #[cfg(test)]
                log::info!("[test][IOMMU] invalidation_queue.lock() succeeded (not poisoned)");
                g
            }
            Err(poisoned) => {
                log::warn!(
                    "[IOMMU] invalidation_queue lock poisoned during init_queued_invalidation"
                );
                // Recovery: Drop inner guard
                drop(poisoned.into_inner());
                self.invalidation_queue
                    .lock_for_init("[IOMMU] invalidation_queue init")
            }
        };
        if guard.is_some() {
            #[cfg(test)]
            log::info!("[test][IOMMU] invalidation_queue already initialized");
            return Err(IommuError::AlreadyInitialized);
        }

        drop(guard);

        #[cfg(test)]
        log::info!(
            "[test][IOMMU] calling InvalidationQueue::new(size_log2={})",
            size_log2
        );

        let iq = InvalidationQueue::new(size_log2).ok_or(IommuError::HardwareError)?;

        #[cfg(test)]
        log::info!(
            "[test][IOMMU] InvalidationQueue::new returned: base=0x{:x} size={} entries",
            iq.base_address(),
            iq.size_log2()
        );

        // Set Invalidation Queue Address (IQA register)
        // Bits 2:0 = queue size (log2 - 8), bits 11:0 reserved
        let iqa_value = (iq.base_address() as u64) | (iq.size_log2() as u64 & 0x7);
        #[cfg(test)]
        log::info!("[test][IOMMU] writing IQA=0x{:x}", iqa_value);

        if let Some(ref cq) = self.command_queue {
            let _ =
                cq.submit_sync(crate::io::iommu::cmdqueue::IommuCommandKind::InvalidateIotlbGlobal);
        } else {
            self.write64(regs::IQA, iqa_value);
        }
        #[cfg(test)]
        log::info!("[test][IOMMU] wrote IQA");

        // Set queue head to 0
        #[cfg(test)]
        log::info!("[test][IOMMU] writing IQH=0");
        if let Some(ref cq) = self.command_queue {
            let _ =
                cq.submit_sync(crate::io::iommu::cmdqueue::IommuCommandKind::InvalidateIotlbGlobal);
        } else {
            self.write64(regs::IQH, 0);
        }
        #[cfg(test)]
        log::info!("[test][IOMMU] wrote IQH=0");

        // Set queue tail to 0
        #[cfg(test)]
        log::info!("[test][IOMMU] writing IQT=0");
        if let Some(ref cq) = self.command_queue {
            let _ =
                cq.submit_sync(crate::io::iommu::cmdqueue::IommuCommandKind::InvalidateIotlbGlobal);
        } else {
            self.write64(regs::IQT, 0);
        }
        #[cfg(test)]
        log::info!("[test][IOMMU] wrote IQT=0");

        let mut guard = self
            .invalidation_queue
            .lock_for_init("[IOMMU] invalidation_queue init");
        #[cfg(test)]
        log::info!("[test][IOMMU] acquired lock_for_init for finalizing");
        *guard = Some(iq);
        #[cfg(test)]
        log::info!("[test][IOMMU] stored InvalidationQueue; finalizing");
        log::info!(
            "[IOMMU] Invalidation Queue initialized ({} entries)\n",
            1 << size_log2
        );

        #[cfg(test)]
        log::info!("[test][IOMMU] init_queued_invalidation completed");

        if let Some(ref cq) = self.command_queue {
            let _ = cq.process_once(|_k| Ok(0));
        }

        Ok(())
    }

    unsafe fn enable_queued_invalidation(&self) -> Result<(), IommuError> {
        match self.invalidation_queue.lock() {
            Ok(guard) => {
                if guard.is_none() {
                    return Err(IommuError::NotPresent);
                }
            }
            Err(_) => {
                log::error!(
                    "[IOMMU] invalidation_queue lock poisoned while enabling QI - cannot enable QI"
                );
                return Err(IommuError::HardwareError);
            }
        }

        // Enable QI (GCMD.QIE)
        self.write32(regs::GCMD, gcmd_bits::GCMD_QIE);

        // Wait for completion
        match self.wait_for_condition(
            || (self.read32(regs::GSTS) & gsts_bits::GSTS_QIES) != 0,
            10_000,
            false,
        ) {
            Ok(_) => {
                self.qi_enabled.store(true, Ordering::Release);
                log::info!("[IOMMU] Queued Invalidation enabled\\n");
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    unsafe fn disable_queued_invalidation(&self) -> Result<(), IommuError> {
        let gcmd = self.read32(regs::GCMD);
        self.write32(regs::GCMD, gcmd & !gcmd_bits::GCMD_QIE);

        match self.wait_for_condition(
            || (self.read32(regs::GSTS) & gsts_bits::GSTS_QIES) == 0,
            10_000,
            false,
        ) {
            Ok(_) => {
                self.qi_enabled.store(false, Ordering::Release);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}
