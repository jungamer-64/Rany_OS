// ============================================================================
// kernel/src/io/iommu/vendors/intel/controller/qi_init.rs
// ============================================================================

//! Queued Invalidation Initialization Methods
//!
//! This module contains QI initialization and control methods for `IommuController` via `QIManager` trait.

use core::sync::atomic::Ordering;

use super::IommuController;
use super::init::CapabilityManager;
use super::utils::IommuUtils;
use crate::io::iommu::types::IommuError;
use crate::io::iommu::vendors::intel::qi::InvalidationQueue;
use crate::io::iommu::vendors::intel::registers::{gcmd_bits, gsts_bits};

pub trait QIManager {
    /// Initialize the Invalidation Queue
    fn init_queued_invalidation(&self, size_log2: u8) -> Result<(), IommuError>;
    /// Enable Queued Invalidation
    unsafe fn enable_queued_invalidation(&self) -> Result<(), IommuError>;
    /// Enable Invalidation Completion Interrupts
    fn enable_queued_invalidation_interrupt(&self, vector: u8, destination: u8);
}

impl QIManager for IommuController {
    fn init_queued_invalidation(&self, size_log2: u8) -> Result<(), IommuError> {
        if !self.supports_queued_invalidation() {
            return Err(IommuError::NotSupported);
        }
        let mut queue = self
            .invalidation_queue
            .lock()
            .map_err(|_| IommuError::Poisoned)?;
        if queue.is_some() {
            return Err(IommuError::AlreadyInitialized);
        }
        let iq = InvalidationQueue::new(size_log2)?;
        let iqa_value = iq.base_address() | (iq.size_log2() as u64 & 7);
        // Install the owner before publishing the pointer. The read-only IQH
        // register is never written by software.
        *queue = Some(iq);
        self.registers.queue_address().write(iqa_value);
        // Set queue tail to 0
        #[cfg(test)]
        log::info!("[test][IOMMU] writing IQT=0");
        self.registers.queue_tail().write(0);
        #[cfg(test)]
        log::info!("[test][IOMMU] wrote IQT=0");

        Ok(())
    }

    unsafe fn enable_queued_invalidation(&self) -> Result<(), IommuError> {
        let _control = self.controls.lock().map_err(|_| IommuError::Poisoned)?;
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

        // Enable QI (GCMD.QIE) while preserving already-enabled bits.
        self.write_gcmd_with_state(gcmd_bits::GCMD_QIE);

        // Wait for completion
        match self.wait_for_condition(
            || (self.registers.global_status().read() & gsts_bits::GSTS_QIES) != 0,
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

    /// Enable Invalidation Completion Interrupts
    ///
    /// # Arguments
    /// * `vector` - IDT vector to use for invalidation completion interrupts
    fn enable_queued_invalidation_interrupt(&self, vector: u8, destination: u8) {
        // 1. Configure Invalidation Event Data (IED)
        let ie_data: u32 = vector as u32;
        self.registers.invalidation_data().write(ie_data);

        // 2. Configure Invalidation Event Address (IEADDR)
        // Standard MSI target address for Local APIC
        let ie_addr = 0xFEE0_0000 | (u32::from(destination) << 12);
        self.registers.invalidation_address().write(ie_addr);

        // 3. Configure Invalidation Event Upper Address (IEUADDR)
        self.registers.invalidation_upper_address().write(0);

        // 4. Unmask Invalidation Completion Interrupts in IECTL
        // Clear IM bit (31) to unmask
        let iectl = self.registers.invalidation_control().read();
        self.registers
            .invalidation_control()
            .write(iectl & !0x8000_0000);
        log::info!(
            "[IOMMU] Invalidation Completion Interrupts enabled (Vector: {:#x})",
            vector
        );
    }
}
