// ============================================================================
// kernel/src/io/iommu/intel/controller/pi.rs
// ============================================================================

//! Posted Interrupts Methods
//!
//! This module contains Posted Interrupt methods for `IommuController` via `PostedInterruptManager` trait.

use core::sync::atomic::Ordering;

use super::IommuController;
use super::init::CapabilityManager;
use super::ir::{InterruptRemapEntry, InterruptRemapper};
use crate::io::iommu::common::{PostedInterruptDescriptor, PostedInterruptPool};
use crate::io::iommu::types::IommuError;

pub trait PostedInterruptManager {
    /// Initialize the Posted Interrupt Descriptor pool
    fn init_posted_interrupts(&mut self, num_pids: usize) -> Result<(), IommuError>;

    /// Allocate a Posted Interrupt Descriptor and configure an IRTE in posted mode
    fn allocate_posted_irte(
        &mut self,
        notification_vector: u8,
        notification_dest: u32,
    ) -> Result<(u16, u16), IommuError>;

    /// Free a Posted Interrupt Descriptor and its IRTE
    fn free_posted_irte(&self, irte_index: u16, pid_index: u16) -> Result<(), IommuError>;

    /// Set a pending vector in a Posted Interrupt Descriptor
    fn post_interrupt(&mut self, pid_index: u16, vector: u8) -> Result<(), IommuError>;
}

impl PostedInterruptManager for IommuController {
    fn init_posted_interrupts(&mut self, num_pids: usize) -> Result<(), IommuError> {
        if !self.supports_posted_interrupts() {
            return Err(IommuError::NotSupported);
        }

        // Check if PID pool already initialized
        let guard = match self.pid_pool.lock() {
            Ok(g) => {
                #[cfg(test)]
                eprintln!("[test][IOMMU] pid_pool.lock() succeeded (not poisoned)");
                g
            }
            Err(poisoned) => {
                log::warn!("[IOMMU] pid_pool lock poisoned during init_posted_interrupts");
                drop(poisoned.into_inner());
                self.pid_pool.lock_for_init("[IOMMU] pid_pool init")
            }
        };
        if guard.is_some() {
            return Err(IommuError::AlreadyInitialized);
        }

        drop(guard);

        let pool = PostedInterruptPool::new(num_pids).ok_or(IommuError::HardwareError)?;
        let mut guard = self.pid_pool.lock_for_init("[IOMMU] pid_pool init");
        *guard = Some(pool);

        log::info!(
            "[IOMMU] Posted Interrupt pool initialized ({} PIDs)\n",
            num_pids
        );
        Ok(())
    }

    fn allocate_posted_irte(
        &mut self,
        notification_vector: u8,
        notification_dest: u32,
    ) -> Result<(u16, u16), IommuError> {
        // Check PI support and initialization
        if !self.supports_posted_interrupts() {
            return Err(IommuError::NotSupported);
        }

        let mut pid_guard = self
            .pid_pool
            .lock()
            .map_err(|_| IommuError::HardwareError)?;
        let pid_pool = pid_guard.as_mut().ok_or(IommuError::NotPresent)?;

        let mut irt_guard = self
            .interrupt_remap_table
            .lock()
            .map_err(|_| IommuError::HardwareError)?;
        let irt = irt_guard.as_mut().ok_or(IommuError::NotPresent)?;

        // Allocate a PID
        let (pid_index, pid_addr) = pid_pool.allocate().ok_or(IommuError::HardwareError)?;

        // Configure the PID with notification info
        if let Some(pid) = pid_pool.get_mut(pid_index) {
            // Set notification vector and destination
            let nv = (notification_vector as u64) << 16;
            let ndst = (notification_dest as u64) << 32;
            pid.notification_info.store(nv | ndst, Ordering::SeqCst);
        }

        // Allocate an IRTE
        let irte_index = irt.allocate().ok_or(IommuError::HardwareError)?;

        // Configure IRTE for posted mode
        let entry = InterruptRemapEntry::posted(pid_addr);
        irt.set(irte_index, entry);

        Ok((irte_index, pid_index))
    }

    fn free_posted_irte(&self, irte_index: u16, pid_index: u16) -> Result<(), IommuError> {
        // Free IRTE (best-effort)
        match self.interrupt_remap_table.lock() {
            Ok(mut guard) => {
                if let Some(irt) = guard.as_mut() {
                    irt.set(irte_index, InterruptRemapEntry::new());
                    irt.free(irte_index);
                }
            }
            Err(poisoned) => {
                log::warn!(
                    "[IOMMU] interrupt_remap_table lock poisoned while freeing IRTE {}",
                    irte_index
                );
                let mut guard = poisoned.into_inner();
                if let Some(irt) = guard.as_mut() {
                    irt.set(irte_index, InterruptRemapEntry::new());
                    irt.free(irte_index);
                }
            }
        }

        // Free PID (best-effort)
        match self.pid_pool.lock() {
            Ok(mut guard) => {
                if let Some(pool) = guard.as_mut() {
                    pool.free(pid_index);
                }
            }
            Err(poisoned) => {
                log::warn!(
                    "[IOMMU] pid_pool lock poisoned while freeing PID {}",
                    pid_index
                );
                let mut guard = poisoned.into_inner();
                if let Some(pool) = guard.as_mut() {
                    pool.free(pid_index);
                }
            }
        }

        Ok(())
    }

    fn post_interrupt(&mut self, pid_index: u16, vector: u8) -> Result<(), IommuError> {
        let mut guard = self
            .pid_pool
            .lock()
            .map_err(|_| IommuError::HardwareError)?;
        let pool = guard.as_mut().ok_or(IommuError::NotPresent)?;
        let pid = pool.get_mut(pid_index).ok_or(IommuError::InvalidAddress)?;

        // Set the vector bit in PIR (Posted Interrupt Request)
        let word_idx = (vector / 64) as usize;
        let bit = (vector % 64) as u64;
        pid.pir[word_idx] |= 1 << bit;

        // Set Outstanding Notification bit
        pid.notification_info
            .fetch_or(PostedInterruptDescriptor::ON, Ordering::SeqCst);

        Ok(())
    }
}
