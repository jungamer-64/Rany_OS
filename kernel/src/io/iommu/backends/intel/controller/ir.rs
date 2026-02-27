// ============================================================================
// kernel/src/io/iommu/backends/intel/controller/ir.rs
// ============================================================================

//! Interrupt Remapping Methods
//!
//! This module contains interrupt remapping methods for `IommuController` via `InterruptRemapper` trait.

use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::IommuController;
use super::init::CapabilityManager;
use super::utils::IommuUtils;
use crate::io::iommu::types::IommuError;
use crate::io::iommu::backends::intel::registers::{ecap_bits, gcmd_bits, gsts_bits, regs};
use crate::io::iommu::core::tables::{HardwareTable, Zeroable};

/// Interrupt Remapping Entry (128-bit)
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default)]
pub struct InterruptRemapEntry {
    pub lo: u64,
    pub hi: u64,
}

impl InterruptRemapEntry {
    pub const fn new() -> Self {
        Self { lo: 0, hi: 0 }
    }

    pub fn fixed(
        vector: u8,
        dest_id: u32,
        logical: bool,
        sid: Option<u16>, // RID/BDF
    ) -> Self {
        // P=1 (bit 0)
        let mut lo = 1;
        // DM (bit 2)
        if logical {
            lo |= 1 << 2;
        }
        // Vector (bits 16-23)
        lo |= (vector as u64) << 16;
        // DestID (bits 32-63)
        lo |= (dest_id as u64) << 32;

        let mut hi = 0;
        if let Some(rid) = sid {
            // SVT=1 (Source Validation Type: Verify SID) - bits 64-65 of IRTE (bits 0-1 of hi)
            hi |= 1;
            // SQ=0 (Source-id Qualifier: Exact match) - bits 66-67 of IRTE (bits 2-3 of hi)
            // SID (Source ID) - bits 80-95 of IRTE (bits 16-31 of hi)
            hi |= (rid as u64) << 16;
        }

        Self { lo, hi }
    }

    pub fn posted(pid_addr: u64) -> Self {
        // P=1 (bit 0), IM=1 (bit 4)
        let lo = (pid_addr & !0xF) | (1 << 4) | 1;
        Self { lo, hi: 0 }
    }
}

// SAFETY: All-zeros is valid (not present)
unsafe impl Zeroable for InterruptRemapEntry {}

/// Interrupt Remapping Table
pub struct InterruptRemapTable {
    pub table: HardwareTable<InterruptRemapEntry>,
    bitmap: Vec<u64>,
}

impl InterruptRemapTable {
    pub fn new(size_log2: u8) -> Option<Self> {
        let count = 1usize << size_log2;
        // HardwareTable handles allocation and checks 4KB limit implies max 256 entries
        let table = HardwareTable::new(count, None).ok()?;
        // Allocation bitmap: 1 bit per entry
        let bitmap_len = (count + 63) / 64;
        Some(Self {
            table,
            bitmap: vec![0; bitmap_len],
        })
    }

    pub fn base_address(&self) -> u64 {
        self.table.phys_addr()
    }

    pub fn allocate(&mut self) -> Option<u16> {
        // Find first free bit
        for (i, &word) in self.bitmap.iter().enumerate() {
            if word != !0 {
                let trailing = (!word).trailing_zeros();
                let idx = i * 64 + trailing as usize;
                if idx < self.table.count() {
                    self.bitmap[i] |= 1 << trailing;
                    return Some(idx as u16);
                }
            }
        }
        None
    }

    pub fn free(&mut self, index: u16) {
        let idx = index as usize;
        let word_idx = idx / 64;
        let bit_idx = idx % 64;
        if word_idx < self.bitmap.len() {
            self.bitmap[word_idx] &= !(1 << bit_idx);
        }
    }

    pub fn set(&mut self, index: u16, entry: InterruptRemapEntry) -> bool {
        if let Some(e) = self.table.get_mut(index as usize) {
            *e = entry;
            true
        } else {
            false
        }
    }
}

/// Delivery Mode for Interrupts (VT-d spec)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryMode {
    Fixed = 0,
    LowestPriority = 1,
    SMI = 2,
    NMI = 4,
    INIT = 5,
    ExtINT = 7,
}

pub trait InterruptRemapper {
    /// Initialize the Interrupt Remapping Table
    fn init_interrupt_remapping(&mut self, size_log2: u8) -> Result<(), IommuError>;
    /// Enable interrupt remapping
    unsafe fn enable_interrupt_remapping(&self) -> Result<(), IommuError>;
    /// Disable interrupt remapping
    unsafe fn disable_interrupt_remapping(&self) -> Result<(), IommuError>;
    /// Check if interrupt remapping is enabled
    fn is_interrupt_remapping_enabled(&self) -> bool;
    /// Allocate an IRTE for a device interrupt
    fn allocate_irte(
        &self,
        segment: u16,
        bus: u8,
        device: u8,
        function: u8,
        vector: u8,
        dest_id: u32,
        logical: bool,
    ) -> Result<u16, IommuError>;
    /// Free an IRTE
    fn free_irte(&self, index: u16) -> Result<(), IommuError>;
    /// Update an existing IRTE
    fn update_irte(&mut self, index: u16, entry: InterruptRemapEntry) -> Result<(), IommuError>;
}

impl InterruptRemapper for IommuController {
    /// Initialize the Interrupt Remapping Table
    fn init_interrupt_remapping(&mut self, size_log2: u8) -> Result<(), IommuError> {
        #[cfg(test)]
        log::info!(
            "[test][IOMMU] init_interrupt_remapping enter: size_log2={}",
            size_log2
        );

        if !self.supports_interrupt_remapping() {
            return Err(IommuError::NotSupported);
        }

        #[cfg(test)]
        log::info!(
            "[test][IOMMU] interrupt_remap_table.is_locked() before lock = {}",
            self.interrupt_remap_table.is_locked()
        );

        let guard = match self.interrupt_remap_table.lock() {
            Ok(g) => {
                #[cfg(test)]
                log::info!("[test][IOMMU] interrupt_remap_table.lock() succeeded (not poisoned)");
                g
            }
            Err(poisoned) => {
                log::warn!(
                    "[IOMMU] interrupt_remap_table lock poisoned during init_interrupt_remapping"
                );
                // Recovery: Drop inner guard to release lock
                drop(poisoned.into_inner());
                self.interrupt_remap_table
                    .lock_for_init("[IOMMU] interrupt_remap_table init")
            }
        };
        if guard.is_some() {
            return Err(IommuError::AlreadyInitialized);
        }

        // Drop the initial guard here to avoid deadlocking when re-acquiring the lock later
        drop(guard);

        // Create the IRT
        let irt = InterruptRemapTable::new(size_log2).ok_or(IommuError::HardwareError)?;

        // Get IRTA register offset from ECAP
        let iro = ((self.ecap & ecap_bits::ECAP_IRO_MASK) >> 8) as u64;
        let irta_reg = self.mmio_base + (iro << 4);

        // Set Interrupt Remap Table Address
        // Bits 11:0 = size (log2 - 1), Bit 11 = Extended Interrupt Mode
        let eime = if (self.ecap & ecap_bits::ECAP_EIM) != 0 {
            1 << 11
        } else {
            0
        };
        let irta_value = (irt.base_address() as u64) | ((size_log2 as u64 - 1) & 0xF) | eime;

        crate::io::mmio::mmio_write_u64(irta_reg as usize, irta_value);

        // Set IRT pointer (GCMD.SIRTP) while preserving other enabled bits.
        self.write_gcmd_with_state(gcmd_bits::GCMD_SIRTP);

        // Wait for completion
        match self.wait_for_condition(
            || (self.read32(regs::GSTS) & gsts_bits::GSTS_IRTPS) != 0,
            10_000,
            false,
        ) {
            Ok(_) => {
                #[cfg(test)]
                log::info!("[test][IOMMU] GSTS.IRTPS set - continue");
            }
            Err(IommuError::Timeout) => {
                log::warn!(
                    "[IOMMU] interrupt_remap_table init: wait for SIRTP timed out - proceeding with best-effort"
                );
            }
            Err(e) => return Err(e),
        }

        let mut guard = self
            .interrupt_remap_table
            .lock_for_init("[IOMMU] interrupt_remap_table init");
        *guard = Some(irt);
        log::info!(
            "[IOMMU] Interrupt Remapping Table initialized ({} entries)",
            1 << size_log2
        );

        Ok(())
    }

    /// Enable interrupt remapping
    unsafe fn enable_interrupt_remapping(&self) -> Result<(), IommuError> {
        if !self.supports_interrupt_remapping() {
            return Err(IommuError::NotSupported);
        }

        let guard = match self.interrupt_remap_table.lock() {
            Ok(g) => g,
            Err(_) => {
                log::error!("[IOMMU] interrupt_remap_table lock poisoned while enabling IR");
                return Err(IommuError::HardwareError);
            }
        };

        if guard.is_none() {
            return Err(IommuError::NotPresent);
        }

        // Enable Interrupt Remapping (GCMD.IRE) while preserving other enabled bits.
        self.write_gcmd_with_state(gcmd_bits::GCMD_IRE);

        // Wait for completion
        match self.wait_for_condition(
            || (self.read32(regs::GSTS) & gsts_bits::GSTS_IRES) != 0,
            10_000,
            false,
        ) {
            Ok(_) => {
                self.ir_enabled.store(true, Ordering::Release);
                log::info!("[IOMMU] Interrupt Remapping enabled");
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Disable interrupt remapping
    unsafe fn disable_interrupt_remapping(&self) -> Result<(), IommuError> {
        let gcmd = self.read32(regs::GCMD);
        self.write32(regs::GCMD, gcmd & !gcmd_bits::GCMD_IRE);

        match self.wait_for_condition(
            || (self.read32(regs::GSTS) & gsts_bits::GSTS_IRES) == 0,
            10_000,
            false,
        ) {
            Ok(_) => {
                self.ir_enabled.store(false, Ordering::Release);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Check if interrupt remapping is enabled
    fn is_interrupt_remapping_enabled(&self) -> bool {
        self.ir_enabled.load(Ordering::Acquire)
    }

    /// Allocate an IRTE for a device interrupt
    fn allocate_irte(
        &self,
        _segment: u16,
        bus: u8,
        device: u8,
        function: u8,
        vector: u8,
        dest_id: u32,
        logical: bool,
    ) -> Result<u16, IommuError> {
        let mut guard = self
            .interrupt_remap_table
            .lock()
            .map_err(|_| IommuError::HardwareError)?;
        let irt = guard.as_mut().ok_or(IommuError::NotPresent)?;

        let index = irt.allocate().ok_or(IommuError::HardwareError)?;

        let rid = ((bus as u16) << 8) | ((device as u16) << 3) | (function as u16);
        let entry = InterruptRemapEntry::fixed(vector, dest_id, logical, Some(rid));
        irt.set(index, entry);

        // Security: Invalidate IEC after allocating IRTE to ensure hardware sees the new entry
        let _ = self.invalidate_iec(false, index);

        Ok(index)
    }

    /// Free an IRTE
    fn free_irte(&self, index: u16) -> Result<(), IommuError> {
        let mut guard = self
            .interrupt_remap_table
            .lock()
            .map_err(|_| IommuError::HardwareError)?;
        let irt = guard.as_mut().ok_or(IommuError::NotPresent)?;

        irt.set(index, InterruptRemapEntry::new());
        irt.free(index);

        // Security: Invalidate IEC after freeing IRTE to prevent stale interrupts
        let _ = self.invalidate_iec(false, index);

        Ok(())
    }

    /// Update an existing IRTE
    fn update_irte(&mut self, index: u16, entry: InterruptRemapEntry) -> Result<(), IommuError> {
        let mut guard = self
            .interrupt_remap_table
            .lock()
            .map_err(|_| IommuError::HardwareError)?;
        let irt = guard.as_mut().ok_or(IommuError::NotPresent)?;

        if !irt.set(index, entry) {
            return Err(IommuError::InvalidAddress);
        }

        // Security: Invalidate IEC after updating IRTE
        let _ = self.invalidate_iec(false, index);

        Ok(())
    }
}
