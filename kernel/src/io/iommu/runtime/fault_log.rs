// ============================================================================
// kernel/src/io/iommu/runtime/fault_log.rs
// ============================================================================

//! Fault Log - Ring buffer for storing fault records
//!
//! Fixed-size buffer to ensure ISR safety (no allocations).

use alloc::vec::Vec;

/// Fault Record (16 bytes)
///
/// Hardware fault record format from the Fault Recording Registers.
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default)]
pub struct FaultRecord {
    /// Lower 64 bits (Source ID, Fault Reason, etc.)
    pub lo: u64,
    /// Upper 64 bits (Fault Address)
    pub hi: u64,
}

impl FaultRecord {
    /// Fault reason mask (bits 0-7 of lo)
    pub const REASON_MASK: u64 = 0xFF;
    /// PASID value mask (bits 8-27 of lo)
    pub const PASID_MASK: u64 = 0xFFFFF00;
    pub const PASID_SHIFT: u64 = 8;
    /// PASID present (bit 28 of lo)
    pub const PASID_PRESENT: u64 = 1 << 28;
    /// Execute request (bit 29 of lo)
    pub const ERQ: u64 = 1 << 29;
    /// Privilege mode requested (bit 30 of lo)
    pub const PRIV: u64 = 1 << 30;
    /// Supervisor request (bit 31 of lo)
    pub const SUPERV: u64 = 1 << 31;
    /// Source ID mask (bits 32-47 of lo)
    pub const SID_MASK: u64 = 0xFFFF_0000_0000;
    pub const SID_SHIFT: u64 = 32;
    /// Type (bits 48-49 of lo)
    pub const TYPE_MASK: u64 = 0x3_0000_0000_0000;
    pub const TYPE_SHIFT: u64 = 48;
    /// Fault (bit 63 of lo)
    pub const FAULT: u64 = 1 << 63;
    /// Fault address mask (bits 12-63 of hi)
    pub const ADDR_MASK: u64 = !0xFFF;

    /// Get fault reason code
    pub fn reason(&self) -> u8 {
        (self.lo & Self::REASON_MASK) as u8
    }

    /// Get source ID (BDF)
    pub fn source_id(&self) -> u16 {
        ((self.lo & Self::SID_MASK) >> Self::SID_SHIFT) as u16
    }

    /// Get fault address
    pub fn fault_address(&self) -> u64 {
        self.hi & Self::ADDR_MASK
    }

    /// Get PASID (if present)
    pub fn pasid(&self) -> Option<u32> {
        if self.lo & Self::PASID_PRESENT != 0 {
            Some(((self.lo & Self::PASID_MASK) >> Self::PASID_SHIFT) as u32)
        } else {
            None
        }
    }

    /// Check if this is a valid fault record
    pub fn is_valid(&self) -> bool {
        self.lo & Self::FAULT != 0
    }

    /// Clear the fault bit
    pub fn clear(&mut self) {
        self.lo &= !Self::FAULT;
    }
}

/// Fault Log - Ring buffer for storing fault records
pub const FAULT_LOG_SIZE: usize = 256;

#[derive(Debug)]
pub struct FaultLog {
    /// Ring buffer of fault records
    records: [FaultRecord; FAULT_LOG_SIZE],
    /// Write index (next slot to write)
    write_idx: usize,
    /// Number of records stored
    count: usize,
    /// Total faults recorded (may exceed capacity)
    total_faults: u64,
}

impl FaultLog {
    /// Create a new fault log
    pub fn new() -> Self {
        Self {
            records: [FaultRecord::default(); FAULT_LOG_SIZE],
            write_idx: 0,
            count: 0,
            total_faults: 0,
        }
    }

    /// Add a fault record
    pub fn push(&mut self, record: FaultRecord) {
        self.records[self.write_idx] = record;
        self.write_idx = (self.write_idx + 1) % FAULT_LOG_SIZE;
        self.total_faults += 1;
        if self.count < FAULT_LOG_SIZE {
            self.count += 1;
        }
    }

    /// Get the most recent fault records (up to count entries)
    pub fn recent(&self, max_count: usize) -> Vec<FaultRecord> {
        let n = max_count.min(self.count);
        let mut result = Vec::with_capacity(n);

        for i in 0..n {
            let idx = if self.write_idx >= i + 1 {
                self.write_idx - i - 1
            } else {
                FAULT_LOG_SIZE - (i + 1 - self.write_idx)
            };
            result.push(self.records[idx]);
        }

        result
    }

    /// Get total number of faults recorded
    pub fn total_count(&self) -> u64 {
        self.total_faults
    }

    /// Get current number of records in buffer
    pub fn len(&self) -> usize {
        self.count
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for FaultLog {
    fn default() -> Self {
        Self::new()
    }
}
