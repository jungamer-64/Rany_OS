// ============================================================================
// kernel/src/io/iommu/runtime/fault_log.rs
// ============================================================================

//! Fault Log - Ring buffer for storing fault records
//!
//! Fixed-size buffer to ensure ISR safety (no allocations).

/// Fault Record (16 bytes)
///
/// Hardware fault record format from the Fault Recording Registers.
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default)]
pub struct FaultRecord {
    /// Fault info, including the faulted page address (bits 63:12).
    pub lo: u64,
    /// Intel FRCD bits 127:64, including F, PASID, reason and requester ID.
    pub hi: u64,
}

impl FaultRecord {
    /// Fault reason occupies bits 103:96 of FRCD.
    pub const REASON_MASK: u64 = 0xff << 32;
    pub const REASON_SHIFT: u64 = 32;
    /// PASID occupies bits 123:104, interpreted only when PP is set.
    pub const PASID_MASK: u64 = 0xfffff << 40;
    pub const PASID_SHIFT: u64 = 40;
    pub const PASID_PRESENT: u64 = 1 << 31;
    /// Requester ID occupies bits 79:64.
    pub const SID_MASK: u64 = 0xffff;
    pub const SID_SHIFT: u64 = 0;
    /// Fault publication/completion acknowledgement bit 127 (high word bit 63).
    pub const FAULT: u64 = 1 << 63;
    pub const ADDR_MASK: u64 = !0xfff;

    pub fn reason(&self) -> u8 {
        ((self.hi & Self::REASON_MASK) >> Self::REASON_SHIFT) as u8
    }
    pub fn source_id(&self) -> u16 {
        (self.hi & Self::SID_MASK) as u16
    }
    pub fn fault_address(&self) -> u64 {
        self.lo & Self::ADDR_MASK
    }
    pub fn pasid(&self) -> Option<u32> {
        (self.hi & Self::PASID_PRESENT != 0)
            .then_some(((self.hi & Self::PASID_MASK) >> Self::PASID_SHIFT) as u32)
    }
    pub fn is_valid(&self) -> bool {
        self.hi & Self::FAULT != 0
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
}

impl Default for FaultLog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(feature = "std", test)]
    #[cfg_attr(not(feature = "std"), test_case)]
    fn decodes_independent_intel_fault_register_vector() {
        // FRCD[127:64]: F=1, PV=0xabcde, FR=0x42, PP=1, SID=0x1234.
        let record = FaultRecord {
            lo: 0x1234_5678_9abc_d000,
            hi: 0x8abc_de42_8000_1234,
        };
        assert!(record.is_valid());
        assert_eq!(record.reason(), 0x42);
        assert_eq!(record.source_id(), 0x1234);
        assert_eq!(record.fault_address(), 0x1234_5678_9abc_d000);
        assert_eq!(record.pasid(), Some(0xabcde));
        let absent = FaultRecord {
            lo: u64::MAX,
            hi: 0x0abc_de42_0000_1234,
        };
        assert!(!absent.is_valid());
        assert_eq!(absent.pasid(), None);
    }
}
