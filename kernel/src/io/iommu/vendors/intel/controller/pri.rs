// ============================================================================
// kernel/src/io/iommu/vendors/intel/controller/pri.rs
// ============================================================================

//! Page Request Interface (PRI) Methods
//!
//! This module contains Page Request Interface methods for `IommuController` via `PageRequestManager` trait.

use alloc::vec::Vec;

use super::IommuController;
use super::init::CapabilityManager;
use super::qi_ops::InvalidationOps;
use super::utils::IommuUtils;
use crate::io::iommu::types::IommuError;
use crate::io::iommu::vendors::intel::qi::InvalidationQueueEntry;
use crate::io::iommu::vendors::intel::registers::regs;
use crate::io::iommu::vendors::shared::{PageRequestEntry, PageRequestQueue};

pub trait PageRequestManager: InvalidationOps {
    /// Initialize the Page Request Queue
    fn init_page_request(&mut self, size: usize) -> Result<(), IommuError>;

    /// Process pending page requests (drains all)
    fn process_page_requests(&mut self) -> Vec<PageRequestEntry>;

    /// Process up to `fuel` page requests, returning (entries, has_more).
    fn process_page_requests_with_fuel(&mut self, fuel: usize) -> (Vec<PageRequestEntry>, bool);

    /// Send a Page Response via Queued Invalidation
    fn send_page_response(
        &mut self,
        source_id: u16,
        pasid: Option<u32>,
        prg_index: u16,
        response_code: u8,
    ) -> Result<(), IommuError>;
}

impl PageRequestManager for IommuController {
    fn init_page_request(&mut self, size: usize) -> Result<(), IommuError> {
        if !self.supports_page_request() {
            return Err(IommuError::NotSupported);
        }

        // Check for existing PRQ
        let guard = match self.page_request_queue.lock() {
            Ok(g) => {
                #[cfg(test)]
                log::info!("[test][IOMMU] page_request_queue.lock() succeeded (not poisoned)");
                g
            }
            Err(poisoned) => {
                log::warn!("[IOMMU] page_request_queue lock poisoned during init_page_request");
                drop(poisoned.into_inner());
                self.page_request_queue
                    .lock_for_init("[IOMMU] page_request_queue init")
            }
        };
        if guard.is_some() {
            return Err(IommuError::AlreadyInitialized);
        }

        drop(guard);

        let prq = PageRequestQueue::new(size).ok_or(IommuError::HardwareError)?;

        // Set PRQ base address register (PQA)
        // Format: [11:0] = Size (log2 - 1), [63:12] = Base Address
        let size_log2 = (prq.size().trailing_zeros()) as u64;
        let pqa_value = prq.base_address() | (size_log2.saturating_sub(1) & 0xF);

        self.write64(regs::PQA, pqa_value);

        // Set PRQ Head to 0
        self.write64(regs::PQH, 0);

        // Enable Page Request via GCMD.PRE (bit 28)
        let gcmd = self.read32(regs::GCMD);
        self.write32(regs::GCMD, gcmd | (1 << 28));

        // Wait for PRS (Page Request Status) bit
        self.wait_for_condition(|| (self.read32(regs::GSTS) & (1 << 28)) != 0, 10_000, false)?;

        let mut guard = self
            .page_request_queue
            .lock_for_init("[IOMMU] page_request_queue init");
        *guard = Some(prq);
        log::info!(
            "[IOMMU] Page Request Queue initialized ({} entries)\n",
            size
        );

        Ok(())
    }

    fn process_page_requests(&mut self) -> Vec<PageRequestEntry> {
        let mut requests = Vec::new();

        // Read current tail first (avoid borrowing `self` mutably while also borrowing it immutably)
        let tail = (self.read64(regs::PQT) >> 4) as usize;

        // Acquire mutable access to PRQ if initialized
        match self.page_request_queue.lock() {
            Ok(mut prq_guard) => {
                if let Some(prq) = prq_guard.as_mut() {
                    prq.update_tail(tail);

                    // Pop all pending entries
                    // LOOP_PROOF: mode=condition; reason=PRQ pop loop drains pending requests and exits when queue pop returns None.;
                    while let Some(entry) = prq.pop() {
                        requests.push(entry);
                    }

                    // Cache head and drop the mutable borrow before writing registers
                    let head = prq.head();
                    // End borrow explicitly
                    let _ = prq;
                    self.write64(regs::PQH, head as u64);
                }
            }
            Err(_) => {
                log::error!(
                    "[IOMMU] page_request_queue lock poisoned while processing requests - cannot process"
                );
                return requests;
            }
        }

        requests
    }

    fn process_page_requests_with_fuel(&mut self, fuel: usize) -> (Vec<PageRequestEntry>, bool) {
        let mut requests = Vec::new();
        let mut has_more = false;

        let tail = (self.read64(regs::PQT) >> 4) as usize;

        match self.page_request_queue.lock() {
            Ok(mut prq_guard) => {
                if let Some(prq) = prq_guard.as_mut() {
                    prq.update_tail(tail);

                    for _ in 0..fuel {
                        match prq.pop() {
                            Some(entry) => requests.push(entry),
                            None => break,
                        }
                    }

                    // Check if there are more entries remaining
                    has_more = prq.has_pending();

                    let head = prq.head();
                    let _ = prq;
                    self.write64(regs::PQH, head as u64);
                }
            }
            Err(_) => {
                log::error!(
                    "[IOMMU] page_request_queue lock poisoned during fuel-based processing"
                );
            }
        }

        (requests, has_more)
    }

    fn send_page_response(
        &mut self,
        source_id: u16,
        pasid: Option<u32>,
        prg_index: u16,
        response_code: u8,
    ) -> Result<(), IommuError> {
        if !self.is_queued_invalidation_enabled() {
            return Err(IommuError::NotSupported);
        }

        // Page Group Response descriptor (VT-d Spec §6.5.2.9)
        let desc =
            InvalidationQueueEntry::page_group_response(source_id, pasid, prg_index, response_code);

        log::trace!(
            "[IOMMU] Page Response: source_id={:04x} pasid={:?} prg={} code={}\n",
            source_id,
            pasid,
            prg_index,
            response_code
        );

        // Submit response and wait for completion
        self.submit_invalidation(desc)?;
        self.qi_wait_sync()
    }
}
