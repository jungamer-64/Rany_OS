// ============================================================================
// kernel/src/io/iommu/vendors/amd/invalidation.rs
// ============================================================================

//! AMD-Vi command state management and invalidation operations.

use alloc::vec::Vec;
use core::future::poll_fn;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::Poll;

use crate::io::iommu::types::{DeviceId, IommuError};

use super::cmd;
use super::fault::AMD_CMD_WAITERS;
use super::AmdIommuDriver;

// ---------------------------------------------------------------------------
// AmdCommandWaitToken
// ---------------------------------------------------------------------------

const AMD_CMD_WAIT_MAX_POLLS: u64 = 1_000_000;

pub(super) struct AmdCommandWaitToken {
    sync_ptr: NonNull<u64>,
    expected_seq: u64,
}

impl AmdCommandWaitToken {
    fn is_complete(&self) -> bool {
        // Commands complete in order; a newer sequence implies this one finished.
        (unsafe { self.sync_ptr.as_ptr().read_volatile() }) >= self.expected_seq
    }

    pub(super) fn wait_blocking(self) -> Result<(), IommuError> {
        let mut spins = 0u64;
        while !self.is_complete() {
            spins += 1;
            if spins > AMD_CMD_WAIT_MAX_POLLS {
                return Err(IommuError::Timeout);
            }
            core::hint::spin_loop();
        }
        Ok(())
    }

    pub(super) async fn wait_async(self) -> Result<(), IommuError> {
        #[cfg(test)]
        {
            let _ = self;
            return Ok(());
        }

        #[cfg(not(test))]
        {
            let mut polls = 0u64;
            let token = self;
            poll_fn(|cx| {
                if token.is_complete() {
                    return Poll::Ready(Ok(()));
                }
                polls += 1;
                if polls > AMD_CMD_WAIT_MAX_POLLS {
                    return Poll::Ready(Err(IommuError::Timeout));
                }
                AMD_CMD_WAITERS.register(cx.waker());
                if token.is_complete() {
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending
            })
            .await
        }
    }
}

// ---------------------------------------------------------------------------
// AmdCommandState
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub(crate) struct AmdCommandState {
    pub(super) buffer: cmd::AmdCommandBuffer,
    pub(super) sync_ptr: NonNull<u64>,
    pub(super) sync_phys: u64,
    pub(super) frame_count: usize,
    pub(super) seq: AtomicU64,
}

// SAFETY: `AmdCommandState` contains raw pointers to memory used for command buffer
// completion synchronization (`sync_ptr`). Access to this state is synchronized by
// PoisonLock wrappers when used in `cmd_states`, ensuring safe concurrent access.
unsafe impl Send for AmdCommandState {}
unsafe impl Sync for AmdCommandState {}

impl Drop for AmdCommandState {
    fn drop(&mut self) {
        // Security: Unregister from DMA protection
        crate::security::dma::unregister_protected_range(self.buffer.phys_base, (self.frame_count * 4096) as u64);
        crate::security::dma::unregister_protected_range(self.sync_phys, 4096);

        // Deallocate frames
        use x86_64::structures::paging::{PhysFrame, Size4KiB};
        unsafe {
            // Command buffer frames
            for i in 0..self.frame_count {
                let addr = self.buffer.phys_base + (i as u64 * 4096);
                let frame = PhysFrame::<Size4KiB>::containing_address(x86_64::PhysAddr::new(addr));
                crate::mm::phys::frame_allocator::dealloc_frame(frame);
            }
            // Sync page frame
            let frame = PhysFrame::<Size4KiB>::containing_address(x86_64::PhysAddr::new(self.sync_phys));
            crate::mm::phys::frame_allocator::dealloc_frame(frame);
        }
    }
}

impl AmdCommandState {
    pub(super) fn submit(&mut self, cmd: cmd::AmdCommand) -> Result<(), IommuError> {
        let _ = self.buffer.submit(cmd)?;
        Ok(())
    }

    pub(super) fn submit_and_wait_token(
        &mut self,
        cmd: cmd::AmdCommand,
        interrupt: bool,
    ) -> Result<AmdCommandWaitToken, IommuError> {
        let next_seq = self.seq.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        self.submit(cmd)?;
        self.submit(cmd::AmdCommand::completion_wait(
            self.sync_phys,
            next_seq,
            interrupt,
        ))?;
        Ok(AmdCommandWaitToken {
            sync_ptr: self.sync_ptr,
            expected_seq: next_seq,
        })
    }

    pub(super) fn submit_and_wait(&mut self, cmd: cmd::AmdCommand) -> Result<(), IommuError> {
        #[cfg(test)]
        {
            self.submit(cmd)?;
            return Ok(());
        }

        #[cfg(not(test))]
        {
            let token = self.submit_and_wait_token(cmd, false)?;
            token.wait_blocking()
        }
    }
}

// ---------------------------------------------------------------------------
// Invalidation methods on AmdIommuDriver
// ---------------------------------------------------------------------------

impl AmdIommuDriver {
    pub(super) fn find_unit_index_for_device(&self, device: DeviceId) -> Option<usize> {
        let devid = device.requester_id();
        self.units.iter().enumerate().find_map(|(idx, unit)| {
            if unit.segment == device.segment && unit.covers_devid(devid) {
                Some(idx)
            } else {
                None
            }
        })
    }

    pub(super) fn with_cmd_state<F, R>(&self, unit_idx: usize, f: F) -> Result<R, IommuError>
    where
        F: FnOnce(&mut AmdCommandState) -> Result<R, IommuError>,
    {
        let state = self
            .cmd_states
            .get(unit_idx)
            .and_then(|state| state.as_ref())
            .ok_or(IommuError::NotSupported)?;

        let mut guard = match state.lock() {
            Ok(guard) => guard,
            Err(_) => return Err(IommuError::Poisoned),
        };
        f(&mut *guard)
    }

    pub(super) async fn submit_cmd_async(
        &self,
        unit_idx: usize,
        cmd: cmd::AmdCommand,
    ) -> Result<(), IommuError> {
        let state = self
            .cmd_states
            .get(unit_idx)
            .and_then(|state| state.as_ref())
            .ok_or(IommuError::NotSupported)?;

        // Advance epoch before invalidation
        let epoch = self.iova_allocator.advance_epoch();

        let token = {
            let mut guard = match state.lock() {
                Ok(guard) => guard,
                Err(_) => return Err(IommuError::Poisoned),
            };
            guard.submit_and_wait_token(cmd, true)?
        };

        let res = token.wait_async().await;
        
        // Complete epoch after async invalidation finishes
        self.iova_allocator.complete_epoch(epoch);
        res
    }

    pub(super) fn invalidate_all_entries(&self) -> Result<(), IommuError> {
        let mut has_state = false;
        
        // Advance epoch before global invalidation
        let epoch = self.iova_allocator.advance_epoch();

        for idx in 0..self.cmd_states.len() {
            if self.cmd_states[idx].is_none() {
                continue;
            }
            has_state = true;
            self.with_cmd_state(idx, |state| {
                state.submit_and_wait(cmd::AmdCommand::invalidate_all())
            })?;
        }

        // Complete epoch after hardware confirmation
        self.iova_allocator.complete_epoch(epoch);

        if !has_state {
            return Err(IommuError::NotSupported);
        }
        Ok(())
    }

    pub(crate) fn invalidate_device_entry(&self, device: DeviceId) -> Result<(), IommuError> {
        let unit_idx = self
            .find_unit_index_for_device(device)
            .ok_or(IommuError::DeviceNotFound)?;
        let devid = device.requester_id();
        self.with_cmd_state(unit_idx, |state| {
            state.submit_and_wait(cmd::AmdCommand::invalidate_device_entry(devid))
        })
    }

    pub(crate) fn invalidate_device_entry_by_devid(&self, segment: u16, devid: u16) -> Result<(), IommuError> {
        let device = Self::device_id_from_devid(segment, devid);
        self.invalidate_device_entry(device)
    }

    pub(crate) fn invalidate_interrupt_table(&self, segment: u16, device_id: u16) -> Result<(), IommuError> {
        let device = Self::device_id_from_devid(segment, device_id);
        let unit_idx = self
            .find_unit_index_for_device(device)
            .ok_or(IommuError::DeviceNotFound)?;
        self.with_cmd_state(unit_idx, |state| {
            state.submit_and_wait(cmd::AmdCommand::invalidate_interrupt_table(device_id))
        })
    }

    fn device_id_from_devid(segment: u16, devid: u16) -> DeviceId {
        let bus = (devid >> 8) as u8;
        let devfn = (devid & 0xff) as u8;
        let device = (devfn >> 3) & 0x1f;
        let function = devfn & 0x07;
        DeviceId::new(segment, bus, device, function)
    }

    pub(super) fn invalidate_iotlb_pages(
        &self,
        device: DeviceId,
        iova: u64,
        size: u64,
    ) -> Result<(), IommuError> {
        let unit_idx = self
            .find_unit_index_for_device(device)
            .ok_or(IommuError::DeviceNotFound)?;
        let devid = device.requester_id();
        
        let epoch = self.iova_allocator.advance_epoch();
        let res = self.with_cmd_state(unit_idx, |state| {
            state.submit_and_wait(cmd::AmdCommand::invalidate_iotlb_pages(
                devid, 0, iova, size, None,
            ))
        });
        self.iova_allocator.complete_epoch(epoch);
        res
    }

    pub(super) fn invalidate_iommu_pages(
        &self,
        device: DeviceId,
        domain_id: u16,
        iova: u64,
        size: u64,
    ) -> Result<(), IommuError> {
        let unit_idx = self
            .find_unit_index_for_device(device)
            .ok_or(IommuError::DeviceNotFound)?;
        
        let epoch = self.iova_allocator.advance_epoch();
        let res = self.with_cmd_state(unit_idx, |state| {
            state.submit_and_wait(cmd::AmdCommand::invalidate_iommu_pages(
                domain_id, iova, size, None,
            ))
        });
        self.iova_allocator.complete_epoch(epoch);
        res
    }

    pub(super) async fn invalidate_iotlb_pages_async(
        &self,
        device: DeviceId,
        iova: u64,
        size: u64,
    ) -> Result<(), IommuError> {
        let unit_idx = self
            .find_unit_index_for_device(device)
            .ok_or(IommuError::DeviceNotFound)?;
        let devid = device.requester_id();
        self.submit_cmd_async(
            unit_idx,
            cmd::AmdCommand::invalidate_iotlb_pages(devid, 0, iova, size, None),
        )
        .await
    }

    pub(super) async fn invalidate_iommu_pages_async(
        &self,
        device: DeviceId,
        domain_id: u16,
        iova: u64,
        size: u64,
    ) -> Result<(), IommuError> {
        let unit_idx = self
            .find_unit_index_for_device(device)
            .ok_or(IommuError::DeviceNotFound)?;
        self.submit_cmd_async(
            unit_idx,
            cmd::AmdCommand::invalidate_iommu_pages(domain_id, iova, size, None),
        )
        .await
    }

    pub(super) fn invalidate_domain_pages(
        &self,
        domain_id: u16,
        iova: u64,
        size: u64,
    ) -> Result<(), IommuError> {
        let mut has_state = false;
        
        // Advance epoch before domain invalidation
        let epoch = self.iova_allocator.advance_epoch();

        for idx in 0..self.cmd_states.len() {
            if self.cmd_states[idx].is_none() {
                continue;
            }
            has_state = true;
            self.with_cmd_state(idx, |state| {
                state.submit_and_wait(cmd::AmdCommand::invalidate_iommu_pages(
                    domain_id, iova, size, None,
                ))
            })?;
        }

        // Complete epoch after invalidation confirmed on all units
        self.iova_allocator.complete_epoch(epoch);

        if !has_state {
            return Err(IommuError::NotSupported);
        }
        Ok(())
    }

    // ========================================================================
    // Flush Operations (for emergency isolation)
    // ========================================================================

    /// Invalidate IOTLB entries for a specific domain.
    pub(crate) fn invalidate_iotlb(
        &self,
        domain_id: u16,
        iova: Option<u64>,
        any_ats: bool,
    ) -> Result<(), IommuError> {
        // AMD-Vi uses INVALIDATE_IOMMU_PAGES command
        // For emergency isolation, we invalidate all pages in the domain
        self.invalidate_domain_all(domain_id)?;
        
        if any_ats {
            self.invalidate_domain_device_tlbs(domain_id, iova, None)?;
        }

        Ok(())
    }

    /// Invalidate all IOTLB entries globally.
    pub(crate) fn invalidate_iotlb_global(&self) -> Result<(), IommuError> {
        // Invalidate all domains - AMD-Vi doesn't have a single global invalidation
        // so we iterate through known domains
        let domain_ids: Vec<u16> = match self.domains.lock() {
            Ok(domains) => domains.keys().cloned().collect(),
            Err(_) => return Err(IommuError::Poisoned),
        };

        for domain_id in domain_ids {
            self.invalidate_domain_all(domain_id)?;
        }

        Ok(())
    }

    /// Invalidate context cache globally.
    pub(crate) fn invalidate_context_global(&self) -> Result<(), IommuError> {
        // AMD-Vi uses device table entries; invalidation is done via
        // INVALIDATE_DEVTAB_ENTRY command
        // For global invalidation, we flush all known devices
        self.invalidate_all_device_entries()
    }


    /// Invalidate all pages in a domain.
    fn invalidate_domain_all(&self, domain_id: u16) -> Result<(), IommuError> {
        let epoch = self.iova_allocator.advance_epoch();
        let mut last_err = None;
        for (idx, _unit) in self.units.iter().enumerate() {
            if let Some(cmd_state) = self.cmd_states.get(idx).and_then(|s| s.as_ref()) {
                // Use invalidate_iommu_pages with size = u64::MAX to invalidate all pages
                let command = cmd::AmdCommand::invalidate_iommu_pages(
                    domain_id,
                    0,         // address
                    u64::MAX,  // size = all pages
                    None,      // pasid
                );
                if let Ok(mut state) = cmd_state.lock() {
                    if let Err(err) = state.submit_and_wait(command) {
                        last_err = Some(err);
                    }
                }
            }
        }
        self.iova_allocator.complete_epoch(epoch);
        if let Some(err) = last_err {
            return Err(err);
        }
        Ok(())
    }

    /// Invalidate Device-TLBs for all devices belonging to a specific domain.
    fn invalidate_domain_device_tlbs(
        &self,
        domain_id: u16,
        iova: Option<u64>,
        size: Option<u64>,
    ) -> Result<(), IommuError> {
        let device_domains = self.device_domains.lock().map_err(|_| IommuError::Poisoned)?;
        for (&device, &did) in device_domains.iter() {
            if did == domain_id {
                // For ATS-aware invalidation, we must send INVALIDATE_IOTLB_PAGES to the device
                match (iova, size) {
                    (Some(iova_val), Some(size_val)) => {
                        self.invalidate_iotlb_pages(device, iova_val, size_val)?;
                    }
                    _ => {
                        self.invalidate_iotlb_pages(device, 0, u64::MAX)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Invalidate all device table entries.
    fn invalidate_all_device_entries(&self) -> Result<(), IommuError> {
        let device_ids: Vec<u16> = match self.device_domains.lock() {
            Ok(device_domains) => device_domains.keys().map(|d| d.bdf()).collect(),
            Err(_) => return Err(IommuError::Poisoned),
        };

        // Advance epoch before global invalidation
        let epoch = self.iova_allocator.advance_epoch();
        let mut last_err = None;

        for (idx, _unit) in self.units.iter().enumerate() {
            if let Some(cmd_state) = self.cmd_states.get(idx).and_then(|s| s.as_ref()) {
                if let Ok(mut state) = cmd_state.lock() {
                    let sync_phys = state.sync_phys;
                    for devid in &device_ids {
                        let command = cmd::AmdCommand::invalidate_device_entry(*devid);
                        if let Err(err) = state.submit(command) {
                            last_err = Some(err);
                            break;
                        }
                    }
                    
                    if last_err.is_none() {
                        // Submit a completion wait and wait for it
                        match state.submit_and_wait_token(
                            cmd::AmdCommand::completion_wait(
                                sync_phys,
                                0, // Dummy, submit_and_wait_token will override it
                                false,
                            ),
                            false,
                        ) {
                            Ok(token) => {
                                if let Err(err) = token.wait_blocking() {
                                    last_err = Some(err);
                                }
                            },
                            Err(err) => {
                                last_err = Some(err);
                            }
                        }
                    }
                }
            }
        }

        // Complete epoch after hardware confirmation
        self.iova_allocator.complete_epoch(epoch);
        if let Some(err) = last_err {
            return Err(err);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// IommuInvalidator implementation for AmdIommuDriver
// ---------------------------------------------------------------------------

use crate::io::iommu::common::domain::{IommuInvalidator, InvalidateKind, InvalidateRequest, InvalidateFlags};

impl IommuInvalidator for AmdIommuDriver {
    fn process_invalidations(&self, requests: &[InvalidateRequest]) -> Result<(), IommuError> {
        if requests.is_empty() {
            return Ok(());
        }

        // Advance epoch before invalidation
        let epoch = self.iova_allocator.advance_epoch();

        for req in requests {
            match req.kind {
                InvalidateKind::Pages { start_iova, bytes } => {
                    // AMD-Vi invalidate_domain_pages iterates over all units
                    self.invalidate_domain_pages(req.domain_id, start_iova, bytes)?;
                                    if req.flags.contains(InvalidateFlags::ATS_AWARE) {
                                        self.invalidate_domain_device_tlbs(
                                            req.domain_id,
                                            Some(start_iova),
                                            Some(bytes),
                                        )?;
                                    }
                                }
                                InvalidateKind::Domain => {
                                    self.invalidate_domain_all(req.domain_id)?;
                                    if req.flags.contains(InvalidateFlags::ATS_AWARE) {
                                        self.invalidate_domain_device_tlbs(req.domain_id, None, None)?;
                                    }
                                }                InvalidateKind::Global => {
                    self.invalidate_all_entries()?;
                }
                InvalidateKind::Context { source_id } => {
                    let device = Self::device_id_from_devid(0, source_id);
                    self.invalidate_device_entry(device)?;
                }
                _ => {
                    // IEC, PasidIotlb, etc. are not yet fully supported on AMD backend
                    // Fall back to global flush for safety if requested and unsupported
                    if req.flags.contains(InvalidateFlags::ATS_AWARE) {
                         self.invalidate_all_entries()?;
                    }
                }
            }
        }

        // Complete epoch after hardware confirmation
        self.iova_allocator.complete_epoch(epoch);
        Ok(())
    }
}
