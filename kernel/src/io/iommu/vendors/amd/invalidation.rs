// ============================================================================
// kernel/src/io/iommu/vendors/amd/invalidation.rs
// ============================================================================

//! AMD-Vi command state management and invalidation operations.

use alloc::vec::Vec;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::io::iommu::types::{DeviceId, IommuError};

use super::AmdIommuDriver;
use super::cmd;

use super::fault::AMD_CMD_WAITERS;
use core::future::poll_fn;
use core::task::Poll;

// ---------------------------------------------------------------------------
// AmdCommandWaitToken
// ---------------------------------------------------------------------------

const AMD_CMD_WAIT_MAX_POLLS: u64 = 1_000_000;

pub(super) struct AmdCommandWaitToken {
    sync_ptr: NonNull<u64>,
    expected_seq: u64,
}

// SAFETY: The token only carries a pointer to a completion counter in DMA-backed
// memory and an expected sequence number. Completion checks are read-only volatile
// loads, and synchronization is handled by hardware command completion ordering.
unsafe impl Send for AmdCommandWaitToken {}
unsafe impl Sync for AmdCommandWaitToken {}

impl AmdCommandWaitToken {
    fn is_complete(&self) -> bool {
        // Wrap-around safe comparison: treat completed if distance < half-space.
        // This mirrors the Intel QI path's wrapping_sub approach.
        let status = unsafe { self.sync_ptr.as_ptr().read_volatile() };
        status.wrapping_sub(self.expected_seq) < (1u64 << 63)
    }

    pub(super) fn wait_blocking(self) -> Result<(), IommuError> {
        let mut spins = 0u64;
        // LOOP_PROOF: mode=condition; reason=Blocking wait loop exits when completion flag flips true or timeout poll budget is exceeded.;
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
        use core::future::Future;

        for _ in 0..100 {
            let mut tick = core::pin::pin!(crate::drivers::time::sleep_ms(1));
            let completed = poll_fn(|cx| {
                if self.is_complete() {
                    return Poll::Ready(Ok(true));
                }
                AMD_CMD_WAITERS.register(cx.waker());
                if self.is_complete() {
                    return Poll::Ready(Ok(true));
                }
                match tick.as_mut().poll(cx) {
                    Poll::Ready(Ok(())) => Poll::Ready(Ok(false)),
                    Poll::Ready(Err(_)) => Poll::Ready(Err(IommuError::RuntimeUnavailable)),
                    Poll::Pending => Poll::Pending,
                }
            })
            .await?;
            if completed {
                return Ok(());
            }
        }
        if self.is_complete() {
            Ok(())
        } else {
            Err(IommuError::Timeout)
        }
    }
}

// ---------------------------------------------------------------------------
// AmdCommandState
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub(crate) struct AmdCommandState {
    // Kept published for the lifetime of the command unit.
    pub(super) _backing: crate::mm::phys::frame_allocator::PhysicalAllocation,
    pub(super) _sync_backing: crate::mm::phys::frame_allocator::PhysicalAllocation,
    pub(super) buffer: cmd::AmdCommandBuffer,
    pub(super) sync_ptr: NonNull<u64>,
    pub(super) sync_phys: u64,
    pub(super) seq: AtomicU64,
}

// SAFETY: `AmdCommandState` contains raw pointers to memory used for command buffer
// completion synchronization (`sync_ptr`). Access to this state is synchronized by
// PoisonLock wrappers when used in `cmd_states`, ensuring safe concurrent access.
unsafe impl Send for AmdCommandState {}
unsafe impl Sync for AmdCommandState {}

// The controller retains command RAM and its DMA-protection registration for
// its enabled lifetime. Losing software references is not hardware retirement:
// PhysicalAllocation deliberately does not release on Drop, and protection
// stays registered until a controller shutdown confirms the processor stopped.

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
        self.submit(cmd)?;
        self.completion(interrupt)
    }

    pub(super) fn completion(
        &mut self,
        interrupt: bool,
    ) -> Result<AmdCommandWaitToken, IommuError> {
        let next_seq = self.seq.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
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
        self.submit_and_wait_token(cmd, false)?.wait_blocking()
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
            .ok_or(IommuError::NotSupported)?;

        let mut guard = match state.lock() {
            Ok(guard) => guard,
            Err(_) => return Err(IommuError::Poisoned),
        };
        f(&mut guard)
    }

    pub(super) async fn submit_cmd_async(
        &self,
        unit_idx: usize,
        cmd: cmd::AmdCommand,
    ) -> Result<(), IommuError> {
        let state = self
            .cmd_states
            .get(unit_idx)
            .ok_or(IommuError::NotSupported)?;

        let token = {
            let mut guard = match state.lock() {
                Ok(guard) => guard,
                Err(_) => return Err(IommuError::Poisoned),
            };
            guard.submit_and_wait_token(cmd, true)?
        };

        // One command on one unit does not cover allocator-wide retirement.
        token.wait_async().await
    }

    pub(super) fn invalidate_requesters(
        &self,
        unit: usize,
        requesters: &[u16],
    ) -> Result<(), IommuError> {
        self.with_cmd_state(unit, |state| {
            for &requester in requesters {
                state.submit(cmd::AmdCommand::invalidate_device_entry(requester))?;
            }
            state.completion(false)?.wait_blocking()
        })
    }

    pub(super) fn invalidate_requester_interrupts(
        &self,
        unit: usize,
        requesters: &[u16],
    ) -> Result<(), IommuError> {
        self.with_cmd_state(unit, |state| {
            for &requester in requesters {
                state.submit(cmd::AmdCommand::invalidate_interrupt_table(requester))?;
            }
            state.completion(false)?.wait_blocking()
        })
    }

    pub(super) fn invalidate_unit_domain(
        &self,
        unit: usize,
        domain: u16,
    ) -> Result<(), IommuError> {
        self.with_cmd_state(unit, |state| {
            state.submit_and_wait(cmd::AmdCommand::invalidate_iommu_pages(
                domain,
                0,
                u64::MAX,
                None,
            ))
        })
    }

    fn invalidate_domain_pages(
        &self,
        domain_id: u16,
        iova: u64,
        size: u64,
    ) -> Result<(), IommuError> {
        if self.cmd_states.is_empty() {
            return Err(IommuError::NotPresent);
        }
        let mut completions = Vec::new();
        completions
            .try_reserve_exact(self.cmd_states.len())
            .map_err(|_| IommuError::MetadataAllocation)?;
        for unit in 0..self.cmd_states.len() {
            let token = self.with_cmd_state(unit, |state| {
                state.submit_and_wait_token(
                    cmd::AmdCommand::invalidate_iommu_pages(domain_id, iova, size, None),
                    false,
                )
            })?;
            completions.push(token);
        }
        for token in completions {
            token.wait_blocking()?;
        }
        Ok(())
    }

    async fn invalidate_domain_pages_async(
        &self,
        domain_id: u16,
        iova: u64,
        size: u64,
    ) -> Result<(), IommuError> {
        if self.cmd_states.is_empty() {
            return Err(IommuError::NotPresent);
        }
        for unit in 0..self.cmd_states.len() {
            self.submit_cmd_async(
                unit,
                cmd::AmdCommand::invalidate_iommu_pages(domain_id, iova, size, None),
            )
            .await?;
        }
        Ok(())
    }

    pub(super) fn invalidate_domain_all(&self, domain_id: u16) -> Result<(), IommuError> {
        self.invalidate_domain_pages(domain_id, 0, u64::MAX)
    }

    pub(crate) fn invalidate_iotlb(
        &self,
        domain_id: u16,
        iova: Option<u64>,
        _any_ats: bool,
    ) -> Result<(), IommuError> {
        match iova {
            Some(iova) => self.invalidate_domain_pages(domain_id, iova, 4096),
            None => self.invalidate_domain_all(domain_id),
        }
    }

    pub(crate) fn invalidate_iotlb_global(&self) -> Result<(), IommuError> {
        if self.units.is_empty() {
            return Err(IommuError::NotPresent);
        }
        for (idx, unit) in self.units.iter().enumerate() {
            if unit.registers.extended_features() & super::registers::EFR_IA_SUP != 0 {
                self.with_cmd_state(idx, |state| {
                    state.submit_and_wait(cmd::AmdCommand::invalidate_all())
                })?;
            } else {
                // Cold start admits no firmware context. Every DID that can
                // still be cached belongs to the registry until retirement.
                let domains = self.domains.lock().map_err(|_| IommuError::Poisoned)?;
                for &domain in domains.keys() {
                    self.invalidate_unit_domain(idx, domain)?;
                }
            }
        }
        Ok(())
    }

    pub(crate) fn invalidate_context_global(&self) -> Result<(), IommuError> {
        let bindings = self
            .device_bindings
            .lock()
            .map_err(|_| IommuError::Poisoned)?;
        for binding in bindings.values() {
            let (unit, requesters) = binding.requesters();
            self.invalidate_requesters(unit, requesters)?;
        }
        Ok(())
    }
}

use crate::io::iommu::common::domain::{InvalidateKind, InvalidateRequest, IommuInvalidator};

impl IommuInvalidator for AmdIommuDriver {
    fn process_invalidations(&self, requests: &[InvalidateRequest]) -> Result<(), IommuError> {
        // Every admitted AMD DTE has I=0: ATS and pretranslated transactions
        // are rejected. COMPLETION_WAIT proves retirement of the IOMMU caches
        // and DMA issued against the invalidated translations.
        for request in requests {
            match request.kind {
                InvalidateKind::Pages { start_iova, bytes } => {
                    self.invalidate_domain_pages(request.domain_id, start_iova, bytes)?;
                }
                InvalidateKind::Domain => self.invalidate_domain_all(request.domain_id)?,
                InvalidateKind::Global => self.invalidate_iotlb_global()?,
            }
        }
        Ok(())
    }

    fn invalidate_async(
        &self,
        request: InvalidateRequest,
    ) -> impl core::future::Future<Output = Result<(), IommuError>> + Send {
        async move {
            match request.kind {
                InvalidateKind::Pages { start_iova, bytes } => {
                    self.invalidate_domain_pages_async(request.domain_id, start_iova, bytes)
                        .await
                }
                InvalidateKind::Domain => {
                    self.invalidate_domain_pages_async(request.domain_id, 0, u64::MAX)
                        .await
                }
                InvalidateKind::Global => self.invalidate_iotlb_global(),
            }
        }
    }
}
