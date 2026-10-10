// ============================================================================
// kernel/src/io/iommu/runtime/security/emergency.rs
// ============================================================================

use core::sync::atomic::{AtomicU32, Ordering};

use crate::io::iommu::types::{DeviceId, IommuError};

/// Maximum number of devices that can be emergency-isolated simultaneously.
const MAX_EMERGENCY_ISOLATED: usize = 32;

/// Emergency isolation slot for a device.
struct EmergencyIsolationSlot {
    state: AtomicU32,
}

#[derive(Clone, Copy)]
enum IsolationState {
    Empty,
    Requested(u16),
    Isolating(u16),
    Isolated(u16),
}

impl IsolationState {
    fn encode(self) -> u32 {
        match self {
            Self::Empty => 0,
            Self::Requested(source) => (u32::from(source) << 2) | 1,
            Self::Isolating(source) => (u32::from(source) << 2) | 2,
            Self::Isolated(source) => (u32::from(source) << 2) | 3,
        }
    }

    fn decode(value: u32) -> Self {
        // Only encode() constructs slot values: the upper bits hold one u16
        // source identity, and identity and phase are published atomically.
        let source = (value >> 2) as u16;
        match value & 3 {
            1 => Self::Requested(source),
            2 => Self::Isolating(source),
            3 => Self::Isolated(source),
            _ => Self::Empty,
        }
    }

    fn source(self) -> Option<u16> {
        match self {
            Self::Empty => None,
            Self::Requested(source) | Self::Isolating(source) | Self::Isolated(source) => {
                Some(source)
            }
        }
    }
}

enum IsolationAdmission {
    Registered,
    Existing,
    Occupied,
}

impl EmergencyIsolationSlot {
    const fn new() -> Self {
        Self {
            state: AtomicU32::new(0),
        }
    }

    fn admit(&self, source: u16) -> IsolationAdmission {
        match self.state.compare_exchange(
            IsolationState::Empty.encode(),
            IsolationState::Requested(source).encode(),
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => IsolationAdmission::Registered,
            Err(value) if IsolationState::decode(value).source() == Some(source) => {
                IsolationAdmission::Existing
            }
            Err(_) => IsolationAdmission::Occupied,
        }
    }

    fn begin(&self) -> Option<PendingIsolation<'_>> {
        let value = self.state.load(Ordering::Acquire);
        let IsolationState::Requested(source) = IsolationState::decode(value) else {
            return None;
        };
        self.state
            .compare_exchange(
                value,
                IsolationState::Isolating(source).encode(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .ok()?;
        Some(PendingIsolation { slot: self, source })
    }
}

// The worker owns a claimed request until hardware revocation completes. A
// failed or interrupted attempt remains pending; another worker cannot execute
// the same request while this owner is on a suspended stack.
struct PendingIsolation<'a> {
    slot: &'a EmergencyIsolationSlot,
    source: u16,
}

#[derive(Debug)]
enum IsolationAttemptError {
    Revoke(IommuError),
    Flush(IommuError),
}

impl PendingIsolation<'_> {
    /// # Errors
    ///
    /// Revocation failure skips the flush. Flush failure retains the request
    /// after revocation; both failures return ownership for a full retry.
    fn finish(
        self,
        revoke: impl FnOnce(u16) -> Result<(), IommuError>,
        flush: impl FnOnce(u16) -> Result<(), IommuError>,
    ) -> Result<(), IsolationAttemptError> {
        revoke(self.source).map_err(IsolationAttemptError::Revoke)?;
        flush(self.source).map_err(IsolationAttemptError::Flush)?;
        self.slot.state.store(
            IsolationState::Isolated(self.source).encode(),
            Ordering::Release,
        );
        Ok(())
    }
}

impl Drop for PendingIsolation<'_> {
    fn drop(&mut self) {
        // A completed request no longer matches Isolating, so Drop cannot undo
        // completion. An unfinished owner returns its request for the next pass.
        let _ = self.slot.state.compare_exchange(
            IsolationState::Isolating(self.source).encode(),
            IsolationState::Requested(self.source).encode(),
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
}

/// Global emergency isolation registry.
pub struct EmergencyIsolationRegistry {
    slots: [EmergencyIsolationSlot; MAX_EMERGENCY_ISOLATED],
}

impl EmergencyIsolationRegistry {
    pub const fn new() -> Self {
        Self {
            slots: [const { EmergencyIsolationSlot::new() }; MAX_EMERGENCY_ISOLATED],
        }
    }

    /// Request emergency isolation for a device.
    ///
    /// Registration is permanent for this registry's lifetime. `Ok(true)`
    /// admits a request; completion is observed separately in the statistics.
    /// `Ok(false)` coalesces a source already registered, including during a
    /// suspended worker's attempt.
    ///
    /// # Errors
    ///
    /// Returns `Err(())` when all request slots belong to other sources.
    pub fn request_isolation(&self, source_id: u16) -> Result<bool, ()> {
        // Stable probing and permanent entries make concurrent requests for the
        // same source converge on the same CAS, without an ISR lock or allocation.
        let start = usize::from(source_id) % MAX_EMERGENCY_ISOLATED;
        for offset in 0..MAX_EMERGENCY_ISOLATED {
            let slot = &self.slots[(start + offset) % MAX_EMERGENCY_ISOLATED];
            match slot.admit(source_id) {
                IsolationAdmission::Registered => {
                    log::warn!(
                        "[IOMMU][Emergency] Device 0x{:x} marked for isolation (pending IOTLB flush)",
                        source_id
                    );
                    return Ok(true);
                }
                IsolationAdmission::Existing => return Ok(false),
                IsolationAdmission::Occupied => {}
            }
        }

        log::error!(
            "[IOMMU][Emergency] Cannot isolate device 0x{:x}: registry full ({} devices)",
            source_id,
            MAX_EMERGENCY_ISOLATED
        );
        Err(())
    }

    /// Complete pending isolations from normal task context.
    ///
    /// Returns the number of completed hardware revocations. Missing hardware
    /// and invalidation failures retain requests for a subsequent pass; other
    /// requests still progress. Completion is published after both the context
    /// revocation and cache flush have succeeded.
    pub fn process_pending_isolations(&self) -> usize {
        let mut processed = 0;

        for slot in &self.slots {
            if let Some(pending) = slot.begin() {
                let source_id = pending.source;
                let Some(driver) = crate::io::iommu::runtime::registry::get_iommu_driver() else {
                    continue;
                };
                match pending.finish(
                    |source| driver.isolate_device(DeviceId::from_bdf(source)),
                    invalidate_device_iotlb,
                ) {
                    Ok(()) => {}
                    Err(IsolationAttemptError::Revoke(cause)) => {
                        log::error!(
                            "[IOMMU][Emergency] Hardware isolation failed for device 0x{:x}: {:?}",
                            source_id,
                            cause
                        );
                        continue;
                    }
                    Err(IsolationAttemptError::Flush(cause)) => {
                        log::error!(
                            "[IOMMU][Emergency] IOTLB flush failed for device 0x{:x}: {:?}",
                            source_id,
                            cause
                        );
                        continue;
                    }
                }

                processed += 1;

                log::info!(
                    "[IOMMU][Emergency] Device 0x{:x} fully isolated (hardware disabled & IOTLB flushed)",
                    source_id
                );
            }
        }

        processed
    }

    pub fn stats(&self) -> EmergencyIsolationStats {
        let mut stats = EmergencyIsolationStats {
            total_isolations: 0,
            pending_count: 0,
            active_count: 0,
        };
        for slot in &self.slots {
            match IsolationState::decode(slot.state.load(Ordering::Acquire)) {
                IsolationState::Empty => {}
                IsolationState::Requested(_) | IsolationState::Isolating(_) => {
                    stats.pending_count += 1;
                    stats.active_count += 1;
                }
                IsolationState::Isolated(_) => {
                    stats.total_isolations += 1;
                    stats.active_count += 1;
                }
            }
        }
        stats
    }
}

impl Default for EmergencyIsolationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics for emergency isolation.
#[derive(Debug, Clone, Copy)]
pub struct EmergencyIsolationStats {
    /// Devices whose hardware isolation and cache invalidation completed.
    pub total_isolations: u64,
    pub pending_count: u32,
    pub active_count: u32,
}

static EMERGENCY_REGISTRY: EmergencyIsolationRegistry = EmergencyIsolationRegistry::new();

/// Get the global emergency isolation registry.
pub fn emergency_isolation_registry() -> &'static EmergencyIsolationRegistry {
    &EMERGENCY_REGISTRY
}

/// Request emergency isolation for a device (convenience function).
pub fn emergency_isolate_device(source_id: u16) -> Result<bool, ()> {
    let res = EMERGENCY_REGISTRY.request_isolation(source_id);
    if res.is_ok() {
        super::notifier::wake_security_monitor_from_isr();
    }
    res
}

/// Invalidate IOTLB entries for a device.
fn invalidate_device_iotlb(source_id: u16) -> Result<(), IommuError> {
    use crate::io::iommu::common::dma::flush;

    flush::invalidate_iotlb_device(source_id)?;
    flush::invalidate_context_device(source_id)?;
    core::sync::atomic::fence(Ordering::SeqCst);

    Ok(())
}

#[cfg(all(test, any(feature = "std", target_os = "linux")))]
mod tests {
    use super::*;
    use alloc::sync::Arc;

    #[test]
    fn unavailable_hardware_retains_requests_without_claiming_completion() {
        let registry = EmergencyIsolationRegistry::new();
        assert_eq!(registry.request_isolation(0), Ok(true));
        assert_eq!(registry.request_isolation(u16::MAX), Ok(true));
        for _ in 0..2 {
            assert_eq!(registry.process_pending_isolations(), 0);
            let stats = registry.stats();
            assert_eq!(
                (
                    stats.total_isolations,
                    stats.pending_count,
                    stats.active_count
                ),
                (0, 2, 2)
            );
        }
        assert_eq!(registry.request_isolation(0), Ok(false));
        assert_eq!(registry.request_isolation(u16::MAX), Ok(false));
    }

    #[test]
    fn unfinished_claim_remains_pending_and_excludes_other_workers() {
        let registry = EmergencyIsolationRegistry::new();
        assert_eq!(registry.request_isolation(0), Ok(true));
        let pending = registry.slots[0].begin().expect("one admitted request");
        assert!(registry.slots[0].begin().is_none());
        assert_eq!(registry.stats().pending_count, 1);
        assert_eq!(registry.stats().total_isolations, 0);
        drop(pending);
        assert_eq!(registry.stats().pending_count, 1);
        let pending = registry.slots[0]
            .begin()
            .expect("unfinished request is retained");
        pending
            .finish(|_| Ok(()), |_| Ok(()))
            .expect("both hardware operations completed");
        let stats = registry.stats();
        assert_eq!(
            (
                stats.total_isolations,
                stats.pending_count,
                stats.active_count
            ),
            (1, 0, 1)
        );
        assert!(registry.slots[0].begin().is_none());
    }

    #[test]
    fn revocation_and_flush_failures_preserve_the_request_and_retry_order() {
        let registry = EmergencyIsolationRegistry::new();
        assert_eq!(registry.request_isolation(0), Ok(true));
        let pending = registry.slots[0].begin().expect("admitted request");
        assert!(matches!(
            pending.finish(
                |_| Err(IommuError::HardwareError),
                |_| panic!("failed revocation must skip the flush"),
            ),
            Err(IsolationAttemptError::Revoke(IommuError::HardwareError))
        ));
        assert_eq!(
            (
                registry.stats().total_isolations,
                registry.stats().pending_count
            ),
            (0, 1)
        );
        let mut steps = alloc::vec::Vec::new();
        let revocations = core::cell::Cell::new(0);
        let pending = registry.slots[0]
            .begin()
            .expect("failed revocation is retryable");
        assert!(matches!(
            pending.finish(
                |source| {
                    assert_eq!(source, 0);
                    revocations.set(revocations.get() + 1);
                    Ok(())
                },
                |source| {
                    assert_eq!(revocations.get(), 1);
                    steps.push(source);
                    Err(IommuError::Timeout)
                },
            ),
            Err(IsolationAttemptError::Flush(IommuError::Timeout))
        ));
        assert_eq!(steps, [0]);
        assert_eq!(
            (
                registry.stats().total_isolations,
                registry.stats().pending_count
            ),
            (0, 1)
        );
        let pending = registry.slots[0]
            .begin()
            .expect("failed flush is retryable");
        pending
            .finish(
                |source| {
                    assert_eq!(source, 0);
                    revocations.set(revocations.get() + 1);
                    Ok(())
                },
                |source| {
                    assert_eq!(revocations.get(), 2);
                    steps.push(source);
                    Ok(())
                },
            )
            .expect("retry confirms both operations");
        assert_eq!(steps, [0, 0]);
        assert_eq!(
            (
                registry.stats().total_isolations,
                registry.stats().pending_count
            ),
            (1, 0)
        );
    }

    #[test]
    fn concurrent_requests_coalesce_and_capacity_rejection_preserves_pending_work() {
        let registry = Arc::new(EmergencyIsolationRegistry::new());
        let mut threads = alloc::vec::Vec::new();
        for _ in 0..8 {
            let registry = Arc::clone(&registry);
            threads.push(std::thread::spawn(move || registry.request_isolation(0)));
        }
        let admitted = threads
            .into_iter()
            .map(|thread| {
                thread
                    .join()
                    .expect("request thread")
                    .expect("free capacity")
            })
            .filter(|accepted| *accepted)
            .count();
        assert_eq!(admitted, 1);
        for index in 1..MAX_EMERGENCY_ISOLATED {
            // Collisions exercise the same probing order used by concurrent ISR requests.
            let source =
                u16::try_from(index * MAX_EMERGENCY_ISOLATED).expect("fixture source fits");
            assert_eq!(registry.request_isolation(source), Ok(true));
        }
        assert_eq!(registry.request_isolation(u16::MAX), Err(()));
        assert_eq!(registry.request_isolation(0), Ok(false));
        let stats = registry.stats();
        assert_eq!(stats.total_isolations, 0);
        assert_eq!(stats.pending_count as usize, MAX_EMERGENCY_ISOLATED);
        assert_eq!(stats.active_count as usize, MAX_EMERGENCY_ISOLATED);
    }
}
