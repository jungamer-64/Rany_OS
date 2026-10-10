// ============================================================================
// kernel/src/io/iommu/runtime/security/emergency.rs
// ============================================================================

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::io::iommu::types::{DeviceId, IommuError};

/// Maximum number of devices that can be emergency-isolated simultaneously.
const MAX_EMERGENCY_ISOLATED: usize = 32;

/// Emergency isolation slot for a device.
struct EmergencyIsolationSlot {
    state: AtomicU32,
}

impl EmergencyIsolationSlot {
    const fn new() -> Self {
        Self { state: AtomicU32::new(0) }
    }
}

/// Global emergency isolation registry.
pub struct EmergencyIsolationRegistry {
    slots: [EmergencyIsolationSlot; MAX_EMERGENCY_ISOLATED],
    total_isolations: AtomicU64,
}

impl EmergencyIsolationRegistry {
    pub const fn new() -> Self {
        const INIT: EmergencyIsolationSlot = EmergencyIsolationSlot::new();
        Self {
            slots: [INIT; MAX_EMERGENCY_ISOLATED],
            total_isolations: AtomicU64::new(0),
        }
    }

    /// Request emergency isolation for a device.
    pub fn request_isolation(&self, source_id: u16) -> Result<bool, ()> {
        for slot in &self.slots {
            if slot.matches(source_id) {
                return Ok(false);
            }
        }

        for slot in &self.slots {
            if slot.try_claim(source_id) {
                self.total_isolations.fetch_add(1, Ordering::Relaxed);
                self.pending_count.fetch_add(1, Ordering::Relaxed);

                log::warn!(
                    "[IOMMU][Emergency] Device 0x{:x} marked for isolation (pending IOTLB flush)",
                    source_id
                );

                return Ok(true);
            }
        }

        log::error!(
            "[IOMMU][Emergency] Cannot isolate device 0x{:x}: registry full ({} devices)",
            source_id,
            MAX_EMERGENCY_ISOLATED
        );
        Err(())
    }

    /// Process pending isolations (called from non-ISR context).
    pub fn process_pending_isolations(&self) -> usize {
        let mut processed = 0;

        for slot in &self.slots {
            if slot.status() == 1 {
                let source_id = slot.source_id.load(Ordering::Acquire) as u16;

                if let Some(driver) = crate::io::iommu::runtime::registry::get_iommu_driver() {
                    let device_id = DeviceId::from_bdf(source_id);
                    if let Err(e) = driver.isolate_device(device_id) {
                        log::error!(
                            "[IOMMU][Emergency] Hardware isolation failed for device 0x{:x}: {:?}",
                            source_id,
                            e
                        );
                    }
                }

                if let Err(e) = invalidate_device_iotlb(source_id) {
                    log::error!(
                        "[IOMMU][Emergency] IOTLB flush failed for device 0x{:x}: {:?}",
                        source_id,
                        e
                    );
                }

                slot.mark_fully_isolated();
                self.pending_count.fetch_sub(1, Ordering::Relaxed);
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
        EmergencyIsolationStats {
            total_isolations: self.total_isolations.load(Ordering::Relaxed),
            pending_count: self.pending_count.load(Ordering::Relaxed),
            active_count: self.slots.iter().filter(|s| s.status() != 0).count() as u32,
        }
    }
}

/// Statistics for emergency isolation.
#[derive(Debug, Clone, Copy)]
pub struct EmergencyIsolationStats {
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
