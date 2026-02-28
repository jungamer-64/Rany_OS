// ============================================================================
// kernel/src/io/iommu/backends/intel/controller/ats_control.rs
// ============================================================================

use super::*;

impl IommuController {

    /// Enable ATS (Address Translation Services) for a device
    ///
    /// # Security Warning
    ///
    /// ATS allows devices to cache address translations in their internal TLBs.
    /// This improves performance but introduces security risks for untrusted devices:
    ///
    /// - Malicious devices could exploit stale TLB entries
    /// - Compromised devices might ignore invalidation requests
    /// - Side-channel attacks via translation timing
    ///
    /// Only enable ATS for devices with verified trust level. For external or
    /// hot-pluggable devices (USB, Thunderbolt), prefer `disable_ats_for_device`.
    ///
    /// # Arguments
    ///
    /// * `device` - Device ID (Bus/Device/Function)
    /// * `trust_level` - Trust level assigned to the device
    ///
    /// # Returns
    ///
    /// `true` if ATS was enabled, `false` if blocked by security policy
    pub fn enable_ats_for_device(
        &self,
        device: DeviceId,
        trust_level: crate::io::iommu::runtime::security::DeviceTrustLevel,
    ) -> bool {
        use crate::io::iommu::runtime::security::{
            AtsChangeReason, DeviceTrustLevel, SecurityEvent,
        };
        use crate::io::iommu::backends::intel::controller::qi_ops::InvalidationOps;

        // Security: ATS requires Queued Invalidation for proper Device-TLB flushing.
        if !self.is_queued_invalidation_enabled() {
            log::error!(
                "[IOMMU] Blocked ATS for device {:04X}:{:02X}.{:X} - QI is disabled",
                device.bus, device.device, device.function
            );
            return false;
        }

        // Block ATS for untrusted devices
        if trust_level == DeviceTrustLevel::Untrusted {
            log::warn!(
                "[IOMMU] ATS blocked for untrusted device {:04X}:{:02X}.{:X} - \
                 external/hot-pluggable devices should not use ATS",
                device.bus,
                device.device,
                device.function
            );

            // Notify security monitor about the blocked attempt
            if let Some(notifier) = self.security_notifier.get() {
                notifier.notify(SecurityEvent::AtsEnabledForUntrustedDevice {
                    source_id: device.requester_id(),
                    vendor_id: 0, // TODO: Get from PCI config
                    device_id: 0,
                    trust_level,
                });
            }
            return false;
        }

        // Warn for partially trusted devices
        if trust_level == DeviceTrustLevel::Partial {
            log::info!(
                "[IOMMU] ATS enabled for partially-trusted device {:04X}:{:02X}.{:X} - \
                 consider verifying device firmware",
                device.bus,
                device.device,
                device.function
            );

            if let Some(notifier) = self.security_notifier.get() {
                notifier.notify(SecurityEvent::AtsEnabledForUntrustedDevice {
                    source_id: device.requester_id(),
                    vendor_id: 0,
                    device_id: 0,
                    trust_level,
                });
            }
        }

        match self.ats_enabled_devices.lock() {
            Ok(mut set) => {
                set.insert(device);
                log::debug!(
                    "[IOMMU] ATS enabled for device {:04X}:{:02X}.{:X}",
                    device.bus,
                    device.device,
                    device.function
                );

                // Notify state change
                if let Some(notifier) = self.security_notifier.get() {
                    notifier.notify(SecurityEvent::AtsStateChanged {
                        source_id: device.requester_id(),
                        enabled: true,
                        reason: AtsChangeReason::DriverInit,
                    });
                }
                true
            }
            Err(_) => {
                log::error!("Failed to lock ats_enabled_devices - ATS not enabled");
                false
            }
        }
    }

    /// Disable ATS (Address Translation Services) for a device
    ///
    /// This should be called when:
    /// - Device is being detached or hot-unplugged
    /// - Security policy requires ATS to be disabled
    /// - Device has experienced fault storms
    /// - Device isolation is triggered
    ///
    /// # Arguments
    ///
    /// * `device` - Device ID (Bus/Device/Function)
    /// * `reason` - Reason for disabling ATS
    ///
    /// # Note
    ///
    /// After disabling ATS, a Device-TLB invalidation should be issued to
    /// ensure the device does not use stale cached translations.
    pub fn disable_ats_for_device(
        &self,
        device: DeviceId,
        reason: crate::io::iommu::runtime::security::AtsChangeReason,
    ) {
        use crate::io::iommu::backends::intel::controller::qi_ops::InvalidationOps;
        use crate::io::iommu::runtime::security::SecurityEvent;

        match self.ats_enabled_devices.lock() {
            Ok(mut set) => {
                if set.remove(&device) {
                    log::info!(
                        "[IOMMU] ATS disabled for device {:04X}:{:02X}.{:X} (reason: {:?})",
                        device.bus,
                        device.device,
                        device.function,
                        reason
                    );

                    // Notify state change
                    if let Some(notifier) = self.security_notifier.get() {
                        notifier.notify(SecurityEvent::AtsStateChanged {
                            source_id: device.requester_id(),
                            enabled: false,
                            reason,
                        });
                    }

                    // Issue Device-TLB invalidation to clear stale entries
                    // Note: This is best-effort since the device may not respond
                    let _ = self.qi_invalidate_device_tlb_all(device.requester_id());
                }
            }
            Err(_) => {
                log::error!("Failed to lock ats_enabled_devices - cannot disable ATS");
            }
        }
    }

    /// Check if ATS is enabled for a device
    pub fn is_ats_enabled(&self, device: &DeviceId) -> bool {
        match self.ats_enabled_devices.lock() {
            Ok(set) => set.contains(device),
            Err(_) => {
                log::error!("Failed to lock ats_enabled_devices - assuming disabled");
                false
            }
        }
    }

    // Removed: `enable_ats_for_device_legacy` (was deprecated).
    // Migration: Use `enable_ats_for_device(device, trust_level)` instead.
}
