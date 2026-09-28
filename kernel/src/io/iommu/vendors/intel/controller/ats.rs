//! Own PCI ATS configuration and translation-cache invalidation as one lifecycle.
#![forbid(unsafe_code)]

use pci_driver::AtsController;

use super::IommuController;
use super::qi_ops::InvalidationOps;
use crate::io::iommu::runtime::security::{AtsChangeReason, DeviceTrustLevel, SecurityEvent};
use crate::io::iommu::types::{DeviceId, IommuError};
use crate::io::iommu::vendors::intel::registers::ecap_bits;

/// A PCI configuration error after publication does not return the resource:
/// hardware may already cache translations, so the controller retains it.
pub(crate) enum AtsEnableError {
    Rejected {
        cause: IommuError,
        resource: AtsController,
    },
    Retained {
        cause: IommuError,
        device: DeviceId,
    },
}

enum AtsState {
    PossiblyEnabled,
    Enabled,
    DisabledAwaitingInvalidation,
}

pub(super) struct AtsDevice {
    resource: AtsController,
    state: AtsState,
}

impl IommuController {
    /// Resource admission only; this does not establish hardware enablement.
    /// The publication operation rechecks admission before consuming a resource.
    pub(crate) fn check_ats_admission(&self, trust: DeviceTrustLevel) -> Result<(), IommuError> {
        check_admission(
            trust,
            (self.ecap & ecap_bits::ECAP_DT) != 0,
            self.is_queued_invalidation_enabled(),
        )
    }

    /// Consume a PCI resource before making hardware ATS visible. Every published
    /// resource, including an unknown outcome, participates in global invalidation.
    ///
    /// # Errors
    /// Rejection returns the resource without issuing configuration writes.
    /// Failure after insertion retains it in this controller until explicit close.
    pub(crate) fn enable_ats(
        &self,
        resource: AtsController,
        trust: DeviceTrustLevel,
    ) -> Result<(), AtsEnableError> {
        if let Err(cause) = self.check_ats_admission(trust) {
            return Err(AtsEnableError::Rejected { cause, resource });
        }
        let bdf = resource.bdf();
        let device = DeviceId::new(resource.segment(), bdf.bus, bdf.device, bdf.function);
        if device.segment != self.segment {
            return Err(AtsEnableError::Rejected {
                cause: IommuError::InvalidAddress,
                resource,
            });
        }
        let domains = match self.device_domains.lock() {
            Ok(domains) => domains,
            Err(_) => {
                return Err(AtsEnableError::Rejected {
                    cause: IommuError::Poisoned,
                    resource,
                });
            }
        };
        if !domains.contains_key(&device) {
            return Err(AtsEnableError::Rejected {
                cause: IommuError::DeviceNotFound,
                resource,
            });
        }
        let mut devices = match self.ats_devices.lock() {
            Ok(devices) => devices,
            Err(_) => {
                return Err(AtsEnableError::Rejected {
                    cause: IommuError::Poisoned,
                    resource,
                });
            }
        };
        let entry = match devices.entry(device) {
            alloc::collections::btree_map::Entry::Vacant(entry) => entry,
            alloc::collections::btree_map::Entry::Occupied(_) => {
                return Err(AtsEnableError::Rejected {
                    cause: IommuError::AlreadyInitialized,
                    resource,
                });
            }
        };
        // BTree storage is acquired before any hardware write. No allocation is
        // introduced after acceptance, including the error-retention path.
        let tracked = entry.insert(AtsDevice {
            resource,
            state: AtsState::PossiblyEnabled,
        });
        if let Err(cause) = tracked.resource.enable_ats(0) {
            return Err(AtsEnableError::Retained {
                cause: IommuError::PciConfiguration(cause),
                device,
            });
        }
        tracked.state = AtsState::Enabled;
        drop(devices);
        drop(domains);
        if trust == DeviceTrustLevel::Partial {
            self.notify_security(SecurityEvent::AtsEnabledForUntrustedDevice {
                source_id: device.requester_id(),
                vendor_id: 0,
                device_id: 0,
                trust_level: trust,
            });
        }
        self.notify_security(SecurityEvent::AtsStateChanged {
            source_id: device.requester_id(),
            enabled: true,
            reason: AtsChangeReason::DriverInit,
        });
        Ok(())
    }

    /// Observe PCI disablement, then Device-TLB completion, before releasing the
    /// resource. A failed configuration read/write or invalidation keeps the owner.
    ///
    /// # Errors
    /// Poisoning leaves ownership unchanged. Configuration failure records unknown
    /// hardware state; invalidation failure retains confirmed PCI disablement so a
    /// retry repeats only the remaining invalidation step.
    pub(crate) fn close_ats(
        &self,
        device: DeviceId,
        reason: AtsChangeReason,
    ) -> Result<(), IommuError> {
        let mut devices = self.ats_devices.lock().map_err(|_| IommuError::Poisoned)?;
        let Some(tracked) = devices.get_mut(&device) else {
            return Ok(());
        };
        if !matches!(tracked.state, AtsState::DisabledAwaitingInvalidation) {
            tracked.state = AtsState::PossiblyEnabled;
            tracked
                .resource
                .disable_ats()
                .map_err(IommuError::PciConfiguration)?;
            tracked.state = AtsState::DisabledAwaitingInvalidation;
        }
        self.qi_invalidate_device_tlb_all(device.requester_id())?;
        self.qi_wait_sync()?;
        devices.remove(&device);
        drop(devices);
        self.notify_security(SecurityEvent::AtsStateChanged {
            source_id: device.requester_id(),
            enabled: false,
            reason,
        });
        Ok(())
    }
}

fn check_admission(
    trust: DeviceTrustLevel,
    device_tlb_supported: bool,
    queued_invalidation: bool,
) -> Result<(), IommuError> {
    if trust == DeviceTrustLevel::Untrusted {
        return Err(IommuError::AtsPolicyDenied);
    }
    if !device_tlb_supported || !queued_invalidation {
        return Err(IommuError::NotSupported);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn ats_policy_requires_both_translation_and_completion_support() {
        assert_eq!(
            check_admission(DeviceTrustLevel::Trusted, true, false),
            Err(IommuError::NotSupported)
        );
        assert_eq!(
            check_admission(DeviceTrustLevel::Trusted, false, true),
            Err(IommuError::NotSupported)
        );
        assert_eq!(
            check_admission(DeviceTrustLevel::Trusted, true, true),
            Ok(())
        );
        assert_eq!(
            check_admission(DeviceTrustLevel::Partial, true, true),
            Ok(())
        );
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn untrusted_device_is_not_admitted_even_with_hardware_support() {
        assert_eq!(
            check_admission(DeviceTrustLevel::Untrusted, true, true),
            Err(IommuError::AtsPolicyDenied)
        );
    }
}
