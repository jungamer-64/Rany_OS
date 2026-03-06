// ============================================================================
// kernel/src/io/iommu/vendors/amd/ivrs_utils.rs
// ============================================================================

//! Helpers for dealing with IVRS/IVHD/IVMD entries.
//!
//! The routines in this module are used by various pieces of the AMD-Vi
//! backend.  They were originally defined inside `qemu_tests.rs` purely to
//! support the smoke‑test exports, but the logic is genuinely part of the
//! backend and should live in a shared helper module.  Keeping them here keeps
//! the `qemu_tests` file focused solely on the export/test interface.

use crate::io::acpi::ivrs::IvhdDeviceEntry;
use crate::io::iommu::types::{DeviceId, IommuError};

use alloc::vec::Vec;

use super::AmdIvmdRange;

/// Returns true if `entries` cover the specified device ID.
///
/// This is essentially the same predicate used by the AMD specification when
/// building filter ranges from IVHD tables.
pub(super) fn unit_covers_devid(entries: &[IvhdDeviceEntry], devid: u16) -> bool {
    entries.iter().any(|entry| match entry {
        IvhdDeviceEntry::All { .. } => true,
        IvhdDeviceEntry::Select {
            devid: entry_devid, ..
        } => *entry_devid == devid,
        IvhdDeviceEntry::Range { start, end, .. } => devid >= *start && devid <= *end,
        IvhdDeviceEntry::Alias {
            devid: entry_devid,
            alias,
            ..
        } => *entry_devid == devid || *alias == devid,
        IvhdDeviceEntry::AliasRange {
            start, end, alias, ..
        } => (devid >= *start && devid <= *end) || *alias == devid,
        IvhdDeviceEntry::ExtSelect {
            devid: entry_devid, ..
        } => *entry_devid == devid,
        IvhdDeviceEntry::ExtRange { start, end, .. } => devid >= *start && devid <= *end,
        IvhdDeviceEntry::Special {
            devid: entry_devid, ..
        } => *entry_devid == devid,
        IvhdDeviceEntry::AcpiHid {
            devid: entry_devid, ..
        } => *entry_devid == devid,
    })
}

/// Collects alias IDs from `entries` that apply to `device`.
pub(super) fn alias_devids_for_entries(entries: &[IvhdDeviceEntry], device: DeviceId) -> Vec<u16> {
    let mut aliases = Vec::new();
    let devid = device.requester_id();

    if !unit_covers_devid(entries, devid) {
        return aliases;
    }

    for entry in entries {
        match entry {
            IvhdDeviceEntry::Alias {
                devid: entry_devid,
                alias,
                ..
            } => {
                if *entry_devid == devid && *alias != devid {
                    aliases.push(*alias);
                }
            }
            IvhdDeviceEntry::AliasRange {
                start, end, alias, ..
            } => {
                if devid >= *start && devid <= *end && *alias != devid {
                    aliases.push(*alias);
                }
            }
            _ => {}
        }
    }

    aliases.sort_unstable();
    aliases.dedup();
    aliases
}

/// Compute the combined IVHD flags for a particular device ID.
pub(super) fn ivhd_flags_for_entries(entries: &[IvhdDeviceEntry], device: DeviceId) -> u8 {
    let devid = device.requester_id();
    let mut flags = 0u8;

    if !unit_covers_devid(entries, devid) {
        return flags;
    }

    for entry in entries {
        match entry {
            IvhdDeviceEntry::All { flags: entry_flags } => flags |= *entry_flags,
            IvhdDeviceEntry::Select {
                devid: entry_devid,
                flags: entry_flags,
            } => {
                if *entry_devid == devid {
                    flags |= *entry_flags;
                }
            }
            IvhdDeviceEntry::Range {
                start,
                end,
                flags: entry_flags,
            } => {
                if devid >= *start && devid <= *end {
                    flags |= *entry_flags;
                }
            }
            IvhdDeviceEntry::Alias {
                devid: entry_devid,
                alias,
                flags: entry_flags,
            } => {
                if *entry_devid == devid || *alias == devid {
                    flags |= *entry_flags;
                }
            }
            IvhdDeviceEntry::AliasRange {
                start,
                end,
                alias,
                flags: entry_flags,
            } => {
                if (devid >= *start && devid <= *end) || *alias == devid {
                    flags |= *entry_flags;
                }
            }
            IvhdDeviceEntry::ExtSelect {
                devid: entry_devid,
                flags: entry_flags,
                ..
            } => {
                if *entry_devid == devid {
                    flags |= *entry_flags;
                }
            }
            IvhdDeviceEntry::ExtRange {
                start,
                end,
                flags: entry_flags,
                ..
            } => {
                if devid >= *start && devid <= *end {
                    flags |= *entry_flags;
                }
            }
            IvhdDeviceEntry::Special {
                devid: entry_devid,
                flags: entry_flags,
                ..
            } => {
                if *entry_devid == devid {
                    flags |= *entry_flags;
                }
            }
            IvhdDeviceEntry::AcpiHid {
                devid: entry_devid,
                flags: entry_flags,
            } => {
                if *entry_devid == devid {
                    flags |= *entry_flags;
                }
            }
        }
    }

    flags
}

/// Validate that an address range does not fall into an excluded IVMD range for
/// the given device.
pub(super) fn reject_excluded_ivmd_range_for_device(
    ranges: &[AmdIvmdRange],
    device: DeviceId,
    phys_addr: u64,
    size: u64,
) -> Result<(), IommuError> {
    if size == 0 {
        return Ok(());
    }

    let devid = device.requester_id();
    let end = phys_addr
        .checked_add(size)
        .ok_or(IommuError::InvalidAddress)?;

    for range in ranges {
        if range.segment != device.segment {
            continue;
        }
        if devid < range.devid_start || devid > range.devid_end {
            continue;
        }
        if !range.exclusion {
            continue;
        }
        if range.range_end <= range.range_start {
            continue;
        }
        if phys_addr < range.range_end && end > range.range_start {
            return Err(IommuError::InvalidAddress);
        }
    }

    Ok(())
}
