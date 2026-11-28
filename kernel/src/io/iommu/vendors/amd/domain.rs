// ============================================================================
// kernel/src/io/iommu/vendors/amd/domain.rs
// ============================================================================

//! AMD-Vi domain management, device attach/detach, and DTE construction.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::io::iommu::common::domain::IommuDomain as DomainState;
use crate::io::iommu::common::tables::virt_ptr_to_phys;
use crate::io::iommu::types::{DeviceId, IommuDomainType, IommuError, PteFormat};
use crate::mm::types::PAGE_SIZE_4K;
use acpi_driver::ivrs::IvhdDeviceEntry;

use super::device_table::{AmdDeviceTable, AmdDeviceTableEntry};
use super::registers::*;
use super::{AmdDomainInfo, AmdIommuDriver, AmdIvmdRange};

// ---------------------------------------------------------------------------
// Alignment helpers
// ---------------------------------------------------------------------------

mod driver_ops;

#[derive(Debug)]
pub(super) struct AmdDeviceBinding {
    unit: usize,
    requesters: Vec<u16>,
    state: BindingState,
}

#[derive(Debug)]
enum BindingState {
    Publishing(Attachment),
    Attached(Attachment),
    Blocking {
        attachment: Option<Attachment>,
        isolate: bool,
    },
    Isolated,
}

#[derive(Debug)]
struct Attachment {
    domain: Arc<DomainState>,
    interrupts: Option<super::irt::InterruptTable>,
}

impl AmdDeviceBinding {
    pub(super) fn requesters(&self) -> (usize, &[u16]) {
        (self.unit, &self.requesters)
    }
}

pub(super) fn align_down(value: u64, align: usize) -> u64 {
    crate::util::align_down_u64(value, align as u64)
}

pub(super) fn align_up(value: u64, align: usize) -> u64 {
    crate::util::align_up_u64(value, align as u64)
}

// ---------------------------------------------------------------------------
// IVMD range mapping
// ---------------------------------------------------------------------------

/// Collect aligned exclusion ranges from IVMD entries.
fn collect_exclusion_ranges(ranges: &[AmdIvmdRange], page_size: usize) -> Vec<(u64, u64)> {
    let mut exclusions = Vec::new();
    for range in ranges {
        if !range.exclusion {
            continue;
        }
        let start = align_down(range.range_start, page_size);
        let end = align_up(range.range_end, page_size);
        if end <= start {
            continue;
        }
        exclusions.push((start, end));
    }
    exclusions
}

/// Remove exclusion ranges from segments, splitting as needed.
fn subtract_exclusions(
    mut segments: Vec<(u64, u64)>,
    exclusions: &[(u64, u64)],
) -> Vec<(u64, u64)> {
    for (ex_start, ex_end) in exclusions {
        let mut next = Vec::new();
        for (seg_start, seg_end) in segments {
            if *ex_end <= seg_start || *ex_start >= seg_end {
                next.push((seg_start, seg_end));
                continue;
            }
            if *ex_start > seg_start {
                next.push((seg_start, *ex_start));
            }
            if *ex_end < seg_end {
                next.push((*ex_end, seg_end));
            }
        }
        segments = next;
        if segments.is_empty() {
            break;
        }
    }
    segments
}

/// Map a set of (start, end) segments into the domain with the given permissions.
fn map_unity_segments(
    domain: &DomainState,
    segments: Vec<(u64, u64)>,
    read: bool,
    write: bool,
) -> Result<(), IommuError> {
    for (seg_start, seg_end) in segments {
        if seg_end <= seg_start {
            continue;
        }
        let size = seg_end - seg_start;
        // Security: Unity map (IVMD) regions are trusted system regions.
        // We use map_privileged to allow mapping BIOS-reserved memory.
        match unsafe { domain.map_privileged(seg_start, seg_start, size, read, write) } {
            Ok(()) | Err(IommuError::AlreadyMapped) => {}
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

pub(crate) fn map_ivmd_ranges(
    domain: &DomainState,
    ranges: &[AmdIvmdRange],
) -> Result<(), IommuError> {
    let page_size = PAGE_SIZE_4K;
    let exclusions = collect_exclusion_ranges(ranges, page_size);

    for range in ranges {
        if !range.unity_map || range.exclusion {
            continue;
        }

        let start = align_down(range.range_start, page_size);
        let end = align_up(range.range_end, page_size);
        if end <= start {
            continue;
        }

        let segments = subtract_exclusions(alloc::vec![(start, end)], &exclusions);
        map_unity_segments(domain, segments, range.read, range.write)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Domain management methods on AmdIommuDriver
// ---------------------------------------------------------------------------

/// デバイスIDが範囲内にあるかチェックする
pub(super) fn devid_in_range(devid: u16, start: u16, end: u16) -> bool {
    devid >= start && devid <= end
}

/// Check if an IVHD device entry matches a given device ID and return its flags.
pub(super) fn ivhd_entry_flags_for_devid(entry: &IvhdDeviceEntry, devid: u16) -> u8 {
    match entry {
        IvhdDeviceEntry::All { flags } => *flags,
        IvhdDeviceEntry::Select { devid: e, flags }
        | IvhdDeviceEntry::ExtSelect {
            devid: e, flags, ..
        }
        | IvhdDeviceEntry::Special {
            devid: e, flags, ..
        }
        | IvhdDeviceEntry::AcpiHid { devid: e, flags } => {
            if *e == devid {
                *flags
            } else {
                0
            }
        }
        IvhdDeviceEntry::Range { start, end, flags }
        | IvhdDeviceEntry::ExtRange {
            start, end, flags, ..
        } => {
            if devid_in_range(devid, *start, *end) {
                *flags
            } else {
                0
            }
        }
        IvhdDeviceEntry::Alias {
            devid: e,
            alias,
            flags,
        } => {
            if *e == devid || *alias == devid {
                *flags
            } else {
                0
            }
        }
        IvhdDeviceEntry::AliasRange {
            start,
            end,
            alias,
            flags,
        } => {
            if devid_in_range(devid, *start, *end) || *alias == devid {
                *flags
            } else {
                0
            }
        }
    }
}

pub(super) fn flags_for_entries(entries: &[IvhdDeviceEntry], devid: u16) -> u8 {
    entries.iter().fold(0, |flags, entry| {
        flags | ivhd_entry_flags_for_devid(entry, devid)
    })
}

/// Derive the lookup from the immutable IVRS inventory once, before admitting DMA.
pub(super) fn requester_aliases(
    units: &[super::AmdIommuUnit],
) -> Result<hashbrown::HashMap<DeviceId, DeviceId>, IommuError> {
    let mut aliases = hashbrown::HashMap::new();
    for unit in units {
        add_requester_aliases(&mut aliases, unit.segment, &unit.device_entries)?;
    }
    Ok(aliases)
}

fn add_requester_aliases(
    aliases: &mut hashbrown::HashMap<DeviceId, DeviceId>,
    segment: u16,
    entries: &[IvhdDeviceEntry],
) -> Result<(), IommuError> {
    for entry in entries {
        let (start, end, alias) = match *entry {
            IvhdDeviceEntry::Alias { devid, alias, .. } => (devid, devid, alias),
            IvhdDeviceEntry::AliasRange {
                start, end, alias, ..
            } => (start, end, alias),
            _ => continue,
        };
        if start > end {
            return Err(IommuError::FirmwareScope);
        }
        aliases
            .try_reserve(usize::from(end - start) + 1)
            .map_err(|_| IommuError::MetadataAllocation)?;
        let canonical = DeviceId::from_bus_devfn(segment, (alias >> 8) as u8, alias as u8);
        for source in start..=end {
            if source == alias {
                continue;
            }
            let source = DeviceId::from_bus_devfn(segment, (source >> 8) as u8, source as u8);
            if aliases
                .insert(source, canonical)
                .is_some_and(|old| old != canonical)
            {
                return Err(IommuError::FirmwareScope);
            }
        }
    }
    Ok(())
}

pub(super) fn reject_excluded_ranges(
    ranges: &[AmdIvmdRange],
    physical: u64,
    size: u64,
) -> Result<(), IommuError> {
    if size == 0 {
        return Ok(());
    }
    let end = physical
        .checked_add(size)
        .ok_or(IommuError::InvalidAddress)?;
    if ranges.iter().any(|range| {
        range.exclusion
            && range.range_start < range.range_end
            && physical < range.range_end
            && end > range.range_start
    }) {
        return Err(IommuError::InvalidAddress);
    }
    Ok(())
}

#[cfg(test)]
mod alias_tests {
    use super::*;

    #[cfg_attr(any(feature = "std", target_os = "linux"), test)]
    #[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
    fn alias_cohorts_are_segment_local_and_reject_ambiguous_requesters() {
        let mut aliases = hashbrown::HashMap::new();
        let range = IvhdDeviceEntry::AliasRange {
            start: 0x108,
            end: 0x10f,
            alias: 0x204,
            flags: 0,
        };
        add_requester_aliases(&mut aliases, 1, &[range]).unwrap();
        assert_eq!(aliases.len(), 8);
        let source = DeviceId::from_bus_devfn(1, 1, 8);
        assert_eq!(aliases[&source], DeviceId::from_bus_devfn(1, 2, 4));
        assert!(!aliases.contains_key(&DeviceId::from_bus_devfn(0, 1, 8)));

        let conflicting = IvhdDeviceEntry::Alias {
            devid: 0x108,
            alias: 0x208,
            flags: 0,
        };
        assert_eq!(
            add_requester_aliases(&mut aliases, 1, &[conflicting]),
            Err(IommuError::FirmwareScope)
        );
    }
}
