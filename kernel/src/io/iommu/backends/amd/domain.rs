// ============================================================================
// kernel/src/io/iommu/backends/amd/domain.rs
// ============================================================================

//! AMD-Vi domain management, device attach/detach, and DTE construction.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::io::acpi::ivrs::IvhdDeviceEntry;
use crate::io::iommu::core::domain::IommuDomain as DomainState;
use crate::io::iommu::core::tables::virt_ptr_to_phys;
use crate::io::iommu::types::{DeviceId, IommuDomainType, IommuError, PteFormat};
use crate::mm::types::PAGE_SIZE_4K;

use super::device_table::{apply_ivhd_flags, AmdDeviceTable, AmdDeviceTableEntry};
use super::registers::*;
use super::{AmdIommuDriver, AmdIvmdRange, AmdDomainInfo};

// ---------------------------------------------------------------------------
// Alignment helpers
// ---------------------------------------------------------------------------

mod driver_ops;
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

pub(super) fn map_ivmd_ranges(domain: &DomainState, ranges: &[AmdIvmdRange]) -> Result<(), IommuError> {
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
        | IvhdDeviceEntry::ExtSelect { devid: e, flags, .. }
        | IvhdDeviceEntry::Special { devid: e, flags, .. }
        | IvhdDeviceEntry::AcpiHid { devid: e, flags } => {
            if *e == devid { *flags } else { 0 }
        }
        IvhdDeviceEntry::Range { start, end, flags }
        | IvhdDeviceEntry::ExtRange { start, end, flags, .. } => {
            if devid_in_range(devid, *start, *end) { *flags } else { 0 }
        }
        IvhdDeviceEntry::Alias { devid: e, alias, flags } => {
            if *e == devid || *alias == devid { *flags } else { 0 }
        }
        IvhdDeviceEntry::AliasRange { start, end, alias, flags } => {
            if devid_in_range(devid, *start, *end) || *alias == devid { *flags } else { 0 }
        }
    }
}
