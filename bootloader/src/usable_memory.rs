//! Pure RAM normalization from a complete firmware snapshot and explicitly
//! owned handoff allocation geometry. No pointer dereference or publication
//! authority is recovered from ABI table metadata.

#![forbid(unsafe_code)]

use boot_proto::UsableMemoryRegion;

const MIN_USABLE_PHYS_ADDR: u64 = 0x0100_0000;
const EFI_PAGE_SIZE: u64 = 4096;
const EFI_MEMORY_TYPE_BOOT_SERVICES_CODE: u32 = 3;
const EFI_MEMORY_TYPE_BOOT_SERVICES_DATA: u32 = 4;
const EFI_MEMORY_TYPE_CONVENTIONAL: u32 = 7;
pub(crate) const MAX_USABLE_MEMORY_REGIONS: usize = 1024;
const MAX_USABLE_TEMP_REGIONS: usize = 256;

fn is_usable_efi_memory_type(memory_type: u32) -> bool {
    matches!(
        memory_type,
        EFI_MEMORY_TYPE_BOOT_SERVICES_CODE
            | EFI_MEMORY_TYPE_BOOT_SERVICES_DATA
            | EFI_MEMORY_TYPE_CONVENTIONAL
    )
}

fn validated_region(desc: &boot_proto::MemoryDescriptor) -> Option<UsableMemoryRegion> {
    if !is_usable_efi_memory_type(desc.r#type) || desc.page_count == 0 {
        return None;
    }

    let size = desc.page_count.checked_mul(EFI_PAGE_SIZE)?;
    let start = desc.phys_start.max(MIN_USABLE_PHYS_ADDR);
    let end = desc.phys_start.checked_add(size)?;
    if end <= start {
        return None;
    }

    Some(UsableMemoryRegion {
        base: start,
        length: end - start,
    })
}

fn push_region(
    dst: &mut [UsableMemoryRegion],
    count: &mut usize,
    base: u64,
    length: u64,
) -> Option<()> {
    if length == 0 {
        return Some(());
    }
    if *count >= dst.len() {
        return None;
    }
    dst[*count] = UsableMemoryRegion { base, length };
    *count += 1;
    Some(())
}

fn subtract_reserved_range(
    src: &[UsableMemoryRegion],
    dst: &mut [UsableMemoryRegion],
    reserved_start: u64,
    reserved_size: u64,
) -> Option<usize> {
    if reserved_size == 0 {
        let copy_count = src.len().min(dst.len());
        dst[..copy_count].copy_from_slice(&src[..copy_count]);
        return (copy_count == src.len()).then_some(copy_count);
    }

    let reserved_end = reserved_start.saturating_add(reserved_size);
    let mut count = 0usize;

    for region in src {
        let start = region.base;
        let end = start.saturating_add(region.length);
        if reserved_end <= start || reserved_start >= end {
            push_region(dst, &mut count, start, end.saturating_sub(start))?;
            continue;
        }
        if start < reserved_start {
            push_region(dst, &mut count, start, reserved_start.saturating_sub(start))?;
        }
        if end > reserved_end {
            push_region(
                dst,
                &mut count,
                reserved_end,
                end.saturating_sub(reserved_end),
            )?;
        }
    }

    Some(count)
}

fn span_with_trailing_nul(span: boot_proto::BootHhdmSpan) -> Option<boot_proto::BootHhdmSpan> {
    boot_proto::BootHhdmSpan::new(span.start(), span.len().checked_add(1)?).ok()
}

fn addr_to_phys(addr: u64, hhdm_start: u64) -> Option<u64> {
    if addr == 0 {
        return None;
    }
    if addr >= hhdm_start {
        Some(addr - hhdm_start)
    } else {
        Some(addr)
    }
}

fn apply_reserved_hhdm_span(
    current: &mut [UsableMemoryRegion; MAX_USABLE_TEMP_REGIONS],
    next: &mut [UsableMemoryRegion; MAX_USABLE_TEMP_REGIONS],
    current_count: usize,
    span: Option<boot_proto::BootHhdmSpan>,
    hhdm_start: u64,
) -> Option<usize> {
    let (start, size) = span
        .and_then(|span| span.phys_range(hhdm_start))
        .map_or((None, 0), |(start, size)| (Some(start), size));
    apply_reserved_range(current, next, current_count, start, size)
}

fn apply_reserved_range(
    current: &mut [UsableMemoryRegion; MAX_USABLE_TEMP_REGIONS],
    next: &mut [UsableMemoryRegion; MAX_USABLE_TEMP_REGIONS],
    current_count: usize,
    start: Option<u64>,
    size: u64,
) -> Option<usize> {
    let Some(start) = start else {
        return Some(current_count);
    };
    let next_count =
        subtract_reserved_range(&current[..current_count], &mut next[..], start, size)?;
    current[..next_count].copy_from_slice(&next[..next_count]);
    Some(next_count)
}

fn append_region_coalesced(
    output: &mut [UsableMemoryRegion],
    output_count: &mut usize,
    base: u64,
    length: u64,
) -> bool {
    if length == 0 {
        return true;
    }

    if *output_count > 0 {
        let prev = &mut output[*output_count - 1];
        if prev.base.saturating_add(prev.length) == base {
            prev.length = prev.length.saturating_add(length);
            return true;
        }
    }

    if *output_count >= output.len() {
        return false;
    }
    output[*output_count] = UsableMemoryRegion { base, length };
    *output_count += 1;
    true
}

/// All handoff-owned ranges that must be excluded before RAM publication.
pub(crate) struct HandoffReservations<'a> {
    pub(crate) boot_info: &'a boot_proto::ExoBootInfo,
    pub(crate) artifact_allocation: Option<(u64, u64)>,
    pub(crate) segment_info: &'a [(u64, u64, u64)],
    pub(crate) boot_info_allocation: (u64, u64),
    pub(crate) map_allocation: (u64, u64),
    pub(crate) usable_allocation: (u64, u64),
}

fn build_usable_memory_regions(
    descriptors: &[boot_proto::MemoryDescriptor],
    output: &mut [UsableMemoryRegion],
    reservations: &HandoffReservations<'_>,
) -> Option<usize> {
    let boot_info = reservations.boot_info;
    let (mmap_buffer_phys, mmap_buffer_bytes) = reservations.map_allocation;
    let (usable_buffer_phys, usable_buffer_bytes) = reservations.usable_allocation;
    let hhdm_start = boot_info.phys_mem_offset;
    let mut output_count = 0usize;

    for desc in descriptors {
        let Some(region) = validated_region(desc) else {
            continue;
        };

        let mut current = [UsableMemoryRegion::default(); MAX_USABLE_TEMP_REGIONS];
        let mut next = [UsableMemoryRegion::default(); MAX_USABLE_TEMP_REGIONS];
        current[0] = region;
        let mut current_count = 1usize;

        current_count = apply_reserved_range(
            &mut current,
            &mut next,
            current_count,
            Some(reservations.boot_info_allocation.0),
            reservations.boot_info_allocation.1,
        )?;
        current_count = apply_reserved_range(
            &mut current,
            &mut next,
            current_count,
            Some(mmap_buffer_phys),
            mmap_buffer_bytes,
        )?;
        current_count = apply_reserved_range(
            &mut current,
            &mut next,
            current_count,
            Some(usable_buffer_phys),
            usable_buffer_bytes,
        )?;
        current_count = apply_reserved_hhdm_span(
            &mut current,
            &mut next,
            current_count,
            boot_info.cmdline_span().and_then(span_with_trailing_nul),
            hhdm_start,
        )?;
        if let Some((start, bytes)) = reservations.artifact_allocation {
            current_count =
                apply_reserved_range(&mut current, &mut next, current_count, Some(start), bytes)?;
        }

        current_count = apply_reserved_range(
            &mut current,
            &mut next,
            current_count,
            addr_to_phys(boot_info.framebuffer.address, hhdm_start),
            boot_info.framebuffer.size() as u64,
        )?;
        let (trampoline_start, trampoline_size) = if boot_info.ap_trampoline.is_present() {
            (
                Some(boot_info.ap_trampoline.physical_address),
                u64::from(boot_info.ap_trampoline.byte_len),
            )
        } else {
            (None, 0)
        };
        current_count = apply_reserved_range(
            &mut current,
            &mut next,
            current_count,
            trampoline_start,
            trampoline_size,
        )?;
        let runtime_count = usize::try_from(boot_info.uefi_runtime.runtime_mmap_count)
            .unwrap_or(usize::MAX)
            .min(boot_info.uefi_runtime.runtime_mmap.len());
        for runtime_region in &boot_info.uefi_runtime.runtime_mmap[..runtime_count] {
            current_count = apply_reserved_range(
                &mut current,
                &mut next,
                current_count,
                Some(runtime_region.phys_addr),
                runtime_region.page_count.saturating_mul(EFI_PAGE_SIZE),
            )?;
        }

        for &(_virt, phys, size) in reservations.segment_info {
            current_count =
                apply_reserved_range(&mut current, &mut next, current_count, Some(phys), size)?;
        }

        for region in &current[..current_count] {
            if !append_region_coalesced(output, &mut output_count, region.base, region.length) {
                return None;
            }
        }
    }

    Some(output_count)
}

#[derive(Debug)]
pub(crate) enum UsableMemoryError {
    NormalizationIncomplete,
    AddressOverflow,
    InvalidSpan(&'static str),
}

impl core::fmt::Display for UsableMemoryError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NormalizationIncomplete => {
                formatter.write_str("usable-memory output or reservation workspace exhausted")
            }
            Self::AddressOverflow => formatter.write_str("usable-memory HHDM address overflowed"),
            Self::InvalidSpan(cause) => write!(formatter, "invalid usable-memory handoff: {cause}"),
        }
    }
}

/// Computes usable RAM from the completed owned descriptor snapshot, not from
/// independently interpreted raw table metadata. Failed normalization returns
/// no prefix; the kernel's existing raw-map fallback receives the complete map.
///
/// # Errors
/// Reports normalization exhaustion or invalid output handoff geometry. The raw
/// input stays immutable; the partially written output is unpublished.
pub(crate) fn build_usable_memory_table(
    descriptors: &[boot_proto::MemoryDescriptor],
    output: &mut [UsableMemoryRegion],
    reservations: &HandoffReservations<'_>,
) -> Result<boot_proto::UsableMemoryTable, UsableMemoryError> {
    let count = build_usable_memory_regions(descriptors, output, reservations)
        .ok_or(UsableMemoryError::NormalizationIncomplete)?;
    let address = reservations
        .boot_info
        .phys_mem_offset
        .checked_add(reservations.usable_allocation.0)
        .ok_or(UsableMemoryError::AddressOverflow)?;
    boot_proto::UsableMemoryTable::from_hhdm_addr(address, count)
        .map_err(UsableMemoryError::InvalidSpan)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn desc(memory_type: u32, start: u64, bytes: u64) -> boot_proto::MemoryDescriptor {
        boot_proto::MemoryDescriptor {
            r#type: memory_type,
            pad: 0,
            phys_start: start,
            virt_start: 0,
            page_count: bytes / EFI_PAGE_SIZE,
            attribute: 0,
        }
    }

    fn sample_boot_info(hhdm_start: u64) -> boot_proto::ExoBootInfo {
        let mut boot_info = boot_proto::ExoBootInfo {
            version: boot_proto::EXO_BOOT_INFO_VERSION,
            phys_mem_offset: hhdm_start,
            rsdp_addr: 0,
            ap_trampoline: boot_proto::ApTrampolineDescriptor::new(0x8000).unwrap(),
            cmdline_ptr: 0,
            cmdline_len: 0,
            boot_policy: boot_proto::BootPolicy::default(),
            page_table_base: 0,
            tls_template: boot_proto::TlsInfo::default(),
            memory_map: boot_proto::MemoryMap::default(),
            usable_memory: boot_proto::UsableMemoryTable::default(),
            framebuffer: graphic_types::FramebufferInfo {
                address: 0x1400_5000,
                width: 1,
                height: 1,
                stride: 4,
                format: graphic_types::PixelFormat::Bgra8888,
                bpp: 32,
            },
            boot_artifacts: boot_proto::BootArtifactTable::from_hhdm_addr(
                hhdm_start + 0x1400_1000,
                1,
            )
            .unwrap(),
            uefi_runtime: boot_proto::UefiRuntimeInfo {
                runtime_mmap_count: 1,
                runtime_mmap: [boot_proto::RuntimeMemoryRegion {
                    phys_addr: 0x1400_b000,
                    virt_addr: 0,
                    page_count: 1,
                    memory_type: 0,
                    attributes: 0,
                }; boot_proto::MAX_RUNTIME_MMAP_ENTRIES],
                ..boot_proto::UefiRuntimeInfo::default()
            },
            mem_encryption: boot_proto::MemoryEncryptionInfo::default(),
            secure_boot: boot_proto::SecureBootInfo::default(),
            shim_mok: boot_proto::ShimMokInfo::default(),
            smbios: boot_proto::SmbiosInfo::default(),
            boot_recovery: boot_proto::BootRecoveryInfo::default(),
            self_test: boot_proto::SelfTestInfo::default(),
            paging_levels: 4,
            la57_enabled: 0,
        };
        boot_info.set_cmdline_span(Some(
            boot_proto::BootHhdmSpan::new(hhdm_start + 0x1400_2000, 31).unwrap(),
        ));
        boot_info
    }

    fn overlaps(range: &UsableMemoryRegion, start: u64, end: u64) -> bool {
        let range_end = range.base + range.length;
        range.base < end && start < range_end
    }

    #[test]
    fn usable_memory_builder_excludes_reserved_ranges_and_coalesces_neighbors() {
        let hhdm_start = 0xffff_8000_0000_0000;
        let boot_info = sample_boot_info(hhdm_start);

        let descriptors = [
            desc(EFI_MEMORY_TYPE_CONVENTIONAL, 0x1400_0000, 0x0020_0000),
            desc(EFI_MEMORY_TYPE_CONVENTIONAL, 0x1500_0000, 0x0010_0000),
            desc(EFI_MEMORY_TYPE_CONVENTIONAL, 0x1510_0000, 0x0010_0000),
        ];
        let mut output = [UsableMemoryRegion::default(); 32];
        let segment_info = [(0, 0x1400_9000, 0x2000)];

        let reservations = HandoffReservations {
            boot_info: &boot_info,
            artifact_allocation: Some((0x1400_1000, 0x4000)),
            segment_info: &segment_info,
            boot_info_allocation: (0x1400_0000, 0x1000),
            map_allocation: (0x1400_c000, 0x1000),
            usable_allocation: (0x1400_d000, 0x2000),
        };
        let count = build_usable_memory_regions(&descriptors, &mut output, &reservations)
            .expect("usable memory build should succeed");
        let regions = &output[..count];

        let reserved = [
            (0x1400_0000, 0x1400_1000),
            (0x1400_1000, 0x1400_5000),
            (0x1400_5000, 0x1400_5004),
            (0x1400_b000, 0x1400_c000),
            (0x1400_c000, 0x1400_d000),
            (0x1400_d000, 0x1400_f000),
            (0x1400_9000, 0x1400_b000),
        ];

        for region in regions {
            for &(start, end) in &reserved {
                assert!(
                    !overlaps(region, start, end),
                    "region {region:?} overlaps reserved {start:#x}..{end:#x}"
                );
            }
        }

        assert!(
            regions
                .iter()
                .any(|region| region.base == 0x1500_0000 && region.length == 0x0020_0000)
        );
    }

    #[test]
    fn usable_memory_builder_does_not_reserve_beyond_artifact_allocation() {
        let hhdm_start = 0xffff_8000_0000_0000;
        let boot_info = sample_boot_info(hhdm_start);

        let descriptors = [desc(EFI_MEMORY_TYPE_CONVENTIONAL, 0x1400_0000, 0x0010_0000)];
        let mut output = [UsableMemoryRegion::default(); 16];

        let reservations = HandoffReservations {
            boot_info: &boot_info,
            artifact_allocation: Some((0x1400_1000, 0x1000)),
            segment_info: &[],
            boot_info_allocation: (0x1400_0000, 0x1000),
            map_allocation: (0x1400_5000, 0x1000),
            usable_allocation: (0x1400_6000, 0x1000),
        };
        let count = build_usable_memory_regions(&descriptors, &mut output, &reservations)
            .expect("usable memory build should succeed");
        let regions = &output[..count];

        assert!(regions.iter().any(|region| {
            region.base <= 0x1400_4000 && region.base + region.length >= 0x1400_4000 + 0x1000
        }));
    }

    #[test]
    fn table_is_returned_only_after_complete_normalization() -> Result<(), UsableMemoryError> {
        let hhdm_start = 0xffff_8000_0000_0000;
        let boot_info = sample_boot_info(hhdm_start);
        let descriptors = [desc(EFI_MEMORY_TYPE_CONVENTIONAL, 0x1400_0000, 0x0020_0000)];
        let reservations = HandoffReservations {
            boot_info: &boot_info,
            artifact_allocation: Some((0x1400_1000, 0x4000)),
            segment_info: &[],
            boot_info_allocation: (0x1400_0000, 0x1000),
            map_allocation: (0x1400_c000, 0x1000),
            usable_allocation: (0x1400_d000, 0x1000),
        };
        let mut short_output = [UsableMemoryRegion::default(); 1];
        assert!(matches!(
            build_usable_memory_table(&descriptors, &mut short_output, &reservations),
            Err(UsableMemoryError::NormalizationIncomplete)
        ));
        assert!(boot_info.usable_memory.is_empty());
        let mut output = [UsableMemoryRegion::default(); MAX_USABLE_MEMORY_REGIONS];
        let table = build_usable_memory_table(&descriptors, &mut output, &reservations)?;
        assert_eq!(table.entries_ptr, hhdm_start + 0x1400_d000);
        assert!(table.len() > short_output.len());
        for range in &output[..table.len()] {
            assert!(!overlaps(range, 0x1400_1000, 0x1400_5000));
        }
        Ok(())
    }

    #[test]
    fn table_publication_rejects_hhdm_overflow() {
        let boot_info = sample_boot_info(u64::MAX - 0x2000_0000);
        let descriptors = [desc(EFI_MEMORY_TYPE_CONVENTIONAL, 0x3000_0000, 0x1000)];
        let reservations = HandoffReservations {
            boot_info: &boot_info,
            artifact_allocation: None,
            segment_info: &[],
            boot_info_allocation: (0x1400_0000, 0x1000),
            map_allocation: (0x1400_c000, 0x1000),
            usable_allocation: (0x3000_0000, 0x1000),
        };
        assert!(matches!(
            build_usable_memory_table(
                &descriptors,
                &mut [UsableMemoryRegion::default(); 2],
                &reservations
            ),
            Err(UsableMemoryError::AddressOverflow)
        ));
    }
}
