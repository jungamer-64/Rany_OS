//! Early NUMA topology detection from ACPI SRAT table
//!
//! This module parses the ACPI SRAT (System Resource Affinity Table) to detect
//! NUMA topology before the kernel's full ACPI subsystem is initialized.

use boot_proto::{MAX_NUMA_NODES, NumaInfo, NumaMemoryRange, NumaNodeInfo};
use log::info;

/// ACPI RSDP signature "RSD PTR "
const RSDP_SIGNATURE: &[u8; 8] = b"RSD PTR ";

/// ACPI table signature for SRAT
const SRAT_SIGNATURE: &[u8; 4] = b"SRAT";

/// SRAT entry type: Processor Local APIC/SAPIC Affinity
const SRAT_TYPE_PROCESSOR_AFFINITY: u8 = 0;
/// SRAT entry type: Memory Affinity
const SRAT_TYPE_MEMORY_AFFINITY: u8 = 1;
/// SRAT entry type: Processor Local x2APIC Affinity
const SRAT_TYPE_X2APIC_AFFINITY: u8 = 2;

/// ACPI RSDP structure (revision 2.0+)
#[repr(C, packed)]
struct Rsdp {
    signature: [u8; 8],
    checksum: u8,
    oem_id: [u8; 6],
    revision: u8,
    rsdt_address: u32,
    // ACPI 2.0+ fields
    length: u32,
    xsdt_address: u64,
    extended_checksum: u8,
    reserved: [u8; 3],
}

/// ACPI SDT header (common to all tables)
#[repr(C, packed)]
struct SdtHeader {
    signature: [u8; 4],
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [u8; 6],
    oem_table_id: [u8; 8],
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,
}

/// SRAT Processor Local APIC Affinity entry
#[repr(C, packed)]
struct SratProcessorAffinity {
    entry_type: u8,
    length: u8,
    proximity_domain_low: u8,
    apic_id: u8,
    flags: u32,
    local_sapic_eid: u8,
    proximity_domain_high: [u8; 3],
    clock_domain: u32,
}

/// SRAT Memory Affinity entry
#[repr(C, packed)]
struct SratMemoryAffinity {
    entry_type: u8,
    length: u8,
    proximity_domain: u32,
    reserved1: u16,
    base_address_low: u32,
    base_address_high: u32,
    length_low: u32,
    length_high: u32,
    reserved2: u32,
    flags: u32,
    reserved3: u64,
}

/// SRAT Processor Local x2APIC Affinity entry
#[repr(C, packed)]
struct SratX2ApicAffinity {
    entry_type: u8,
    length: u8,
    reserved1: u16,
    proximity_domain: u32,
    x2apic_id: u32,
    flags: u32,
    clock_domain: u32,
    reserved2: u32,
}

/// Detect NUMA topology from ACPI SRAT table
///
/// # Arguments
/// * `rsdp_addr` - Physical address of ACPI RSDP
/// * `hhdm_offset` - Higher Half Direct Map offset for physical to virtual conversion
///
/// Detect NUMA topology from ACPI SRAT table
///
/// # Arguments
/// * `rsdp_addr` - Physical address of ACPI RSDP
///
/// # Returns
/// NumaInfo structure with detected topology (node_count = 0 if SRAT not found)
pub fn detect_numa_topology(rsdp_addr: u64) -> NumaInfo {
    if rsdp_addr == 0 {
        info!("NUMA: No RSDP address provided");
        return NumaInfo::default();
    }

    // Access RSDP directly (Identity Mapped in UEFI)
    let rsdp_ptr = rsdp_addr as *const Rsdp;

    // Verify RSDP signature (signature is at offset 0, aligned, so direct read is OK)
    let signature = unsafe { core::ptr::addr_of!((*rsdp_ptr).signature).read() };
    if &signature != RSDP_SIGNATURE {
        info!("NUMA: Invalid RSDP signature");
        return NumaInfo::default();
    }

    // Find SRAT table
    let srat_addr = find_srat_table(rsdp_ptr);
    if srat_addr == 0 {
        info!("NUMA: SRAT table not found (single-node system assumed)");
        return NumaInfo::default();
    }

    // Parse SRAT
    parse_srat(srat_addr)
}

/// Find SRAT table address from XSDT/RSDT
fn find_srat_table(rsdp_ptr: *const Rsdp) -> u64 {
    // Read packed fields via read_unaligned
    let revision = unsafe { core::ptr::addr_of!((*rsdp_ptr).revision).read_unaligned() };
    let rsdt_address = unsafe { core::ptr::addr_of!((*rsdp_ptr).rsdt_address).read_unaligned() };
    let xsdt_address = unsafe { core::ptr::addr_of!((*rsdp_ptr).xsdt_address).read_unaligned() };

    // Prefer XSDT (64-bit) over RSDT (32-bit) if available
    if revision >= 2 && xsdt_address != 0 {
        find_table_in_xsdt(xsdt_address)
    } else if rsdt_address != 0 {
        find_table_in_rsdt(rsdt_address as u64)
    } else {
        0
    }
}

/// Search for SRAT in XSDT (64-bit pointers)
fn find_table_in_xsdt(xsdt_addr: u64) -> u64 {
    let xsdt_ptr = xsdt_addr as *const SdtHeader;
    let header_length = unsafe { core::ptr::addr_of!((*xsdt_ptr).length).read_unaligned() };

    let entry_count = (header_length as usize - core::mem::size_of::<SdtHeader>()) / 8;
    let entries_ptr = (xsdt_addr + core::mem::size_of::<SdtHeader>() as u64) as *const u64;

    for i in 0..entry_count {
        let table_addr = unsafe { entries_ptr.add(i).read_unaligned() };
        let table_header_ptr = table_addr as *const SdtHeader;
        let table_signature =
            unsafe { core::ptr::addr_of!((*table_header_ptr).signature).read_unaligned() };

        if &table_signature == SRAT_SIGNATURE {
            return table_addr;
        }
    }

    0
}

/// Search for SRAT in RSDT (32-bit pointers)
fn find_table_in_rsdt(rsdt_addr: u64) -> u64 {
    let rsdt_ptr = rsdt_addr as *const SdtHeader;
    let header_length = unsafe { core::ptr::addr_of!((*rsdt_ptr).length).read_unaligned() };

    let entry_count = (header_length as usize - core::mem::size_of::<SdtHeader>()) / 4;
    let entries_ptr = (rsdt_addr + core::mem::size_of::<SdtHeader>() as u64) as *const u32;

    for i in 0..entry_count {
        let table_addr = unsafe { entries_ptr.add(i).read_unaligned() } as u64;
        let table_header_ptr = table_addr as *const SdtHeader;
        let table_signature =
            unsafe { core::ptr::addr_of!((*table_header_ptr).signature).read_unaligned() };

        if &table_signature == SRAT_SIGNATURE {
            return table_addr;
        }
    }

    0
}

/// Handle SRAT Processor Affinity entry
fn handle_srat_processor(
    offset: u64,
    numa_info: &mut NumaInfo,
    node_map: &mut [Option<usize>; 256],
) {
    let entry_ptr = offset as *const SratProcessorAffinity;
    let flags = unsafe { core::ptr::addr_of!((*entry_ptr).flags).read_unaligned() };
    if flags & 1 == 0 {
        return;
    }
    let proximity_domain_low =
        unsafe { core::ptr::addr_of!((*entry_ptr).proximity_domain_low).read_unaligned() };
    let proximity_domain_high =
        unsafe { core::ptr::addr_of!((*entry_ptr).proximity_domain_high).read_unaligned() };
    let apic_id = unsafe { core::ptr::addr_of!((*entry_ptr).apic_id).read_unaligned() };
    let proximity_domain = proximity_domain_low as u32
        | ((proximity_domain_high[0] as u32) << 8)
        | ((proximity_domain_high[1] as u32) << 16)
        | ((proximity_domain_high[2] as u32) << 24);
    if let Some(idx) = get_or_create_node(numa_info, node_map, proximity_domain) {
        add_cpu_to_node(&mut numa_info.nodes[idx], apic_id as u32);
    }
}

/// Handle SRAT Memory Affinity entry
fn handle_srat_memory(offset: u64, numa_info: &mut NumaInfo, node_map: &mut [Option<usize>; 256]) {
    let entry_ptr = offset as *const SratMemoryAffinity;
    let flags = unsafe { core::ptr::addr_of!((*entry_ptr).flags).read_unaligned() };
    if flags & 1 == 0 {
        return;
    }
    let base_low = unsafe { core::ptr::addr_of!((*entry_ptr).base_address_low).read_unaligned() };
    let base_high = unsafe { core::ptr::addr_of!((*entry_ptr).base_address_high).read_unaligned() };
    let length_low = unsafe { core::ptr::addr_of!((*entry_ptr).length_low).read_unaligned() };
    let length_high = unsafe { core::ptr::addr_of!((*entry_ptr).length_high).read_unaligned() };
    let proximity_domain =
        unsafe { core::ptr::addr_of!((*entry_ptr).proximity_domain).read_unaligned() };
    let base = (base_low as u64) | ((base_high as u64) << 32);
    let length = (length_low as u64) | ((length_high as u64) << 32);
    if let Some(idx) = get_or_create_node(numa_info, node_map, proximity_domain) {
        add_memory_to_node(&mut numa_info.nodes[idx], base, length);
    }
}

/// Handle SRAT X2APIC Affinity entry
fn handle_srat_x2apic(offset: u64, numa_info: &mut NumaInfo, node_map: &mut [Option<usize>; 256]) {
    let entry_ptr = offset as *const SratX2ApicAffinity;
    let flags = unsafe { core::ptr::addr_of!((*entry_ptr).flags).read_unaligned() };
    if flags & 1 == 0 {
        return;
    }
    let proximity_domain =
        unsafe { core::ptr::addr_of!((*entry_ptr).proximity_domain).read_unaligned() };
    let x2apic_id = unsafe { core::ptr::addr_of!((*entry_ptr).x2apic_id).read_unaligned() };
    if let Some(idx) = get_or_create_node(numa_info, node_map, proximity_domain) {
        add_cpu_to_node(&mut numa_info.nodes[idx], x2apic_id);
    }
}

/// Parse SRAT table and extract NUMA information
fn parse_srat(srat_phys: u64) -> NumaInfo {
    let srat_ptr = srat_phys as *const SdtHeader;

    // Read packed field via read_unaligned to avoid misaligned reference
    let table_length = unsafe { core::ptr::addr_of!((*srat_ptr).length).read_unaligned() };

    info!(
        "NUMA: Found SRAT table at 0x{:x}, length {}",
        srat_phys, table_length
    );

    let mut numa_info = NumaInfo::default();
    let mut node_map: [Option<usize>; 256] = [None; 256]; // proximity domain -> node index

    // SRAT entries start after header + 12 bytes reserved
    let entries_start = srat_phys + core::mem::size_of::<SdtHeader>() as u64 + 12;
    let entries_end = srat_phys + table_length as u64;
    let mut offset = entries_start;

    while offset < entries_end {
        let entry_type = unsafe { *(offset as *const u8) };
        let entry_length = unsafe { *((offset + 1) as *const u8) };

        if entry_length == 0 {
            break; // Prevent infinite loop
        }

        match entry_type {
            SRAT_TYPE_PROCESSOR_AFFINITY => {
                handle_srat_processor(offset, &mut numa_info, &mut node_map);
            }
            SRAT_TYPE_MEMORY_AFFINITY => {
                handle_srat_memory(offset, &mut numa_info, &mut node_map);
            }
            SRAT_TYPE_X2APIC_AFFINITY => {
                handle_srat_x2apic(offset, &mut numa_info, &mut node_map);
            }
            _ => {}
        }

        offset += entry_length as u64;
    }

    info!("NUMA: Detected {} node(s)", numa_info.node_count);
    for i in 0..numa_info.node_count as usize {
        let node = &numa_info.nodes[i];
        info!(
            "  Node {}: {} memory range(s), {} CPU(s)",
            i, node.memory_range_count, node.cpu_count
        );
    }

    numa_info
}

/// Get existing node index or create a new one for the proximity domain
fn get_or_create_node(
    numa_info: &mut NumaInfo,
    node_map: &mut [Option<usize>; 256],
    proximity_domain: u32,
) -> Option<usize> {
    let domain_idx = (proximity_domain & 0xFF) as usize;

    if let Some(idx) = node_map[domain_idx] {
        return Some(idx);
    }

    if numa_info.node_count as usize >= MAX_NUMA_NODES {
        return None; // Max nodes reached
    }

    let new_idx = numa_info.node_count as usize;
    numa_info.nodes[new_idx].proximity_domain = proximity_domain;
    numa_info.node_count += 1;
    node_map[domain_idx] = Some(new_idx);

    Some(new_idx)
}

/// Add CPU (APIC ID) to a NUMA node
fn add_cpu_to_node(node: &mut NumaNodeInfo, apic_id: u32) {
    node.cpu_count += 1;

    // Store in bitmask (supports APIC IDs 0-127)
    if apic_id < 64 {
        node.cpu_apic_mask_low |= 1u64 << apic_id;
    } else if apic_id < 128 {
        node.cpu_apic_mask_high |= 1u64 << (apic_id - 64);
    }
    // APIC IDs >= 128 are not stored in the bitmask but still counted
}

/// Add memory range to a NUMA node
fn add_memory_to_node(node: &mut NumaNodeInfo, base: u64, length: u64) {
    if node.memory_range_count as usize >= 4 {
        // Try to merge with existing range if adjacent
        for range in &mut node.memory_ranges[..node.memory_range_count as usize] {
            if range.base + range.length == base {
                range.length += length;
                return;
            }
            if base + length == range.base {
                range.base = base;
                range.length += length;
                return;
            }
        }
        return; // Max ranges reached, cannot add
    }

    let idx = node.memory_range_count as usize;
    node.memory_ranges[idx] = NumaMemoryRange { base, length };
    node.memory_range_count += 1;
}
