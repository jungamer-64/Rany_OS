extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::domain_system::DomainId;
use crate::io::interrupt_manager::{self, InterruptError, VectorAllocation};
use crate::io::pci::{
    self, BdfAddress, ConfigSpaceAccessor, MsixCapability, MsixTableEntry, PciDeviceInfo,
};
use crate::sync::PoisonLock;
use kernel_api::abi::driver::PackedPciLocation;
use kernel_api::error::{KapiError, KapiResult};
use kernel_api::msix::MsixVectorInfo;
use x86_64::PhysAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MsixVectorOwner {
    pub owner: DomainId,
    pub device: PackedPciLocation,
}

#[derive(Debug, Clone)]
struct MsixAllocationRecord {
    owner: DomainId,
    device: PackedPciLocation,
    vectors: Vec<MsixVectorInfo>,
}

impl MsixAllocationRecord {
    fn vector_numbers(&self) -> Vec<u8> {
        self.vectors.iter().map(|info| info.vector as u8).collect()
    }
}

struct MsixRegistry {
    allocations: BTreeMap<(u64, u64), MsixAllocationRecord>,
    vector_owners: BTreeMap<u8, MsixVectorOwner>,
}

impl MsixRegistry {
    const fn new() -> Self {
        Self {
            allocations: BTreeMap::new(),
            vector_owners: BTreeMap::new(),
        }
    }

    fn key(owner: DomainId, device: PackedPciLocation) -> (u64, u64) {
        (owner.as_u64(), device.raw())
    }

    fn find_by_device(&self, device: PackedPciLocation) -> Option<&MsixAllocationRecord> {
        self.allocations
            .values()
            .find(|record| record.device == device)
    }
}

static MSIX_REGISTRY: PoisonLock<MsixRegistry> = PoisonLock::new(MsixRegistry::new());

struct LegacyConfigAccessor;

impl LegacyConfigAccessor {
    fn read_aligned_dword(&self, bdf: BdfAddress, offset: u16) -> u32 {
        pci::pci_read(
            bdf.bus(),
            bdf.device(),
            bdf.function(),
            (offset & !0x3) as u8,
        )
    }

    fn write_partial(&self, bdf: BdfAddress, offset: u16, mask: u32, value: u32) {
        let aligned = offset & !0x3;
        let shift = ((offset & 0x3) * 8) as u32;
        let mut dword = self.read_aligned_dword(bdf, offset);
        dword &= !(mask << shift);
        dword |= (value & mask) << shift;
        pci::pci_write(
            bdf.bus(),
            bdf.device(),
            bdf.function(),
            aligned as u8,
            dword,
        );
    }
}

impl ConfigSpaceAccessor for LegacyConfigAccessor {
    fn read8(&self, bdf: BdfAddress, offset: u16) -> u8 {
        pci::pci_read8(bdf.bus(), bdf.device(), bdf.function(), offset as u8)
    }

    fn read16(&self, bdf: BdfAddress, offset: u16) -> u16 {
        pci::pci_read16(bdf.bus(), bdf.device(), bdf.function(), offset as u8)
    }

    fn read32(&self, bdf: BdfAddress, offset: u16) -> u32 {
        pci::pci_read(bdf.bus(), bdf.device(), bdf.function(), offset as u8)
    }

    fn write8(&self, bdf: BdfAddress, offset: u16, value: u8) {
        self.write_partial(bdf, offset, 0xFF, value as u32);
    }

    fn write16(&self, bdf: BdfAddress, offset: u16, value: u16) {
        self.write_partial(bdf, offset, 0xFFFF, value as u32);
    }

    fn write32(&self, bdf: BdfAddress, offset: u16, value: u32) {
        pci::pci_write(bdf.bus(), bdf.device(), bdf.function(), offset as u8, value);
    }
}

fn map_interrupt_error(err: InterruptError) -> KapiError {
    match err {
        InterruptError::NoAvailableVector => KapiError::ResourceExhausted,
        InterruptError::VectorInUse => KapiError::AlreadyExists,
        InterruptError::InvalidVector | InterruptError::InvalidGsi => KapiError::InvalidHandle,
        InterruptError::HardwareError => KapiError::IoError,
    }
}

fn packed_locator(device: &PciDeviceInfo) -> PackedPciLocation {
    PackedPciLocation::new(
        device.segment,
        device.bdf.bus(),
        device.bdf.device(),
        device.bdf.function(),
    )
}

fn find_device(locator: PackedPciLocation) -> Option<PciDeviceInfo> {
    if locator.is_null() {
        return None;
    }

    pci::scan_all_devices()
        .into_iter()
        .find(|device| packed_locator(device) == locator)
}

fn validate_request(requested_count: u16, table_size: u16) -> KapiResult<()> {
    if requested_count == 0 {
        return Err(KapiError::InvalidHandle);
    }
    if requested_count > table_size {
        return Err(KapiError::InvalidHandle);
    }
    Ok(())
}

fn map_bar(base_phys: u64, bar_size: u64) -> Option<u64> {
    if base_phys == 0 || bar_size == 0 {
        return None;
    }

    let base_virt = crate::memory::phys_to_virt(PhysAddr::new_truncate(base_phys)).as_u64();
    let page_size = 0x1000u64;
    let map_size = crate::util::align_up_u64(bar_size, page_size);
    let virt_start = crate::mm::virt::higher_half::VirtAddr::new(base_virt);
    let phys_start = crate::mm::virt::higher_half::PhysAddr::new(base_phys);

    if let Some(pte) = crate::mm::virt::higher_half::get_current_pte(virt_start) {
        if pte.is_present() && pte.phys_addr() == phys_start {
            return Some(base_virt);
        }
    }

    let pm_offset = crate::mm::virt::higher_half::physical_memory_offset();
    let mut manager =
        unsafe { crate::mm::virt::higher_half::PageTableManager::from_current_cr3(pm_offset) };
    let flags = crate::mm::virt::higher_half::PageFlags::write_combining();

    match unsafe { manager.map_range(virt_start, phys_start, map_size, flags) } {
        Ok(()) | Err(crate::mm::virt::higher_half::MapError::AlreadyMapped) => Some(base_virt),
        Err(err) => {
            log::error!(
                target: "msix",
                "BAR mapping failed: phys={:#x} size={:#x} err={:?}",
                base_phys,
                bar_size,
                err
            );
            None
        }
    }
}

fn map_msix_table(
    device: &PciDeviceInfo,
    capability: &MsixCapability,
    requested_count: u16,
) -> KapiResult<*mut MsixTableEntry> {
    let table_bar = device
        .bars
        .get(capability.table_bar() as usize)
        .and_then(|bar| *bar)
        .ok_or(KapiError::IoError)?;

    if !table_bar.is_memory() {
        return Err(KapiError::NotSupported);
    }

    let table_bytes = (requested_count as u64) * (core::mem::size_of::<MsixTableEntry>() as u64);
    let table_end = capability
        .table_offset()
        .checked_add(table_bytes as u32)
        .ok_or(KapiError::IoError)? as u64;
    if table_end > table_bar.size() {
        return Err(KapiError::IoError);
    }

    let bar_base = map_bar(table_bar.base(), table_bar.size()).ok_or(KapiError::IoError)?;
    Ok((bar_base + capability.table_offset() as u64) as *mut MsixTableEntry)
}

unsafe fn program_table_entry(
    table_base: *mut MsixTableEntry,
    table_index: u16,
    allocation: &VectorAllocation,
) {
    let entry = unsafe { &mut *table_base.add(table_index as usize) };
    let address = allocation.config.msi_address();
    entry.msg_addr_lo = address as u32;
    entry.msg_addr_hi = (address >> 32) as u32;
    entry.msg_data = allocation.config.msi_data();
    entry.vector_ctrl = 0;
}

fn program_device_msix(
    accessor: &impl ConfigSpaceAccessor,
    device: &PciDeviceInfo,
    capability: &MsixCapability,
    table_base: *mut MsixTableEntry,
    allocations: &[VectorAllocation],
) -> KapiResult<Vec<MsixVectorInfo>> {
    validate_request(allocations.len() as u16, capability.table_size())?;

    capability.enable(accessor);

    for (table_index, allocation) in allocations.iter().enumerate() {
        unsafe {
            program_table_entry(table_base, table_index as u16, allocation);
        }
    }

    pci::disable_intx(accessor, device);
    capability.clear_function_mask(accessor);

    Ok(allocations
        .iter()
        .enumerate()
        .map(|(table_index, allocation)| {
            MsixVectorInfo::new(allocation.vector as u32, table_index as u16)
        })
        .collect())
}

fn free_vectors(vectors: &[u8]) {
    for &vector in vectors {
        interrupt_manager::unregister_handler(vector);
        interrupt_manager::unregister_waker(vector);
        crate::task::interrupt_waker::interrupt_waker_registry()
            .unregister(crate::task::interrupt_waker::InterruptSource::Irq(vector));
        interrupt_manager::free_vector(vector);
    }
}

pub fn enable_for_current_owner(
    device: PackedPciLocation,
    requested_count: u16,
) -> KapiResult<Vec<MsixVectorInfo>> {
    enable_for_owner(
        crate::task::context::current_subject().domain,
        device,
        requested_count,
    )
}

pub fn enable_for_owner(
    owner: DomainId,
    device: PackedPciLocation,
    requested_count: u16,
) -> KapiResult<Vec<MsixVectorInfo>> {
    if device.is_null() {
        return Err(KapiError::InvalidHandle);
    }

    let pci_device = find_device(device).ok_or(KapiError::NotFound)?;
    let accessor = LegacyConfigAccessor;
    let capability =
        MsixCapability::probe(&accessor, &pci_device).ok_or(KapiError::NotSupported)?;
    validate_request(requested_count, capability.table_size())?;

    {
        let registry = MSIX_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = registry.find_by_device(device) {
            return if existing.owner == owner {
                Err(KapiError::AlreadyExists)
            } else {
                Err(KapiError::PermissionDenied)
            };
        }
    }

    let allocations = interrupt_manager::allocate_msix(
        pci_device.bdf.to_u16() as u32,
        requested_count,
        "driver_msix",
        Some(0),
    )
    .map_err(map_interrupt_error)?;
    let vectors: Vec<u8> = allocations.iter().map(|alloc| alloc.vector).collect();

    let result = (|| {
        let table_base = map_msix_table(&pci_device, &capability, requested_count)?;
        program_device_msix(
            &accessor,
            &pci_device,
            &capability,
            table_base,
            &allocations,
        )
    })();

    let vector_infos = match result {
        Ok(vector_infos) => vector_infos,
        Err(err) => {
            free_vectors(&vectors);
            return Err(err);
        }
    };

    let record = MsixAllocationRecord {
        owner,
        device,
        vectors: vector_infos.clone(),
    };
    let mut registry = MSIX_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    for vector in record.vector_numbers() {
        registry
            .vector_owners
            .insert(vector, MsixVectorOwner { owner, device });
    }
    registry
        .allocations
        .insert(MsixRegistry::key(owner, device), record);

    Ok(vector_infos)
}

pub fn owned_vectors(owner: DomainId, device: PackedPciLocation) -> KapiResult<Vec<u8>> {
    let registry = MSIX_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(record) = registry.allocations.get(&MsixRegistry::key(owner, device)) {
        return Ok(record.vector_numbers());
    }
    if registry.find_by_device(device).is_some() {
        return Err(KapiError::PermissionDenied);
    }
    Err(KapiError::NotFound)
}

pub fn owner_for_vector(vector: u8) -> Option<MsixVectorOwner> {
    MSIX_REGISTRY
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .vector_owners
        .get(&vector)
        .copied()
}

pub fn disable_for_current_owner(device: PackedPciLocation) -> KapiResult<()> {
    disable_for_owner(crate::task::context::current_subject().domain, device)
}

pub fn disable_for_owner(owner: DomainId, device: PackedPciLocation) -> KapiResult<()> {
    let record = {
        let mut registry = MSIX_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
        let key = MsixRegistry::key(owner, device);
        match registry.allocations.remove(&key) {
            Some(record) => {
                for vector in record.vector_numbers() {
                    registry.vector_owners.remove(&vector);
                }
                record
            }
            None => {
                return if registry.find_by_device(device).is_some() {
                    Err(KapiError::PermissionDenied)
                } else {
                    Err(KapiError::NotFound)
                };
            }
        }
    };

    if let Some(pci_device) = find_device(device) {
        let accessor = LegacyConfigAccessor;
        if let Some(capability) = MsixCapability::probe(&accessor, &pci_device) {
            capability.disable(&accessor);
        } else {
            log::warn!(
                target: "msix",
                "device {}:{:02x}.{}.{} lost MSI-X capability during disable",
                device.segment(),
                device.bus(),
                device.device(),
                device.function()
            );
        }
    }

    free_vectors(&record.vector_numbers());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::interrupt_manager::InterruptConfig;

    #[test_case]
    fn validate_request_rejects_zero() {
        assert_eq!(validate_request(0, 1), Err(KapiError::InvalidHandle));
    }

    #[test_case]
    fn validate_request_rejects_oversized_request() {
        assert_eq!(validate_request(4, 2), Err(KapiError::InvalidHandle));
    }

    #[test_case]
    fn program_device_msix_writes_table_and_control_bits() {
        use alloc::collections::BTreeMap;

        struct FakeAccessor {
            regs: PoisonLock<BTreeMap<(u8, u8, u8, u16), u32>>,
        }

        impl FakeAccessor {
            fn new() -> Self {
                Self {
                    regs: PoisonLock::new(BTreeMap::new()),
                }
            }

            fn write_reg(&self, bdf: BdfAddress, offset: u16, value: u32) {
                self.regs
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert((bdf.bus(), bdf.device(), bdf.function(), offset), value);
            }
        }

        impl ConfigSpaceAccessor for FakeAccessor {
            fn read8(&self, bdf: BdfAddress, offset: u16) -> u8 {
                (self.read32(bdf, offset & !0x3) >> ((offset & 0x3) * 8)) as u8
            }

            fn read16(&self, bdf: BdfAddress, offset: u16) -> u16 {
                (self.read32(bdf, offset & !0x3) >> ((offset & 0x2) * 8)) as u16
            }

            fn read32(&self, bdf: BdfAddress, offset: u16) -> u32 {
                *self
                    .regs
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .get(&(bdf.bus(), bdf.device(), bdf.function(), offset))
                    .unwrap_or(&0)
            }

            fn write8(&self, bdf: BdfAddress, offset: u16, value: u8) {
                let aligned = offset & !0x3;
                let shift = ((offset & 0x3) * 8) as u32;
                let mut dword = self.read32(bdf, aligned);
                dword &= !(0xFF << shift);
                dword |= (value as u32) << shift;
                self.write32(bdf, aligned, dword);
            }

            fn write16(&self, bdf: BdfAddress, offset: u16, value: u16) {
                let aligned = offset & !0x3;
                let shift = ((offset & 0x2) * 8) as u32;
                let mut dword = self.read32(bdf, aligned);
                dword &= !(0xFFFF << shift);
                dword |= (value as u32) << shift;
                self.write32(bdf, aligned, dword);
            }

            fn write32(&self, bdf: BdfAddress, offset: u16, value: u32) {
                self.write_reg(bdf, offset, value);
            }
        }

        let accessor = FakeAccessor::new();
        let bdf = BdfAddress::new(0, 2, 0);
        let device = PciDeviceInfo {
            segment: 0,
            bdf,
            vendor_id: pci::VendorId(0x15b3),
            device_id: pci::DeviceId(0x1017),
            revision_id: 0,
            class_code: pci::ClassCode::new(0x02, 0x00, 0x00),
            header_type: 0,
            subsystem_vendor_id: 0,
            subsystem_id: 0,
            interrupt_line: 0,
            interrupt_pin: 0,
            bars: [
                Some(pci::Bar::Memory64 {
                    base: 0x1000_0000,
                    size: 0x1000,
                    prefetchable: false,
                }),
                None,
                None,
                None,
                None,
                None,
            ],
            capabilities: alloc::vec![],
            msi_cap_offset: None,
            msix_cap_offset: Some(0x50),
            pcie_cap_offset: None,
            iommu_domain_id: None,
        };

        accessor.write_reg(bdf, 0x50, 0x0001_0000);
        accessor.write_reg(bdf, 0x54, 0);
        accessor.write_reg(bdf, pci::config_regs::COMMAND, 0);

        let capability = MsixCapability::probe(&accessor, &device).expect("msix capability");
        let mut table = [MsixTableEntry::default(); 2];
        let allocations = [
            VectorAllocation {
                vector: 0x66,
                config: InterruptConfig {
                    vector: 0x66,
                    target_apic_id: Some(2),
                    ..InterruptConfig::default()
                },
            },
            VectorAllocation {
                vector: 0x67,
                config: InterruptConfig {
                    vector: 0x67,
                    target_apic_id: Some(3),
                    ..InterruptConfig::default()
                },
            },
        ];

        let infos = program_device_msix(
            &accessor,
            &device,
            &capability,
            table.as_mut_ptr(),
            &allocations,
        )
        .expect("program success");

        assert_eq!(infos.len(), 2);
        assert_eq!(infos[0], MsixVectorInfo::new(0x66, 0));
        assert_eq!(infos[1], MsixVectorInfo::new(0x67, 1));
        assert_eq!(table[0].msg_addr_lo, 0xfee0_2000);
        assert_eq!(table[0].msg_data, 0x66);
        assert_eq!(table[0].vector_ctrl, 0);
        assert_eq!(table[1].msg_addr_lo, 0xfee0_3000);
        assert_eq!(table[1].msg_data, 0x67);
        assert_eq!(table[1].vector_ctrl, 0);
        assert_eq!(accessor.read16(bdf, 0x52) & 0x8000, 0x8000);
        assert_eq!(accessor.read16(bdf, 0x52) & 0x4000, 0);
        assert_ne!(
            accessor.read16(bdf, pci::config_regs::COMMAND) & pci::command_bits::INTERRUPT_DISABLE,
            0
        );
    }
}
