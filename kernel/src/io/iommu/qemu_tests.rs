use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use super::domain::IommuDomain;
use super::fault_log::FaultRecord;
use super::groups::{IommuGroupManager, PciTopologyProvider};
use super::intel::controller::dma::DomainManager;
use super::intel::controller::fault::{
    drain_deferred_faults_with_controller, push_deferred_fault_for_test, FaultHandler,
    RawFaultEvent,
};
use super::intel::controller::iova::IovaManager;
use super::intel::controller::ir::InterruptRemapper;
use super::intel::controller::pri::PageRequestManager;
use super::intel::controller::qi_init::QIManager;
use super::intel::controller::qi_ops::InvalidationOps;
use super::intel::controller::IommuController;
use super::intel::qi::InvalidationQueueEntry;
use super::intel::registers::ecap_bits;
use super::intel::tables::{ContextEntry, RootEntry, ScalableContextEntry};
use super::page_table_pool::{
    get_ref_count, inc_ref, register_page_table, unregister_page_table, PageTablePool,
};
use super::security::{
    FaultSummary, IsolationDecision, IsolationReason, SecurityEvent, SecurityNotifier,
};
use super::tables::{HardwareTable, PageTableScope, SlPte};
use super::types::{DeviceId, IommuDomainType, IommuError, PteFormat};
mod wave2_tests;
pub use wave2_tests::*;

struct MockSecurityNotifier {
    events: spin::Mutex<[Option<SecurityEvent>; 16]>,
    event_count: AtomicUsize,
    isolation_decision: IsolationDecision,
}

impl MockSecurityNotifier {
    fn new() -> Self {
        Self {
            events: spin::Mutex::new([None; 16]),
            event_count: AtomicUsize::new(0),
            isolation_decision: IsolationDecision::default(),
        }
    }
}

impl SecurityNotifier for MockSecurityNotifier {
    fn notify(&self, event: SecurityEvent) {
        let idx = self.event_count.fetch_add(1, Ordering::Relaxed) % 16;
        self.events.lock()[idx] = Some(event);
    }

    fn decide(&self, _fault: &FaultSummary) -> IsolationDecision {
        self.isolation_decision
    }
}

unsafe fn is_4k_mapped(domain: &IommuDomain, iova: u64, format: PteFormat) -> bool {
    let pml4_idx = ((iova >> 39) & 0x1FF) as usize;
    let pdp_idx = ((iova >> 30) & 0x1FF) as usize;
    let pd_idx = ((iova >> 21) & 0x1FF) as usize;
    let pt_idx = ((iova >> 12) & 0x1FF) as usize;

    let pml4_entry = domain.page_table.add(pml4_idx);
    if !(*pml4_entry).is_present() {
        return false;
    }
    let pdp_table = (*pml4_entry).phys_addr() as *mut SlPte;
    let pdp_entry = pdp_table.add(pdp_idx);
    if !(*pdp_entry).is_present() {
        return false;
    }
    if (*pdp_entry).is_super_page(format) {
        return false;
    }
    let pd_table = (*pdp_entry).phys_addr() as *mut SlPte;
    let pd_entry = pd_table.add(pd_idx);
    if !(*pd_entry).is_present() {
        return false;
    }
    if (*pd_entry).is_super_page(format) {
        return false;
    }
    let pt_table = (*pd_entry).phys_addr() as *mut SlPte;
    let pt_entry = pt_table.add(pt_idx);
    (*pt_entry).is_present()
}

unsafe fn is_superpage_2mb_mapped(domain: &IommuDomain, iova: u64, format: PteFormat) -> bool {
    let pml4_idx = ((iova >> 39) & 0x1FF) as usize;
    let pdp_idx = ((iova >> 30) & 0x1FF) as usize;
    let pd_idx = ((iova >> 21) & 0x1FF) as usize;

    let pml4_entry = domain.page_table.add(pml4_idx);
    if !(*pml4_entry).is_present() {
        return false;
    }
    let pdp_table = (*pml4_entry).phys_addr() as *mut SlPte;
    let pdp_entry = pdp_table.add(pdp_idx);
    if !(*pdp_entry).is_present() {
        return false;
    }
    if (*pdp_entry).is_super_page(format) {
        return false;
    }
    let pd_table = (*pdp_entry).phys_addr() as *mut SlPte;
    let pd_entry = pd_table.add(pd_idx);
    (*pd_entry).is_present() && (*pd_entry).is_super_page(format)
}

pub fn wave2_device_id_smoke() -> bool {
    let dev = DeviceId::new(0, 0, 1, 0);
    dev.requester_id() == 0x08
}

pub fn wave2_sl_pte_smoke() -> bool {
    let pte = SlPte::mapping(0x1000, true, true);
    pte.is_present() && pte.can_read() && pte.can_write() && pte.phys_addr() == 0x1000
}

pub fn wave2_iommu_domain_smoke() -> bool {
    let domain = IommuDomain::new(
        1,
        None,
        false,
        false,
        48,
        IommuDomainType::Translated,
        PageTablePool::new(1, 32),
        PteFormat::Intel,
    );

    if domain.id() != 1 {
        crate::io::log::early_print("[qemu-suite] wave2_iommu_domain: id mismatch\n");
        return false;
    }
    if domain.map(0x1000, 0x2000, 0x1000, true, false).is_err() {
        crate::io::log::early_print("[qemu-suite] wave2_iommu_domain: first map failed\n");
        return false;
    }
    let overlap = domain.map(0x1000, 0x3000, 0x1000, true, false);
    if overlap != Err(IommuError::AlreadyMapped) {
        crate::io::log::early_print("[qemu-suite] wave2_iommu_domain: overlap result mismatch\n");
        return false;
    }
    true
}

pub fn wave2_map_rollback_hidden_mapping_smoke() -> bool {
    let format = PteFormat::Intel;
    let domain = IommuDomain::new(
        1,
        None,
        false,
        false,
        48,
        IommuDomainType::Translated,
        PageTablePool::new(1, 32),
        format,
    );

    let base_iova = 0x10000;
    let phys_base = 0x20000;
    let mine_iova = base_iova + 0x1000;
    if domain.map(mine_iova, phys_base + 0x1000, 0x1000, true, true).is_err() {
        return false;
    }
    if !unsafe { is_4k_mapped(&domain, mine_iova, format) } {
        return false;
    }
    if domain.mapping(mine_iova).is_none() {
        return false;
    }
    if domain.map(base_iova, phys_base, 0x3000, true, true) != Err(IommuError::AlreadyMapped) {
        return false;
    }

        !unsafe { is_4k_mapped(&domain, base_iova, format) }
        && unsafe { is_4k_mapped(&domain, mine_iova, format) }
        && !unsafe { is_4k_mapped(&domain, base_iova + 0x2000, format) }
        && domain.mapped_size() == 0x1000
        && domain.mappings_snapshot().len() == 1
}

pub fn wave2_map_rollback_hidden_mapping_amd_smoke() -> bool {
    let format = PteFormat::Amd;
    let domain = IommuDomain::new(
        2,
        None,
        true,
        true,
        48,
        IommuDomainType::Translated,
        PageTablePool::new(1, 32),
        format,
    );

    let base_iova = 0x10000;
    let phys_base = 0x20000;
    let mine_iova = base_iova + 0x1000;

    if domain.map(mine_iova, phys_base + 0x1000, 0x1000, true, true).is_err() {
        return false;
    }
    if !unsafe { is_4k_mapped(&domain, mine_iova, format) } {
        return false;
    }
    if domain.mapping(mine_iova).is_none() {
        return false;
    }
    if domain.map(base_iova, phys_base, 0x3000, true, true) != Err(IommuError::AlreadyMapped) {
        return false;
    }

        !unsafe { is_4k_mapped(&domain, base_iova, format) }
        && unsafe { is_4k_mapped(&domain, mine_iova, format) }
        && !unsafe { is_4k_mapped(&domain, base_iova + 0x2000, format) }
        && domain.mapped_size() == 0x1000
        && domain.mappings_snapshot().len() == 1
}

pub fn wave2_map_rollback_superpage_2mb_collision_smoke() -> bool {
    let format = PteFormat::Amd;
    let domain = IommuDomain::new(
        3,
        None,
        true,
        false,
        48,
        IommuDomainType::Translated,
        PageTablePool::new(1, 32),
        format,
    );

    const SIZE_2MB: u64 = 2 * 1024 * 1024;
    let start_iova = 0x2000_0000;
    let phys_base = 0x4000_0000;
    let mine_iova = start_iova + SIZE_2MB;

    if domain.map(mine_iova, phys_base + SIZE_2MB, 0x1000, true, true).is_err() {
        return false;
    }

    if domain.map(start_iova, phys_base, SIZE_2MB * 2, true, true) != Err(IommuError::AlreadyMapped)
    {
        return false;
    }

    !unsafe { is_superpage_2mb_mapped(&domain, start_iova, format) }
        && !unsafe { is_4k_mapped(&domain, start_iova, format) }
        && unsafe { is_4k_mapped(&domain, mine_iova, format) }
        && domain.mapped_size() == 0x1000
        && domain.mappings_snapshot().len() == 1
}

pub fn wave2_create_domain_with_numa_hint_smoke() -> bool {
    let ctrl = IommuController::new(0x0, 0);
    let id = match ctrl.create_domain(Some(2), IommuDomainType::Translated) {
        Ok(id) => id,
        Err(_) => return false,
    };
    let domain_arc = match ctrl.domain(id) {
        Some(domain_arc) => domain_arc,
        None => return false,
    };
    if domain_arc.id() != id || domain_arc.numa_node() != Some(2) {
        return false;
    }
    if ctrl.set_domain_numa(id, Some(5)).is_err() {
        return false;
    }
    ctrl.get_domain_numa(id) == Some(5)
}

pub fn wave2_iova_allocator_basic_smoke() -> bool {
    let ctrl = IommuController::new(0x0, 0);
    if ctrl.init_iova(0x1000_0000, 0x10000).is_err() {
        return false;
    }
    let a = match ctrl.allocate_iova(4096) {
        Ok(a) => a,
        Err(_) => return false,
    };
    if a % 4096 != 0 {
        return false;
    }
    let b = match ctrl.allocate_iova(4096) {
        Ok(b) => b,
        Err(_) => return false,
    };
    if a == b {
        return false;
    }
    if ctrl.free_iova(a, 4096).is_err() {
        return false;
    }
    ctrl.allocate_iova(4096).is_ok()
}

pub fn wave2_map_for_dma_alloc_non_identity_smoke() -> bool {
    let ctrl = IommuController::new(0x0, 0);
    if ctrl.init_iova(0x8000_0000, 0x10000).is_err() {
        crate::io::log::early_print("[qemu-suite] wave2_map_for_dma: init_iova failed\n");
        return false;
    }

    let domain = Arc::new(IommuDomain::new(
        0,
        None,
        false,
        false,
        48,
        IommuDomainType::Translated,
        PageTablePool::new(1, 32),
        PteFormat::Intel,
    ));
    match ctrl.domains.lock() {
        Ok(mut domains) => {
            domains.insert(0, domain.clone());
        }
        Err(poisoned) => {
            let mut domains = poisoned.into_inner();
            domains.insert(0, domain.clone());
        }
    }

    let size = 0x1000;
    let phys = 0x2000_0000;
    let iova = match ctrl.allocate_iova(size) {
        Ok(iova) => iova,
        Err(_) => {
            crate::io::log::early_print("[qemu-suite] wave2_map_for_dma: allocate_iova failed\n");
            return false;
        }
    };

    let mapping_ok = if let Some(domain_arc) = ctrl.domain(0) {
        if domain_arc.map(iova, phys, size, true, true).is_err() {
            crate::io::log::early_print("[qemu-suite] wave2_map_for_dma: map failed\n");
            false
        } else if domain_arc.mapping(iova).is_none() {
            crate::io::log::early_print("[qemu-suite] wave2_map_for_dma: mapping missing\n");
            false
        } else {
            match domain_arc.unmap(iova) {
                Ok(mapping) => {
                    if mapping.iova != iova || mapping.phys != phys {
                        crate::io::log::early_print(
                            "[qemu-suite] wave2_map_for_dma: unmap payload mismatch\n",
                        );
                        false
                    } else {
                        true
                    }
                }
                Err(_) => {
                    crate::io::log::early_print("[qemu-suite] wave2_map_for_dma: unmap failed\n");
                    false
                }
            }
        }
    } else {
        crate::io::log::early_print("[qemu-suite] wave2_map_for_dma: domain lookup failed\n");
        false
    };

    let free_ok = if ctrl.free_iova(iova, size).is_ok() {
        true
    } else {
        crate::io::log::early_print("[qemu-suite] wave2_map_for_dma: free_iova failed\n");
        false
    };
    mapping_ok && free_ok
}

pub fn wave2_unmap_reclaims_empty_tables_smoke() -> bool {
    let domain = IommuDomain::new(
        1,
        None,
        false,
        false,
        48,
        IommuDomainType::Translated,
        PageTablePool::new(1, 32),
        PteFormat::Intel,
    );
    if domain.map(0x1000, 0x2000, 0x1000, true, true).is_err() {
        return false;
    }
    if domain.mapping(0x1000).is_none() {
        return false;
    }
    let mapping = match domain.unmap(0x1000) {
        Ok(mapping) => mapping,
        Err(_) => return false,
    };
    if mapping.iova != 0x1000 || mapping.phys != 0x2000 {
        return false;
    }
    unsafe {
        let pml4_entry = *domain.page_table.add(0);
        !pml4_entry.is_present()
    }
}

pub fn wave2_unmap_partial_keeps_tables_smoke() -> bool {
    let domain = IommuDomain::new(
        1,
        None,
        false,
        false,
        48,
        IommuDomainType::Translated,
        PageTablePool::new(1, 32),
        PteFormat::Intel,
    );

    if domain.map(0x1000, 0x2000, 0x1000, true, true).is_err() {
        return false;
    }
    if domain.map(0x2000, 0x3000, 0x1000, true, true).is_err() {
        return false;
    }
    if domain.unmap(0x1000).is_err() {
        return false;
    }
    let still_present = unsafe {
        let pml4_entry = *domain.page_table.add(0);
        pml4_entry.is_present()
    };
    if !still_present {
        return false;
    }
    if domain.unmap(0x2000).is_err() {
        return false;
    }
    unsafe {
        let pml4_entry = *domain.page_table.add(0);
        !pml4_entry.is_present()
    }
}

pub fn wave2_unmap_mixed_superpages_smoke() -> bool {
    const SIZE_1GB: u64 = 1024 * 1024 * 1024;
    const SIZE_2MB: u64 = 2 * 1024 * 1024;
    const SIZE_4KB: u64 = 4096;
    const SIZE_TOTAL: u64 = SIZE_1GB + SIZE_2MB + SIZE_4KB;
    const IOVA_BASE: u64 = 0x4000_0000;
    const PHYS_BASE: u64 = 0x8000_0000;

    let domain = IommuDomain::new(
        1,
        None,
        true,
        true,
        48,
        IommuDomainType::Translated,
        PageTablePool::new(1, 32),
        PteFormat::Intel,
    );
    if domain
        .map(IOVA_BASE, PHYS_BASE, SIZE_TOTAL, true, true)
        .is_err()
    {
        return false;
    }
    if domain.mapping(IOVA_BASE).is_none() {
        return false;
    }
    let mapping = match domain.unmap(IOVA_BASE) {
        Ok(mapping) => mapping,
        Err(_) => return false,
    };
    if mapping.iova != IOVA_BASE || mapping.phys != PHYS_BASE || mapping.size != SIZE_TOTAL {
        return false;
    }
    if domain.mapping(IOVA_BASE).is_some() {
        return false;
    }

    let pml4_idx = ((IOVA_BASE >> 39) & 0x1FF) as usize;
    unsafe {
        let pml4_entry = *domain.page_table.add(pml4_idx);
        !pml4_entry.is_present()
    }
}

pub fn wave2_page_table_scope_commit_preserves_counts_smoke() -> bool {
    let mut scope = match PageTableScope::new(None) {
        Ok(scope) => scope,
        Err(_) => return false,
    };
    let scope_phys = scope.phys();
    let parent_phys = 0xDEADBEEF;

    register_page_table(scope_phys);
    for _ in 0..42 {
        let _ = inc_ref(scope_phys);
    }
    register_page_table(parent_phys);

    let mut parent_entry = SlPte::new();
    scope.attach_to_parent(
        &mut parent_entry as *mut SlPte,
        parent_phys,
        PteFormat::Intel,
        1,
    );
    scope.commit();

    let ok = get_ref_count(scope_phys) == 42 && get_ref_count(parent_phys) == 1;
    unregister_page_table(parent_phys);
    unregister_page_table(scope_phys);
    ok
}
