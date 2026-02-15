use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use super::domain::IommuDomain;
use super::fault_log::FaultRecord;
use super::intel::controller::dma::DomainManager;
use super::intel::controller::fault::FaultHandler;
use super::intel::controller::iova::IovaManager;
use super::intel::controller::ir::InterruptRemapper;
use super::intel::controller::pri::PageRequestManager;
use super::intel::controller::qi_init::QIManager;
use super::intel::controller::qi_ops::InvalidationOps;
use super::intel::controller::IommuController;
use super::intel::qi::InvalidationQueueEntry;
use super::intel::registers::ecap_bits;
use super::intel::tables::ContextEntry;
use super::page_table_pool::{
    get_ref_count, inc_ref, register_page_table, unregister_page_table, PageTablePool,
};
use super::security::{
    FaultSummary, IsolationDecision, IsolationReason, SecurityEvent, SecurityNotifier,
};
use super::tables::{HardwareTable, PageTableScope, SlPte};
use super::types::{DeviceId, IommuDomainType, IommuError, PteFormat};

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
    let b = match ctrl.allocate_iova(8192) {
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

    let size = 0x3000;
    let phys = 0x2000_0000;
    let iova = match ctrl.allocate_iova(size) {
        Ok(iova) => iova,
        Err(_) => return false,
    };

    let mapping_ok = if let Some(domain_arc) = ctrl.domain(0) {
        if domain_arc.map(iova, phys, size, true, true).is_err() {
            false
        } else if domain_arc.mapping(iova).is_none() {
            false
        } else {
            match domain_arc.unmap(iova) {
                Ok(mapping) => mapping.iova == iova && mapping.phys == phys,
                Err(_) => false,
            }
        }
    } else {
        false
    };

    let free_ok = ctrl.free_iova(iova, size).is_ok();
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

pub fn wave2_page_table_scope_drop_rolls_back_parent_smoke() -> bool {
    let parent_phys = 0xBABA;
    let mut parent_entry = SlPte::new();
    {
        let mut scope = match PageTableScope::new(None) {
            Ok(scope) => scope,
            Err(_) => return false,
        };
        scope.attach_to_parent(
            &mut parent_entry as *mut SlPte,
            parent_phys,
            PteFormat::Intel,
            1,
        );
        if !unsafe { (*(&parent_entry as *const SlPte)).is_present() } {
            return false;
        }
    }
    !unsafe { (*(&parent_entry as *const SlPte)).is_present() }
}

pub fn wave2_security_notifier_registration_smoke() -> bool {
    let ctrl = IommuController::new(0x0, 0);
    let notifier = Arc::new(MockSecurityNotifier::new());
    if !ctrl.set_security_notifier(notifier.clone()) {
        return false;
    }
    let notifier2 = Arc::new(MockSecurityNotifier::new());
    !ctrl.set_security_notifier(notifier2)
}

pub fn wave2_security_event_types_are_copy_smoke() -> bool {
    let event1 = SecurityEvent::DmaViolation {
        source_id: 0x0108,
        fault_address: 0x1000,
        reason: 0x01,
        domain_id: Some(0x10),
    };
    let event2 = event1;
    match event2 {
        SecurityEvent::DmaViolation {
            source_id,
            domain_id,
            ..
        } => {
            if source_id != 0x0108 || domain_id != Some(0x10) {
                return false;
            }
        }
        _ => return false,
    }

    let event3 = SecurityEvent::DeviceIsolated {
        source_id: 0x0208,
        reason: IsolationReason::DmaFault,
    };
    let _event4 = event3;
    let event5 = SecurityEvent::QuarantinePoisoned { domain_id: 42 };
    let _event6 = event5;
    let event7 = SecurityEvent::EventsDropped { count: 10 };
    let _event8 = event7;
    true
}

pub fn wave2_fault_summary_from_fault_record_smoke() -> bool {
    let record = FaultRecord {
        lo: (0x0108u64 << FaultRecord::SID_SHIFT) | 0x42,
        hi: 0x2000,
    };

    let summary = FaultSummary::from(&record);
    summary.source_id == 0x0108 && summary.fault_address == 0x2000 && summary.reason == 0x42
}

pub fn wave2_isolation_decision_default_smoke() -> bool {
    matches!(
        IsolationDecision::default(),
        IsolationDecision::Isolate(IsolationReason::DmaFault)
    )
}

pub fn wave2_identity_mapping_disabled_by_default_smoke() -> bool {
    #[cfg(not(any(feature = "unsafe_iommu_bypass", debug_assertions)))]
    {
        if crate::io::iommu::api::is_unsafe_identity_mapping_allowed() {
            return false;
        }
    }
    true
}

pub fn wave2_iova_not_equal_phys_smoke() -> bool {
    let ctrl = IommuController::new(0x0, 0);
    if ctrl.init_iova(0xF000_0000, 0x10000).is_err() {
        return false;
    }
    let size = 0x1000;
    let iova = match ctrl.allocate_iova(size) {
        Ok(iova) => iova,
        Err(_) => return false,
    };
    let in_expected_range = iova >= 0xF000_0000;
    let free_ok = ctrl.free_iova(iova, size).is_ok();
    in_expected_range && free_ok
}

pub fn wave2_domain_type_not_passthrough_smoke() -> bool {
    let domain = IommuDomain::new(
        0,
        None,
        false,
        false,
        48,
        IommuDomainType::Translated,
        PageTablePool::new(1, 32),
        PteFormat::Intel,
    );
    matches!(domain.domain_type(), IommuDomainType::Translated)
}

pub fn wave2_mapping_iova_phys_distinct_smoke() -> bool {
    let ctrl = IommuController::new(0x0, 0);
    if ctrl.init_iova(0x8000_0000, 0x10000).is_err() {
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
        Err(_) => return false,
    };

    if domain.map(iova, phys, size, true, true).is_err() {
        let _ = ctrl.free_iova(iova, size);
        return false;
    }
    if iova == phys {
        let _ = domain.unmap(iova);
        let _ = ctrl.free_iova(iova, size);
        return false;
    }
    let mapping = match domain.mapping(iova) {
        Some(mapping) => mapping,
        None => {
            let _ = domain.unmap(iova);
            let _ = ctrl.free_iova(iova, size);
            return false;
        }
    };
    let mapping_ok = mapping.iova == iova
        && mapping.phys == phys
        && mapping.iova != mapping.phys;
    let _ = domain.unmap(iova);
    let _ = ctrl.free_iova(iova, size);
    mapping_ok
}

pub fn wave2_process_page_requests_poisoned_returns_empty_smoke() -> bool {
    use crate::sync::set_panicking;

    let mut ctrl = IommuController::new(0x0, 0);
    set_panicking(true);
    if let Ok(_g) = ctrl.page_request_queue.lock() {}
    set_panicking(false);

    ctrl.process_page_requests().is_empty()
}

pub fn wave2_create_domain_poisoned_returns_hw_error_smoke() -> bool {
    use crate::sync::set_panicking;

    let ctrl = IommuController::new(0x0, 0);
    set_panicking(true);
    if let Ok(_g) = ctrl.domains.lock() {}
    set_panicking(false);

    ctrl.create_domain(Some(0), IommuDomainType::Translated)
        .err()
        == Some(IommuError::HardwareError)
}

pub fn wave2_isolate_faulting_device_poisoned_attempts_isolation_smoke() -> bool {
    use crate::sync::set_panicking;

    let ctrl = IommuController::new(0x0, 0);
    let mut table = match HardwareTable::<ContextEntry>::new(256, None) {
        Ok(table) => table,
        Err(_) => return false,
    };
    if let Some(entry) = table.get_mut(0) {
        entry.lo = 1;
    } else {
        return false;
    }

    {
        match ctrl.hardware.lock() {
            Ok(mut hw) => {
                hw.legacy_context_tables.push(table);
            }
            Err(poisoned) => {
                let mut hw = poisoned.into_inner();
                hw.legacy_context_tables.push(table);
            }
        }
    }

    set_panicking(true);
    if let Ok(_g) = ctrl.hardware.lock() {}
    set_panicking(false);

    if !ctrl.hardware.is_poisoned() {
        return false;
    }

    let _ = ctrl.isolate_faulting_device(FaultRecord {
        lo: FaultRecord::FAULT,
        hi: 0,
    });

    let present = match ctrl.hardware.lock() {
        Ok(hw) => hw
            .legacy_context_tables
            .get(0)
            .and_then(|t| t.get(0))
            .map(|e| e.is_present())
            .unwrap_or(false),
        Err(poisoned) => {
            let hw = poisoned.into_inner();
            hw.legacy_context_tables
                .get(0)
                .and_then(|t| t.get(0))
                .map(|e| e.is_present())
                .unwrap_or(false)
        }
    };
    !present
}

pub fn wave2_domain_map_poisoned_returns_none_smoke() -> bool {
    use crate::sync::set_panicking;

    let ctrl = IommuController::new(0x0, 0);
    let id = match ctrl.create_domain(None, IommuDomainType::Translated) {
        Ok(id) => id,
        Err(_) => return false,
    };

    set_panicking(true);
    if let Ok(_g) = ctrl.domains.lock() {}
    set_panicking(false);

    ctrl.domain(id).is_none()
}

pub fn wave2_get_domain_for_device_poisoned_returns_hw_error_smoke() -> bool {
    use crate::sync::set_panicking;

    let ctrl = IommuController::new(0x0, 0);
    let id = match ctrl.create_domain(None, IommuDomainType::Translated) {
        Ok(id) => id,
        Err(_) => return false,
    };
    let device = DeviceId::new(0, 0, 1, 0);
    if let Ok(mut dmap) = ctrl.device_domains.lock() {
        dmap.insert(device, id);
    }

    set_panicking(true);
    if let Ok(_g) = ctrl.device_domains.lock() {}
    set_panicking(false);

    ctrl.get_domain_for_device(device).err() == Some(IommuError::HardwareError)
}

pub fn wave2_set_domain_numa_poisoned_returns_hw_error_smoke() -> bool {
    use crate::sync::set_panicking;

    let ctrl = IommuController::new(0x0, 0);
    let id = match ctrl.create_domain(None, IommuDomainType::Translated) {
        Ok(id) => id,
        Err(_) => return false,
    };

    set_panicking(true);
    if let Ok(_g) = ctrl.domains.lock() {}
    set_panicking(false);

    ctrl.set_domain_numa(id, Some(1)).err() == Some(IommuError::HardwareError)
}

pub fn wave2_init_iova_poisoned_proceeds_with_best_effort_smoke() -> bool {
    use crate::sync::set_panicking;

    let ctrl = IommuController::new(0x0, 0);

    set_panicking(true);
    if let Ok(_g) = ctrl.iova_allocator.lock() {}
    set_panicking(false);

    if ctrl.init_iova(0x2000_0000, 0x10000).is_err() {
        return false;
    }

    match ctrl.iova_allocator.lock() {
        Ok(g) => g.is_some(),
        Err(poisoned) => poisoned.into_inner().is_some(),
    }
}

pub fn wave2_init_interrupt_remapping_poisoned_proceeds_with_best_effort_smoke() -> bool {
    use crate::sync::set_panicking;

    let mut ctrl = IommuController::new(0x0, 0);
    ctrl.ecap |= ecap_bits::ECAP_IR;

    set_panicking(true);
    if let Ok(_g) = ctrl.interrupt_remap_table.lock() {}
    set_panicking(false);

    if ctrl.init_interrupt_remapping(4).is_err() {
        return false;
    }

    match ctrl.interrupt_remap_table.lock() {
        Ok(g) => g.is_some(),
        Err(poisoned) => poisoned.into_inner().is_some(),
    }
}

pub fn wave2_enable_queued_invalidation_poisoned_returns_hw_error_smoke() -> bool {
    use crate::sync::set_panicking;

    let ctrl = IommuController::new(0x0, 0);
    set_panicking(true);
    if let Ok(_g) = ctrl.invalidation_queue.lock() {}
    set_panicking(false);

    unsafe { ctrl.enable_queued_invalidation() }.err() == Some(IommuError::HardwareError)
}

pub fn wave2_submit_invalidation_poisoned_returns_error_smoke() -> bool {
    use crate::sync::set_panicking;

    let mut ctrl = IommuController::new(0x0, 0);
    ctrl.ecap = ecap_bits::ECAP_QI;
    if ctrl.init_queued_invalidation(8).is_err() {
        return false;
    }

    set_panicking(true);
    if let Ok(_g) = ctrl.invalidation_queue.lock() {}
    set_panicking(false);

    ctrl.submit_invalidation(InvalidationQueueEntry::iec_invalidate_global())
        .err()
        == Some(IommuError::HardwareError)
}

pub fn wave2_qi_wait_sync_poisoned_returns_error_smoke() -> bool {
    use crate::sync::set_panicking;

    let mut ctrl = IommuController::new(0x0, 0);
    ctrl.ecap = ecap_bits::ECAP_QI;
    if ctrl.init_queued_invalidation(8).is_err() {
        return false;
    }

    set_panicking(true);
    if let Ok(_g) = ctrl.invalidation_queue.lock() {}
    set_panicking(false);

    ctrl.qi_wait_sync() == Err(IommuError::HardwareError)
}

pub fn wave2_qi_wait_async_poisoned_returns_error_smoke() -> bool {
    use crate::sync::set_panicking;

    let mut ctrl = IommuController::new(0x0, 0);
    ctrl.ecap = ecap_bits::ECAP_QI;
    if ctrl.init_queued_invalidation(8).is_err() {
        return false;
    }

    set_panicking(true);
    if let Ok(_g) = ctrl.invalidation_queue.lock() {}
    set_panicking(false);

    crate::task::block_on(async { ctrl.qi_wait_async().await }) == Err(IommuError::HardwareError)
}

pub fn cmdqueue_reclaim_completed_slot_smoke() -> bool {
    super::cmdqueue::qemu_smoke_reclaim_completed_slot()
}

pub fn cmdqueue_cancel_queued_command_smoke() -> bool {
    super::cmdqueue::qemu_smoke_cancel_queued_command()
}

pub fn cmdqueue_drop_triggers_cancel_smoke() -> bool {
    super::cmdqueue::qemu_smoke_drop_triggers_cancel()
}

pub fn cmdqueue_process_up_to_respects_fuel_smoke() -> bool {
    super::cmdqueue::qemu_smoke_process_up_to_respects_fuel()
}

pub fn cmdqueue_fuel_shim_basic_smoke() -> bool {
    super::cmdqueue::qemu_smoke_fuel_shim_basic()
}

pub fn cmdqueue_metrics_counts_smoke() -> bool {
    super::cmdqueue::qemu_smoke_metrics_counts()
}
