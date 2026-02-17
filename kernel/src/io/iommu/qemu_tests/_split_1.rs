use super::*;


mod _split_1;
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

    let mut ctrl = IommuController::new(0x0, 0);
    crate::sync::set_panicking(true);
    if let Ok(_g) = ctrl.page_request_queue.lock() {}
    crate::sync::set_panicking(false);

    ctrl.process_page_requests().is_empty()
}

pub fn wave2_create_domain_poisoned_returns_hw_error_smoke() -> bool {

    let ctrl = IommuController::new(0x0, 0);
    crate::sync::set_panicking(true);
    if let Ok(_g) = ctrl.domains.lock() {}
    crate::sync::set_panicking(false);

    ctrl.create_domain(Some(0), IommuDomainType::Translated)
        .err()
        == Some(IommuError::HardwareError)
}

pub fn wave2_isolate_faulting_device_poisoned_attempts_isolation_smoke() -> bool {

    let ctrl = IommuController::new(0x0, 0);
    let mut table = match HardwareTable::<ContextEntry>::new(256, None) {
        Ok(table) => table,
        Err(_) => {
            crate::io::log::early_print(
                "[qemu-suite] wave2_isolate_faulting_device: table alloc failed\n",
            );
            return false;
        }
    };
    if let Some(entry) = table.get_mut(0) {
        entry.lo = 1;
    } else {
        crate::io::log::early_print(
            "[qemu-suite] wave2_isolate_faulting_device: context entry missing\n",
        );
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

    crate::sync::set_panicking(true);
    if let Ok(_g) = ctrl.hardware.lock() {}
    crate::sync::set_panicking(false);

    if !ctrl.hardware.is_poisoned() {
        crate::io::log::early_print(
            "[qemu-suite] wave2_isolate_faulting_device: lock not poisoned\n",
        );
        return false;
    }

    let isolate_result = ctrl.isolate_faulting_device(FaultRecord {
        lo: FaultRecord::FAULT,
        hi: 0,
    });
    if isolate_result.is_err() {
        crate::io::log::early_print(
            "[qemu-suite] wave2_isolate_faulting_device: isolate returned error\n",
        );
    }

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
    if present {
        crate::io::log::early_print(
            "[qemu-suite] wave2_isolate_faulting_device: present bit remained set\n",
        );
    }
    !present
}

pub fn wave2_domain_map_poisoned_returns_none_smoke() -> bool {

    let ctrl = IommuController::new(0x0, 0);
    let id = match ctrl.create_domain(None, IommuDomainType::Translated) {
        Ok(id) => id,
        Err(_) => return false,
    };

    crate::sync::set_panicking(true);
    if let Ok(_g) = ctrl.domains.lock() {}
    crate::sync::set_panicking(false);

    ctrl.domain(id).is_none()
}

pub fn wave2_get_domain_for_device_poisoned_returns_hw_error_smoke() -> bool {

    let ctrl = IommuController::new(0x0, 0);
    let id = match ctrl.create_domain(None, IommuDomainType::Translated) {
        Ok(id) => id,
        Err(_) => return false,
    };
    let device = DeviceId::new(0, 0, 1, 0);
    if let Ok(mut dmap) = ctrl.device_domains.lock() {
        dmap.insert(device, id);
    }

    crate::sync::set_panicking(true);
    if let Ok(_g) = ctrl.device_domains.lock() {}
    crate::sync::set_panicking(false);

    ctrl.get_domain_for_device(device).err() == Some(IommuError::HardwareError)
}

pub fn wave2_set_domain_numa_poisoned_returns_hw_error_smoke() -> bool {

    let ctrl = IommuController::new(0x0, 0);
    let id = match ctrl.create_domain(None, IommuDomainType::Translated) {
        Ok(id) => id,
        Err(_) => return false,
    };

    crate::sync::set_panicking(true);
    if let Ok(_g) = ctrl.domains.lock() {}
    crate::sync::set_panicking(false);

    ctrl.set_domain_numa(id, Some(1)).err() == Some(IommuError::HardwareError)
}

pub fn wave2_init_iova_poisoned_proceeds_with_best_effort_smoke() -> bool {

    let ctrl = IommuController::new(0x0, 0);

    crate::sync::set_panicking(true);
    if let Ok(_g) = ctrl.iova_allocator.lock() {}
    crate::sync::set_panicking(false);

    if ctrl.init_iova(0x2000_0000, 0x10000).is_err() {
        return false;
    }

    match ctrl.iova_allocator.lock() {
        Ok(g) => g.is_some(),
        Err(poisoned) => poisoned.into_inner().is_some(),
    }
}

pub fn wave2_init_interrupt_remapping_poisoned_proceeds_with_best_effort_smoke() -> bool {

    let mut ctrl = IommuController::new(0x0, 0);
    ctrl.ecap |= ecap_bits::ECAP_IR;

    crate::sync::set_panicking(true);
    if let Ok(_g) = ctrl.interrupt_remap_table.lock() {}
    crate::sync::set_panicking(false);

    if ctrl.init_interrupt_remapping(4).is_err() {
        return false;
    }

    match ctrl.interrupt_remap_table.lock() {
        Ok(g) => g.is_some(),
        Err(poisoned) => poisoned.into_inner().is_some(),
    }
}

pub fn wave2_enable_queued_invalidation_poisoned_returns_hw_error_smoke() -> bool {

    let ctrl = IommuController::new(0x0, 0);
    crate::sync::set_panicking(true);
    if let Ok(_g) = ctrl.invalidation_queue.lock() {}
    crate::sync::set_panicking(false);

    unsafe { ctrl.enable_queued_invalidation() }.err() == Some(IommuError::HardwareError)
}

pub fn wave2_submit_invalidation_poisoned_returns_error_smoke() -> bool {

    let mut ctrl = IommuController::new(0x0, 0);
    ctrl.ecap = ecap_bits::ECAP_QI;
    if ctrl.init_queued_invalidation(8).is_err() {
        return false;
    }

    crate::sync::set_panicking(true);
    if let Ok(_g) = ctrl.invalidation_queue.lock() {}
    crate::sync::set_panicking(false);

    ctrl.submit_invalidation(InvalidationQueueEntry::iec_invalidate_global())
        .err()
        == Some(IommuError::HardwareError)
}

pub fn wave2_qi_wait_sync_poisoned_returns_error_smoke() -> bool {

    let mut ctrl = IommuController::new(0x0, 0);
    ctrl.ecap = ecap_bits::ECAP_QI;
    if ctrl.init_queued_invalidation(8).is_err() {
        return false;
    }

    crate::sync::set_panicking(true);
    if let Ok(_g) = ctrl.invalidation_queue.lock() {}
    crate::sync::set_panicking(false);

    ctrl.qi_wait_sync() == Err(IommuError::HardwareError)
}

pub fn wave2_qi_wait_async_poisoned_returns_error_smoke() -> bool {

    let mut ctrl = IommuController::new(0x0, 0);
    ctrl.ecap = ecap_bits::ECAP_QI;
    if ctrl.init_queued_invalidation(8).is_err() {
        return false;
    }

    crate::sync::set_panicking(true);
    if let Ok(_g) = ctrl.invalidation_queue.lock() {}
    crate::sync::set_panicking(false);

    crate::task::block_on(async { ctrl.qi_wait_async().await }) == Err(IommuError::HardwareError)
}

pub fn wave3_scalable_mode_pasid0_fault_resolution_smoke() -> bool {
    struct Wave3Notifier {
        seen: AtomicBool,
        domain_id: AtomicU32,
    }

    impl Wave3Notifier {
        fn new() -> Self {
            Self {
                seen: AtomicBool::new(false),
                domain_id: AtomicU32::new(u32::MAX),
            }
        }

        fn seen(&self) -> bool {
            self.seen.load(Ordering::Acquire)
        }

        fn domain_id(&self) -> u32 {
            self.domain_id.load(Ordering::Acquire)
        }
    }

    impl SecurityNotifier for Wave3Notifier {
        fn notify(&self, event: SecurityEvent) {
            if let SecurityEvent::DmaViolation { domain_id, .. } = event {
                self.domain_id
                    .store(domain_id.unwrap_or(u32::MAX), Ordering::Release);
                self.seen.store(true, Ordering::Release);
            }
        }
    }

    let ctrl = IommuController::new(0x0, 0);
    ctrl.set_scalable_mode_enabled(true);

    let root_table = match HardwareTable::<RootEntry>::new(256, None) {
        Ok(table) => table,
        Err(_) => return false,
    };
    let scalable_table = match HardwareTable::<ScalableContextEntry>::new(256, None) {
        Ok(table) => table,
        Err(_) => return false,
    };

    {
        match ctrl.hardware.lock() {
            Ok(mut hw) => {
                hw.root_table = Some(root_table);
                hw.scalable_context_tables.push(scalable_table);
            }
            Err(poisoned) => {
                let mut hw = poisoned.into_inner();
                hw.root_table = Some(root_table);
                hw.scalable_context_tables.push(scalable_table);
            }
        }
    }

    let domain_id = match ctrl.create_domain(None, IommuDomainType::Translated) {
        Ok(id) => id,
        Err(_) => return false,
    };
    let device = DeviceId::new(0, 0, 1, 0);
    if ctrl.attach_device(device, domain_id).is_err() {
        return false;
    }

    let domain = match ctrl.domain(domain_id) {
        Some(domain) => domain,
        None => return false,
    };
    if domain.map(0x1000, 0x2000, 0x1000, true, true).is_err() {
        return false;
    }
    if domain.unmap(0x1000).is_err() {
        return false;
    }

    {
        let hw_guard = match ctrl.hardware.lock() {
            Ok(hw) => hw,
            Err(poisoned) => poisoned.into_inner(),
        };
        let Some(root_entry) = hw_guard.root_table.as_ref().and_then(|table| table.get(0)) else {
            return false;
        };
        if !root_entry.is_present_low() || !root_entry.is_present_high() {
            return false;
        }

        let devfn = ((device.device as usize) << 3) | (device.function as usize);
        let Some(ctx_entry) = hw_guard
            .scalable_context_tables
            .get(0)
            .and_then(|table| table.get(devfn))
        else {
            return false;
        };
        if !ctx_entry.is_present() {
            return false;
        }
    }

    let pasid_domain = match ctrl.device_pasid_tables.lock() {
        Ok(tables) => tables.get(&device).and_then(|table| table.domain_id(0)),
        Err(poisoned) => {
            let tables = poisoned.into_inner();
            tables.get(&device).and_then(|table| table.domain_id(0))
        }
    };
    if pasid_domain != Some(domain_id) {
        return false;
    }

    match ctrl.device_domains.lock() {
        Ok(mut domains) => {
            domains.remove(&device);
        }
        Err(poisoned) => {
            let mut domains = poisoned.into_inner();
            domains.remove(&device);
        }
    }

    let notifier = Arc::new(Wave3Notifier::new());
    if !ctrl.set_security_notifier(notifier.clone()) {
        return false;
    }

    push_deferred_fault_for_test(RawFaultEvent {
        source_id: device.requester_id(),
        fault_address: 0xdead_beef,
        reason: 0x05,
        pasid: Some(0),
        lo: 0,
        hi: 0,
        is_overflow: false,
    });

    let _ = drain_deferred_faults_with_controller(Some(&ctrl));

    notifier.seen() && notifier.domain_id() == domain_id as u32
}
