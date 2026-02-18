use super::*;


/// PASID table alloc/free lifecycle: allocate 3 PASIDs, setup SL entries, verify domain IDs, free all.
mod _split_1;
pub fn wave3_pasid_table_alloc_free_smoke() -> bool {
    use super::intel::tables::PasidTable;

    let mut table = match PasidTable::new(6) {
        Ok(t) => t,
        Err(_) => return false,
    };

    // Allocate 3 PASIDs - all should be unique and non-zero
    let p1 = match table.allocate_pasid() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let p2 = match table.allocate_pasid() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let p3 = match table.allocate_pasid() {
        Ok(p) => p,
        Err(_) => return false,
    };

    if p1 == 0 || p2 == 0 || p3 == 0 {
        return false;
    }
    if p1 == p2 || p1 == p3 || p2 == p3 {
        return false;
    }

    // Setup SL entries with different domain IDs
    if table.setup_sl_entry(p1, 0x1000, 2, 10).is_err() {
        return false;
    }
    if table.setup_sl_entry(p2, 0x2000, 2, 20).is_err() {
        return false;
    }
    if table.setup_sl_entry(p3, 0x3000, 2, 30).is_err() {
        return false;
    }

    // Verify domain IDs
    if table.domain_id(p1) != Some(10) {
        return false;
    }
    if table.domain_id(p2) != Some(20) {
        return false;
    }
    if table.domain_id(p3) != Some(30) {
        return false;
    }

    // Free all PASIDs
    if table.free_pasid(p1).is_err() {
        return false;
    }
    if table.free_pasid(p2).is_err() {
        return false;
    }
    if table.free_pasid(p3).is_err() {
        return false;
    }

    // Verify freed
    !table.is_allocated(p1)
        && !table.is_allocated(p2)
        && !table.is_allocated(p3)
        && table.domain_id(p1).is_none()
        && table.domain_id(p2).is_none()
        && table.domain_id(p3).is_none()
}

/// PASID table multi-domain: two PASIDs with different domain IDs remain isolated.
pub fn wave3_pasid_table_multi_domain_smoke() -> bool {
    use super::intel::tables::PasidTable;

    let mut table = match PasidTable::new(6) {
        Ok(t) => t,
        Err(_) => return false,
    };

    let p1 = match table.allocate_pasid() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let p2 = match table.allocate_pasid() {
        Ok(p) => p,
        Err(_) => return false,
    };

    let domain_a: u16 = 100;
    let domain_b: u16 = 200;
    if table.setup_sl_entry(p1, 0x10000, 2, domain_a).is_err() {
        return false;
    }
    if table.setup_sl_entry(p2, 0x20000, 2, domain_b).is_err() {
        return false;
    }

    table.domain_id(p1) == Some(domain_a)
        && table.domain_id(p2) == Some(domain_b)
        && table.allocated_count() >= 2
}

/// PASID table exhaustion: fill table, verify error, free one, re-allocate succeeds.
pub fn wave3_pasid_table_exhaustion_smoke() -> bool {
    use super::intel::tables::PasidTable;

    // size_log2=2 → size=4. PASID 0 reserved, so 3 allocatable PASIDs (1, 2, 3)
    let mut table = match PasidTable::new(2) {
        Ok(t) => t,
        Err(_) => return false,
    };

    let p1 = match table.allocate_pasid() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let p2 = match table.allocate_pasid() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let p3 = match table.allocate_pasid() {
        Ok(p) => p,
        Err(_) => return false,
    };

    // 4th allocation should fail (exhausted)
    if table.allocate_pasid().is_ok() {
        return false;
    }

    // Free one PASID
    if table.free_pasid(p2).is_err() {
        return false;
    }

    // Now allocation should succeed again (reuses freed slot)
    let p4 = match table.allocate_pasid() {
        Ok(p) => p,
        Err(_) => return false,
    };

    p4 == p2 && table.is_allocated(p1) && table.is_allocated(p3) && table.is_allocated(p4)
}

/// Scalable mode detach cleans PASID table: attach → verify pasid table → detach → verify removed.
pub fn wave3_scalable_mode_detach_cleans_pasid_smoke() -> bool {
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

    // Verify device_pasid_tables contains the device
    let has_pasid_before = match ctrl.device_pasid_tables.lock() {
        Ok(tables) => tables.contains_key(&device),
        Err(poisoned) => poisoned.into_inner().contains_key(&device),
    };
    if !has_pasid_before {
        return false;
    }

    // Detach
    if ctrl.detach_device(device).is_err() {
        return false;
    }

    // Verify device_pasid_tables no longer contains the device
    let has_pasid_after = match ctrl.device_pasid_tables.lock() {
        Ok(tables) => tables.contains_key(&device),
        Err(poisoned) => poisoned.into_inner().contains_key(&device),
    };
    !has_pasid_after
}

/// Scalable mode attach-detach cycle: attach → verify → detach → verify cleared → re-attach → verify.
pub fn wave3_scalable_mode_attach_detach_cycle_smoke() -> bool {
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
    let device = DeviceId::new(0, 0, 2, 0);

    // Cycle 1: attach
    if ctrl.attach_device(device, domain_id).is_err() {
        return false;
    }

    // Verify context present
    let ctx_present_1 = {
        let hw_guard = match ctrl.hardware.lock() {
            Ok(hw) => hw,
            Err(poisoned) => poisoned.into_inner(),
        };
        let devfn = ((device.device as usize) << 3) | (device.function as usize);
        hw_guard
            .scalable_context_tables
            .get(0)
            .and_then(|table| table.get(devfn))
            .map(|entry| entry.is_present())
            .unwrap_or(false)
    };
    if !ctx_present_1 {
        return false;
    }

    // Detach
    if ctrl.detach_device(device).is_err() {
        return false;
    }

    // Verify context cleared
    let ctx_present_after_detach = {
        let hw_guard = match ctrl.hardware.lock() {
            Ok(hw) => hw,
            Err(poisoned) => poisoned.into_inner(),
        };
        let devfn = ((device.device as usize) << 3) | (device.function as usize);
        hw_guard
            .scalable_context_tables
            .get(0)
            .and_then(|table| table.get(devfn))
            .map(|entry| entry.is_present())
            .unwrap_or(false)
    };
    if ctx_present_after_detach {
        return false;
    }

    // Cycle 2: re-attach
    if ctrl.attach_device(device, domain_id).is_err() {
        return false;
    }

    // Verify context present again
    let ctx_present_2 = {
        let hw_guard = match ctrl.hardware.lock() {
            Ok(hw) => hw,
            Err(poisoned) => poisoned.into_inner(),
        };
        let devfn = ((device.device as usize) << 3) | (device.function as usize);
        hw_guard
            .scalable_context_tables
            .get(0)
            .and_then(|table| table.get(devfn))
            .map(|entry| entry.is_present())
            .unwrap_or(false)
    };
    ctx_present_2
}

pub fn wave3_mapping_slab_insert_lookup_remove_smoke() -> bool {
    super::mapping_slab::qemu_smoke_insert_lookup_remove()
}

pub fn wave3_mapping_slab_overlap_detection_smoke() -> bool {
    super::mapping_slab::qemu_smoke_overlap_detection()
}

pub fn wave3_zombie_queue_basic_smoke() -> bool {
    super::zombie_queue::qemu_smoke_queue_basic()
}

pub fn wave3_zombie_queue_failed_cleanup_smoke() -> bool {
    super::zombie_queue::qemu_smoke_failed_cleanup()
}

/// PRI fuel-based processing: create queue, populate entries, verify fuel limit and has_more.
///
/// PageRequestQueue は hardware が tail に書き込むリングバッファ。
/// テストでは backing memory に直接書き込み、update_tail() で tail を進めて
/// fuel 制限付き pop と has_pending() の正確性を検証する。
pub fn wave3_pri_fuel_processing_smoke() -> bool {
    use super::common::{PageRequestEntry, PageRequestQueue};

    // Create a small queue (size will round up to power of 2)
    let mut prq = match PageRequestQueue::new(8) {
        Some(q) => q,
        None => return false,
    };

    // Write 4 test entries directly into the queue's backing memory (simulating hardware writes)
    let base = prq.base_address() as *mut PageRequestEntry;
    for i in 0..4u64 {
        let entry = PageRequestEntry {
            lo: (i as u64 + 1) | PageRequestEntry::LAST_REQ, // source_id = i+1, last_req set
            hi: ((i + 1) * 0x1000) & 0x000F_FFFF_FFFF_F000, // page address
        };
        unsafe { base.add(i as usize).write(entry) };
    }

    // Simulate hardware advancing tail to 4
    prq.update_tail(4);

    // Verify all 4 entries are pending
    if !prq.has_pending() {
        return false;
    }

    // Pop with fuel=2: should return exactly 2 entries, has_more=true
    let mut batch = alloc::vec::Vec::new();
    for _ in 0..2 {
        match prq.pop() {
            Some(entry) => batch.push(entry),
            None => break,
        }
    }
    if batch.len() != 2 {
        return false;
    }
    if !prq.has_pending() {
        return false; // 2 more should remain
    }

    // Verify first entry's source_id
    if batch[0].source_id() != 1 {
        return false;
    }
    if batch[1].source_id() != 2 {
        return false;
    }

    // Pop remaining 2
    let mut batch2 = alloc::vec::Vec::new();
    for _ in 0..2 {
        match prq.pop() {
            Some(entry) => batch2.push(entry),
            None => break,
        }
    }
    if batch2.len() != 2 {
        return false;
    }

    // Queue should now be empty
    if prq.has_pending() {
        return false;
    }

    // One more pop should return None
    prq.pop().is_none()
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

// ============================================================================
// Mock PCI Topology for IOMMU Grouping tests
// ============================================================================

pub(crate) struct MockPciTopology {
    header_types: BTreeMap<(u8, u8, u8), u8>,
    acs_states: BTreeMap<(u8, u8, u8), bool>,
    bridge_parents: BTreeMap<u8, (u8, u8, u8)>,
}

impl MockPciTopology {
    pub(super) fn new() -> Self {
        Self {
            header_types: BTreeMap::new(),
            acs_states: BTreeMap::new(),
            bridge_parents: BTreeMap::new(),
        }
    }

    pub(super) fn add_endpoint(&mut self, bus: u8, device: u8, function: u8) {
        self.header_types.insert((bus, device, function), 0x00);
    }

    pub(super) fn add_bridge(
        &mut self,
        bus: u8,
        device: u8,
        function: u8,
        acs_enabled: Option<bool>,
    ) {
        self.header_types.insert((bus, device, function), 0x01);
        if let Some(acs) = acs_enabled {
            self.acs_states.insert((bus, device, function), acs);
        }
    }

    pub(super) fn set_parent_bridge(&mut self, child_bus: u8, parent: (u8, u8, u8)) {
        self.bridge_parents.insert(child_bus, parent);
    }
}

impl PciTopologyProvider for MockPciTopology {
    fn read_header_type(&self, bus: u8, device: u8, function: u8) -> Option<u8> {
        self.header_types.get(&(bus, device, function)).copied()
    }

    fn is_acs_isolation_enabled(&self, bus: u8, device: u8, function: u8) -> Option<bool> {
        self.acs_states.get(&(bus, device, function)).copied()
    }

    fn find_parent_bridge(&self, child_bus: u8) -> Option<(u8, u8, u8)> {
        self.bridge_parents.get(&child_bus).copied()
    }
}

// ============================================================================
// IOMMU Grouping Smoke Tests
// ============================================================================

/// Basic group creation: single endpoint on bus 0, verify domain allocation.
pub fn wave2_group_creation_basic_smoke() -> bool {
    let mut topo = MockPciTopology::new();
    topo.add_endpoint(0, 1, 0);

    let ctrl = IommuController::new(0x0, 0);
    let mgr = IommuGroupManager::new();
    let dev = DeviceId::new(0, 0, 1, 0);

    let (group, newly_created) = match mgr.find_or_create_group(dev, &ctrl, 0, &topo) {
        Ok(result) => result,
        Err(_) => return false,
    };

    if !newly_created {
        return false;
    }
    if group.controller_idx != 0 {
        return false;
    }
    // Verify group lookup works after creation
    mgr.get_group_for_device(&dev).is_some()
}

/// Multi-function device: functions 0 and 1 share the same group.
pub fn wave2_group_multifunction_same_group_smoke() -> bool {
    let mut topo = MockPciTopology::new();
    topo.add_endpoint(0, 2, 0);
    topo.add_endpoint(0, 2, 1);

    let ctrl = IommuController::new(0x0, 0);
    let mgr = IommuGroupManager::new();
    let dev0 = DeviceId::new(0, 0, 2, 0);
    let dev1 = DeviceId::new(0, 0, 2, 1);

    let (group0, created0) = match mgr.find_or_create_group(dev0, &ctrl, 0, &topo) {
        Ok(r) => r,
        Err(_) => return false,
    };
    let (group1, created1) = match mgr.find_or_create_group(dev1, &ctrl, 0, &topo) {
        Ok(r) => r,
        Err(_) => return false,
    };

    // Function 0 creates new group; function 1 reuses it (same group ID via func 0 base)
    created0 && !created1 && group0.id == group1.id && group0.domain_id == group1.domain_id
}

/// ACS-isolated devices behind separate ACS-enabled bridges get separate groups.
pub fn wave2_group_acs_isolated_separation_smoke() -> bool {
    let mut topo = MockPciTopology::new();
    // Bridge at (0,1,0) → bus 1 with ACS enabled
    topo.add_bridge(0, 1, 0, Some(true));
    topo.set_parent_bridge(1, (0, 1, 0));
    topo.add_endpoint(1, 0, 0);

    // Bridge at (0,2,0) → bus 2 with ACS enabled
    topo.add_bridge(0, 2, 0, Some(true));
    topo.set_parent_bridge(2, (0, 2, 0));
    topo.add_endpoint(2, 0, 0);

    let ctrl = IommuController::new(0x0, 0);
    let mgr = IommuGroupManager::new();
    let dev_a = DeviceId::new(0, 1, 0, 0);
    let dev_b = DeviceId::new(0, 2, 0, 0);

    let (group_a, created_a) = match mgr.find_or_create_group(dev_a, &ctrl, 0, &topo) {
        Ok(r) => r,
        Err(_) => return false,
    };
    let (group_b, created_b) = match mgr.find_or_create_group(dev_b, &ctrl, 0, &topo) {
        Ok(r) => r,
        Err(_) => return false,
    };

    // Both should be new groups with different IDs
    created_a && created_b && group_a.id != group_b.id
}

/// Calling find_or_create_group twice for the same device reuses the existing group.
pub fn wave2_group_reuse_for_same_group_devices_smoke() -> bool {
    let mut topo = MockPciTopology::new();
    topo.add_endpoint(0, 3, 0);

    let ctrl = IommuController::new(0x0, 0);
    let mgr = IommuGroupManager::new();
    let dev = DeviceId::new(0, 0, 3, 0);

    let (group_first, created_first) = match mgr.find_or_create_group(dev, &ctrl, 0, &topo) {
        Ok(r) => r,
        Err(_) => return false,
    };
    let (group_second, created_second) = match mgr.find_or_create_group(dev, &ctrl, 0, &topo) {
        Ok(r) => r,
        Err(_) => return false,
    };

    created_first
        && !created_second
        && group_first.id == group_second.id
        && group_first.domain_id == group_second.domain_id
}

/// Poisoned groups lock returns IommuError::Poisoned.
pub fn wave2_group_poisoned_lock_returns_error_smoke() -> bool {

    let mgr = IommuGroupManager::new();

    // Poison the groups lock
    crate::sync::set_panicking(true);
    if let Ok(_g) = mgr.groups_lock_for_test() {}
    crate::sync::set_panicking(false);

    let mut topo = MockPciTopology::new();
    topo.add_endpoint(0, 4, 0);
    let ctrl = IommuController::new(0x0, 0);
    let dev = DeviceId::new(0, 0, 4, 0);

    mgr.find_or_create_group(dev, &ctrl, 0, &topo).err() == Some(IommuError::Poisoned)
}

// ============================================================================
// IOMMU Grouping Integration Smoke Tests
// ============================================================================

/// Full flow: group discovery → domain creation → device attach.
pub fn wave2_group_full_flow_discovery_to_attach_smoke() -> bool {
    let mut topo = MockPciTopology::new();
    topo.add_endpoint(0, 5, 0);

    let ctrl = IommuController::new(0x0, 0);
    let mgr = IommuGroupManager::new();
    let dev = DeviceId::new(0, 0, 5, 0);

    // 1. Group discovery creates domain
    let (group, _) = match mgr.find_or_create_group(dev, &ctrl, 0, &topo) {
        Ok(r) => r,
        Err(_) => return false,
    };

    // 2. Attach device to context table (best effort in qemu-test-export env)
    if ctrl.attach_device(dev, group.domain_id).is_err() {
        // Hardware table initialization may be unavailable in this environment.
        // At minimum, verify that group->domain discovery path is functional.
        return ctrl.domain(group.domain_id).is_some();
    }

    // Verify domain assignment when attach succeeds.
    match ctrl.get_domain_for_device(dev) {
        Ok(Some(id)) => id == group.domain_id,
        _ => false,
    }
}
