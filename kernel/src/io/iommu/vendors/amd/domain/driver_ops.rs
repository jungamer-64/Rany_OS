// ============================================================================
// kernel/src/io/iommu/vendors/amd/domain/driver_ops.rs
// ============================================================================

use super::*;

impl AmdIommuDriver {
    pub(crate) fn ivhd_flags_for_device(&self, device: DeviceId) -> u8 {
        let flags = 0u8;
        let devid = device.requester_id();
        let unit = match self.find_unit_for_device(device) {
            Some(unit) => unit,
            None => return flags,
        };

        flags_for_entries(&unit.device_entries, devid)
    }

    pub(super) fn ivhd_global_flags(&self, segment: u16) -> u8 {
        let mut flags = 0u8;
        for unit in &self.units {
            if unit.segment != segment {
                continue;
            }
            for entry in &unit.device_entries {
                if let IvhdDeviceEntry::All { flags: entry_flags } = entry {
                    flags |= *entry_flags;
                }
            }
        }
        flags
    }

    pub(crate) fn domain_for_id(&self, domain_id: u16) -> Result<Arc<DomainState>, IommuError> {
        let domains = self.domains.lock().map_err(|_| IommuError::Poisoned)?;
        let info = domains.get(&domain_id).ok_or(IommuError::DomainNotFound)?;
        Ok(info.domain.clone())
    }

    pub(in crate::io::iommu::vendors::amd) fn device_table_for_segment(
        &self,
        segment: u16,
    ) -> Result<&AmdDeviceTable, IommuError> {
        self.device_tables
            .get(&segment)
            .ok_or(IommuError::NotPresent)
    }

    pub(super) fn build_dte_entry(
        &self,
        domain_id: u16,
        domain: &DomainState,
        ivhd_flags: u8,
    ) -> Result<AmdDeviceTableEntry, IommuError> {
        let root = if domain.domain_type == IommuDomainType::Passthrough {
            0
        } else {
            let address = virt_ptr_to_phys(domain.page_table as *const u8)?;
            if address & !PM_ADDR_MASK != 0 {
                return Err(IommuError::InvalidAddress);
            }
            address | (PAGE_MODE_4_LEVEL << DEV_ENTRY_MODE_SHIFT)
        };
        Ok(AmdDeviceTableEntry::translated(domain_id, root, ivhd_flags))
    }

    pub(crate) fn reject_excluded_ivmd_range(
        &self,
        device: DeviceId,
        phys_addr: u64,
        size: u64,
    ) -> Result<(), IommuError> {
        reject_excluded_ranges(&self.ivmd_ranges_for_device(device), phys_addr, size)
    }

    /// IVRS aliases identify the same requester. Bind devices sharing that
    /// requester to the same DTE cohort, domain and interrupt-remapping table.
    fn requester_route(&self, device: DeviceId) -> Result<(DeviceId, usize), IommuError> {
        if device.device >= 32 || device.function >= 8 {
            return Err(IommuError::InvalidAddress);
        }
        let unit = self
            .find_unit_index_for_device(device)
            .ok_or(IommuError::DeviceNotFound)?;
        let key = self
            .requester_aliases
            .get(&device)
            .copied()
            .unwrap_or(device);
        Ok((key, unit))
    }

    pub(in crate::io::iommu::vendors::amd) fn attached_domain(
        &self,
        device: DeviceId,
    ) -> Result<Arc<DomainState>, IommuError> {
        let key = self
            .requester_aliases
            .get(&device)
            .copied()
            .unwrap_or(device);
        let bindings = self
            .device_bindings
            .lock()
            .map_err(|_| IommuError::Poisoned)?;
        match bindings.get(&key) {
            Some(binding) if binding.requesters.contains(&device.requester_id()) => {
                match &binding.state {
                    BindingState::Attached(attachment) => Ok(Arc::clone(&attachment.domain)),
                    _ => Err(IommuError::DomainNotFound),
                }
            }
            _ => Err(IommuError::DomainNotFound),
        }
    }

    pub(crate) fn domain_id_for_device(&self, device: DeviceId) -> Result<u16, IommuError> {
        Ok(self.attached_domain(device)?.id())
    }

    pub(crate) fn populate_default_entries(&self) -> Result<(), IommuError> {
        let default_domain = self.domain_for_id(0)?;
        map_ivmd_ranges(default_domain.as_ref(), &self.ivmd_ranges)?;

        for (segment, table) in &self.device_tables {
            let flags = AmdIommuDriver::ivhd_global_flags(self, *segment);
            let domain = self.domain_for_id(0)?;
            let entry = self.build_dte_entry(0, domain.as_ref(), flags)?;
            table.fill(entry)?;
        }

        Ok(())
    }

    pub(crate) fn create_domain(
        &self,
        numa_node: Option<usize>,
        domain_type: IommuDomainType,
    ) -> Result<u16, IommuError> {
        let raw_id = self
            .next_domain_id
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        if raw_id > u16::MAX as u64 {
            return Err(IommuError::OutOfMemory);
        }
        let domain_id = raw_id as u16;
        let domain = DomainState::new(
            domain_id,
            numa_node,
            false,
            false,
            self.max_addr_bits,
            4,
            domain_type,
            self.page_table_pool.clone(),
            PteFormat::Amd,
        );
        let domain = Arc::new(domain);
        let info = AmdDomainInfo { domain };

        let mut domains = self.domains.lock().map_err(|_| IommuError::Poisoned)?;
        if domains.insert(domain_id, info).is_some() {
            return Err(IommuError::HardwareError);
        }
        Ok(domain_id)
    }

    pub(crate) fn destroy_domain(&self, domain_id: u16) -> Result<(), IommuError> {
        if domain_id == 0 {
            return Err(IommuError::InUse);
        }
        let mut domains = self.domains.lock().map_err(|_| IommuError::Poisoned)?;
        let info = domains.get(&domain_id).ok_or(IommuError::DomainNotFound)?;
        // Attach retains its domain through DTE/device-registry publication.
        // Holding the registry lock excludes all subsequent CPU admissions.
        if Arc::strong_count(&info.domain) != 1 || info.domain.active_dma_count() != 0 {
            return Err(IommuError::InUse);
        }
        crate::io::iommu::common::domain::IommuInvalidator::invalidate(
            self,
            crate::io::iommu::common::domain::InvalidateRequest::domain(domain_id).with_ats(),
        )?;
        let info = domains
            .remove(&domain_id)
            .ok_or(IommuError::DomainNotFound)?;
        let domain = match Arc::try_unwrap(info.domain) {
            Ok(domain) => domain,
            Err(owner) => {
                domains.insert(domain_id, AmdDomainInfo { domain: owner });
                return Err(IommuError::InUse);
            }
        };
        drop(domains);
        // SAFETY: no DTE/ATS or CPU borrower remains, lookup admission was
        // excluded, and domain paging-structure invalidation completed.
        unsafe { domain.retire_after_invalidation() };
        Ok(())
    }

    /// Retain the domain before writing any DTE. A publication that may have
    /// reached hardware must finish or go through revocation before reuse.
    pub(crate) fn attach_device(&self, device: DeviceId, domain_id: u16) -> Result<(), IommuError> {
        let (key, unit) = self.requester_route(device)?;
        let domain = self.domain_for_id(domain_id)?;
        let flags = self.ivhd_flags_for_device(device);
        let table = self.device_table_for_segment(device.segment)?;
        let mut entry = self.build_dte_entry(domain_id, &domain, flags)?;
        let mut bindings = self
            .device_bindings
            .lock()
            .map_err(|_| IommuError::Poisoned)?;

        let requester = device.requester_id();
        if bindings.iter().any(|(other_key, binding)| {
            other_key.segment == key.segment
                && *other_key != key
                && (binding.requesters.contains(&requester)
                    || binding.requesters.contains(&key.requester_id()))
        }) {
            return Err(IommuError::AlreadyMapped);
        }

        if let Some(binding) = bindings.get_mut(&key) {
            if binding.unit != unit {
                return Err(IommuError::FirmwareScope);
            }
            let attachment = match &binding.state {
                BindingState::Attached(attachment) | BindingState::Publishing(attachment)
                    if attachment.domain.id() == domain_id =>
                {
                    attachment
                }
                _ => return Err(IommuError::AlreadyMapped),
            };
            if matches!(binding.state, BindingState::Attached(_))
                && binding.requesters.contains(&requester)
            {
                return Ok(());
            }
            if let Some(irta) = attachment.interrupts.as_ref() {
                entry.set_interrupt_table(irta);
            }
            map_ivmd_ranges(&domain, &self.ivmd_ranges_for_device(device))?;
            if !binding.requesters.contains(&requester) {
                binding
                    .requesters
                    .try_reserve(1)
                    .map_err(|_| IommuError::MetadataAllocation)?;
                // Each newly admitted requester may still cache the default DTE.
                table.write_requesters(&[requester], entry)?;
                binding.requesters.push(requester);
            }
        } else {
            map_ivmd_ranges(&domain, &self.ivmd_ranges_for_device(device))?;
            let mut requesters = Vec::new();
            requesters
                .try_reserve_exact(2)
                .map_err(|_| IommuError::MetadataAllocation)?;
            requesters.push(key.requester_id());
            if requester != key.requester_id() {
                requesters.push(requester);
            }
            bindings
                .try_reserve(1)
                .map_err(|_| IommuError::MetadataAllocation)?;
            let binding = AmdDeviceBinding {
                unit,
                requesters,
                state: BindingState::Publishing(Attachment {
                    domain,
                    interrupts: None,
                }),
            };
            bindings.insert(key, binding);
            let requesters = &bindings.get(&key).expect("new binding").requesters;
            if let Err(error) = table.write_requesters(requesters, entry) {
                bindings.remove(&key);
                return Err(error);
            }
        }

        let binding = bindings.get_mut(&key).expect("retained DTE binding");
        // An alias admitted to an otherwise attached group is unavailable
        // until its DTE publication is confirmed as well.
        if matches!(binding.state, BindingState::Attached(_)) {
            let BindingState::Attached(attachment) =
                core::mem::replace(&mut binding.state, BindingState::Isolated)
            else {
                unreachable!("binding lock held");
            };
            binding.state = BindingState::Publishing(attachment);
        }
        self.invalidate_requesters(unit, &binding.requesters)?;
        self.invalidate_unit_domain(unit, 0)?;
        if domain_id != 0 {
            self.invalidate_domain_all(domain_id)?;
        }
        let BindingState::Publishing(attachment) =
            core::mem::replace(&mut binding.state, BindingState::Isolated)
        else {
            unreachable!("binding lock held");
        };
        binding.state = BindingState::Attached(attachment);
        Ok(())
    }

    pub(crate) fn detach_device(&self, device: DeviceId) -> Result<(), IommuError> {
        self.block_device(device, false)
    }

    pub fn isolate_device(&self, device: DeviceId) -> Result<(), IommuError> {
        self.block_device(device, true)
    }

    fn block_device(&self, device: DeviceId, isolate: bool) -> Result<(), IommuError> {
        let (key, unit) = self.requester_route(device)?;
        let table = self.device_table_for_segment(device.segment)?;
        let mut bindings = self
            .device_bindings
            .lock()
            .map_err(|_| IommuError::Poisoned)?;
        if !bindings.contains_key(&key) {
            if !isolate {
                return Err(IommuError::DeviceNotFound);
            }
            bindings
                .try_reserve(1)
                .map_err(|_| IommuError::MetadataAllocation)?;
            let mut requesters = Vec::new();
            requesters
                .try_reserve_exact(2)
                .map_err(|_| IommuError::MetadataAllocation)?;
            requesters.push(key.requester_id());
            if device != key {
                requesters.push(device.requester_id());
            }
            bindings.insert(
                key,
                AmdDeviceBinding {
                    unit,
                    requesters,
                    state: BindingState::Blocking {
                        attachment: None,
                        isolate,
                    },
                },
            );
        }
        let binding = bindings.get_mut(&key).expect("retained DTE binding");
        if binding.unit != unit {
            return Err(IommuError::FirmwareScope);
        }
        binding.state = match core::mem::replace(&mut binding.state, BindingState::Isolated) {
            BindingState::Publishing(attachment) | BindingState::Attached(attachment) => {
                BindingState::Blocking {
                    attachment: Some(attachment),
                    isolate,
                }
            }
            BindingState::Blocking {
                attachment,
                isolate: pending,
            } => BindingState::Blocking {
                attachment,
                isolate: pending || isolate,
            },
            BindingState::Isolated => return Ok(()),
        };
        let BindingState::Blocking {
            attachment,
            isolate,
        } = &binding.state
        else {
            unreachable!("blocking state retained");
        };
        let old_domain = attachment.as_ref().map_or(0, |owner| owner.domain.id());
        let permanently_blocked = *isolate;
        table.write_requesters(&binding.requesters, AmdDeviceTableEntry::BLOCKED)?;
        self.invalidate_requesters(unit, &binding.requesters)?;
        self.invalidate_unit_domain(unit, old_domain)?;
        self.invalidate_requester_interrupts(unit, &binding.requesters)?;
        if let BindingState::Blocking {
            attachment: Some(attachment),
            ..
        } = core::mem::replace(&mut binding.state, BindingState::Isolated)
            && let Some(table) = attachment.interrupts
        {
            // SAFETY: this requester cohort no longer refers to the table and
            // both relevant IOMMU caches have acknowledged invalidation.
            unsafe { table.retire() };
        }
        if !permanently_blocked {
            bindings.remove(&key);
        }
        Ok(())
    }

    pub(crate) fn map_interrupt(
        &self,
        segment: u16,
        bus: u8,
        device: u8,
        function: u8,
        vector: u8,
        destination: crate::cpu::ApicId,
        logical: bool,
    ) -> Result<u16, IommuError> {
        let device = DeviceId::new(segment, bus, device, function);
        let (key, unit) = self.requester_route(device)?;
        let mut bindings = self
            .device_bindings
            .lock()
            .map_err(|_| IommuError::Poisoned)?;
        let binding = bindings.get_mut(&key).ok_or(IommuError::DeviceNotFound)?;
        if binding.unit != unit || !binding.requesters.contains(&device.requester_id()) {
            return Err(IommuError::DeviceNotFound);
        }
        let BindingState::Attached(attachment) = &mut binding.state else {
            return Err(IommuError::InUse);
        };
        self.interrupt_mode.check_destination(destination)?;
        if attachment.interrupts.is_none() {
            attachment.interrupts =
                Some(super::super::irt::InterruptTable::new(self.interrupt_mode)?);
        }
        let interrupts = attachment
            .interrupts
            .as_mut()
            .expect("owned interrupt table");
        let table = self.device_table_for_segment(segment)?;
        table.write_interrupt_routes(&binding.requesters, interrupts)?;
        self.invalidate_requesters(unit, &binding.requesters)?;
        let index = interrupts.install(vector, destination, logical)?;
        self.invalidate_requester_interrupts(unit, &binding.requesters)?;
        Ok(index)
    }

    pub(crate) fn retire_interrupt(
        &self,
        device: DeviceId,
        index: u16,
        vector: u8,
    ) -> Result<(), IommuError> {
        let (key, unit) = self.requester_route(device)?;
        let mut bindings = self
            .device_bindings
            .lock()
            .map_err(|_| IommuError::Poisoned)?;
        let Some(binding) = bindings.get_mut(&key) else {
            return Ok(());
        };
        let attachment = match &mut binding.state {
            BindingState::Attached(attachment) | BindingState::Publishing(attachment) => attachment,
            BindingState::Isolated => return Ok(()),
            BindingState::Blocking { .. } => return Err(IommuError::InUse),
        };
        let Some(table) = &mut attachment.interrupts else {
            return Ok(());
        };
        if table.mask(index, vector)? {
            self.invalidate_requester_interrupts(unit, &binding.requesters)?;
            table.release(index);
        }
        Ok(())
    }

    pub(crate) fn get_remap_msi_message(&self, handle: u16) -> (u64, u32) {
        super::super::irt::encode_remap_msi(handle)
    }

    pub fn lookup_device_domain(&self, source_id: u16) -> Option<u16> {
        self.domain_id_for_device(DeviceId::from_bdf(source_id))
            .ok()
    }

    pub(crate) fn set_domain_numa(
        &self,
        domain_id: u16,
        numa_node: Option<usize>,
    ) -> Result<(), IommuError> {
        let domain = self.domain_for_id(domain_id)?;
        domain.set_numa_node(numa_node);
        Ok(())
    }

    /// Get domain by ID
    pub(crate) fn get_domain(&self, domain_id: u16) -> Result<Arc<DomainState>, IommuError> {
        self.domain_for_id(domain_id)
    }

    pub(crate) fn get_domain_numa(&self, domain_id: u16) -> Result<Option<usize>, IommuError> {
        let domain = self.domain_for_id(domain_id)?;
        Ok(domain.numa_node())
    }

    pub(crate) fn dump_diagnostics(&self) {
        let unit_count = self.units.len();
        let cmd_ready = self.cmd_states.len();
        let evt_ready = self.event_logs.iter().filter(|log| log.is_some()).count();

        log::info!(
            "[IOMMU][AMD-Vi] units={} cmd_buffers={} event_logs={} enabled={}",
            unit_count,
            cmd_ready,
            evt_ready,
            self.is_enabled()
        );

        match self.domains.lock() {
            Ok(domains) => {
                log::info!("[IOMMU][AMD-Vi] domains={}", domains.len());
            }
            Err(_) => {
                log::warn!("[IOMMU][AMD-Vi] domains lock poisoned");
            }
        }

        match self.device_bindings.lock() {
            Ok(bindings) => {
                log::info!("[IOMMU][AMD-Vi] device_mappings={}", bindings.len());
            }
            Err(_) => {
                log::warn!("[IOMMU][AMD-Vi] device_bindings lock poisoned");
            }
        }

        if let Some(cq) = self.command_queue.as_ref() {
            log::info!(
                "[IOMMU][AMD-Vi] CQ: processed={} cancelled={} cancel_attempts={} reclaimed={} backpressure={}",
                cq.processed_total(),
                cq.cancelled_total(),
                cq.cancel_attempts_total(),
                cq.reclaimed_total(),
                cq.send_backpressure_total()
            );
        } else {
            log::info!("[IOMMU][AMD-Vi] CQ: not initialized");
        }
    }
}
