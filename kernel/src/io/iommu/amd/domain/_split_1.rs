use super::*;


impl AmdIommuDriver {
    pub(super) fn ivhd_flags_for_device(&self, device: DeviceId) -> u8 {
        let mut flags = 0u8;
        let devid = device.requester_id();
        let unit = match self.find_unit_for_device(device) {
            Some(unit) => unit,
            None => return flags,
        };

        for entry in &unit.device_entries {
            flags |= ivhd_entry_flags_for_devid(entry, devid);
        }

        flags
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

    pub(super) fn domain_for_id(&self, domain_id: u16) -> Result<Arc<DomainState>, IommuError> {
        let domains = self.domains.lock().map_err(|_| IommuError::Poisoned)?;
        let info = domains.get(&domain_id).ok_or(IommuError::DomainNotFound)?;
        Ok(info.domain.clone())
    }

    pub(super) fn device_table_for_segment(&self, segment: u16) -> Result<&AmdDeviceTable, IommuError> {
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
        let mut entry = AmdDeviceTableEntry::default();
        entry.data[0] |= DTE_FLAG_V | DTE_FLAG_TV | DTE_FLAG_IR | DTE_FLAG_IW;

        if domain.domain_type != IommuDomainType::Passthrough {
            let root_phys = virt_ptr_to_phys(domain.page_table as *const u8)?;
            if (root_phys & 0xfff) != 0 {
                return Err(IommuError::InvalidAlignment);
            }
            entry.data[0] |=
                (root_phys & PM_ADDR_MASK) | (PAGE_MODE_4_LEVEL << DEV_ENTRY_MODE_SHIFT);
        }

        if ivhd_flags != 0 {
            apply_ivhd_flags(&mut entry, ivhd_flags);
        }

        entry.data[1] |= domain_id as u64;
        Ok(entry)
    }

    pub(super) fn alias_devids_for_device(&self, device: DeviceId) -> Vec<u16> {
        let mut aliases = Vec::new();
        let devid = device.requester_id();
        let unit = match self.find_unit_for_device(device) {
            Some(unit) => unit,
            None => return aliases,
        };

        for entry in &unit.device_entries {
            Self::collect_alias_from_entry(entry, devid, &mut aliases);
        }

        aliases.sort_unstable();
        aliases.dedup();
        aliases
    }

    pub(super) fn collect_alias_from_entry(entry: &IvhdDeviceEntry, devid: u16, aliases: &mut Vec<u16>) {
        match entry {
            IvhdDeviceEntry::Alias {
                devid: entry_devid,
                alias,
                ..
            } => {
                if *entry_devid == devid && *alias != devid {
                    aliases.push(*alias);
                }
            }
            IvhdDeviceEntry::AliasRange {
                start, end, alias, ..
            } => {
                if devid >= *start && devid <= *end && *alias != devid {
                    aliases.push(*alias);
                }
            }
            _ => {}
        }
    }

    pub(super) fn map_ivmd_ranges_for_device(
        &self,
        device: DeviceId,
        domain_id: u16,
    ) -> Result<(), IommuError> {
        let ranges = self.ivmd_ranges_for_device(device);
        if ranges.is_empty() {
            return Ok(());
        }

        let domain = self.domain_for_id(domain_id)?;
        map_ivmd_ranges(domain.as_ref(), &ranges)
    }

    pub(super) fn reject_excluded_ivmd_range(
        &self,
        device: DeviceId,
        phys_addr: u64,
        size: u64,
    ) -> Result<(), IommuError> {
        if size == 0 {
            return Ok(());
        }
        let end = phys_addr
            .checked_add(size)
            .ok_or(IommuError::InvalidAddress)?;
        for range in self.ivmd_ranges_for_device(device) {
            if !range.exclusion {
                continue;
            }
            if range.range_end <= range.range_start {
                continue;
            }
            if phys_addr < range.range_end && end > range.range_start {
                return Err(IommuError::InvalidAddress);
            }
        }
        Ok(())
    }

    /// DTEエントリを書き込み（デバイス本体+エイリアス）
    pub(super) fn write_dte_with_aliases(
        &self,
        table: &AmdDeviceTable,
        device: DeviceId,
        aliases: &[u16],
        entry: AmdDeviceTableEntry,
    ) -> Result<(), IommuError> {
        let devid = device.requester_id();
        table.write_entry(devid, entry)?;
        for alias in aliases {
            table.write_entry(*alias, entry)?;
        }
        Ok(())
    }

    /// DTEエントリをクリア（デバイス本体+エイリアス）
    pub(super) fn clear_dte_with_aliases(
        &self,
        table: &AmdDeviceTable,
        device: DeviceId,
        aliases: &[u16],
    ) -> Result<(), IommuError> {
        let devid = device.requester_id();
        table.clear_entry(devid)?;
        for alias in aliases {
            table.clear_entry(*alias)?;
        }
        Ok(())
    }

    pub(super) fn write_device_entries_for_domain(
        &self,
        device: DeviceId,
        aliases: &[u16],
        domain_id: Option<u16>,
    ) -> Result<(), IommuError> {
        let table = self.device_table_for_segment(device.segment)?;
        match domain_id {
            Some(domain_id) => {
                let domain = self.domain_for_id(domain_id)?;
                let flags = AmdIommuDriver::ivhd_flags_for_device(self, device);
                let entry = self.build_dte_entry(domain_id, domain.as_ref(), flags)?;
                self.write_dte_with_aliases(table, device, aliases, entry)
            }
            None => self.clear_dte_with_aliases(table, device, aliases),
        }
    }

    pub(crate) fn domain_id_for_device(&self, device: DeviceId) -> Result<u16, IommuError> {
        let device_domains = self
            .device_domains
            .lock()
            .map_err(|_| IommuError::Poisoned)?;
        device_domains
            .get(&device)
            .copied()
            .ok_or(IommuError::DomainNotFound)
    }

    /// Invalidate all entries, treating NotSupported as success.
    pub(super) fn invalidate_ignoring_unsupported(&self) -> Result<(), IommuError> {
        match self.invalidate_all_entries() {
            Ok(()) | Err(IommuError::NotSupported) => Ok(()),
            Err(err) => Err(err),
        }
    }

    pub(super) fn populate_default_entries(&self) -> Result<(), IommuError> {
        let default_domain = self.domain_for_id(0)?;
        map_ivmd_ranges(default_domain.as_ref(), &self.ivmd_ranges)?;

        for (segment, table) in &self.device_tables {
            let flags = AmdIommuDriver::ivhd_global_flags(self, *segment);
            let domain = self.domain_for_id(0)?;
            let entry = self.build_dte_entry(0, domain.as_ref(), flags)?;
            table.fill(entry)?;
        }

        self.invalidate_ignoring_unsupported()?;
        Ok(())
    }

    pub(crate) fn create_domain(
        &self,
        numa_node: Option<usize>,
        domain_type: IommuDomainType,
    ) -> Result<u16, IommuError> {
        let raw_id = self.next_domain_id.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
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
            domain_type,
            self.page_table_pool.clone(),
            PteFormat::Amd,
        );
        let domain = Arc::new(domain);
        if let Some(notifier) = self.security_notifier.get() {
            let _ = domain.set_security_notifier(Arc::clone(notifier));
        }
        let info = AmdDomainInfo { domain };

        let mut domains = self.domains.lock().map_err(|_| IommuError::Poisoned)?;
        if domains.insert(domain_id, info).is_some() {
            return Err(IommuError::HardwareError);
        }
        Ok(domain_id)
    }

    /// Rollback device_domains and DTE entries on attach failure.
    pub(super) fn rollback_device_attach(
        &self,
        device: DeviceId,
        aliases: &[u16],
        previous: Option<u16>,
    ) {
        let Ok(mut device_domains) = self
            .device_domains
            .lock()
            .map_err(|_| IommuError::Poisoned)
        else {
            return;
        };
        match previous {
            Some(prev_id) => {
                device_domains.insert(device, prev_id);
                let _ = self.write_device_entries_for_domain(device, aliases, Some(prev_id));
            }
            None => {
                device_domains.remove(&device);
                let _ = self.write_device_entries_for_domain(device, aliases, None);
            }
        }
    }

    /// Write DTE and invalidate entries; returns first error if any step fails.
    pub(super) fn apply_device_entries_and_invalidate(
        &self,
        device: DeviceId,
        aliases: &[u16],
        domain_id: u16,
    ) -> Result<(), IommuError> {
        self.write_device_entries_for_domain(device, aliases, Some(domain_id))?;
        self.invalidate_device_entry(device)?;
        for alias in aliases {
            self.invalidate_device_entry_by_devid(device.segment, *alias)?;
        }
        Ok(())
    }

    pub(crate) fn attach_device(
        &self,
        device: DeviceId,
        domain_id: u16,
    ) -> Result<(), IommuError> {
        if self.find_unit_for_device(device).is_none() {
            return Err(IommuError::DeviceNotFound);
        }
        let _domain = self.domain_for_id(domain_id)?;
        let aliases = self.alias_devids_for_device(device);

        self.map_ivmd_ranges_for_device(device, domain_id)?;

        let existing = {
            let device_domains = self
                .device_domains
                .lock()
                .map_err(|_| IommuError::Poisoned)?;
            device_domains.get(&device).copied()
        };

        if existing == Some(domain_id) {
            return Ok(());
        }

        let previous = {
            let mut device_domains = self
                .device_domains
                .lock()
                .map_err(|_| IommuError::Poisoned)?;
            device_domains.insert(device, domain_id)
        };

        if let Err(err) = self.apply_device_entries_and_invalidate(device, &aliases, domain_id) {
            self.rollback_device_attach(device, &aliases, previous);
            return Err(err);
        }

        Ok(())
    }

    /// DTEクリアと無効化を実行し、失敗時にロールバック
    pub(super) fn clear_and_invalidate_device(
        &self,
        device: DeviceId,
        aliases: &[u16],
        previous_domain: u16,
    ) -> Result<(), IommuError> {
        self.write_device_entries_for_domain(device, aliases, None)?;
        self.invalidate_device_entry(device)?;
        for alias in aliases {
            self.invalidate_device_entry_by_devid(device.segment, *alias)?;
        }
        Ok(())
    }

    /// デバイスデタッチ失敗時にデバイスドメインを復元
    pub(super) fn rollback_device_detach(
        &self,
        device: DeviceId,
        aliases: &[u16],
        previous_domain: u16,
    ) {
        if let Ok(mut device_domains) = self.device_domains.lock() {
            device_domains.insert(device, previous_domain);
            let _ = self.write_device_entries_for_domain(device, aliases, Some(previous_domain));
        }
    }

    pub(crate) fn detach_device(&self, device: DeviceId) -> Result<(), IommuError> {
        if self.find_unit_for_device(device).is_none() {
            return Err(IommuError::DeviceNotFound);
        }
        let aliases = self.alias_devids_for_device(device);

        let previous = {
            let mut device_domains = self
                .device_domains
                .lock()
                .map_err(|_| IommuError::Poisoned)?;
            device_domains.remove(&device)
        };

        let previous_domain = previous.ok_or(IommuError::DeviceNotFound)?;

        if let Err(err) = self.clear_and_invalidate_device(device, &aliases, previous_domain) {
            self.rollback_device_detach(device, &aliases, previous_domain);
            return Err(err);
        }

        Ok(())
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
        let cmd_ready = self.cmd_states.iter().filter(|state| state.is_some()).count();
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

        match self.device_domains.lock() {
            Ok(device_domains) => {
                log::info!("[IOMMU][AMD-Vi] device_mappings={}", device_domains.len());
            }
            Err(_) => {
                log::warn!("[IOMMU][AMD-Vi] device_domains lock poisoned");
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
