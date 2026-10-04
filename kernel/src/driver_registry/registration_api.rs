use super::*;

/// Register a driver implemented as a DriverExports header
pub fn register_exports_driver(
    exports: *const DriverExportsV1,
) -> Result<DriverHandle, DriverError> {
    register_exports_driver_with_context(exports, AbiDriverContext::new())
}

pub fn register_exports_driver_with_context(
    exports: *const DriverExportsV1,
    ctx: AbiDriverContext,
) -> Result<DriverHandle, DriverError> {
    register_exports_driver_owned_with_context(exports, ctx, crate::domain::DomainId::KERNEL)
}

pub(crate) fn register_exports_driver_owned_with_context(
    exports: *const DriverExportsV1,
    ctx: AbiDriverContext,
    owner: crate::domain::DomainId,
) -> Result<DriverHandle, DriverError> {
    let _owner_guard = super::enter_driver_execution_domain(owner)?;
    let prepared = prepare_driver_exports(exports, true)?;
    register_abi_instance(
        prepared.entry,
        prepared.providers,
        prepared.state_hooks,
        ctx,
        owner,
    )
}

pub(crate) fn register_abi_instance(
    entry: AbiEntryFn,
    providers: Vec<ProviderDescriptorV1>,
    state_hooks: AbiDriverStateHooks,
    context: AbiDriverContext,
    owner: crate::domain::DomainId,
) -> Result<DriverHandle, DriverError> {
    let driver = build_abi_driver(entry, providers, state_hooks, context)?;
    DRIVER_REGISTRY.register_owned(owner, driver)
}

/// Register a driver implemented as an ABI vtable
pub fn register_abi_driver(entry: AbiEntryFn) -> Result<DriverHandle, DriverError> {
    register_abi_driver_with_context(entry, AbiDriverContext::new())
}

pub fn register_abi_driver_with_context(
    entry: AbiEntryFn,
    ctx: AbiDriverContext,
) -> Result<DriverHandle, DriverError> {
    let vtable_ptr = entry();
    if vtable_ptr.is_null() {
        return Err(DriverError::InvalidState);
    }

    let providers = super::collect_provider_descriptors_from_vtable(unsafe { &*vtable_ptr });
    register_abi_instance(
        entry,
        providers,
        AbiDriverStateHooks::default(),
        ctx,
        crate::domain::DomainId::KERNEL,
    )
}

pub(crate) fn register_abi_driver_owned_with_context(
    entry: AbiEntryFn,
    ctx: AbiDriverContext,
    owner: crate::domain::DomainId,
) -> Result<DriverHandle, DriverError> {
    let _owner_guard = super::enter_driver_execution_domain(owner)?;
    let vtable_ptr = entry();
    if vtable_ptr.is_null() {
        return Err(DriverError::InvalidState);
    }

    let providers = super::collect_provider_descriptors_from_vtable(unsafe { &*vtable_ptr });
    register_abi_instance(entry, providers, AbiDriverStateHooks::default(), ctx, owner)
}

/// Unregister a driver by handle
pub fn unregister_driver(handle: DriverHandle) -> Result<(), DriverError> {
    DRIVER_REGISTRY.unregister(handle)
}

pub(crate) fn prepare_driver_replacement(
    handle: DriverHandle,
    prepared: &PreparedDriverExports,
    state: Option<Arc<DriverStateBlob>>,
    mut context: AbiDriverContext,
) -> Result<DriverReplacement, DriverError> {
    let owner = DRIVER_REGISTRY
        .driver_owner(handle)
        .ok_or(DriverError::NotFound)?;
    let _scope = match &prepared.code {
        Some(code) => Some(
            crate::task::enter_cell_domain(owner, code.cell())
                .map_err(|_| DriverError::ExecutionContextUnavailable)?,
        ),
        None => super::enter_driver_execution_domain(owner)?,
    };
    context.driver_data = 0;
    let mut providers = Vec::new();
    providers
        .try_reserve_exact(prepared.providers.len())
        .map_err(|_| DriverError::OutOfMemory)?;
    providers.extend_from_slice(&prepared.providers);
    let driver = build_abi_driver(prepared.entry, providers, prepared.state_hooks, context)?;
    let candidate = DriverEntry::prepare(owner, driver, prepared.code.clone())?;
    Ok(DriverReplacement {
        handle,
        candidate: Some(candidate),
        state,
    })
}

// Adapter to delegate trait calls to ABI vtable
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct AbiDriverStateHooks {
    pub(crate) export_state: Option<kernel_api::abi::driver::DriverExportStateFn>,
    pub(crate) import_state: Option<kernel_api::abi::driver::DriverImportStateFn>,
}

pub(crate) struct AbiDriver {
    pub(crate) vtable: *const AbiDriverVTable,
    pub(crate) name: alloc::string::String,
    pub(crate) ctx: AbiDriverContext,
    pub(crate) provider_descriptors: Vec<ProviderDescriptorV1>,
    pub(crate) state_hooks: AbiDriverStateHooks,
}

// Safety: AbiDriver contains a raw pointer to a statically allocated vtable that
// is anchored in the driver binary memory. We ensure that the pointer remains
// valid during the driver lifetime (loader must hold driver loaded) and so
// it is safe to mark Send/Sync for sharing across kernel threads.
unsafe impl Send for AbiDriver {}
unsafe impl Sync for AbiDriver {}

impl AbiDriver {
    pub(super) fn vtable(&self) -> &AbiDriverVTable {
        unsafe { &*self.vtable }
    }

    fn state_blob_from_abi(
        state: kernel_api::abi::driver::AbiExportedState,
    ) -> KapiResult<DriverStateBlob> {
        if state.data_ptr.is_null() {
            return Ok(DriverStateBlob::new(state.version, Vec::new()));
        }

        let bytes = unsafe { Vec::from_raw_parts(state.data_ptr, state.data_len, state.data_cap) };
        Ok(DriverStateBlob::new(state.version, bytes))
    }
}

impl Driver for AbiDriver {
    fn name(&self) -> &str {
        &self.name
    }

    fn version(&self) -> kernel_api::driver::DriverVersion {
        let v = (self.vtable().version)();
        let (major, minor, patch) = kernel_api::abi::driver::unpack_version(v);
        kernel_api::driver::DriverVersion::new(major, minor, patch)
    }

    fn driver_type(&self) -> DriverType {
        let t = (self.vtable().driver_type)();
        match t {
            x if x == AbiDriverType::Pci as u32 => DriverType::Pci,
            x if x == AbiDriverType::Usb as u32 => DriverType::Usb,
            x if x == AbiDriverType::Block as u32 => DriverType::Block,
            x if x == AbiDriverType::Network as u32 => DriverType::Network,
            x if x == AbiDriverType::Hid as u32 => DriverType::Hid,
            x if x == AbiDriverType::Graphics as u32 => DriverType::Graphics,
            x if x == AbiDriverType::Serial as u32 => DriverType::Serial,
            _ => DriverType::Other,
        }
    }

    fn abi_context(&self) -> Option<AbiDriverContext> {
        Some(self.ctx)
    }

    fn probe(&mut self) -> KapiResult<()> {
        // Request capabilities if present
        if let Some(req) = self.vtable().request_capabilities {
            let mut caps = AbiDriverCapabilities::default();
            req(&mut caps);
            // We ignore capabilities for now; future work: map to kernel capabilities
        }

        let res = (self.vtable().probe)(&mut self.ctx as *mut _);
        AbiErrorCode::from_raw(res).into_result()
    }

    fn start(&mut self) -> KapiResult<()> {
        let res = (self.vtable().start)(&mut self.ctx as *mut _);
        AbiErrorCode::from_raw(res).into_result()
    }

    fn stop(&mut self) -> KapiResult<()> {
        let res = (self.vtable().stop)(&mut self.ctx as *mut _);
        AbiErrorCode::from_raw(res).into_result()
    }

    fn remove(&mut self) -> KapiResult<()> {
        let res = (self.vtable().remove)(&mut self.ctx as *mut _);
        AbiErrorCode::from_raw(res).into_result()?;
        Ok(())
    }

    fn supported_devices(&self) -> &[DeviceId] {
        &[]
    }

    fn handle_irq(&mut self, irq: u32) -> bool {
        let Some(handle_irq) = self.vtable().handle_irq else {
            return false;
        };

        self.ctx.irq = irq;
        handle_irq(&mut self.ctx as *mut _)
    }

    fn has_irq_handler(&self) -> bool {
        self.vtable().handle_irq.is_some()
    }

    fn provider_descriptors(&self) -> &[ProviderDescriptorV1] {
        &self.provider_descriptors
    }

    fn export_live_state(&self) -> KapiResult<Option<DriverStateBlob>> {
        if self.ctx.driver_data == 0 {
            return Ok(None);
        }
        let Some(export_state) = self.state_hooks.export_state else {
            return Err(KapiError::NotSupported);
        };

        let mut ctx = self.ctx;
        let mut abi_state = kernel_api::abi::driver::AbiExportedState::default();
        let status = export_state(&mut ctx as *mut _, &mut abi_state);
        AbiErrorCode::from_raw(status).into_result()?;
        Self::state_blob_from_abi(abi_state).map(Some)
    }

    fn import_live_state(&mut self, state: &DriverStateBlob) -> KapiResult<()> {
        if state.bytes.is_empty()
            && self.ctx.driver_data == 0
            && self.state_hooks.import_state.is_none()
        {
            return Ok(());
        }
        let Some(import_state) = self.state_hooks.import_state else {
            return Err(KapiError::NotSupported);
        };

        // The foreign import borrows one owned copy only for this callback.
        // Rollback retains the authoritative exported snapshot across retries.
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(state.bytes.len())
            .map_err(|_| KapiError::OutOfMemory)?;
        bytes.extend_from_slice(&state.bytes);
        let mut abi_state = kernel_api::abi::driver::AbiExportedState {
            version: state.version,
            reserved0: 0,
            data_ptr: bytes.as_mut_ptr(),
            data_len: bytes.len(),
            data_cap: bytes.capacity(),
            reserved: [0; 4],
        };
        let result = import_state(&mut self.ctx as *mut _, &mut abi_state);
        AbiErrorCode::from_raw(result).into_result()
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
