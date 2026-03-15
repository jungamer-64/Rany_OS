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
    let prepared = prepare_driver_exports(exports, true)?;
    let res = register_abi_driver_with_fini_and_context(
        prepared.entry,
        prepared.fini,
        prepared.providers,
        prepared.state_hooks,
        ctx,
    );
    if res.is_err() {
        if let Some(fini) = prepared.fini {
            let _ = fini();
        }
    }
    res
}

pub(crate) fn register_abi_driver_with_fini(
    entry: AbiEntryFn,
    exports_fini: Option<extern "C" fn() -> i32>,
    provider_descriptors: Vec<ProviderDescriptorV1>,
) -> Result<DriverHandle, DriverError> {
    register_abi_driver_with_fini_and_context(
        entry,
        exports_fini,
        provider_descriptors,
        AbiDriverStateHooks::default(),
        AbiDriverContext::new(),
    )
}

pub(crate) fn register_abi_driver_with_fini_and_context(
    entry: AbiEntryFn,
    exports_fini: Option<extern "C" fn() -> i32>,
    provider_descriptors: Vec<ProviderDescriptorV1>,
    state_hooks: AbiDriverStateHooks,
    ctx: AbiDriverContext,
) -> Result<DriverHandle, DriverError> {
    let abi_driver = build_abi_driver(entry, exports_fini, provider_descriptors, state_hooks, ctx)?;
    DRIVER_REGISTRY.register(abi_driver)
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
    register_abi_driver_with_fini_and_context(
        entry,
        None,
        providers,
        AbiDriverStateHooks::default(),
        ctx,
    )
}

/// Unregister a driver by handle
pub fn unregister_driver(handle: DriverHandle) -> Result<(), DriverError> {
    DRIVER_REGISTRY.unregister(handle)
}

/// Update an existing driver with a new ABI implementation
pub(crate) fn update_abi_driver_with_fini(
    handle: DriverHandle,
    entry: AbiEntryFn,
    exports_fini: Option<extern "C" fn() -> i32>,
) -> Result<(), DriverError> {
    let vtable_ptr = entry();
    if vtable_ptr.is_null() {
        return Err(DriverError::InvalidState);
    }

    let provider_descriptors =
        super::collect_provider_descriptors_from_vtable(unsafe { &*vtable_ptr });
    let abi_driver = build_abi_driver(
        entry,
        exports_fini,
        provider_descriptors,
        AbiDriverStateHooks::default(),
        DRIVER_REGISTRY
            .driver_abi_context(handle)
            .unwrap_or_else(AbiDriverContext::new),
    )?;
    DRIVER_REGISTRY.replace_driver(handle, abi_driver)
}

pub fn update_abi_driver(handle: DriverHandle, entry: AbiEntryFn) -> Result<(), DriverError> {
    update_abi_driver_with_fini(handle, entry, None)
}

pub(crate) fn update_prepared_abi_driver(
    handle: DriverHandle,
    prepared: PreparedDriverExports,
    state: Option<DriverStateBlob>,
) -> Result<(), DriverError> {
    let mut abi_driver = build_abi_driver(
        prepared.entry,
        prepared.fini,
        prepared.providers,
        prepared.state_hooks,
        DRIVER_REGISTRY
            .driver_abi_context(handle)
            .unwrap_or_else(AbiDriverContext::new),
    )?;
    if let Some(state) = state {
        abi_driver
            .import_live_state(state)
            .map_err(|_| DriverError::InvalidState)?;
    }
    DRIVER_REGISTRY.replace_driver(handle, abi_driver)
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
    pub(crate) exports_fini: Option<extern "C" fn() -> i32>,
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

    pub(super) fn map_abi_error(code: i32) -> Result<(), KapiError> {
        let abi = AbiErrorCode::from_raw(code);
        match abi {
            AbiErrorCode::Success => Ok(()),
            AbiErrorCode::DeviceNotFound => Err(KapiError::NotFound),
            AbiErrorCode::OutOfMemory => Err(KapiError::OutOfMemory),
            AbiErrorCode::NotSupported => Err(KapiError::NotSupported),
            // generic fallback
            _ => Err(KapiError::Internal(code)),
        }
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

    fn state_blob_into_abi(
        state: DriverStateBlob,
    ) -> (
        kernel_api::abi::driver::AbiExportedState,
        *mut u8,
        usize,
        usize,
    ) {
        let version = state.version;
        let mut bytes = core::mem::ManuallyDrop::new(state.bytes);
        let data_ptr = bytes.as_mut_ptr();
        let data_len = bytes.len();
        let data_cap = bytes.capacity();
        (
            kernel_api::abi::driver::AbiExportedState {
                version,
                reserved0: 0,
                data_ptr,
                data_len,
                data_cap,
                reserved: [0; 4],
            },
            data_ptr,
            data_len,
            data_cap,
        )
    }
}

/// A null driver used to replace unregistered drivers in the registry.
pub(crate) struct NullDriver {
    name: alloc::string::String,
    ty: DriverType,
}

impl NullDriver {
    pub(super) fn new(name: &str, ty: DriverType) -> Self {
        Self {
            name: alloc::string::String::from(name),
            ty,
        }
    }
}

impl Driver for NullDriver {
    fn name(&self) -> &str {
        &self.name
    }

    fn version(&self) -> kernel_api::driver::DriverVersion {
        kernel_api::driver::DriverVersion::new(0, 0, 0)
    }

    fn driver_type(&self) -> DriverType {
        self.ty
    }

    fn probe(&mut self) -> KapiResult<()> {
        Err(KapiError::NotSupported)
    }

    fn start(&mut self) -> KapiResult<()> {
        Err(KapiError::NotSupported)
    }

    fn stop(&mut self) -> KapiResult<()> {
        Ok(())
    }

    fn supported_devices(&self) -> &[kernel_api::driver::DeviceId] {
        &[]
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
        match Self::map_abi_error(res) {
            Ok(()) => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn start(&mut self) -> KapiResult<()> {
        let res = (self.vtable().start)(&mut self.ctx as *mut _);
        Self::map_abi_error(res)
    }

    fn stop(&mut self) -> KapiResult<()> {
        let res = (self.vtable().stop)(&mut self.ctx as *mut _);
        Self::map_abi_error(res)
    }

    fn remove(&mut self) -> KapiResult<()> {
        let res = (self.vtable().remove)(&mut self.ctx as *mut _);
        let mut out = Self::map_abi_error(res);
        if let Some(fini) = self.exports_fini {
            let fini_res = fini();
            if out.is_ok() {
                out = Self::map_abi_error(fini_res);
            }
        }
        out
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
        Self::map_abi_error(status)?;
        Self::state_blob_from_abi(abi_state).map(Some)
    }

    fn import_live_state(&mut self, state: DriverStateBlob) -> KapiResult<()> {
        if state.bytes.is_empty()
            && self.ctx.driver_data == 0
            && self.state_hooks.import_state.is_none()
        {
            return Ok(());
        }
        let Some(import_state) = self.state_hooks.import_state else {
            return Err(KapiError::NotSupported);
        };

        let (mut abi_state, data_ptr, data_len, data_cap) = Self::state_blob_into_abi(state);
        let result = import_state(&mut self.ctx as *mut _, &mut abi_state);
        let _ = unsafe { Vec::from_raw_parts(data_ptr, data_len, data_cap) };
        Self::map_abi_error(result)
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
