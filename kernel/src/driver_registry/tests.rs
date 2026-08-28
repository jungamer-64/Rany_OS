use super::*;
use crate::loader::{unload_cell, with_registry_mut};
use alloc::string::String;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use kernel_api::abi::driver::{
    AbiDmaSlice, AbiDriverType, AbiError, DRIVER_ABI_VERSION, DriverContext, DriverVTable,
    DriverVTableFns, PackedPciLocation,
};
use kernel_api::provider::{ProviderDescriptorV1, ProviderKind};

static PROBE_CALLED: AtomicBool = AtomicBool::new(false);
static REMOVE_CALLED: AtomicBool = AtomicBool::new(false);
static IRQ_HANDLER_CALLED: AtomicBool = AtomicBool::new(false);
static LAST_IRQ: AtomicU32 = AtomicU32::new(0);
static LAST_PROBE_CONTEXT: spin::Mutex<Option<DriverContext>> = spin::Mutex::new(None);

extern "C" fn probe(ctx: *mut DriverContext) -> i32 {
    PROBE_CALLED.store(true, Ordering::SeqCst);
    if !ctx.is_null() {
        *LAST_PROBE_CONTEXT.lock() = Some(unsafe { *ctx });
    }
    0
}

extern "C" fn start(_ctx: *mut DriverContext) -> i32 {
    0
}
extern "C" fn stop(_ctx: *mut DriverContext) -> i32 {
    0
}
extern "C" fn remove(_ctx: *mut DriverContext) -> i32 {
    REMOVE_CALLED.store(true, Ordering::SeqCst);
    0
}

extern "C" fn irq_handler(ctx: *mut DriverContext) -> bool {
    IRQ_HANDLER_CALLED.store(true, Ordering::SeqCst);
    if !ctx.is_null() {
        LAST_IRQ.store(unsafe { (*ctx).irq }, Ordering::SeqCst);
    }
    true
}

static NAME_BYTES: &[u8] = b"test_abi_driver\0";

extern "C" fn name_fn() -> *const u8 {
    NAME_BYTES.as_ptr()
}
extern "C" fn name_len_fn() -> usize {
    NAME_BYTES.len() - 1
}
extern "C" fn type_fn() -> u32 {
    AbiDriverType::Block as u32
}
extern "C" fn version_fn() -> u64 {
    0
}

extern "C" fn providers_fn(count_out: *mut usize) -> *const () {
    static PROVIDERS: [ProviderDescriptorV1; 1] = [ProviderDescriptorV1::new(
        ProviderKind::Storage,
        core::ptr::null(),
    )];

    if !count_out.is_null() {
        unsafe {
            *count_out = PROVIDERS.len();
        }
    }

    PROVIDERS.as_ptr() as *const ()
}

static VTABLE: DriverVTable = DriverVTable::new(
    DRIVER_ABI_VERSION,
    DriverVTableFns {
        probe,
        start,
        stop,
        remove,
        name: name_fn,
        name_len: name_len_fn,
        driver_type: type_fn,
        version: version_fn,
        request_capabilities: None,
        handle_irq: None,
    },
)
.with_provider_descriptors_export(Some(providers_fn));

static OLD_ABI_VTABLE: DriverVTable = DriverVTable::new(
    DRIVER_ABI_VERSION - 1,
    DriverVTableFns {
        probe,
        start,
        stop,
        remove,
        name: name_fn,
        name_len: name_len_fn,
        driver_type: type_fn,
        version: version_fn,
        request_capabilities: None,
        handle_irq: None,
    },
);

static IRQ_VTABLE: DriverVTable = DriverVTable::new(
    DRIVER_ABI_VERSION,
    DriverVTableFns {
        probe,
        start,
        stop,
        remove,
        name: name_fn,
        name_len: name_len_fn,
        driver_type: type_fn,
        version: version_fn,
        request_capabilities: None,
        handle_irq: Some(irq_handler),
    },
);

extern "C" fn entry_fn() -> *const DriverVTable {
    &VTABLE
}

extern "C" fn old_abi_entry_fn() -> *const DriverVTable {
    &OLD_ABI_VTABLE
}

extern "C" fn irq_entry_fn() -> *const DriverVTable {
    &IRQ_VTABLE
}

fn reset_test_state() -> crate::host_test_support::Guard {
    let guard = crate::host_test_support::guard();
    crate::loader::reset_for_tests();
    super::reset_for_tests();
    PROBE_CALLED.store(false, Ordering::SeqCst);
    REMOVE_CALLED.store(false, Ordering::SeqCst);
    IRQ_HANDLER_CALLED.store(false, Ordering::SeqCst);
    LAST_IRQ.store(0, Ordering::SeqCst);
    *LAST_PROBE_CONTEXT.lock() = None;
    guard
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_register_abi_driver_and_block_unload() {
    let _guard = reset_test_state();
    // Register driver
    let handle = register_abi_driver(entry_fn).expect("register failed");

    // Probe driver
    let _ = DRIVER_REGISTRY.probe(handle);
    assert!(PROBE_CALLED.load(Ordering::SeqCst));

    // Allocate and register a fake cell
    let cell_id = with_registry_mut(|r| {
        let id = r.allocate_id();
        let entry = crate::loader::CellEntry {
            id,
            name: String::from("test-cell"),
            state: crate::loader::CellState::Loaded,
            load_address: 0, // test: no real allocation
            load_size: 0,
            allocation_base: 0,
            allocation_size: 0,
            entry_point: None,
            exports: Vec::new(),
            imports: Vec::new(),
            dependencies: Vec::new(),
            is_safe: true,
            signature_verified: true,
            required_caps: 0,
            registered_drivers: alloc::vec![handle],
            pkey: None,
            stats: crate::loader::ModuleStats::default(),
        };
        r.register(entry);
        id
    });

    // Attempt to unload - should fail because driver is registered
    let res = unload_cell(cell_id);
    assert!(res.is_err());

    // Unregister the driver and try again
    let _ = crate::loader::unload_driver(handle).expect("unregister failed");
    assert!(REMOVE_CALLED.load(Ordering::SeqCst));
    let res2 = unload_cell(cell_id);
    assert!(res2.is_ok());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_register_abi_driver_with_context_passes_pci_locator() {
    let _guard = reset_test_state();

    let locator = PackedPciLocation::new(0x1234, 0x56, 0x1a, 0x07);
    let ctx = DriverContext::for_pci(0xfeed_0000, 11, 0x8086, 0x1234, 0x0108_02, locator);

    let handle = register_abi_driver_with_context(entry_fn, ctx).expect("register failed");
    DRIVER_REGISTRY.probe(handle).expect("probe failed");

    let captured = LAST_PROBE_CONTEXT
        .lock()
        .take()
        .expect("probe context missing");
    assert!(PROBE_CALLED.load(Ordering::SeqCst));
    assert_eq!(captured.device_address, 0xfeed_0000);
    assert_eq!(captured.irq, 11);
    assert_eq!(captured.vendor_id, 0x8086);
    assert_eq!(captured.device_id, 0x1234);
    assert_eq!(captured.class_code, 0x0108_02);
    assert_eq!(captured.pci_location(), locator);

    DRIVER_REGISTRY
        .unregister(handle)
        .expect("unregister after probe failed");
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_register_abi_driver_rejects_old_abi_version() {
    let _guard = reset_test_state();
    let res = register_abi_driver(old_abi_entry_fn);
    assert!(res.is_err());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_unregister_running_fails() {
    let _guard = reset_test_state();
    // Register driver
    let handle = register_abi_driver(entry_fn).expect("register failed");

    // Probe and start driver
    let _ = DRIVER_REGISTRY.probe(handle);
    let _ = DRIVER_REGISTRY.start(handle);

    // Attempt to unload driver while running - should fail
    let res = crate::loader::unload_driver(handle);
    assert!(res.is_err());

    DRIVER_REGISTRY.stop(handle).expect("stop failed");
    DRIVER_REGISTRY
        .unregister(handle)
        .expect("unregister after stop failed");
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_driver_provider_descriptors_follow_lifecycle() {
    let _guard = reset_test_state();
    let handle = register_abi_driver(entry_fn).expect("register failed");
    assert!(
        crate::provider_registry::provider_registry()
            .descriptors_for_driver(handle)
            .is_empty()
    );

    DRIVER_REGISTRY.probe(handle).expect("probe failed");
    DRIVER_REGISTRY.start(handle).expect("start failed");

    let descriptors = crate::provider_registry::provider_registry().descriptors_for_driver(handle);
    assert_eq!(descriptors.len(), 1);
    assert_eq!(descriptors[0].kind, ProviderKind::Storage);

    DRIVER_REGISTRY.stop(handle).expect("stop failed");
    assert!(
        crate::provider_registry::provider_registry()
            .descriptors_for_driver(handle)
            .is_empty()
    );

    DRIVER_REGISTRY
        .unregister(handle)
        .expect("unregister failed");
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_dispatch_irq_updates_ctx_irq_for_abi_driver() {
    let _guard = reset_test_state();

    let handle = register_abi_driver(irq_entry_fn).expect("register failed");
    DRIVER_REGISTRY.probe(handle).expect("probe failed");
    DRIVER_REGISTRY.start(handle).expect("start failed");

    assert!(DRIVER_REGISTRY.has_irq_handler(handle));
    assert!(DRIVER_REGISTRY.dispatch_irq(handle, 0x88));
    assert!(IRQ_HANDLER_CALLED.load(Ordering::SeqCst));
    assert_eq!(LAST_IRQ.load(Ordering::SeqCst), 0x88);

    DRIVER_REGISTRY.stop(handle).expect("stop failed");
    DRIVER_REGISTRY
        .unregister(handle)
        .expect("unregister failed");
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_registry_poisoned_readers_return_defaults() {
    let _guard = reset_test_state();
    use crate::sync::set_panicking;

    let reg = DriverRegistry::new();

    // Poison the registry lock
    set_panicking(true);
    if let Ok(_g) = reg.drivers.lock() {
        // dropping _g while panicking will mark the lock as poisoned
    }
    set_panicking(false);

    assert_eq!(reg.count(), 0);
    assert!(reg.list().is_empty());
    assert_eq!(reg.find_by_type(DriverType::Block).len(), 0);
    assert!(reg.name(DriverHandle(0)).is_none());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_kapi_alloc_dma_raw_rejects_invalid_requests() {
    let _guard = reset_test_state();
    let mut out = AbiDmaSlice {
        dma_handle_id: 7,
        device_addr: 8,
        virt_addr: 9,
        size: 10,
    };

    assert_eq!(
        super::kapi_alloc_dma_for_device_raw(
            0,
            PackedPciLocation::NULL.raw(),
            1,
            kernel_api::dma::DmaDirection::Bidirectional as u8,
            &mut out,
        ),
        AbiError::InvalidParam as i32
    );
    assert_eq!(out.dma_handle_id, 0);
    assert_eq!(out.device_addr, 0);
    assert_eq!(out.virt_addr, 0);
    assert_eq!(out.size, 0);

    out = AbiDmaSlice {
        dma_handle_id: 11,
        device_addr: 12,
        virt_addr: 13,
        size: 14,
    };
    assert_eq!(
        super::kapi_alloc_dma_for_device_raw(
            4096,
            PackedPciLocation::NULL.raw(),
            3,
            kernel_api::dma::DmaDirection::Bidirectional as u8,
            &mut out,
        ),
        AbiError::InvalidParam as i32
    );
    assert_eq!(out.dma_handle_id, 0);
    assert_eq!(out.device_addr, 0);
    assert_eq!(out.virt_addr, 0);
    assert_eq!(out.size, 0);

    out = AbiDmaSlice {
        dma_handle_id: 15,
        device_addr: 16,
        virt_addr: 17,
        size: 18,
    };
    assert_eq!(
        super::kapi_alloc_dma_for_device_raw(
            4096,
            PackedPciLocation::NULL.raw(),
            crate::mm::types::PAGE_SIZE_4K * 2,
            kernel_api::dma::DmaDirection::Bidirectional as u8,
            &mut out,
        ),
        AbiError::NotSupported as i32
    );
    assert_eq!(out.dma_handle_id, 0);
    assert_eq!(out.device_addr, 0);
    assert_eq!(out.virt_addr, 0);
    assert_eq!(out.size, 0);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_kapi_release_dma_raw_rejects_unknown_handle() {
    let _guard = reset_test_state();
    assert_eq!(
        super::kapi_release_dma_raw(u64::MAX),
        AbiError::InvalidParam as i32
    );
}
