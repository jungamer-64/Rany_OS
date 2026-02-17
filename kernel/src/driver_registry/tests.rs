use super::*;
use crate::loader::{unload_cell, with_registry_mut};
use alloc::string::String;
use core::sync::atomic::{AtomicBool, Ordering};
use kernel_api::driver_abi::{
    AbiDriverType, DRIVER_ABI_VERSION, DriverContext, DriverVTable,
};

static PROBE_CALLED: AtomicBool = AtomicBool::new(false);
static REMOVE_CALLED: AtomicBool = AtomicBool::new(false);

extern "C" fn probe(_ctx: *mut DriverContext) -> i32 {
    PROBE_CALLED.store(true, Ordering::SeqCst);
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

static VTABLE: DriverVTable = DriverVTable::new(
    DRIVER_ABI_VERSION,
    probe,
    start,
    stop,
    remove,
    name_fn,
    name_len_fn,
    type_fn,
    version_fn,
    None,
    None,
);

extern "C" fn entry_fn() -> *const DriverVTable {
    &VTABLE
}

#[test_case]
fn test_register_abi_driver_and_block_unload() {
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

#[test_case]
fn test_unregister_running_fails() {
    // Register driver
    let handle = register_abi_driver(entry_fn).expect("register failed");

    // Probe and start driver
    let _ = DRIVER_REGISTRY.probe(handle);
    let _ = DRIVER_REGISTRY.start(handle);

    // Attempt to unload driver while running - should fail
    let res = crate::loader::unload_driver(handle);
    assert!(res.is_err());
}

#[test_case]
fn test_registry_poisoned_readers_return_defaults() {
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
