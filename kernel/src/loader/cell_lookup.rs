use super::*;

/// Find the CellId that owns the given driver handle
pub fn find_cell_by_driver(handle: DriverHandle) -> Option<CellId> {
    with_registry(|r| {
        for entry in r.cells.values() {
            if entry.registered_drivers.contains(&handle) {
                return Some(entry.id);
            }
        }
        None
    })
}

/// カーネルセルを初期化（起動時に呼ばれる）
pub fn init_kernel_cell() {
    crate::io::log::early_print("[LDBG] init_kernel_cell: enter\n");
    crate::io::log::early_print("[LDBG] init_kernel_cell: before init_kernel_interfaces\n");
    super::type_id::init_kernel_interfaces();
    crate::io::log::early_print("[LDBG] init_kernel_cell: after init_kernel_interfaces\n");
    with_registry_mut(|r| {
        crate::io::log::early_print("[LDBG] init_kernel_cell: in registry closure\n");
        let entry = CellEntry {
            id: CellId::KERNEL,
            name: "kernel".into(),
            state: CellState::Running,
            load_address: 0,
            load_size: 0,
            allocation_base: 0,
            allocation_size: 0,
            entry_point: None,
            exports: Vec::new(),
            imports: Vec::new(),
            dependencies: Vec::new(),
            is_safe: false, // カーネルはunsafeを含む
            signature_verified: true,
            required_caps: 0,
            registered_drivers: Vec::new(),
            pkey: None,
            stats: ModuleStats::default(),
        };
        crate::io::log::early_print("[LDBG] init_kernel_cell: before register\n");
        r.register(entry);
        crate::io::log::early_print("[LDBG] init_kernel_cell: after register\n");
    });
    crate::io::log::early_print("[LDBG] init_kernel_cell: done\n");
}
