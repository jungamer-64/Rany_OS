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
    with_registry_mut(|r| {
        let entry = CellEntry {
            id: CellId::KERNEL,
            name: "kernel".into(),
            state: CellState::Running,
            load_address: 0,
            load_size: 0,
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
        r.register(entry);
    });
}
