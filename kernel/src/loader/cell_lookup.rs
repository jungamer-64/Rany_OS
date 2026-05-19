use super::*;

/// カーネルセルを初期化（起動時に呼ばれる）
pub(crate) fn init_kernel_cell() {
    super::type_id::init_kernel_interfaces();
    with_registry_mut(|r| {
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
        r.register(entry);
    });
}
