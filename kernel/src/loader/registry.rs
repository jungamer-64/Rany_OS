use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use spin::RwLock;

use crate::driver_registry::DriverHandle;

/// Unique Identifier for a Cell
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CellId(u64);

impl CellId {
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    pub fn from_u64(id: u64) -> Self {
        Self(id)
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

/// Represents a loaded Cell (module)
pub struct Cell {
    pub id: CellId,
    pub name: String,
    pub base_address: u64,
    pub size: usize,
    /// Exported symbols (Name -> Address)
    pub exports: BTreeMap<String, u64>,
    /// Drivers registered by this cell
    pub registered_drivers: Vec<DriverHandle>,
    // TODO: Track memory allocations for cleanup
}

pub struct CellRegistry {
    cells: BTreeMap<CellId, Cell>,
    next_id: u64,
    /// Symbol table for kernel API exports (Name -> Address)
    pub symbol_table: BTreeMap<String, usize>,
}

impl CellRegistry {
    pub const fn new() -> Self {
        Self {
            cells: BTreeMap::new(),
            next_id: 1, // 0 is reserved for Kernel
            symbol_table: BTreeMap::new(),
        }
    }

    pub fn get(&self, id: CellId) -> Option<&Cell> {
        self.cells.get(&id)
    }

    pub fn get_mut(&mut self, id: CellId) -> Option<&mut Cell> {
        self.cells.get_mut(&id)
    }

    pub fn register(&mut self, mut cell: Cell) -> CellId {
        // If ID is auto-assigned (0 passed)
        let final_id = if cell.id.as_u64() == 0 {
            let id = self.next_id;
            self.next_id += 1;
            CellId(id)
        } else {
            // Respect provided ID if non-zero (careful with collisions)
            if cell.id.as_u64() >= self.next_id {
                self.next_id = cell.id.as_u64() + 1;
            }
            cell.id
        };

        cell.id = final_id;
        self.cells.insert(final_id, cell);
        final_id
    }

    pub fn unload(&mut self, id: CellId) -> Result<(), &'static str> {
        self.cells.remove(&id).ok_or("Cell not found")?;
        Ok(())
    }

    /// Find the cell that owns a given driver handle
    pub fn find_cell_by_driver(&self, handle: DriverHandle) -> Option<CellId> {
        self.cells
            .iter()
            .find(|(_, cell)| cell.registered_drivers.contains(&handle))
            .map(|(id, _)| *id)
    }

    /// List all loaded cells
    pub fn list(&self) -> Vec<CellInfo> {
        self.cells
            .values()
            .map(|c| CellInfo {
                id: c.id,
                name: c.name.clone(),
                base_address: c.base_address,
                size: c.size,
                driver_count: c.registered_drivers.len(),
            })
            .collect()
    }
}

/// Public info about a cell for listing
#[derive(Debug, Clone)]
pub struct CellInfo {
    pub id: CellId,
    pub name: String,
    pub base_address: u64,
    pub size: usize,
    pub driver_count: usize,
}

static REGISTRY: RwLock<CellRegistry> = RwLock::new(CellRegistry::new());

/// Access the registry read-only
pub fn with_registry<F, R>(f: F) -> R
where
    F: FnOnce(&CellRegistry) -> R,
{
    let registry = REGISTRY.read();
    f(&registry)
}

/// Access the registry mutably
pub fn with_registry_mut<F, R>(f: F) -> R
where
    F: FnOnce(&mut CellRegistry) -> R,
{
    let mut registry = REGISTRY.write();
    f(&mut registry)
}

/// Load a cell from ELF data
///
/// This is a high-level wrapper around ElfLoader
pub fn load_cell(
    name: &str,
    elf_data: &[u8],
    _is_update: bool,
) -> Result<CellId, crate::loader::LoadError> {
    use crate::loader::{ElfLoader, Loader};

    // Parse and load
    let loaded = ElfLoader::load(elf_data)
        .map_err(|_| crate::loader::LoadError::InvalidFormat(String::from("ELF parse error")))?;

    // Create Cell struct
    let mut exports = BTreeMap::new();
    // HACK: For Phase 5 prototype, register the entry point as "driver_entry"
    exports.insert(String::from("driver_entry"), loaded.entry_point);

    let cell = Cell {
        id: CellId(0), // Auto-assign
        name: String::from(name),
        base_address: loaded.base_address,
        size: loaded.size,
        exports,
        registered_drivers: Vec::new(),
    };

    let id = with_registry_mut(|r| r.register(cell));

    log::info!("Loaded cell '{}' as ID {}", name, id.as_u64());

    Ok(id)
}

pub fn unload_cell(id: CellId) -> Result<(), crate::loader::LoadError> {
    with_registry_mut(|r| {
        r.unload(id)
            .map_err(|_| crate::loader::LoadError::CellNotFound)
    })
}

/// Initialize the "Kernel Cell" entry
pub fn init_kernel_cell() {
    let kernel_cell = Cell {
        id: CellId(0), // Special ID 0 for Kernel
        name: String::from("kernel"),
        base_address: 0, // Logical
        size: 0,
        exports: BTreeMap::new(),
        registered_drivers: Vec::new(),
    };

    // Insert directly
    let mut r = REGISTRY.write();
    r.cells.insert(CellId(0), kernel_cell);
    log::info!("Kernel cell initialized (ID 0)");
}

/// Find the cell that owns a given driver
pub fn find_cell_by_driver(handle: DriverHandle) -> Option<CellId> {
    with_registry(|r| r.find_cell_by_driver(handle))
}
