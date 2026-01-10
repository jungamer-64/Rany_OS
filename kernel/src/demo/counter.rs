// ============================================================================
// src/demo/counter.rs - State Persistence Demo
// ============================================================================

use crate::loader::live_update::{
    ExportedState, StateExportError, StateImportError, StateTransfer,
};

/// A demo driver logic that maintains a counter.
/// This would be part of a cell in a real hot-swap scenario.
#[derive(Debug)]
pub struct CounterDriver {
    pub counter: u64,
}

impl CounterDriver {
    pub const STATE_VERSION: u32 = 1;

    pub fn new() -> Self {
        Self { counter: 0 }
    }

    pub fn increment(&mut self) {
        self.counter += 1;
    }
}

impl StateTransfer for CounterDriver {
    const STATE_VERSION: u32 = 1;

    fn export_state(&self) -> Result<ExportedState, StateExportError> {
        // Serialize state (simple u64 byte representation)
        let data = self.counter.to_le_bytes().to_vec();
        
        // Return exported state
        Ok(ExportedState::new(
            Self::STATE_VERSION, 
            0, // Mock Cell ID
            data
        ))
    }

    fn import_state(state: ExportedState) -> Result<Self, StateImportError> {
        // Check version
        if state.metadata.version != Self::STATE_VERSION {
            return Err(StateImportError::VersionMismatch);
        }

        // Deserialize
        if state.data.len() != 8 {
             return Err(StateImportError::CorruptedData);
        }

        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&state.data);
        let counter = u64::from_le_bytes(bytes);

        Ok(Self { counter })
    }
}

/// Verify state transfer logic
pub fn test_persistence() -> bool {
    log::info!("[DEMO] Testing State Persistence (CounterDriver)...\n");

    // 1. Create initial driver and modify state
    let mut driver = CounterDriver::new();
    driver.increment();
    driver.increment();
    driver.increment();
    log::info!("[DEMO] Old Driver State: counter = {}\n", driver.counter);
    assert_eq!(driver.counter, 3);

    // 2. Export state (Simulate Hot-Swap Unload)
    let state = driver.export_state().expect("Export failed");
    log::info!(
        "[DEMO] State Exported: size={} bytes, checksum={:#x}\n", 
        state.metadata.data_size, state.metadata.checksum
    );

    // 3. Import state into NEW driver instance (Simulate Hot-Swap Load)
    let new_driver = CounterDriver::import_state(state).expect("Import failed");
    log::info!("[DEMO] New Driver Restored State: counter = {}\n", new_driver.counter);

    // 4. Verify state persisted
    if new_driver.counter == 3 {
        log::info!("[DEMO] PASS: State successfully persisted across instances.\n");
        true
    } else {
        log::error!("[DEMO] FAIL: State mismatch (expected 3, got {})\n", new_driver.counter);
        false
    }
}
