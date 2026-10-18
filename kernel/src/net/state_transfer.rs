// ============================================================================
// kernel/src/net/state_transfer.rs - Network Stack Live Update & State Transfer
// ============================================================================

//! Serializes the canonical network primary and interface-scoped bridge counters.

use crate::loader::live_update::{
    ExportedState, StateExportError, StateImportError, StateTransfer,
};
use crate::net::runtime::NetRuntimeHandle;
use alloc::vec::Vec;

const STATE_HEADER_LEN: usize = 7;
const INTERFACE_STATS_LEN: usize = 19;

/// State-transfer endpoint for one network runtime.
pub struct NetworkCellState {
    pub runtime: NetRuntimeHandle,
}

impl NetworkCellState {
    pub fn new(runtime: NetRuntimeHandle) -> Self {
        Self { runtime }
    }

    /// Restore state into an already initialized runtime with matching interfaces.
    pub fn import_state_into(&self, state: &ExportedState) -> Result<(), StateImportError> {
        if !state.verify() {
            return Err(StateImportError::CorruptedData);
        }
        if state.metadata.version != Self::STATE_VERSION {
            return Err(StateImportError::VersionMismatch);
        }
        if state.data.len() < STATE_HEADER_LEN {
            return Err(StateImportError::DeserializationFailed);
        }

        let primary = match state.data[0] {
            0 => None,
            1 => Some(crate::net::runtime::manager::NetIfId(u16::from_le_bytes([
                state.data[1],
                state.data[2],
            ]))),
            _ => return Err(StateImportError::DeserializationFailed),
        };
        let stats_count =
            u32::from_le_bytes([state.data[3], state.data[4], state.data[5], state.data[6]])
                as usize;
        let expected_len = stats_count
            .checked_mul(INTERFACE_STATS_LEN)
            .and_then(|stats_len| STATE_HEADER_LEN.checked_add(stats_len))
            .ok_or(StateImportError::DeserializationFailed)?;
        if state.data.len() != expected_len {
            return Err(StateImportError::DeserializationFailed);
        }

        let mut restored = Vec::new();
        restored
            .try_reserve_exact(stats_count)
            .map_err(|_| StateImportError::RestoreFailed)?;
        let mut offset = STATE_HEADER_LEN;
        let mut previous_if = None;
        for _ in 0..stats_count {
            let if_id = crate::net::runtime::manager::NetIfId(u16::from_le_bytes([
                state.data[offset],
                state.data[offset + 1],
            ]));
            if previous_if.is_some_and(|previous| previous >= if_id) {
                return Err(StateImportError::DeserializationFailed);
            }
            previous_if = Some(if_id);
            offset += 2;

            let mut rx_bytes = [0u8; 8];
            rx_bytes.copy_from_slice(&state.data[offset..offset + 8]);
            offset += 8;
            let mut tx_bytes = [0u8; 8];
            tx_bytes.copy_from_slice(&state.data[offset..offset + 8]);
            offset += 8;
            let initialized = match state.data[offset] {
                0 => false,
                1 => true,
                _ => return Err(StateImportError::DeserializationFailed),
            };
            offset += 1;

            if crate::net::runtime::manager::get_interface_in(self.runtime, if_id)
                .map_err(|_| StateImportError::RestoreFailed)?
                .is_none()
            {
                return Err(StateImportError::RestoreFailed);
            }
            restored.push(crate::net::runtime::bridge::StackGlueInterfaceStats {
                if_id,
                rx_packets: u64::from_le_bytes(rx_bytes),
                tx_packets: u64::from_le_bytes(tx_bytes),
                initialized,
            });
        }

        match primary {
            Some(if_id) => {
                crate::net::runtime::manager::set_primary_interface_in(self.runtime, if_id)
                    .map_err(|_| StateImportError::RestoreFailed)?;
            }
            None if crate::net::runtime::manager::primary_interface_in(self.runtime).is_some() => {
                return Err(StateImportError::RestoreFailed);
            }
            None => {}
        }
        crate::net::runtime::bridge::replace_stack_glue_interface_stats_in(self.runtime, restored);

        Ok(())
    }
}

impl StateTransfer for NetworkCellState {
    const STATE_VERSION: u32 = 2;

    fn export_state(&self) -> Result<ExportedState, StateExportError> {
        let mut data = Vec::new();

        let primary_id =
            crate::net::runtime::manager::primary_interface_in(self.runtime).map(|id| id.0);
        if let Some(id) = primary_id {
            data.push(1);
            data.extend_from_slice(&id.to_le_bytes());
        } else {
            data.push(0);
            data.extend_from_slice(&[0; 2]);
        }

        let stats = crate::net::runtime::bridge::list_stack_glue_stats_in(self.runtime);
        let stats_count =
            u32::try_from(stats.len()).map_err(|_| StateExportError::SerializationFailed)?;
        data.extend_from_slice(&stats_count.to_le_bytes());
        for entry in stats {
            data.extend_from_slice(&entry.if_id.0.to_le_bytes());
            data.extend_from_slice(&entry.rx_packets.to_le_bytes());
            data.extend_from_slice(&entry.tx_packets.to_le_bytes());
            data.push(u8::from(entry.initialized));
        }

        Ok(ExportedState::new(
            Self::STATE_VERSION,
            self.cell_id(),
            data,
        ))
    }

    fn import_state(state: ExportedState) -> Result<Self, StateImportError> {
        let target_runtime = crate::net::runtime::default_runtime();
        let instance = Self::new(target_runtime);
        instance.import_state_into(&state)?;
        Ok(instance)
    }

    fn cell_id(&self) -> u64 {
        self.runtime.id().0
    }
}
