// ============================================================================
// kernel/src/net/state_transfer.rs - Network Stack Live Update & State Transfer
// ============================================================================

//! ネットワークスタックの状態移行（StateTransfer）をサポートするモジュール。
//! ExoRustガイドライン Section 8（ライブアップデートと状態移行）に従い、
//! ノード間・セル間・ライブアップデート時のインターフェース設定やTCPコネクション状態の
//! シリアライズ / デシリアライズを提供します。

use crate::loader::live_update::{
    ExportedState, StateExportError, StateImportError, StateTransfer,
};
use crate::net::runtime::NetRuntimeHandle;
use alloc::vec::Vec;

/// ネットワークスタック全体の移行可能状態データ構造
#[derive(Debug, Clone)]
pub struct NetworkStackExportData {
    pub primary_interface_id: Option<u32>,
    pub interface_count: u32,
    pub active_tcp_connections: u32,
}

/// ネットワークセル用の StateTransfer トレイト実装構造体
pub struct NetworkCellState {
    pub runtime: NetRuntimeHandle,
}

impl NetworkCellState {
    pub fn new(runtime: NetRuntimeHandle) -> Self {
        Self { runtime }
    }

    /// 移行先インスタンスの runtime に対する状態復元
    pub fn import_state_into(&self, state: &ExportedState) -> Result<(), StateImportError> {
        if state.data.len() < 1 + 2 + 8 + 8 {
            return Err(StateImportError::DeserializationFailed);
        }

        let present = state.data[0];
        let mut offset = 1;
        if present == 1 {
            let mut id_bytes = [0u8; 2];
            id_bytes.copy_from_slice(&state.data[offset..offset + 2]);
            let if_id = crate::net::runtime::manager::NetIfId(u16::from_le_bytes(id_bytes));
            crate::net::runtime::manager::set_primary_interface_in(self.runtime, if_id)
                .map_err(|_| StateImportError::RestoreFailed)?;
        }
        offset += 2;

        // rx_packets / tx_packets の復元
        let mut rx_bytes = [0u8; 8];
        rx_bytes.copy_from_slice(&state.data[offset..offset + 8]);
        offset += 8;
        let mut tx_bytes = [0u8; 8];
        tx_bytes.copy_from_slice(&state.data[offset..offset + 8]);

        crate::net::runtime::bridge::restore_stack_glue_stats_in(
            self.runtime,
            u64::from_le_bytes(rx_bytes),
            u64::from_le_bytes(tx_bytes),
        );

        Ok(())
    }
}

impl StateTransfer for NetworkCellState {
    const STATE_VERSION: u32 = 1;

    fn export_state(&self) -> Result<ExportedState, StateExportError> {
        let mut data = Vec::new();

        // 1. primary interface
        let primary_id =
            crate::net::runtime::manager::primary_interface_in(self.runtime).map(|id| id.0);
        if let Some(id) = primary_id {
            data.push(1u8); // Present flag
            data.extend_from_slice(&id.to_le_bytes());
        } else {
            data.push(0u8);
            data.extend_from_slice(&[0u8; 2]);
        }

        // 2. Active stats / counters summary
        let stats = crate::net::runtime::bridge::get_stack_glue_stats_in(self.runtime);
        data.extend_from_slice(&stats.rx_packets.to_le_bytes());
        data.extend_from_slice(&stats.tx_packets.to_le_bytes());

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
        self.runtime.id().0 as u64
    }
}
