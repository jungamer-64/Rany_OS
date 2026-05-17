// ============================================================================
// kernel/src/net/runtime/transport.rs - ランタイム / transport state
// ============================================================================
//! Transport-layer state owned by a network runtime.

use crate::net::l4::tcp::tcb::TcbTable;
use crate::net::runtime::NetRuntimeHandle;

pub(crate) struct TransportState {
    tcp: TcpRuntimeState,
}

impl TransportState {
    pub(crate) const fn new() -> Self {
        Self {
            tcp: TcpRuntimeState::new(),
        }
    }

    pub(crate) const fn tcp(&self) -> &TcpRuntimeState {
        &self.tcp
    }
}

pub(crate) struct TcpRuntimeState {
    tcbs: TcbTable,
}

impl TcpRuntimeState {
    const fn new() -> Self {
        Self {
            tcbs: TcbTable::new(),
        }
    }

    pub(crate) const fn tcbs(&self) -> &TcbTable {
        &self.tcbs
    }
}

pub(crate) fn tcp_table_in(runtime: NetRuntimeHandle) -> &'static TcbTable {
    runtime.context().transport.tcp().tcbs()
}
