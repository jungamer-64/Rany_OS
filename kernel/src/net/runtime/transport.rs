// ============================================================================
// kernel/src/net/runtime/transport.rs - ランタイム / transport state
// ============================================================================
//! Transport-layer state owned by a network runtime.

use crate::net::l4::tcp::ooo_queue::OooRuntimeState;
use crate::net::l4::tcp::retransmit::RetransmitRuntimeState;
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
    ooo: OooRuntimeState,
    retransmit: RetransmitRuntimeState,
}

impl TcpRuntimeState {
    const fn new() -> Self {
        Self {
            tcbs: TcbTable::new(),
            ooo: OooRuntimeState::new(),
            retransmit: RetransmitRuntimeState::new(),
        }
    }

    pub(crate) const fn tcbs(&self) -> &TcbTable {
        &self.tcbs
    }

    pub(crate) const fn ooo(&self) -> &OooRuntimeState {
        &self.ooo
    }

    pub(crate) const fn retransmit(&self) -> &RetransmitRuntimeState {
        &self.retransmit
    }
}

pub(crate) fn tcp_runtime_in(runtime: NetRuntimeHandle) -> &'static TcpRuntimeState {
    runtime.context().transport.tcp()
}

pub(crate) fn tcp_table_in(runtime: NetRuntimeHandle) -> &'static TcbTable {
    tcp_runtime_in(runtime).tcbs()
}
