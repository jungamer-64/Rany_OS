// ============================================================================
// kernel/src/net/runtime/transport.rs - ランタイム / transport state
// ============================================================================
//! Transport-layer state owned by a network runtime.

use crate::net::l4::tcp::ooo_queue::OooRuntimeState;
use crate::net::l4::tcp::retransmit::RetransmitRuntimeState;
use crate::net::l4::tcp::tcb::TcbTable;
use crate::net::runtime::NetRuntimeHandle;
use core::sync::atomic::{AtomicBool, Ordering};

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
    initialized: AtomicBool,
}

impl TcpRuntimeState {
    const fn new() -> Self {
        Self {
            tcbs: TcbTable::new(),
            ooo: OooRuntimeState::new(),
            retransmit: RetransmitRuntimeState::new(),
            initialized: AtomicBool::new(false),
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

    fn ensure_initialized(&self) -> Result<(), crate::net::security::tls::crypto::RandomError> {
        if self
            .initialized
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(());
        }

        if let Err(error) = crate::net::l4::types::init_hash_secrets() {
            self.initialized.store(false, Ordering::Release);
            return Err(error);
        }

        if let Err(error) = self.tcbs.init_syncookies() {
            self.initialized.store(false, Ordering::Release);
            return Err(error);
        }

        self.ooo.reset();
        self.retransmit.init_timer_wheel();
        Ok(())
    }
}

pub(crate) fn tcp_runtime_in(runtime: NetRuntimeHandle) -> &'static TcpRuntimeState {
    runtime.context().transport.tcp()
}

pub(crate) fn tcp_table_in(runtime: NetRuntimeHandle) -> &'static TcbTable {
    tcp_runtime_in(runtime).tcbs()
}

pub(crate) fn ensure_tcp_runtime_initialized_in(
    runtime: NetRuntimeHandle,
) -> Result<(), crate::net::security::tls::crypto::RandomError> {
    tcp_runtime_in(runtime).ensure_initialized()
}
