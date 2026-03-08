// ============================================================================
// kernel/src/net/l4/endpoint/manager.rs
// ============================================================================
//! # EndpointManager - RwLockによる読み取り並列化
//!
//! ソケット管理マネージャ

use crate::sync::PoisonRwLock;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU32, Ordering};

use super::endpoint_core::Endpoint;
use super::types::{EndpointError, EndpointFd, EndpointResult, EndpointType};

const EPHEMERAL_PORT_START: u16 = 49152;
const EPHEMERAL_PORT_END: u16 = 65535;

pub struct EndpointManager {
    endpoints: PoisonRwLock<BTreeMap<EndpointFd, Endpoint>>,
    tcp_ports: PoisonRwLock<BTreeMap<u16, EndpointFd>>,
    udp_ports: PoisonRwLock<BTreeMap<u16, EndpointFd>>,
    next_ephemeral_port: AtomicU32,
}

impl EndpointManager {
    pub const fn new() -> Self {
        Self {
            endpoints: PoisonRwLock::new(BTreeMap::new()),
            tcp_ports: PoisonRwLock::new(BTreeMap::new()),
            udp_ports: PoisonRwLock::new(BTreeMap::new()),
            next_ephemeral_port: AtomicU32::new(EPHEMERAL_PORT_START as u32),
        }
    }

    pub fn allocate_ephemeral_port(&self, endpoint_type: EndpointType) -> Option<u16> {
        let ports = match endpoint_type {
            EndpointType::Tcp => &self.tcp_ports,
            EndpointType::Udp => &self.udp_ports,
            _ => return Some(0),
        };

        let mut start = self.next_ephemeral_port.fetch_add(1, Ordering::Relaxed) as u16;
        if start < EPHEMERAL_PORT_START || start > EPHEMERAL_PORT_END {
            start = EPHEMERAL_PORT_START;
            self.next_ephemeral_port
                .store((EPHEMERAL_PORT_START + 1) as u32, Ordering::Relaxed);
        }

        let range_size = (EPHEMERAL_PORT_END - EPHEMERAL_PORT_START + 1) as u16;
        let ports_guard = ports.read().unwrap_or_else(|e| e.into_inner());
        for i in 0..range_size {
            let port = EPHEMERAL_PORT_START
                + ((start
                    .wrapping_sub(EPHEMERAL_PORT_START)
                    .wrapping_add(i))
                    % range_size);
            if !ports_guard.contains_key(&port) {
                return Some(port);
            }
        }
        None
    }

    pub fn register(&self, endpoint: Endpoint) {
        self.endpoints
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(endpoint.fd(), endpoint);
    }

    pub fn unregister(&self, fd: EndpointFd) -> Option<Endpoint> {
        let removed = self.endpoints
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&fd);
        if let Some(ref s) = removed {
            if let Some(addr) = s.local_addr() {
                match s.socket_type() {
                    EndpointType::Tcp => {
                        self.tcp_ports
                            .write()
                            .unwrap_or_else(|e| e.into_inner())
                            .remove(&addr.port());
                    }
                    EndpointType::Udp => {
                        self.udp_ports
                            .write()
                            .unwrap_or_else(|e| e.into_inner())
                            .remove(&addr.port());
                    }
                    _ => {}
                }
            }
        }
        removed
    }

    pub fn get(&self, fd: EndpointFd) -> Option<Endpoint> {
        self.endpoints
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&fd)
            .cloned()
    }

    pub fn bind_port(
        &self,
        endpoint_type: EndpointType,
        port: u16,
        fd: EndpointFd,
    ) -> EndpointResult<()> {
        let ports = match endpoint_type {
            EndpointType::Tcp => &self.tcp_ports,
            EndpointType::Udp => &self.udp_ports,
            _ => return Ok(()),
        };

        let mut guard = ports.write().unwrap_or_else(|e| e.into_inner());
        if guard.contains_key(&port) {
            return Err(EndpointError::PortInUse);
        }
        guard.insert(port, fd);
        Ok(())
    }

    pub fn find_by_port(&self, endpoint_type: EndpointType, port: u16) -> Option<Endpoint> {
        let ports = match endpoint_type {
            EndpointType::Tcp => &self.tcp_ports,
            EndpointType::Udp => &self.udp_ports,
            _ => return None,
        };

        let fd = *ports.read().unwrap_or_else(|e| e.into_inner()).get(&port)?;
        self.get(fd)
    }

    pub fn endpoint_count(&self) -> usize {
        self.endpoints.read().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn for_each<F>(&self, mut f: F)
    where
        F: FnMut(&Endpoint),
    {
        let endpoints = self.endpoints.read().unwrap_or_else(|e| e.into_inner());
        for ep in endpoints.values() {
            f(ep);
        }
    }

    pub fn generate_fd(&self) -> EndpointFd {
        static FD_COUNTER: AtomicU32 = AtomicU32::new(1);
        EndpointFd::from_raw(FD_COUNTER.fetch_add(1, Ordering::Relaxed))
    }
}

impl Default for EndpointManager {
    fn default() -> Self {
        Self::new()
    }
}

pub static ENDPOINT_MANAGER: PoisonRwLock<Option<EndpointManager>> = PoisonRwLock::new(None);

pub fn init_endpoint_manager() {
    *ENDPOINT_MANAGER.write().unwrap_or_else(|e| e.into_inner()) = Some(EndpointManager::new());
}

pub fn is_endpoint_manager_initialized() -> bool {
    ENDPOINT_MANAGER
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .is_some()
}

pub fn endpoint_manager() -> Option<&'static PoisonRwLock<Option<EndpointManager>>> {
    Some(&ENDPOINT_MANAGER)
}
