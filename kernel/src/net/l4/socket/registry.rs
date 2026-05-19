// ============================================================================
// kernel/src/net/l4/socket/registry.rs - L4 / ソケット / レジストリ
// ============================================================================
//! Socket registry indexed by protocol-specific lookup tables.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::net::l4::socket::Socket;
use crate::net::l4::socket::state::SocketState;
use crate::net::l4::types::{EndpointAddr, EndpointError, SocketId, SocketResult};
use crate::net::runtime::NetRuntimeHandle;
use crate::net::runtime::manager::NetIfId;
use crate::net::types::InterfaceScope;
use crate::sync::{PoisonLock, PoisonRwLock};

const EPHEMERAL_PORT_START: u16 = 49152;
const EPHEMERAL_PORT_END: u16 = 65535;
const SOCKET_TABLE_BUCKETS: usize = 256;
const SOCKET_TABLE_CAPACITY: usize = 4096;
const PORT_TABLE_BUCKETS: usize = 256;
const PORT_TABLE_CAPACITY: usize = 4096;
const RAW_SCOPE_TABLE_BUCKETS: usize = 64;
const RAW_SCOPE_TABLE_CAPACITY: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum SocketFamily {
    Ipv4,
    Ipv6,
}

impl SocketFamily {
    pub(crate) fn from_addr(addr: EndpointAddr) -> Self {
        if addr.is_ipv6() {
            Self::Ipv6
        } else {
            Self::Ipv4
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct PortBindingKey {
    family: SocketFamily,
    port: u16,
    scope: InterfaceScope,
}

impl PortBindingKey {
    fn new(family: SocketFamily, port: u16, scope: InterfaceScope) -> Self {
        Self {
            family,
            port,
            scope,
        }
    }
}

fn socket_family_hash(family: SocketFamily) -> u32 {
    match family {
        SocketFamily::Ipv4 => 0x9E37_79B9,
        SocketFamily::Ipv6 => 0x85EB_CA6B,
    }
}

fn scope_hash(scope: InterfaceScope) -> u32 {
    match scope {
        InterfaceScope::Any => 0xC2B2_AE35,
        InterfaceScope::Pinned(if_id) => u32::from(if_id.0).wrapping_mul(0x27D4_EB2D),
    }
}

fn mix_hash(mut value: u32) -> usize {
    value ^= value >> 16;
    value = value.wrapping_mul(0x7FEB_352D);
    value ^= value >> 15;
    value = value.wrapping_mul(0x846C_A68B);
    (value ^ (value >> 16)) as usize
}

fn scopes_conflict(lhs: InterfaceScope, rhs: InterfaceScope) -> bool {
    match (lhs, rhs) {
        (InterfaceScope::Any, _) | (_, InterfaceScope::Any) => true,
        (InterfaceScope::Pinned(a), InterfaceScope::Pinned(b)) => a == b,
    }
}

struct SocketRecordEntry {
    key: SocketId,
    record: SocketRecord,
    next: Option<usize>,
}

struct SocketRecordTable {
    buckets: [Option<usize>; SOCKET_TABLE_BUCKETS],
    entries: Vec<SocketRecordEntry>,
}

impl SocketRecordTable {
    const fn new() -> Self {
        Self {
            buckets: [None; SOCKET_TABLE_BUCKETS],
            entries: Vec::new(),
        }
    }

    fn bucket_for(socket_id: SocketId) -> usize {
        mix_hash(socket_id.raw()) & (SOCKET_TABLE_BUCKETS - 1)
    }

    fn find_index(&self, socket_id: SocketId) -> Option<usize> {
        let mut index = self.buckets[Self::bucket_for(socket_id)];
        while let Some(current) = index {
            let entry = &self.entries[current];
            if entry.key == socket_id {
                return Some(current);
            }
            index = entry.next;
        }
        None
    }

    fn get(&self, socket_id: SocketId) -> Option<&SocketRecord> {
        self.find_index(socket_id)
            .map(|index| &self.entries[index].record)
    }

    fn insert(&mut self, socket_id: SocketId, record: SocketRecord) -> Result<(), SocketRecord> {
        if let Some(index) = self.find_index(socket_id) {
            self.entries[index].record = record;
            return Ok(());
        }
        if self.entries.len() >= SOCKET_TABLE_CAPACITY {
            return Err(record);
        }
        let bucket = Self::bucket_for(socket_id);
        let next = self.buckets[bucket];
        self.entries.push(SocketRecordEntry {
            key: socket_id,
            record,
            next,
        });
        self.buckets[bucket] = Some(self.entries.len() - 1);
        Ok(())
    }

    fn remove(&mut self, socket_id: SocketId) -> Option<SocketRecord> {
        let index = self.find_index(socket_id)?;
        let removed = self.entries.swap_remove(index).record;
        self.rebuild_index();
        Some(removed)
    }

    fn iter(&self) -> impl Iterator<Item = (SocketId, &SocketRecord)> {
        self.entries.iter().map(|entry| (entry.key, &entry.record))
    }

    fn rebuild_index(&mut self) {
        self.buckets = [None; SOCKET_TABLE_BUCKETS];
        for index in 0..self.entries.len() {
            let bucket = Self::bucket_for(self.entries[index].key);
            self.entries[index].next = self.buckets[bucket];
            self.buckets[bucket] = Some(index);
        }
    }
}

#[derive(Clone, Copy)]
struct PortBindingEntry {
    key: PortBindingKey,
    socket_id: SocketId,
    next: Option<usize>,
}

struct PortBindingTable {
    buckets: [Option<usize>; PORT_TABLE_BUCKETS],
    entries: Vec<PortBindingEntry>,
}

impl PortBindingTable {
    const fn new() -> Self {
        Self {
            buckets: [None; PORT_TABLE_BUCKETS],
            entries: Vec::new(),
        }
    }

    fn bucket_for(key: PortBindingKey) -> usize {
        let hash = socket_family_hash(key.family)
            ^ u32::from(key.port).wrapping_mul(0x9E37_79B9)
            ^ scope_hash(key.scope);
        mix_hash(hash) & (PORT_TABLE_BUCKETS - 1)
    }

    fn find_index(&self, key: PortBindingKey) -> Option<usize> {
        let mut index = self.buckets[Self::bucket_for(key)];
        while let Some(current) = index {
            let entry = self.entries[current];
            if entry.key == key {
                return Some(current);
            }
            index = entry.next;
        }
        None
    }

    fn get(&self, key: PortBindingKey) -> Option<SocketId> {
        self.find_index(key)
            .map(|index| self.entries[index].socket_id)
    }

    fn has_conflict(&self, family: SocketFamily, port: u16, scope: InterfaceScope) -> bool {
        self.entries.iter().any(|entry| {
            entry.key.family == family
                && entry.key.port == port
                && scopes_conflict(entry.key.scope, scope)
        })
    }

    fn has_any_scope_port(&self, port: u16) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.key.port == port && matches!(entry.key.scope, InterfaceScope::Any))
    }

    fn has_port(&self, port: u16) -> bool {
        self.entries.iter().any(|entry| entry.key.port == port)
    }

    fn insert(&mut self, key: PortBindingKey, socket_id: SocketId) -> SocketResult<()> {
        if let Some(index) = self.find_index(key) {
            self.entries[index].socket_id = socket_id;
            return Ok(());
        }
        if self.entries.len() >= PORT_TABLE_CAPACITY {
            return Err(EndpointError::ResourceExhausted);
        }
        let bucket = Self::bucket_for(key);
        let next = self.buckets[bucket];
        self.entries.push(PortBindingEntry {
            key,
            socket_id,
            next,
        });
        self.buckets[bucket] = Some(self.entries.len() - 1);
        Ok(())
    }

    fn remove_socket(&mut self, socket_id: SocketId) {
        self.entries.retain(|entry| entry.socket_id != socket_id);
        self.rebuild_index();
    }

    fn rebuild_index(&mut self) {
        self.buckets = [None; PORT_TABLE_BUCKETS];
        for index in 0..self.entries.len() {
            let bucket = Self::bucket_for(self.entries[index].key);
            self.entries[index].next = self.buckets[bucket];
            self.buckets[bucket] = Some(index);
        }
    }
}

#[derive(Clone, Copy)]
struct RawScopeEntry {
    key: InterfaceScope,
    socket_id: SocketId,
    next: Option<usize>,
}

struct RawScopeTable {
    buckets: [Option<usize>; RAW_SCOPE_TABLE_BUCKETS],
    entries: Vec<RawScopeEntry>,
}

impl RawScopeTable {
    const fn new() -> Self {
        Self {
            buckets: [None; RAW_SCOPE_TABLE_BUCKETS],
            entries: Vec::new(),
        }
    }

    fn bucket_for(scope: InterfaceScope) -> usize {
        mix_hash(scope_hash(scope)) & (RAW_SCOPE_TABLE_BUCKETS - 1)
    }

    fn find_index(&self, scope: InterfaceScope) -> Option<usize> {
        let mut index = self.buckets[Self::bucket_for(scope)];
        while let Some(current) = index {
            let entry = self.entries[current];
            if entry.key == scope {
                return Some(current);
            }
            index = entry.next;
        }
        None
    }

    fn get(&self, scope: InterfaceScope) -> Option<SocketId> {
        self.find_index(scope)
            .map(|index| self.entries[index].socket_id)
    }

    fn insert(&mut self, scope: InterfaceScope, socket_id: SocketId) -> SocketResult<()> {
        if self.find_index(scope).is_some() {
            return Err(EndpointError::ResourceExhausted);
        }
        if self.entries.len() >= RAW_SCOPE_TABLE_CAPACITY {
            return Err(EndpointError::ResourceExhausted);
        }
        let bucket = Self::bucket_for(scope);
        let next = self.buckets[bucket];
        self.entries.push(RawScopeEntry {
            key: scope,
            socket_id,
            next,
        });
        self.buckets[bucket] = Some(self.entries.len() - 1);
        Ok(())
    }

    fn remove_socket(&mut self, socket_id: SocketId) {
        self.entries.retain(|entry| entry.socket_id != socket_id);
        self.rebuild_index();
    }

    fn rebuild_index(&mut self) {
        self.buckets = [None; RAW_SCOPE_TABLE_BUCKETS];
        for index in 0..self.entries.len() {
            let bucket = Self::bucket_for(self.entries[index].key);
            self.entries[index].next = self.buckets[bucket];
            self.buckets[bucket] = Some(index);
        }
    }
}

fn random_ephemeral_start() -> Option<u16> {
    let random_bytes = crate::net::security::tls::crypto::generate_random().ok()?;
    let random_start = u16::from_be_bytes([random_bytes[0], random_bytes[1]]);
    let range_size = EPHEMERAL_PORT_END - EPHEMERAL_PORT_START + 1;
    Some(EPHEMERAL_PORT_START + (random_start % range_size))
}

fn allocate_ephemeral_port_from(
    ports: &PoisonRwLock<PortBindingTable>,
    next_ephemeral_port: &AtomicU32,
) -> Option<u16> {
    let range_size = EPHEMERAL_PORT_END - EPHEMERAL_PORT_START + 1;
    let start_port = random_ephemeral_start()?;
    let ports_guard = ports.read().unwrap_or_else(|e| e.into_inner());
    for offset in 0..range_size {
        let port = EPHEMERAL_PORT_START
            + ((start_port
                .wrapping_sub(EPHEMERAL_PORT_START)
                .wrapping_add(offset))
                % range_size);
        if !ports_guard.has_any_scope_port(port) {
            next_ephemeral_port.store(port.wrapping_add(1) as u32, Ordering::Relaxed);
            return Some(port);
        }
    }
    None
}

fn find_socket_by_port(
    ports: &PoisonRwLock<PortBindingTable>,
    sockets: &PoisonRwLock<SocketRecordTable>,
    family: SocketFamily,
    port: u16,
    ingress_if_id: Option<NetIfId>,
) -> Option<Socket> {
    let guard = ports.read().unwrap_or_else(|e| e.into_inner());
    let socket_id = ingress_if_id
        .map(|if_id| PortBindingKey::new(family, port, InterfaceScope::Pinned(if_id)))
        .and_then(|key| guard.get(key))
        .or_else(|| guard.get(PortBindingKey::new(family, port, InterfaceScope::Any)))?;
    drop(guard);
    sockets
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get(socket_id)
        .map(|record| Socket::from_registered(socket_id, record.runtime))
}

pub(crate) struct SocketRecord {
    runtime: NetRuntimeHandle,
    state: PoisonLock<SocketState>,
}

impl SocketRecord {
    fn new(runtime: NetRuntimeHandle, state: SocketState) -> Self {
        Self {
            runtime,
            state: PoisonLock::new(state),
        }
    }
}

pub(crate) struct SocketRegistry {
    sockets: PoisonRwLock<SocketRecordTable>,
    tcp_ports: PoisonRwLock<PortBindingTable>,
    udp_ports: PoisonRwLock<PortBindingTable>,
    raw_scopes: PoisonRwLock<RawScopeTable>,
    next_socket_id: AtomicU32,
    next_ephemeral_port: AtomicU32,
}

impl SocketRegistry {
    pub const fn new() -> Self {
        Self {
            sockets: PoisonRwLock::new(SocketRecordTable::new()),
            tcp_ports: PoisonRwLock::new(PortBindingTable::new()),
            udp_ports: PoisonRwLock::new(PortBindingTable::new()),
            raw_scopes: PoisonRwLock::new(RawScopeTable::new()),
            next_socket_id: AtomicU32::new(1),
            next_ephemeral_port: AtomicU32::new(EPHEMERAL_PORT_START as u32),
        }
    }

    pub fn allocate_tcp_ephemeral_port(&self) -> Option<u16> {
        allocate_ephemeral_port_from(&self.tcp_ports, &self.next_ephemeral_port)
    }

    pub fn allocate_udp_ephemeral_port(&self) -> Option<u16> {
        allocate_ephemeral_port_from(&self.udp_ports, &self.next_ephemeral_port)
    }

    pub fn register(&self, socket: Socket, state: SocketState) {
        let record = SocketRecord::new(socket.runtime(), state);
        if self
            .sockets
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(socket.socket_id(), record)
            .is_err()
        {
            log::error!(
                "[NET] socket registry capacity exhausted while registering {:?}",
                socket.socket_id()
            );
        }
    }

    pub fn unregister(&self, socket_id: SocketId) -> Option<Socket> {
        let removed = self
            .sockets
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(socket_id);
        if let Some(record) = removed.as_ref() {
            let socket = Socket::from_registered(socket_id, record.runtime);
            let state = record.state.lock().unwrap_or_else(|e| e.into_inner());
            if state.is_tcp() {
                self.tcp_ports
                    .write()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove_socket(socket_id);
            } else if state.is_udp() {
                self.udp_ports
                    .write()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove_socket(socket_id);
                drop(state);
                let mut state = record.state.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(token) = state.udp_mut().and_then(|udp| udp.token.take()) {
                    let _ = crate::security::capability::manager().decrement_in_flight(token);
                }
            } else if state.is_raw() {
                self.raw_scopes
                    .write()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove_socket(socket_id);
            }
            return Some(socket);
        }
        None
    }

    pub fn get(&self, socket_id: SocketId) -> Option<Socket> {
        self.sockets
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(socket_id)
            .map(|record| Socket::from_registered(socket_id, record.runtime))
    }

    pub fn with_socket_state<R>(
        &self,
        socket_id: SocketId,
        f: impl FnOnce(&SocketState) -> R,
    ) -> Option<R> {
        let sockets = self.sockets.read().unwrap_or_else(|e| e.into_inner());
        let record = sockets.get(socket_id)?;
        let state = record.state.lock().unwrap_or_else(|e| e.into_inner());
        Some(f(&state))
    }

    pub fn with_socket_state_mut<R>(
        &self,
        socket_id: SocketId,
        f: impl FnOnce(&mut SocketState) -> R,
    ) -> Option<R> {
        let sockets = self.sockets.read().unwrap_or_else(|e| e.into_inner());
        let record = sockets.get(socket_id)?;
        let mut state = record.state.lock().unwrap_or_else(|e| e.into_inner());
        Some(f(&mut state))
    }

    pub fn bind_udp_dual_stack(
        &self,
        port: u16,
        scope: InterfaceScope,
        socket_id: SocketId,
    ) -> SocketResult<()> {
        let mut guard = self.udp_ports.write().unwrap_or_else(|e| e.into_inner());
        let ipv4 = PortBindingKey::new(SocketFamily::Ipv4, port, scope);
        let ipv6 = PortBindingKey::new(SocketFamily::Ipv6, port, scope);
        let ipv4_conflict = guard.has_conflict(SocketFamily::Ipv4, port, scope);
        let ipv6_conflict = guard.has_conflict(SocketFamily::Ipv6, port, scope);
        if ipv4_conflict || ipv6_conflict {
            return Err(EndpointError::PortInUse);
        }
        guard.insert(ipv4, socket_id)?;
        guard.insert(ipv6, socket_id)?;
        Ok(())
    }

    pub fn register_raw_scope(
        &self,
        scope: InterfaceScope,
        socket_id: SocketId,
    ) -> SocketResult<()> {
        let mut guard = self.raw_scopes.write().unwrap_or_else(|e| e.into_inner());
        guard.insert(scope, socket_id)
    }

    pub fn find_tcp_by_port(
        &self,
        family: SocketFamily,
        port: u16,
        ingress_if_id: Option<NetIfId>,
    ) -> Option<Socket> {
        find_socket_by_port(&self.tcp_ports, &self.sockets, family, port, ingress_if_id)
    }

    pub fn find_udp_by_port(
        &self,
        family: SocketFamily,
        port: u16,
        ingress_if_id: Option<NetIfId>,
    ) -> Option<Socket> {
        find_socket_by_port(&self.udp_ports, &self.sockets, family, port, ingress_if_id)
    }

    pub fn find_raw_by_scope(&self, ingress_if_id: NetIfId) -> Option<Socket> {
        let socket_id = {
            let guard = self.raw_scopes.read().unwrap_or_else(|e| e.into_inner());
            guard
                .get(InterfaceScope::Pinned(ingress_if_id))
                .or_else(|| guard.get(InterfaceScope::Any))
        }?;
        self.get(socket_id)
    }

    pub fn has_udp_port(&self, port: u16) -> bool {
        self.udp_ports
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .has_port(port)
    }

    pub fn for_each<F>(&self, mut f: F)
    where
        F: FnMut(Socket),
    {
        let sockets = self.sockets.read().unwrap_or_else(|e| e.into_inner());
        for (socket_id, record) in sockets.iter() {
            f(Socket::from_registered(socket_id, record.runtime));
        }
    }

    pub fn generate_socket_id(&self) -> Option<SocketId> {
        loop {
            let current = self.next_socket_id.load(Ordering::Relaxed);
            if current == SocketId::INVALID.raw() {
                return None;
            }
            let next = current.checked_add(1)?;
            if self
                .next_socket_id
                .compare_exchange(current, next, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return Some(SocketId::from_raw(current));
            }
        }
    }
}

impl Default for SocketRegistry {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) fn find_listening_tcp_socket_in(
    runtime: NetRuntimeHandle,
    local: EndpointAddr,
    ingress_if_id: Option<NetIfId>,
) -> Option<Socket> {
    let socket = runtime.context().sockets.find_tcp_by_port(
        SocketFamily::from_addr(local),
        local.port(),
        ingress_if_id,
    )?;
    socket
        .with_inner(|inner| inner.is_tcp_listening().then_some(socket))
        .flatten()
}
