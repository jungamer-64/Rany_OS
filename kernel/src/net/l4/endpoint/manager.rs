// ============================================================================
// kernel/src/net/endpoint/manager.rs
// ============================================================================
//! # EndpointManager - RwLockによる読み取り並列化
//!
//! ソケット管理マネージャ

use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU32, Ordering};
use spin::RwLock;

use super::endpoint_core::Endpoint;
use super::types::{EndpointError, EndpointFd, EndpointResult, EndpointType};

/// エフェメラルポート範囲
const EPHEMERAL_PORT_START: u16 = 49152;
const EPHEMERAL_PORT_END: u16 = 65535;

/// ソケット管理（RwLockで読み取り並列化）
pub struct EndpointManager {
    /// ソケットテーブル
    endpoints: RwLock<BTreeMap<EndpointFd, Endpoint>>,
    /// 使用中ポート（プロトコル別）
    tcp_ports: RwLock<BTreeMap<u16, EndpointFd>>,
    udp_ports: RwLock<BTreeMap<u16, EndpointFd>>,
    /// 次のエフェメラルポート
    next_ephemeral_port: AtomicU32,
}

impl EndpointManager {
    /// 新規マネージャ作成
    pub const fn new() -> Self {
        Self {
            sockets: RwLock::new(BTreeMap::new()),
            tcp_ports: RwLock::new(BTreeMap::new()),
            udp_ports: RwLock::new(BTreeMap::new()),
            next_ephemeral_port: AtomicU32::new(EPHEMERAL_PORT_START as u32),
        }
    }

    /// エフェメラルポート割り当て（ランダム化）
    pub fn allocate_ephemeral_port(&self, socket_type: EndpointType) -> Option<u16> {
        let ports = match socket_type {
            EndpointType::Tcp => &self.tcp_ports,
            EndpointType::Udp => &self.udp_ports,
            _ => return Some(0),
        };

        // 暗号論的に安全な乱数から開始ポートを決定
        let random_bytes = crate::net::security::tls::crypto::random::generate_random();
        let seed = u16::from_be_bytes([random_bytes[0], random_bytes[1]]);

        let ports_guard = ports.read();
        let range_size = (EPHEMERAL_PORT_END - EPHEMERAL_PORT_START + 1) as u16;
        let start_port = EPHEMERAL_PORT_START + (seed % range_size);

        // 最大でrange_size回試行
        for i in 0..range_size {
            let port = EPHEMERAL_PORT_START + ((start_port.wrapping_sub(EPHEMERAL_PORT_START).wrapping_add(i)) % range_size);

            if !ports_guard.contains_key(&port) {
                return Some(port);
            }
        }

        None // 全ポート使用中
    }

    /// ソケット登録
    pub fn register(&self, endpoint: Endpoint) {
        self.endpoints.write().insert(socket.fd(), socket);
    }

    /// ソケット登録解除
    pub fn unregister(&self, fd: EndpointFd) -> Option<Endpoint> {
        let socket = self.endpoints.write().remove(&fd);

        if let Some(ref s) = socket {
            // ポートの解放
            if let Some(addr) = s.local_addr() {
                match s.socket_type() {
                    EndpointType::Tcp => {
                        self.tcp_ports.write().remove(&addr.port());
                    }
                    EndpointType::Udp => {
                        self.udp_ports.write().remove(&addr.port());
                    }
                    _ => {}
                }
            }
        }

        socket
    }

    /// ソケット取得（読み取りロック）
    pub fn get(&self, fd: EndpointFd) -> Option<Endpoint> {
        self.endpoints.read().get(&fd).cloned()
    }

    /// ポートバインド
    pub fn bind_port(&self, socket_type: EndpointType, port: u16, fd: EndpointFd) -> EndpointResult<()> {
        let ports = match socket_type {
            EndpointType::Tcp => &self.tcp_ports,
            EndpointType::Udp => &self.udp_ports,
            _ => return Ok(()),
        };

        let mut guard = ports.write();
        if guard.contains_key(&port) {
            return Err(EndpointError::PortInUse);
        }
        guard.insert(port, fd);
        Ok(())
    }

    /// ポートでソケット検索
    pub fn find_by_port(&self, socket_type: EndpointType, port: u16) -> Option<Endpoint> {
        let ports = match socket_type {
            EndpointType::Tcp => &self.tcp_ports,
            EndpointType::Udp => &self.udp_ports,
            _ => return None,
        };

        let fd = *ports.read().get(&port)?;
        self.get(fd)
    }

    /// 登録ソケット数
    pub fn endpoint_count(&self) -> usize {
        self.endpoints.read().len()
    }

    /// 全ソケット処理（イテレーション）
    pub fn for_each<F>(&self, mut f: F)
    where
        F: FnMut(&Endpoint),
    {
        for socket in self.endpoints.read().values() {
            f(socket);
        }
    }

    /// 次のソケットFD生成（内部用）
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

/// グローバルソケットマネージャ（RwLock）
pub static ENDPOINT_MANAGER: RwLock<Option<EndpointManager>> = RwLock::new(None);

/// ソケットマネージャ初期化
pub fn init_endpoint_manager() {
    *ENDPOINT_MANAGER.write() = Some(EndpointManager::new());
}

/// ソケットマネージャが初期化済みかを返す
pub fn is_endpoint_manager_initialized() -> bool {
    ENDPOINT_MANAGER.read().is_some()
}

/// ソケットマネージャ取得
pub fn endpoint_manager() -> Option<&'static RwLock<Option<EndpointManager>>> {
    Some(&ENDPOINT_MANAGER)
}
