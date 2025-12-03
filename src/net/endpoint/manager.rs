//! # SocketManager - RwLockによる読み取り並列化
//!
//! ソケット管理マネージャ

use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU32, Ordering};
use spin::RwLock;

use super::socket::Socket;
use super::types::{SocketError, SocketFd, SocketResult, SocketType};

/// エフェメラルポート範囲
const EPHEMERAL_PORT_START: u16 = 49152;
const EPHEMERAL_PORT_END: u16 = 65535;

/// ソケット管理（RwLockで読み取り並列化）
pub struct SocketManager {
    /// ソケットテーブル
    sockets: RwLock<BTreeMap<SocketFd, Socket>>,
    /// 使用中ポート（プロトコル別）
    tcp_ports: RwLock<BTreeMap<u16, SocketFd>>,
    udp_ports: RwLock<BTreeMap<u16, SocketFd>>,
    /// 次のエフェメラルポート
    next_ephemeral_port: AtomicU32,
}

impl SocketManager {
    /// 新規マネージャ作成
    pub const fn new() -> Self {
        Self {
            sockets: RwLock::new(BTreeMap::new()),
            tcp_ports: RwLock::new(BTreeMap::new()),
            udp_ports: RwLock::new(BTreeMap::new()),
            next_ephemeral_port: AtomicU32::new(EPHEMERAL_PORT_START as u32),
        }
    }

    /// エフェメラルポート割り当て
    pub fn allocate_ephemeral_port(&self, socket_type: SocketType) -> Option<u16> {
        let ports = match socket_type {
            SocketType::Tcp => &self.tcp_ports,
            SocketType::Udp => &self.udp_ports,
            _ => return Some(0),
        };

        let ports_guard = ports.read();
        let range_size = (EPHEMERAL_PORT_END - EPHEMERAL_PORT_START + 1) as u32;

        // 最大でrange_size回試行
        for _ in 0..range_size {
            let port = self.next_ephemeral_port.fetch_add(1, Ordering::Relaxed);
            let port =
                EPHEMERAL_PORT_START + ((port - EPHEMERAL_PORT_START as u32) % range_size) as u16;

            if !ports_guard.contains_key(&port) {
                return Some(port);
            }
        }

        None // 全ポート使用中
    }

    /// ソケット登録
    pub fn register(&self, socket: Socket) {
        self.sockets.write().insert(socket.fd(), socket);
    }

    /// ソケット登録解除
    pub fn unregister(&self, fd: SocketFd) -> Option<Socket> {
        let socket = self.sockets.write().remove(&fd);

        if let Some(ref s) = socket {
            // ポートの解放
            if let Some(addr) = s.local_addr() {
                match s.socket_type() {
                    SocketType::Tcp => {
                        self.tcp_ports.write().remove(&addr.port);
                    }
                    SocketType::Udp => {
                        self.udp_ports.write().remove(&addr.port);
                    }
                    _ => {}
                }
            }
        }

        socket
    }

    /// ソケット取得（読み取りロック）
    pub fn get(&self, fd: SocketFd) -> Option<Socket> {
        self.sockets.read().get(&fd).cloned()
    }

    /// ポートバインド
    pub fn bind_port(&self, socket_type: SocketType, port: u16, fd: SocketFd) -> SocketResult<()> {
        let ports = match socket_type {
            SocketType::Tcp => &self.tcp_ports,
            SocketType::Udp => &self.udp_ports,
            _ => return Ok(()),
        };

        let mut guard = ports.write();
        if guard.contains_key(&port) {
            return Err(SocketError::PortInUse);
        }
        guard.insert(port, fd);
        Ok(())
    }

    /// ポートでソケット検索
    pub fn find_by_port(&self, socket_type: SocketType, port: u16) -> Option<Socket> {
        let ports = match socket_type {
            SocketType::Tcp => &self.tcp_ports,
            SocketType::Udp => &self.udp_ports,
            _ => return None,
        };

        let fd = *ports.read().get(&port)?;
        self.get(fd)
    }

    /// 登録ソケット数
    pub fn socket_count(&self) -> usize {
        self.sockets.read().len()
    }

    /// 全ソケット処理（イテレーション）
    pub fn for_each<F>(&self, mut f: F)
    where
        F: FnMut(&Socket),
    {
        for socket in self.sockets.read().values() {
            f(socket);
        }
    }

    /// 次のソケットFD生成（内部用）
    pub fn generate_fd(&self) -> SocketFd {
        static FD_COUNTER: AtomicU32 = AtomicU32::new(1);
        SocketFd::from_raw(FD_COUNTER.fetch_add(1, Ordering::Relaxed))
    }
}

impl Default for SocketManager {
    fn default() -> Self {
        Self::new()
    }
}

/// グローバルソケットマネージャ（RwLock）
pub static SOCKET_MANAGER: RwLock<Option<SocketManager>> = RwLock::new(None);

/// ソケットマネージャ初期化
pub fn init_socket_manager() {
    *SOCKET_MANAGER.write() = Some(SocketManager::new());
}

/// ソケットマネージャ取得
pub fn socket_manager() -> Option<&'static RwLock<Option<SocketManager>>> {
    Some(&SOCKET_MANAGER)
}
