// ============================================================================
// kernel/src/net/endpoint/types.rs
// ============================================================================
//! # 基本型定義 - ソケットAPI用の型
//!
//! SocketFd, SocketType, SocketState, SocketError, SocketAddr, AcceptedConnection等


use core::sync::atomic::AtomicU32;

use super::tcb::TcpControlBlockEntry;

/// ソケットファイルディスクリプタ
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct SocketFd(u32);

impl SocketFd {
    /// 無効なファイルディスクリプタ
    pub const INVALID: Self = Self(u32::MAX);

    /// 生の値を取得
    #[inline(always)]
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// 生の値から作成（内部用）
    #[inline(always)]
    pub const fn from_raw(fd: u32) -> Self {
        Self(fd)
    }

    /// 有効かどうか
    #[inline(always)]
    pub const fn is_valid(self) -> bool {
        self.0 != u32::MAX
    }
}

/// 次のファイルディスクリプタ
pub static NEXT_FD: AtomicU32 = AtomicU32::new(0);

/// ソケットタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketType {
    /// TCPストリームソケット
    Tcp,
    /// UDPデータグラムソケット
    Udp,
    /// RAWソケット（直接IP層アクセス）
    Raw,
}

/// ソケット状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketState {
    /// 作成直後
    Created,
    /// バインド済み
    Bound,
    /// リスニング中（TCP only）
    Listening,
    /// 接続中（TCP only）
    Connecting,
    /// 接続済み
    Connected,
    /// クローズ中
    Closing,
    /// クローズ済み
    Closed,
}

impl SocketState {
    /// 送信可能な状態か
    #[inline(always)]
    pub const fn can_send(self) -> bool {
        matches!(self, Self::Connected | Self::Bound)
    }

    /// 受信可能な状態か
    #[inline(always)]
    pub const fn can_receive(self) -> bool {
        matches!(self, Self::Connected | Self::Bound | Self::Listening)
    }

    /// バインド可能な状態か
    #[inline(always)]
    pub const fn can_bind(self) -> bool {
        matches!(self, Self::Created)
    }

    /// 接続可能な状態か
    #[inline(always)]
    pub const fn can_connect(self) -> bool {
        matches!(self, Self::Created | Self::Bound)
    }

    /// リッスン可能な状態か
    #[inline(always)]
    pub const fn can_listen(self) -> bool {
        matches!(self, Self::Bound)
    }
}

/// ソケットエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketError {
    /// ソケットが見つからない
    NotFound,
    /// 無効な引数
    InvalidArgument,
    /// 既にバインド済み
    AlreadyBound,
    /// 既に接続済み
    AlreadyConnected,
    /// 接続されていない
    NotConnected,
    /// アドレス使用中
    AddressInUse,
    /// 接続拒否
    ConnectionRefused,
    /// タイムアウト
    Timeout,
    /// 操作中断
    Interrupted,
    /// バッファフル
    BufferFull,
    /// 不正な状態遷移
    InvalidStateTransition,
    /// リソース不足
    ResourceExhausted,
    /// ポートがすでに使用中
    PortInUse,
    /// 内部エラー
    Internal,
}

impl core::fmt::Display for SocketError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotFound => write!(f, "Socket not found"),
            Self::InvalidArgument => write!(f, "Invalid argument"),
            Self::AlreadyBound => write!(f, "Already bound"),
            Self::AlreadyConnected => write!(f, "Already connected"),
            Self::NotConnected => write!(f, "Not connected"),
            Self::AddressInUse => write!(f, "Address in use"),
            Self::ConnectionRefused => write!(f, "Connection refused"),
            Self::Timeout => write!(f, "Operation timed out"),
            Self::Interrupted => write!(f, "Operation interrupted"),
            Self::BufferFull => write!(f, "Buffer full"),
            Self::InvalidStateTransition => write!(f, "Invalid state transition"),
            Self::ResourceExhausted => write!(f, "Resource exhausted"),
            Self::PortInUse => write!(f, "Port already in use"),
            Self::Internal => write!(f, "Internal error"),
        }
    }
}

/// ソケット結果型
pub type SocketResult<T> = Result<T, SocketError>;

/// ソケットアドレス（IPv4 / IPv6 - unified）
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SocketAddr {
    /// IPv4 address + port
    V4 { ip: [u8; 4], port: u16 },
    /// IPv6 address + port
    V6 { ip: [u8; 16], port: u16 },
}

impl SocketAddr {
    /// Backwards-compatible constructor for IPv4
    #[inline(always)]
    pub const fn new(ip: [u8; 4], port: u16) -> Self {
        SocketAddr::V4 { ip, port }
    }

    /// Create an IPv6 socket address
    #[inline(always)]
    pub const fn new_v6(ip: [u8; 16], port: u16) -> Self {
        SocketAddr::V6 { ip, port }
    }

    /// Any/unspecified (IPv4)
    pub const ANY: Self = SocketAddr::V4 { ip: [0, 0, 0, 0], port: 0 };

    /// IPv4 loopback
    pub const LOCALHOST: Self = SocketAddr::V4 { ip: [127, 0, 0, 1], port: 0 };

    /// Any/unspecified (IPv6)
    pub const ANY_V6: Self = SocketAddr::V6 { ip: [0u8; 16], port: 0 };

    /// IPv6 loopback ::1
    pub const LOCALHOST_V6: Self = SocketAddr::V6 { ip: {
        let mut a = [0u8; 16];
        a[15] = 1;
        a
    }, port: 0 };

    /// Return true if IPv4
    #[inline(always)]
    pub fn is_ipv4(&self) -> bool {
        matches!(self, SocketAddr::V4 { .. })
    }

    /// Return true if IPv6
    #[inline(always)]
    pub fn is_ipv6(&self) -> bool {
        matches!(self, SocketAddr::V6 { .. })
    }

    /// Get port
    #[inline(always)]
    pub fn port(&self) -> u16 {
        match *self {
            SocketAddr::V4 { port, .. } => port,
            SocketAddr::V6 { port, .. } => port,
        }
    }

    /// Return IPv4 bytes if this is an IPv4 address, otherwise None.
    #[inline]
    pub fn as_ipv4(&self) -> Option<[u8; 4]> {
        match *self {
            SocketAddr::V4 { ip, .. } => Some(ip),
            SocketAddr::V6 { ip, .. } => {
                // Check for IPv4-mapped IPv6 ::ffff:a.b.c.d
                if ip[..10] == [0u8; 10] && ip[10] == 0xff && ip[11] == 0xff {
                    Some([ip[12], ip[13], ip[14], ip[15]])
                } else {
                    None
                }
            }
        }
    }

    /// Return IPv6 bytes; for IPv4 addresses returns IPv4-mapped IPv6 form
    #[inline]
    pub fn as_ipv6(&self) -> [u8; 16] {
        match *self {
            SocketAddr::V6 { ip, .. } => ip,
            SocketAddr::V4 { ip, .. } => {
                let mut v6 = [0u8; 16];
                v6[10] = 0xff;
                v6[11] = 0xff;
                v6[12..16].copy_from_slice(&ip);
                v6
            }
        }
    }

    /// Convenience: return IPv4 u32 when available
    #[inline]
    pub fn ip_u32(&self) -> Option<u32> {
        self.as_ipv4().map(|b| u32::from_be_bytes(b))
    }

    /// Set port
    #[inline]
    pub fn with_port(self, port: u16) -> Self {
        match self {
            SocketAddr::V4 { ip, .. } => SocketAddr::V4 { ip, port },
            SocketAddr::V6 { ip, .. } => SocketAddr::V6 { ip, port },
        }
    }
}

impl core::fmt::Display for SocketAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            SocketAddr::V4 { ip, port } => write!(f, "{}.{}.{}.{}:{}", ip[0], ip[1], ip[2], ip[3], port),
            SocketAddr::V6 { ip, port } => write!(f, "[{}]:{}", crate::net::l3::ipv6::Ipv6Address::new(ip), port),
        }
    }
}

// =====================================================
// AcceptedConnection - Accept待ちの接続情報
// =====================================================

/// ハンドシェイク完了済みの接続（Acceptキュー用）
#[derive(Debug, Clone)]
pub struct AcceptedConnection {
    /// 新規作成されたソケットFD
    pub fd: SocketFd,
    /// ローカルアドレス
    pub local_addr: SocketAddr,
    /// リモートアドレス
    pub remote_addr: SocketAddr,
    /// TCB情報（シーケンス番号など）
    pub tcb: TcpControlBlockEntry,
}

impl AcceptedConnection {
    /// 新規作成
    pub fn new(
        fd: SocketFd,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        tcb: TcpControlBlockEntry,
    ) -> Self {
        Self {
            fd,
            local_addr,
            remote_addr,
            tcb,
        }
    }
}

// =====================================================
// テスト
// =====================================================

#[cfg(any(test, feature = "qemu-test-export"))]
pub mod tests {
    use super::*;

    #[cfg_attr(test, test_case)]
    pub fn test_socket_fd() {
        let fd1 = SocketFd::from_raw(1);
        let fd2 = SocketFd::from_raw(2);

        assert!(fd1.is_valid());
        assert!(!SocketFd::INVALID.is_valid());
        assert!(fd1 < fd2);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_socket_addr() {
        let addr = SocketAddr::new([192, 168, 1, 1], 8080);
        assert_eq!(addr.as_ipv4().unwrap(), [192, 168, 1, 1]);
        assert_eq!(addr.port(), 8080);

        let localhost = SocketAddr::LOCALHOST.with_port(3000);
        assert_eq!(localhost.as_ipv4().unwrap(), [127, 0, 0, 1]);
        assert_eq!(localhost.port(), 3000);
    }
}


#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests {
    use super::*;

    pub fn socket_fd_smoke() -> bool {
        let fd1 = SocketFd::from_raw(1);
        let fd2 = SocketFd::from_raw(2);

        fd1.is_valid() && !SocketFd::INVALID.is_valid() && fd1 < fd2
    }

    pub fn socket_addr_smoke() -> bool {
        let addr = SocketAddr::new([192, 168, 1, 1], 8080);
        if addr.as_ipv4().unwrap() != [192, 168, 1, 1] || addr.port() != 8080 {
            return false;
        }

        let localhost = SocketAddr::LOCALHOST.with_port(3000);
        localhost.as_ipv4().unwrap() == [127, 0, 0, 1] && localhost.port() == 3000
    }
}
