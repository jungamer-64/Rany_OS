//! # 基本型定義 - ソケットAPI用の型
//!
//! SocketFd, SocketType, SocketState, SocketError, SocketAddr, AcceptedConnection等

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

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

/// ソケットアドレス（IPv4）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, PartialOrd, Ord, Hash)]
pub struct SocketAddr {
    /// IPアドレス
    pub ip: [u8; 4],
    /// ポート番号
    pub port: u16,
}

impl SocketAddr {
    /// 任意アドレス
    pub const ANY: Self = Self {
        ip: [0, 0, 0, 0],
        port: 0,
    };

    /// ループバックアドレス
    pub const LOCALHOST: Self = Self {
        ip: [127, 0, 0, 1],
        port: 0,
    };

    /// 新規作成
    #[inline(always)]
    pub const fn new(ip: [u8; 4], port: u16) -> Self {
        Self { ip, port }
    }

    /// ポート付きで作成
    #[inline(always)]
    pub const fn with_port(self, port: u16) -> Self {
        Self { ip: self.ip, port }
    }

    /// IPアドレスをu32で取得
    #[inline(always)]
    pub const fn ip_u32(self) -> u32 {
        u32::from_be_bytes(self.ip)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socket_fd() {
        let fd1 = SocketFd::from_raw(1);
        let fd2 = SocketFd::from_raw(2);

        assert!(fd1.is_valid());
        assert!(!SocketFd::INVALID.is_valid());
        assert!(fd1 < fd2);
    }

    #[test]
    fn test_socket_addr() {
        let addr = SocketAddr::new([192, 168, 1, 1], 8080);
        assert_eq!(addr.ip, [192, 168, 1, 1]);
        assert_eq!(addr.port, 8080);

        let localhost = SocketAddr::LOCALHOST.with_port(3000);
        assert_eq!(localhost.ip, [127, 0, 0, 1]);
        assert_eq!(localhost.port, 3000);
    }
}
