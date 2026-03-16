// ============================================================================
// kernel/src/net/l4/endpoint/types.rs
// ============================================================================
//! # 基本型定義 - エンドポイントAPI用の型
//!
//! EndpointFd, EndpointType, EndpointState, EndpointError, EndpointAddr, AcceptedConnection等

use core::sync::atomic::AtomicU32;

use super::tcb::TcpControlBlockEntry;
use crate::net::runtime::manager::NetIfId;

/// エンドポイントファイルディスクリプタ
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct EndpointFd(u32);

impl EndpointFd {
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

/// エンドポイントタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointType {
    /// TCPストリームエンドポイント
    Tcp,
    /// UDPデータグラムエンドポイント
    Udp,
    /// RAWエンドポイント（直接IP層アクセス）
    Raw,
}

/// エンドポイント状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointState {
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

impl EndpointState {
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

/// エンドポイントエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointError {
    /// エンドポイントが見つからない
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
    /// プロトコル到達不能 (RFC 1122)
    ProtocolUnreachable,
    /// ネットワーク到達不能 (RFC 1122)
    NetworkUnreachable,
    /// ホスト到達不能 (RFC 1122)
    HostUnreachable,
    /// タイムアウト
    Timeout,
    /// 操作中断
    Interrupted,
    /// バッファフル
    BufferFull,
    /// 権限不足
    PermissionDenied,
    /// 不正な状態遷移
    InvalidStateTransition,
    /// リソース不足
    ResourceExhausted,
    /// ポートがすでに使用中
    PortInUse,
    /// 内部エラー
    Internal,
}

impl core::fmt::Display for EndpointError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotFound => write!(f, "Endpoint not found"),
            Self::InvalidArgument => write!(f, "Invalid argument"),
            Self::AlreadyBound => write!(f, "Already bound"),
            Self::AlreadyConnected => write!(f, "Already connected"),
            Self::NotConnected => write!(f, "Not connected"),
            Self::AddressInUse => write!(f, "Address in use"),
            Self::ConnectionRefused => write!(f, "Connection refused"),
            Self::ProtocolUnreachable => write!(f, "Protocol unreachable"),
            Self::NetworkUnreachable => write!(f, "Network unreachable"),
            Self::HostUnreachable => write!(f, "Host unreachable"),
            Self::Timeout => write!(f, "Operation timed out"),
            Self::Interrupted => write!(f, "Operation interrupted"),
            Self::BufferFull => write!(f, "Buffer full"),
            Self::PermissionDenied => write!(f, "Permission denied"),
            Self::InvalidStateTransition => write!(f, "Invalid state transition"),
            Self::ResourceExhausted => write!(f, "Resource exhausted"),
            Self::PortInUse => write!(f, "Port already in use"),
            Self::Internal => write!(f, "Internal error"),
        }
    }
}

impl EndpointError {
    /// TcpErrorからEndpointErrorへの変換
    pub fn from_tcp_error(e: crate::net::l4::tcp::TcpError) -> Self {
        use crate::net::l4::tcp::TcpError;
        match e {
            TcpError::ConnectionClosed => EndpointError::NotConnected,
            TcpError::ConnectionRefused => EndpointError::ConnectionRefused,
            TcpError::ConnectionReset => EndpointError::NotConnected,
            TcpError::Timeout => EndpointError::Timeout,
            TcpError::AddressInUse => EndpointError::AddressInUse,
            TcpError::BufferFull => EndpointError::BufferFull,
            TcpError::PermissionDenied => EndpointError::PermissionDenied,
            TcpError::InvalidState => EndpointError::InvalidStateTransition,
            TcpError::NetworkUnreachable => EndpointError::ResourceExhausted,
        }
    }
}

/// エンドポイント結果型
pub type EndpointResult<T> = Result<T, EndpointError>;

/// エンドポイントアドレス（IPv4 / IPv6 - unified）
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EndpointAddr {
    /// IPv4 address + port
    V4 { ip: [u8; 4], port: u16 },
    /// IPv6 address + port
    V6 { ip: [u8; 16], port: u16 },
}

impl EndpointAddr {
    /// Create an IPv4 endpoint address
    #[inline(always)]
    pub const fn new(ip: [u8; 4], port: u16) -> Self {
        EndpointAddr::V4 { ip, port }
    }

    /// Create an IPv6 endpoint address
    #[inline(always)]
    pub const fn new_v6(ip: [u8; 16], port: u16) -> Self {
        EndpointAddr::V6 { ip, port }
    }

    /// Any/unspecified (IPv4)
    pub const ANY: Self = EndpointAddr::V4 {
        ip: [0, 0, 0, 0],
        port: 0,
    };

    /// IPv4 loopback
    pub const LOCALHOST: Self = EndpointAddr::V4 {
        ip: [127, 0, 0, 1],
        port: 0,
    };

    /// Any/unspecified (IPv6)
    pub const ANY_V6: Self = EndpointAddr::V6 {
        ip: [0u8; 16],
        port: 0,
    };

    /// IPv6 loopback ::1
    pub const LOCALHOST_V6: Self = EndpointAddr::V6 {
        ip: {
            let mut a = [0u8; 16];
            a[15] = 1;
            a
        },
        port: 0,
    };

    /// Return true if IPv4
    #[inline(always)]
    pub fn is_ipv4(&self) -> bool {
        matches!(self, EndpointAddr::V4 { .. })
    }

    /// Return true if IPv6
    #[inline(always)]
    pub fn is_ipv6(&self) -> bool {
        matches!(self, EndpointAddr::V6 { .. })
    }

    /// Get default MSS for this address family (RFC 1122 Section 4.2.2.6)
    pub fn default_mss(&self) -> u16 {
        if self.is_ipv6() {
            1220 // IPv6 minimum MTU (1280) - IPv6 header (40) - TCP header (20)
        } else {
            536 // IPv4 default (RFC 793/1122)
        }
    }

    /// Get port
    #[inline(always)]
    pub fn port(&self) -> u16 {
        match *self {
            EndpointAddr::V4 { port, .. } => port,
            EndpointAddr::V6 { port, .. } => port,
        }
    }

    /// Return IPv4 bytes if this is an IPv4 address, otherwise None.
    #[inline]
    pub fn as_ipv4(&self) -> Option<[u8; 4]> {
        match *self {
            EndpointAddr::V4 { ip, .. } => Some(ip),
            EndpointAddr::V6 { ip, .. } => {
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
            EndpointAddr::V6 { ip, .. } => ip,
            EndpointAddr::V4 { ip, .. } => {
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
            EndpointAddr::V4 { ip, .. } => EndpointAddr::V4 { ip, port },
            EndpointAddr::V6 { ip, .. } => EndpointAddr::V6 { ip, port },
        }
    }

    #[inline]
    pub fn as_bytes(&self) -> [u8; 18] {
        let mut bytes = [0u8; 18];
        bytes[..16].copy_from_slice(&self.as_ipv6());
        bytes[16..18].copy_from_slice(&self.port().to_be_bytes());
        bytes
    }
}

impl core::fmt::Display for EndpointAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            EndpointAddr::V4 { ip, port } => {
                write!(f, "{}.{}.{}.{}:{}", ip[0], ip[1], ip[2], ip[3], port)
            }
            EndpointAddr::V6 { ip, port } => write!(
                f,
                "[{}]:{}",
                crate::net::l3::ipv6::Ipv6Address::new(ip),
                port
            ),
        }
    }
}

// =====================================================
// AcceptedConnection - Accept待ちの接続情報
// =====================================================

/// ハンドシェイク完了済みの接続（Acceptキュー用）
#[derive(Debug, Clone)]
pub struct AcceptedConnection {
    /// 新規作成されたエンドポイントFD
    pub fd: EndpointFd,
    /// ローカルアドレス
    pub local_addr: EndpointAddr,
    /// リモートアドレス
    pub remote_addr: EndpointAddr,
    /// 着信インターフェース
    pub if_id: NetIfId,
    /// TCB情報（シーケンス番号など）
    pub tcb: TcpControlBlockEntry,
}

impl AcceptedConnection {
    /// 新規作成
    pub fn new(
        fd: EndpointFd,
        local_addr: EndpointAddr,
        remote_addr: EndpointAddr,
        if_id: NetIfId,
        tcb: TcpControlBlockEntry,
    ) -> Self {
        Self {
            fd,
            local_addr,
            remote_addr,
            if_id,
            tcb,
        }
    }
}

/// 接続キーのハッシュ用シークレット（起動ごとにランダム化）
static CONN_HASH_SECRET: AtomicU32 = AtomicU32::new(0);

/// ハッシュシークレットを初期化（ネットワークスタック起動時に一度だけ呼ぶ）
pub fn init_hash_secrets() {
    let mut bytes = [0u8; 4];
    // RDRAND または別のセキュアなソースから取得
    let rand = crate::net::security::tls::crypto::random::generate_random();
    bytes.copy_from_slice(&rand[0..4]);
    let secret = u32::from_le_bytes(bytes);
    CONN_HASH_SECRET.store(secret, core::sync::atomic::Ordering::Relaxed);
}

/// (EndpointAddr, EndpointAddr) の接続キーから FNV-1a ハッシュを計算する。
///
/// シャードインデックスの決定に使用。ハッシュフロッディング防止のため
/// 起動ごとに生成されるシークレットをシードとして使用する。
#[inline]
pub fn conn_key_hash(local: &EndpointAddr, remote: &EndpointAddr) -> u32 {
    const FNV_OFFSET: u32 = 0x811c9dc5;
    const FNV_PRIME: u32 = 0x01000193;

    let mut h = FNV_OFFSET ^ CONN_HASH_SECRET.load(core::sync::atomic::Ordering::Relaxed);
    let hash_bytes = |h: &mut u32, addr: &EndpointAddr| match addr {
        EndpointAddr::V4 { ip, port } => {
            for &b in ip {
                *h ^= b as u32;
                *h = h.wrapping_mul(FNV_PRIME);
            }
            for b in port.to_le_bytes() {
                *h ^= b as u32;
                *h = h.wrapping_mul(FNV_PRIME);
            }
        }
        EndpointAddr::V6 { ip, port } => {
            for &b in ip {
                *h ^= b as u32;
                *h = h.wrapping_mul(FNV_PRIME);
            }
            for b in port.to_le_bytes() {
                *h ^= b as u32;
                *h = h.wrapping_mul(FNV_PRIME);
            }
        }
    };
    hash_bytes(&mut h, local);
    hash_bytes(&mut h, remote);
    h
}

// =====================================================
// TCPシーケンス番号ユーティリティ
// =====================================================
//
// TCP の 32bit シーケンス番号はラップアラウンドするため、
// 単純な大小比較（<, >）では正しく判定できない。
// 以下のユーティリティ関数は RFC 793 のシーケンス空間
// ($2^{31}$ 以内の距離を「前」とみなす) に準拠した比較を提供する。
//
// プロジェクト内で i32 キャスト方式に統一する。

/// a が b より前（strictly before）か判定する（ラップアラウンド対応）
///
/// $a < b$ iff $(a - b)$ を符号付き 32bit として解釈したとき負。
/// 距離が $2^{31}$ 未満のときのみ有効。
#[inline(always)]
pub fn seq_before(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

/// a が b 以前（before or equal）か判定する
#[inline(always)]
pub fn seq_leq(a: u32, b: u32) -> bool {
    a == b || seq_before(a, b)
}

/// a と b のうち前（earlier）の方を返す
#[inline(always)]
pub fn seq_min(a: u32, b: u32) -> u32 {
    if seq_before(a, b) { a } else { b }
}

/// a と b のうち後（later）の方を返す
#[inline(always)]
pub fn seq_max(a: u32, b: u32) -> u32 {
    if seq_after(a, b) { a } else { b }
}

/// a が b より後（strictly after）か判定する
#[inline(always)]
pub fn seq_after(a: u32, b: u32) -> bool {
    seq_before(b, a)
}

/// a が b 以後（after or equal）か判定する
#[inline(always)]
pub fn seq_geq(a: u32, b: u32) -> bool {
    a == b || seq_after(a, b)
}

// =====================================================
// テスト
// =====================================================

#[cfg(any(test, feature = "qemu-test-export"))]
pub mod tests {
    use super::*;

    fn endpoint_fd_impl() {
        let fd1 = EndpointFd::from_raw(1);
        let fd2 = EndpointFd::from_raw(2);

        assert!(fd1.is_valid());
        assert!(!EndpointFd::INVALID.is_valid());
        assert!(fd1 < fd2);
    }

    fn endpoint_addr_impl() {
        let addr = EndpointAddr::new([192, 168, 1, 1], 8080);
        assert_eq!(addr.as_ipv4().unwrap(), [192, 168, 1, 1]);
        assert_eq!(addr.port(), 8080);

        let localhost = EndpointAddr::LOCALHOST.with_port(3000);
        assert_eq!(localhost.as_ipv4().unwrap(), [127, 0, 0, 1]);
        assert_eq!(localhost.port(), 3000);
    }

    #[cfg_attr(test, test_case)]
    pub fn test_endpoint_fd() {
        endpoint_fd_impl();
    }

    #[cfg_attr(test, test_case)]
    pub fn test_endpoint_addr() {
        endpoint_addr_impl();
    }
}

#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests {
    use super::*;

    pub fn endpoint_fd_smoke() -> bool {
        let fd1 = EndpointFd::from_raw(1);
        let fd2 = EndpointFd::from_raw(2);

        fd1.is_valid() && !EndpointFd::INVALID.is_valid() && fd1 < fd2
    }

    pub fn endpoint_addr_smoke() -> bool {
        let addr = EndpointAddr::new([192, 168, 1, 1], 8080);
        if addr.as_ipv4().unwrap() != [192, 168, 1, 1] || addr.port() != 8080 {
            return false;
        }

        let localhost = EndpointAddr::LOCALHOST.with_port(3000);
        localhost.as_ipv4().unwrap() == [127, 0, 0, 1] && localhost.port() == 3000
    }
}
