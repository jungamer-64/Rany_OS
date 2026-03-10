// ============================================================================
// kernel/src/net/security/firewall/rules.rs - ファイアウォールルール定義
// ============================================================================
//! ファイアウォールルールの型定義。
//!
//! 各ルールは以下の5タプルで照合を行う:
//! - 方向（Ingress / Egress / Both）
//! - 送信元 IP（単一 / CIDR / Any）
//! - 宛先 IP（単一 / CIDR / Any）
//! - プロトコル（TCP / UDP / ICMP / Any）
//! - ポート（単一 / 範囲 / Any）

use alloc::format;
use alloc::string::String;

extern crate alloc;

/// ルール識別子（自動採番）
pub type RuleId = u64;

/// ファイアウォールアクション
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallAction {
    /// パケットを許可
    Allow,
    /// パケットを拒否（サイレントドロップ）
    Deny,
    /// パケットをログ記録して許可
    LogAllow,
    /// パケットをログ記録して拒否
    LogDeny,
}

impl FirewallAction {
    /// このアクションがパケットを許可するかどうか
    pub fn is_allow(self) -> bool {
        matches!(self, FirewallAction::Allow | FirewallAction::LogAllow)
    }

    /// このアクションがログ記録を要求するかどうか
    pub fn is_log(self) -> bool {
        matches!(self, FirewallAction::LogAllow | FirewallAction::LogDeny)
    }
}

impl core::fmt::Display for FirewallAction {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FirewallAction::Allow => write!(f, "ALLOW"),
            FirewallAction::Deny => write!(f, "DENY"),
            FirewallAction::LogAllow => write!(f, "LOG+ALLOW"),
            FirewallAction::LogDeny => write!(f, "LOG+DENY"),
        }
    }
}

/// パケット方向
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallDirection {
    /// 受信パケット
    Ingress,
    /// 送信パケット
    Egress,
    /// 両方向
    Both,
}

impl core::fmt::Display for FirewallDirection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FirewallDirection::Ingress => write!(f, "IN"),
            FirewallDirection::Egress => write!(f, "OUT"),
            FirewallDirection::Both => write!(f, "BOTH"),
        }
    }
}

/// プロトコルマッチ条件
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallProtocol {
    /// 全プロトコル
    Any,
    /// TCP (プロトコル番号 6)
    Tcp,
    /// UDP (プロトコル番号 17)
    Udp,
    /// ICMP (プロトコル番号 1)
    Icmp,
    /// 任意のプロトコル番号
    Number(u8),
}

impl FirewallProtocol {
    /// IP プロトコル番号に一致するかどうか
    pub fn matches(&self, proto: u8) -> bool {
        match self {
            FirewallProtocol::Any => true,
            FirewallProtocol::Tcp => proto == 6,
            FirewallProtocol::Udp => proto == 17,
            FirewallProtocol::Icmp => proto == 1,
            FirewallProtocol::Number(n) => proto == *n,
        }
    }
}

impl core::fmt::Display for FirewallProtocol {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FirewallProtocol::Any => write!(f, "*"),
            FirewallProtocol::Tcp => write!(f, "TCP"),
            FirewallProtocol::Udp => write!(f, "UDP"),
            FirewallProtocol::Icmp => write!(f, "ICMP"),
            FirewallProtocol::Number(n) => write!(f, "proto:{}", n),
        }
    }
}

/// IP アドレス（IPv4 または IPv6）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpAddress {
    /// IPv4 アドレス
    V4([u8; 4]),
    /// IPv6 アドレス
    V6([u8; 16]),
}

impl IpAddress {
    /// IPv4 アドレスとして取得（V4 の場合のみ）
    pub fn as_v4(&self) -> Option<[u8; 4]> {
        match self {
            IpAddress::V4(ip) => Some(*ip),
            _ => None,
        }
    }

    /// IPv6 アドレスとして取得（V6 の場合のみ）
    pub fn as_v6(&self) -> Option<[u8; 16]> {
        match self {
            IpAddress::V6(ip) => Some(*ip),
            _ => None,
        }
    }
}

impl From<[u8; 4]> for IpAddress {
    fn from(value: [u8; 4]) -> Self {
        IpAddress::V4(value)
    }
}

impl From<[u8; 16]> for IpAddress {
    fn from(value: [u8; 16]) -> Self {
        IpAddress::V6(value)
    }
}

impl core::fmt::Display for IpAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            IpAddress::V4(ip) => write!(f, "{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
            IpAddress::V6(ip) => {
                for i in 0..8 {
                    write!(f, "{:02x}{:02x}", ip[i * 2], ip[i * 2 + 1])?;
                    if i < 7 {
                        write!(f, ":")?;
                    }
                }
                Ok(())
            }
        }
    }
}

/// IP アドレスマッチ条件
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpMatch {
    /// 全アドレスに一致
    Any,
    /// IPv4 単一アドレスに完全一致
    Exact([u8; 4]),
    /// IPv4 CIDR サブネットマッチ
    Cidr([u8; 4], u8),
    /// IPv6 単一アドレスに完全一致
    ExactV6([u8; 16]),
    /// IPv6 CIDR サブネットマッチ
    CidrV6([u8; 16], u8),
}

impl IpMatch {
    /// 指定された IP アドレスがこの条件に一致するかどうか
    pub fn matches(&self, addr: IpAddress) -> bool {
        match (self, addr) {
            (IpMatch::Any, _) => true,
            (IpMatch::Exact(expected), IpAddress::V4(actual)) => actual == *expected,
            (IpMatch::Cidr(network, prefix_len), IpAddress::V4(actual)) => {
                if *prefix_len == 0 {
                    return true;
                }
                if *prefix_len >= 32 {
                    return actual == *network;
                }
                let mask = u32::MAX << (32 - prefix_len);
                let net = u32::from_be_bytes(*network) & mask;
                let tgt = u32::from_be_bytes(actual) & mask;
                net == tgt
            }
            (IpMatch::ExactV6(expected), IpAddress::V6(actual)) => actual == *expected,
            (IpMatch::CidrV6(network, prefix_len), IpAddress::V6(actual)) => {
                if *prefix_len == 0 {
                    return true;
                }
                if *prefix_len >= 128 {
                    return actual == *network;
                }

                // IPv6 mask evaluation (byte by byte)
                let full_bytes = (*prefix_len / 8) as usize;
                let remaining_bits = *prefix_len % 8;

                for i in 0..full_bytes {
                    if actual[i] != network[i] {
                        return false;
                    }
                }

                if remaining_bits > 0 {
                    let mask = 0xFFu8 << (8 - remaining_bits);
                    if (actual[full_bytes] & mask) != (network[full_bytes] & mask) {
                        return false;
                    }
                }
                true
            }
            _ => false, // IPv4 rule vs IPv6 packet or vice versa
        }
    }
}

impl core::fmt::Display for IpMatch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            IpMatch::Any => write!(f, "*"),
            IpMatch::Exact(ip) => write!(f, "{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
            IpMatch::Cidr(ip, prefix) => {
                write!(f, "{}.{}.{}.{}/{}", ip[0], ip[1], ip[2], ip[3], prefix)
            }
            IpMatch::ExactV6(ip) => {
                let addr = IpAddress::V6(*ip);
                write!(f, "{}", addr)
            }
            IpMatch::CidrV6(ip, prefix) => {
                let addr = IpAddress::V6(*ip);
                write!(f, "{}/{}", addr, prefix)
            }
        }
    }
}

/// ポートマッチ条件
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortMatch {
    /// 全ポートに一致
    Any,
    /// 単一ポートに完全一致
    Exact(u16),
    /// ポート範囲に一致（始端・終端を含む）
    Range(u16, u16),
}

impl PortMatch {
    /// 指定されたポート番号がこの条件に一致するかどうか
    pub fn matches(&self, port: u16) -> bool {
        match self {
            PortMatch::Any => true,
            PortMatch::Exact(expected) => port == *expected,
            PortMatch::Range(start, end) => port >= *start && port <= *end,
        }
    }
}

impl core::fmt::Display for PortMatch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PortMatch::Any => write!(f, "*"),
            PortMatch::Exact(p) => write!(f, "{}", p),
            PortMatch::Range(s, e) => write!(f, "{}-{}", s, e),
        }
    }
}

/// ICMP マッチ条件
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpMatch {
    /// 全ての ICMP パケットに一致
    Any,
    /// 特定のタイプに一致
    Type(u8),
    /// 特定のタイプとコードに一致
    TypeCode(u8, u8),
}

impl IcmpMatch {
    /// 指定されたタイプとコードがこの条件に一致するかどうか
    pub fn matches(&self, icmp_type: u8, icmp_code: u8) -> bool {
        match self {
            IcmpMatch::Any => true,
            IcmpMatch::Type(t) => icmp_type == *t,
            IcmpMatch::TypeCode(t, c) => icmp_type == *t && icmp_code == *c,
        }
    }
}

impl core::fmt::Display for IcmpMatch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            IcmpMatch::Any => write!(f, "*"),
            IcmpMatch::Type(t) => write!(f, "type:{}", t),
            IcmpMatch::TypeCode(t, c) => write!(f, "type:{},code:{}", t, c),
        }
    }
}

/// ファイアウォールルール
///
/// 5タプル（送信元IP、宛先IP、プロトコル、送信元ポート、宛先ポート）と
/// 方向・アクション・優先度で構成される。
#[derive(Debug, Clone)]
pub struct FirewallRule {
    /// ルール識別子（エンジンが自動採番）
    pub id: RuleId,
    /// ルール名（表示用、オプション）
    pub name: String,
    /// パケット方向
    pub direction: FirewallDirection,
    /// アクション
    pub action: FirewallAction,
    /// 優先度（小さいほど先に評価される）
    pub priority: u16,
    /// 送信元 IP マッチ条件
    pub src_ip: IpMatch,
    /// 宛先 IP マッチ条件
    pub dst_ip: IpMatch,
    /// プロトコル
    pub protocol: FirewallProtocol,
    /// 送信元ポート
    pub src_port: PortMatch,
    /// 宛先ポート
    pub dst_port: PortMatch,
    /// ICMP マッチ条件
    pub icmp_match: IcmpMatch,
    /// TCP フラグマッチ（全ビット一致、0 の場合は無視）
    pub tcp_flags_mask: u8,
    pub tcp_flags_value: u8,
}

impl FirewallRule {
    /// 新規ルールをビルダーパターンで作成開始
    pub fn builder() -> FirewallRuleBuilder {
        FirewallRuleBuilder::new()
    }

    /// このルールが指定されたパケットに一致するかどうか
    pub fn matches(
        &self,
        direction: FirewallDirection,
        src_ip: IpAddress,
        dst_ip: IpAddress,
        protocol: u8,
        src_port: u16,
        dst_port: u16,
        tcp_flags: u8,
    ) -> bool {
        // 方向チェック
        let dir_match = self.direction == FirewallDirection::Both || self.direction == direction;
        if !dir_match {
            return false;
        }

        let ip_match = self.src_ip.matches(src_ip)
            && self.dst_ip.matches(dst_ip)
            && self.protocol.matches(protocol);

        if !ip_match {
            return false;
        }

        // プロトコル固有のチェック
        match protocol {
            6 => {
                // TCP
                if !self.src_port.matches(src_port) || !self.dst_port.matches(dst_port) {
                    return false;
                }
                if self.tcp_flags_mask != 0 {
                    if (tcp_flags & self.tcp_flags_mask) != self.tcp_flags_value {
                        return false;
                    }
                }
            }
            17 => {
                // UDP
                if !self.src_port.matches(src_port) || !self.dst_port.matches(dst_port) {
                    return false;
                }
            }
            1 => {
                // ICMP
                // src_port, dst_port に ICMP type/code が入っていると想定
                if !self.icmp_match.matches(src_port as u8, dst_port as u8) {
                    return false;
                }
            }
            _ => {}
        }

        true
    }

    /// ルールのサマリーを文字列で取得
    pub fn summary(&self) -> String {
        let mut s = format!(
            "#{} [{}] {} {} src={}/{} dst={}/{} proto={}",
            self.id,
            self.priority,
            self.direction,
            self.action,
            self.src_ip,
            self.src_port,
            self.dst_ip,
            self.dst_port,
            self.protocol,
        );
        if matches!(self.protocol, FirewallProtocol::Icmp) && !matches!(self.icmp_match, IcmpMatch::Any) {
            s.push_str(&format!(" icmp={}", self.icmp_match));
        }
        s
    }
}

impl core::fmt::Display for FirewallRule {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.name.is_empty() {
            write!(f, "{}", self.summary())
        } else {
            write!(f, "{} ({})", self.summary(), self.name)
        }
    }
}

// ============================================================================
// ビルダーパターン
// ============================================================================

/// ファイアウォールルールビルダー
pub struct FirewallRuleBuilder {
    name: String,
    direction: FirewallDirection,
    action: FirewallAction,
    priority: u16,
    src_ip: IpMatch,
    dst_ip: IpMatch,
    protocol: FirewallProtocol,
    src_port: PortMatch,
    dst_port: PortMatch,
    icmp_match: IcmpMatch,
    tcp_flags_mask: u8,
    tcp_flags_value: u8,
}

impl FirewallRuleBuilder {
    fn new() -> Self {
        Self {
            name: String::new(),
            direction: FirewallDirection::Both,
            action: FirewallAction::Deny,
            priority: 1000,
            src_ip: IpMatch::Any,
            dst_ip: IpMatch::Any,
            protocol: FirewallProtocol::Any,
            src_port: PortMatch::Any,
            dst_port: PortMatch::Any,
            icmp_match: IcmpMatch::Any,
            tcp_flags_mask: 0,
            tcp_flags_value: 0,
        }
    }

    /// ルール名を設定
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// 方向を設定
    pub fn direction(mut self, dir: FirewallDirection) -> Self {
        self.direction = dir;
        self
    }

    /// Ingress 方向に設定
    pub fn ingress(self) -> Self {
        self.direction(FirewallDirection::Ingress)
    }

    /// Egress 方向に設定
    pub fn egress(self) -> Self {
        self.direction(FirewallDirection::Egress)
    }

    /// アクションを設定
    pub fn action(mut self, action: FirewallAction) -> Self {
        self.action = action;
        self
    }

    /// 許可に設定
    pub fn allow(self) -> Self {
        self.action(FirewallAction::Allow)
    }

    /// 拒否に設定
    pub fn deny(self) -> Self {
        self.action(FirewallAction::Deny)
    }

    /// 優先度を設定（小さいほど先に評価）
    pub fn priority(mut self, priority: u16) -> Self {
        self.priority = priority;
        self
    }

    /// 送信元 IP を設定
    pub fn src_ip(mut self, ip: IpMatch) -> Self {
        self.src_ip = ip;
        self
    }

    /// 宛先 IP を設定
    pub fn dst_ip(mut self, ip: IpMatch) -> Self {
        self.dst_ip = ip;
        self
    }

    /// プロトコルを設定
    pub fn protocol(mut self, proto: FirewallProtocol) -> Self {
        self.protocol = proto;
        self
    }

    /// TCP プロトコルに設定
    pub fn tcp(self) -> Self {
        self.protocol(FirewallProtocol::Tcp)
    }

    /// UDP プロトコルに設定
    pub fn udp(self) -> Self {
        self.protocol(FirewallProtocol::Udp)
    }

    /// ICMP プロトコルに設定
    pub fn icmp(self) -> Self {
        self.protocol(FirewallProtocol::Icmp)
    }

    /// ICMP タイプを設定
    pub fn icmp_type(mut self, t: u8) -> Self {
        self.icmp_match = IcmpMatch::Type(t);
        self.icmp()
    }

    /// ICMP タイプとコードを設定
    pub fn icmp_type_code(mut self, t: u8, c: u8) -> Self {
        self.icmp_match = IcmpMatch::TypeCode(t, c);
        self.icmp()
    }

    /// 送信元ポートを設定
    pub fn src_port(mut self, port: PortMatch) -> Self {
        self.src_port = port;
        self
    }

    /// 宛先ポートを設定
    pub fn dst_port(mut self, port: PortMatch) -> Self {
        self.dst_port = port;
        self
    }

    /// TCP フラグマッチを設定
    pub fn tcp_flags(mut self, mask: u8, value: u8) -> Self {
        self.tcp_flags_mask = mask;
        self.tcp_flags_value = value;
        self
    }

    /// ルールを構築
    pub fn build(self) -> FirewallRule {
        FirewallRule {
            id: 0, // エンジン側で設定
            name: self.name,
            direction: self.direction,
            action: self.action,
            priority: self.priority,
            src_ip: self.src_ip,
            dst_ip: self.dst_ip,
            protocol: self.protocol,
            src_port: self.src_port,
            dst_port: self.dst_port,
            icmp_match: self.icmp_match,
            tcp_flags_mask: self.tcp_flags_mask,
            tcp_flags_value: self.tcp_flags_value,
        }
    }
}
