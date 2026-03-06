// ============================================================================
// kernel/src/net/security/firewall/stats.rs - ファイアウォール統計
// ============================================================================
//! ファイアウォールの統計情報。

/// ファイアウォール統計情報
#[derive(Debug, Clone, Default)]
pub struct FirewallStats {
    /// 許可されたパケット数
    pub allowed: u64,
    /// 拒否されたパケット数
    pub denied: u64,
    /// ルール評価回数
    pub evaluated: u64,
    /// ルールにマッチした回数
    pub matched: u64,
    /// デフォルトポリシーが適用された回数
    pub default_applied: u64,
}

impl core::fmt::Display for FirewallStats {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "evaluated={} matched={} allowed={} denied={} default={}",
            self.evaluated, self.matched, self.allowed, self.denied, self.default_applied,
        )
    }
}
