// ============================================================================
// kernel/src/net/security/firewall/tests.rs - ファイアウォールユニットテスト
// ============================================================================

#[cfg(test)]
mod tests {
    use super::super::engine::{FirewallEngine, FirewallVerdict};
    use super::super::rules::*;

    fn eval_ipv4(
        engine: &FirewallEngine,
        direction: FirewallDirection,
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        protocol: u8,
        src_port: u16,
        dst_port: u16,
    ) -> FirewallVerdict {
        engine.evaluate(
            direction,
            IpAddress::V4(src_ip),
            IpAddress::V4(dst_ip),
            protocol,
            src_port,
            dst_port,
            0,
        )
    }

    fn eval_ipv4_mut(
        engine: &mut FirewallEngine,
        direction: FirewallDirection,
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        protocol: u8,
        src_port: u16,
        dst_port: u16,
    ) -> FirewallVerdict {
        engine.evaluate_mut(
            direction,
            IpAddress::V4(src_ip),
            IpAddress::V4(dst_ip),
            protocol,
            src_port,
            dst_port,
            0,
        )
    }

    fn matches_ipv4(rule: &IpMatch, addr: [u8; 4]) -> bool {
        rule.matches(IpAddress::V4(addr))
    }

    /// ヘルパー: デフォルトのエンジンを作成して有効化する
    fn make_engine() -> FirewallEngine {
        let mut engine = FirewallEngine::new_const();
        engine.set_enabled(true);
        engine
    }

    #[test_case]
    fn test_disabled_engine_allows_all() {
        let engine = FirewallEngine::new_const();
        assert!(!engine.enabled());
        assert_eq!(
            eval_ipv4(
                &engine,
                FirewallDirection::Ingress,
                [10, 0, 0, 1],
                [192, 168, 1, 1],
                6,
                12345,
                80,
            ),
            FirewallVerdict::Allow
        );
    }

    #[test_case]
    fn test_default_allow_policy() {
        let engine = make_engine();
        // ルールなし → デフォルトポリシー (Allow)
        assert_eq!(
            eval_ipv4(
                &engine,
                FirewallDirection::Ingress,
                [10, 0, 0, 1],
                [192, 168, 1, 1],
                6,
                12345,
                80,
            ),
            FirewallVerdict::Allow
        );
    }

    #[test_case]
    fn test_default_deny_policy() {
        let mut engine = make_engine();
        engine.set_default_policy(FirewallDirection::Ingress, FirewallAction::Deny);
        assert_eq!(
            eval_ipv4(
                &engine,
                FirewallDirection::Ingress,
                [10, 0, 0, 1],
                [192, 168, 1, 1],
                6,
                12345,
                80,
            ),
            FirewallVerdict::Deny
        );
    }

    #[test_case]
    fn test_deny_specific_port() {
        let mut engine = make_engine();
        let rule = FirewallRule::builder()
            .name("block-ssh")
            .ingress()
            .deny()
            .tcp()
            .dst_port(PortMatch::Exact(22))
            .build();
        engine.add_rule(rule);

        // SSH → Deny
        assert_eq!(
            eval_ipv4(
                &engine,
                FirewallDirection::Ingress,
                [10, 0, 0, 1],
                [192, 168, 1, 1],
                6,
                55555,
                22,
            ),
            FirewallVerdict::Deny
        );

        // HTTP → Allow (no matching rule)
        assert_eq!(
            eval_ipv4(
                &engine,
                FirewallDirection::Ingress,
                [10, 0, 0, 1],
                [192, 168, 1, 1],
                6,
                55555,
                80,
            ),
            FirewallVerdict::Allow
        );
    }

    #[test_case]
    fn test_allow_specific_subnet() {
        let mut engine = make_engine();
        engine.set_default_policy(FirewallDirection::Ingress, FirewallAction::Deny);

        let rule = FirewallRule::builder()
            .name("allow-lan")
            .ingress()
            .allow()
            .src_ip(IpMatch::Cidr([192, 168, 1, 0], 24))
            .build();
        engine.add_rule(rule);

        // LAN → Allow
        assert_eq!(
            eval_ipv4(
                &engine,
                FirewallDirection::Ingress,
                [192, 168, 1, 100],
                [10, 0, 0, 1],
                6,
                55555,
                80,
            ),
            FirewallVerdict::Allow
        );

        // WAN → Deny
        assert_eq!(
            eval_ipv4(
                &engine,
                FirewallDirection::Ingress,
                [8, 8, 8, 8],
                [10, 0, 0, 1],
                6,
                55555,
                80,
            ),
            FirewallVerdict::Deny
        );
    }

    #[test_case]
    fn test_priority_ordering() {
        let mut engine = make_engine();

        // Low priority: deny all SSH
        let deny_ssh = FirewallRule::builder()
            .name("deny-ssh")
            .ingress()
            .deny()
            .tcp()
            .dst_port(PortMatch::Exact(22))
            .priority(1000)
            .build();

        // High priority: allow SSH from trusted subnet
        let allow_trusted = FirewallRule::builder()
            .name("allow-trusted-ssh")
            .ingress()
            .allow()
            .tcp()
            .src_ip(IpMatch::Cidr([10, 0, 0, 0], 8))
            .dst_port(PortMatch::Exact(22))
            .priority(100)
            .build();

        engine.add_rule(deny_ssh);
        engine.add_rule(allow_trusted);

        // Trusted SSH → Allow (higher priority rule matched first)
        assert_eq!(
            eval_ipv4(
                &engine,
                FirewallDirection::Ingress,
                [10, 0, 0, 5],
                [192, 168, 1, 1],
                6,
                55555,
                22,
            ),
            FirewallVerdict::Allow
        );

        // Untrusted SSH → Deny
        assert_eq!(
            eval_ipv4(
                &engine,
                FirewallDirection::Ingress,
                [8, 8, 8, 8],
                [192, 168, 1, 1],
                6,
                55555,
                22,
            ),
            FirewallVerdict::Deny
        );
    }

    #[test_case]
    fn test_port_range() {
        let mut engine = make_engine();
        let rule = FirewallRule::builder()
            .name("block-high-ports")
            .ingress()
            .deny()
            .tcp()
            .dst_port(PortMatch::Range(1024, 65535))
            .build();
        engine.add_rule(rule);

        // Well-known port → Allow
        assert_eq!(
            eval_ipv4(
                &engine,
                FirewallDirection::Ingress,
                [10, 0, 0, 1],
                [192, 168, 1, 1],
                6,
                55555,
                80,
            ),
            FirewallVerdict::Allow
        );

        // High port → Deny
        assert_eq!(
            eval_ipv4(
                &engine,
                FirewallDirection::Ingress,
                [10, 0, 0, 1],
                [192, 168, 1, 1],
                6,
                55555,
                8080,
            ),
            FirewallVerdict::Deny
        );
    }

    #[test_case]
    fn test_exact_ip_match() {
        let mut engine = make_engine();
        let rule = FirewallRule::builder()
            .name("block-specific-ip")
            .ingress()
            .deny()
            .src_ip(IpMatch::Exact([203, 0, 113, 42]))
            .build();
        engine.add_rule(rule);

        assert_eq!(
            eval_ipv4(
                &engine,
                FirewallDirection::Ingress,
                [203, 0, 113, 42],
                [10, 0, 0, 1],
                6,
                55555,
                80,
            ),
            FirewallVerdict::Deny
        );

        assert_eq!(
            eval_ipv4(
                &engine,
                FirewallDirection::Ingress,
                [203, 0, 113, 43],
                [10, 0, 0, 1],
                6,
                55555,
                80,
            ),
            FirewallVerdict::Allow
        );
    }

    #[test_case]
    fn test_egress_rule() {
        let mut engine = make_engine();
        let rule = FirewallRule::builder()
            .name("block-egress-dns")
            .egress()
            .deny()
            .udp()
            .dst_port(PortMatch::Exact(53))
            .build();
        engine.add_rule(rule);

        // Egress DNS → Deny
        assert_eq!(
            eval_ipv4(
                &engine,
                FirewallDirection::Egress,
                [192, 168, 1, 1],
                [8, 8, 8, 8],
                17,
                55555,
                53,
            ),
            FirewallVerdict::Deny
        );

        // Ingress DNS → Allow (rule is egress-only)
        assert_eq!(
            eval_ipv4(
                &engine,
                FirewallDirection::Ingress,
                [8, 8, 8, 8],
                [192, 168, 1, 1],
                17,
                53,
                55555,
            ),
            FirewallVerdict::Allow
        );
    }

    #[test_case]
    fn test_both_direction_rule() {
        let mut engine = make_engine();
        let rule = FirewallRule::builder()
            .name("block-icmp-both")
            .direction(FirewallDirection::Both)
            .deny()
            .icmp()
            .build();
        engine.add_rule(rule);

        // ICMP Ingress → Deny
        assert_eq!(
            eval_ipv4(
                &engine,
                FirewallDirection::Ingress,
                [10, 0, 0, 1],
                [192, 168, 1, 1],
                1,
                0,
                0,
            ),
            FirewallVerdict::Deny
        );

        // ICMP Egress → Deny
        assert_eq!(
            eval_ipv4(
                &engine,
                FirewallDirection::Egress,
                [192, 168, 1, 1],
                [10, 0, 0, 1],
                1,
                0,
                0,
            ),
            FirewallVerdict::Deny
        );
    }

    #[test_case]
    fn test_remove_rule() {
        let mut engine = make_engine();
        let id = engine.add_rule(
            FirewallRule::builder()
                .ingress()
                .deny()
                .tcp()
                .dst_port(PortMatch::Exact(22))
                .build(),
        );

        // ルール有効: Deny
        assert_eq!(
            eval_ipv4(
                &engine,
                FirewallDirection::Ingress,
                [10, 0, 0, 1],
                [192, 168, 1, 1],
                6,
                55555,
                22,
            ),
            FirewallVerdict::Deny
        );

        // ルール削除
        assert!(engine.remove_rule(id));

        // ルール削除後: Allow
        assert_eq!(
            eval_ipv4(
                &engine,
                FirewallDirection::Ingress,
                [10, 0, 0, 1],
                [192, 168, 1, 1],
                6,
                55555,
                22,
            ),
            FirewallVerdict::Allow
        );
    }

    #[test_case]
    fn test_clear_rules() {
        let mut engine = make_engine();
        engine.add_rule(
            FirewallRule::builder()
                .ingress()
                .deny()
                .tcp()
                .dst_port(PortMatch::Exact(22))
                .build(),
        );
        engine.add_rule(
            FirewallRule::builder()
                .ingress()
                .deny()
                .tcp()
                .dst_port(PortMatch::Exact(80))
                .build(),
        );
        assert_eq!(engine.rule_count(), 2);

        engine.clear_rules();
        assert_eq!(engine.rule_count(), 0);
    }

    #[test_case]
    fn test_cidr_masks() {
        // /0 は全アドレスにマッチ
        assert!(matches_ipv4(&IpMatch::Cidr([0, 0, 0, 0], 0), [1, 2, 3, 4]));
        // /32 は完全一致
        assert!(matches_ipv4(
            &IpMatch::Cidr([10, 0, 0, 1], 32),
            [10, 0, 0, 1]
        ));
        assert!(!matches_ipv4(
            &IpMatch::Cidr([10, 0, 0, 1], 32),
            [10, 0, 0, 2],
        ));
        // /24
        assert!(matches_ipv4(
            &IpMatch::Cidr([192, 168, 1, 0], 24),
            [192, 168, 1, 255],
        ));
        assert!(!matches_ipv4(
            &IpMatch::Cidr([192, 168, 1, 0], 24),
            [192, 168, 2, 0],
        ));
        // /16
        assert!(matches_ipv4(
            &IpMatch::Cidr([172, 16, 0, 0], 16),
            [172, 16, 255, 255],
        ));
        assert!(!matches_ipv4(
            &IpMatch::Cidr([172, 16, 0, 0], 16),
            [172, 17, 0, 0],
        ));
        // /8
        assert!(matches_ipv4(
            &IpMatch::Cidr([10, 0, 0, 0], 8),
            [10, 255, 255, 255],
        ));
        assert!(!matches_ipv4(
            &IpMatch::Cidr([10, 0, 0, 0], 8),
            [11, 0, 0, 0],
        ));
    }

    #[test_case]
    fn test_stats_tracking() {
        let mut engine = make_engine();
        engine.add_rule(
            FirewallRule::builder()
                .ingress()
                .deny()
                .tcp()
                .dst_port(PortMatch::Exact(22))
                .build(),
        );

        // パケットを評価
        eval_ipv4_mut(
            &mut engine,
            FirewallDirection::Ingress,
            [10, 0, 0, 1],
            [192, 168, 1, 1],
            6,
            55555,
            22,
        );
        eval_ipv4_mut(
            &mut engine,
            FirewallDirection::Ingress,
            [10, 0, 0, 1],
            [192, 168, 1, 1],
            6,
            55555,
            80,
        );

        let stats = engine.stats();
        assert_eq!(stats.evaluated, 2);
        assert_eq!(stats.matched, 1);
        assert_eq!(stats.denied, 1);
        assert_eq!(stats.allowed, 1);
        assert_eq!(stats.default_applied, 1);
    }

    // ── API パーサーテスト ──

    #[test_case]
    fn test_ip_match_display() {
        assert_eq!(format!("{}", IpMatch::Any), "*");
        assert_eq!(format!("{}", IpMatch::Exact([10, 0, 2, 15])), "10.0.2.15");
        assert_eq!(
            format!("{}", IpMatch::Cidr([192, 168, 1, 0], 24)),
            "192.168.1.0/24"
        );
    }

    #[test_case]
    fn test_port_match_display() {
        assert_eq!(format!("{}", PortMatch::Any), "*");
        assert_eq!(format!("{}", PortMatch::Exact(80)), "80");
        assert_eq!(format!("{}", PortMatch::Range(1024, 65535)), "1024-65535");
    }

    #[test_case]
    fn test_protocol_match() {
        assert!(FirewallProtocol::Any.matches(6));
        assert!(FirewallProtocol::Any.matches(17));
        assert!(FirewallProtocol::Tcp.matches(6));
        assert!(!FirewallProtocol::Tcp.matches(17));
        assert!(FirewallProtocol::Udp.matches(17));
        assert!(!FirewallProtocol::Udp.matches(6));
        assert!(FirewallProtocol::Icmp.matches(1));
        assert!(FirewallProtocol::Number(47).matches(47));
    }
}
