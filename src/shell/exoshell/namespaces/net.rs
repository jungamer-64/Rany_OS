// ============================================================================
// src/shell/exoshell/namespaces/net.rs - Network Namespace
// ============================================================================

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::shell::exoshell::types::ExoValue;

/// ネットワーク名前空間
pub struct NetNamespace;

impl NetNamespace {
    /// ネットワーク設定を取得
    pub fn config() -> ExoValue {
        if let Some(cfg) = crate::net::get_network_config() {
            let mut map = BTreeMap::new();
            map.insert(
                String::from("ip"),
                ExoValue::String(format!(
                    "{}.{}.{}.{}",
                    cfg.ip[0], cfg.ip[1], cfg.ip[2], cfg.ip[3]
                )),
            );
            map.insert(
                String::from("netmask"),
                ExoValue::String(format!(
                    "{}.{}.{}.{}",
                    cfg.netmask[0], cfg.netmask[1], cfg.netmask[2], cfg.netmask[3]
                )),
            );
            map.insert(
                String::from("mac"),
                ExoValue::String(format!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    cfg.mac[0], cfg.mac[1], cfg.mac[2],
                    cfg.mac[3], cfg.mac[4], cfg.mac[5]
                )),
            );
            ExoValue::Map(map)
        } else {
            ExoValue::Error(String::from("Network not configured"))
        }
    }

    /// ネットワーク統計
    pub fn stats() -> ExoValue {
        if let Some(stats) = crate::net::get_network_stats() {
            let mut map = BTreeMap::new();
            map.insert(String::from("rx_packets"), ExoValue::Int(stats.rx_packets as i64));
            map.insert(String::from("tx_packets"), ExoValue::Int(stats.tx_packets as i64));
            map.insert(String::from("rx_bytes"), ExoValue::Int(stats.rx_bytes as i64));
            map.insert(String::from("tx_bytes"), ExoValue::Int(stats.tx_bytes as i64));
            map.insert(String::from("rx_errors"), ExoValue::Int(stats.rx_errors as i64));
            map.insert(String::from("rx_dropped"), ExoValue::Int(stats.rx_dropped as i64));
            ExoValue::Map(map)
        } else {
            ExoValue::Error(String::from("No network statistics"))
        }
    }

    /// ARP キャッシュ
    pub fn arp_cache() -> ExoValue {
        if let Some(entries) = crate::net::get_arp_cache() {
            let values: Vec<ExoValue> = entries
                .into_iter()
                .map(|e| {
                    let mut map = BTreeMap::new();
                    map.insert(
                        String::from("ip"),
                        ExoValue::String(format!(
                            "{}.{}.{}.{}",
                            e.ip[0], e.ip[1], e.ip[2], e.ip[3]
                        )),
                    );
                    map.insert(
                        String::from("mac"),
                        ExoValue::String(format!(
                            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                            e.mac[0], e.mac[1], e.mac[2],
                            e.mac[3], e.mac[4], e.mac[5]
                        )),
                    );
                    map.insert(String::from("complete"), ExoValue::Bool(e.complete));
                    ExoValue::Map(map)
                })
                .collect();
            ExoValue::Array(values)
        } else {
            ExoValue::Array(Vec::new())
        }
    }

    /// ICMP エコー送信（async版 - パケット間でyield）
    pub async fn ping(ip: [u8; 4], count: u16) -> ExoValue {
        let mut results = Vec::new();
        for seq in 1..=count {
            // 各パケット送信前にyield（他タスクに機会を与える）
            crate::task::yield_now().await;
            
            match crate::net::send_icmp_echo(ip, seq) {
                Ok(rtt) => {
                    let mut map = BTreeMap::new();
                    map.insert(String::from("seq"), ExoValue::Int(seq as i64));
                    map.insert(String::from("rtt_ms"), ExoValue::Float(rtt as f64));
                    map.insert(String::from("success"), ExoValue::Bool(true));
                    results.push(ExoValue::Map(map));
                }
                Err(e) => {
                    let mut map = BTreeMap::new();
                    map.insert(String::from("seq"), ExoValue::Int(seq as i64));
                    map.insert(String::from("error"), ExoValue::String(e));
                    map.insert(String::from("success"), ExoValue::Bool(false));
                    results.push(ExoValue::Map(map));
                }
            }
            
            // パケット間に少し待機（async sleep）
            if seq < count {
                crate::task::sleep_ms(100).await;
            }
        }
        ExoValue::Array(results)
    }
}
