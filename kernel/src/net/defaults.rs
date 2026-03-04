// ============================================================================
// kernel/src/net/defaults.rs - ネットワークデフォルト定数
// ============================================================================
//! QEMUユーザモードネットワーキング (slirp) のデフォルト設定値。
//!
//! IP/MACアドレスを一元管理し、複数箇所でのハードコーディングを排除する。
//! DHCPで動的に取得できない場合のフォールバック値として使用される。

use crate::net::l2::ethernet::MacAddress;
use crate::net::l3::ipv4::Ipv4Address;

// ---------------------------------------------------------------------------
// MAC アドレス
// ---------------------------------------------------------------------------

/// QEMUデフォルトのMACアドレス (`52:54:00:12:34:56`)
///
/// VirtIO-Netデバイスが未初期化、またはMAC読み取りに失敗した場合のフォールバック。
pub const QEMU_DEFAULT_MAC: MacAddress =
    MacAddress::new([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);

/// QEMUデフォルトMACアドレスのバイト配列表現
pub const QEMU_DEFAULT_MAC_BYTES: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

// ---------------------------------------------------------------------------
// IPv4 アドレス (QEMU slirp モード)
// ---------------------------------------------------------------------------

/// QEMUデフォルトのゲスト IPアドレス (`10.0.2.15`)
pub const QEMU_DEFAULT_IP: Ipv4Address = Ipv4Address::new([10, 0, 2, 15]);

/// QEMUデフォルトのゲスト IPアドレス (バイト配列)
pub const QEMU_DEFAULT_IP_BYTES: [u8; 4] = [10, 0, 2, 15];

/// QEMUデフォルトのサブネットマスク (`255.255.255.0`)
pub const QEMU_DEFAULT_SUBNET_MASK: Ipv4Address = Ipv4Address::new([255, 255, 255, 0]);

/// QEMUデフォルトのゲートウェイ (`10.0.2.2`)
pub const QEMU_DEFAULT_GATEWAY: Ipv4Address = Ipv4Address::new([10, 0, 2, 2]);

/// QEMUデフォルトのゲートウェイ (バイト配列)
pub const QEMU_DEFAULT_GATEWAY_BYTES: [u8; 4] = [10, 0, 2, 2];

/// QEMUデフォルトのDNSサーバ (`10.0.2.3`)
pub const QEMU_DEFAULT_DNS: Ipv4Address = Ipv4Address::new([10, 0, 2, 3]);
