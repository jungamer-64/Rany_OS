// ============================================================================
// kernel/src/net/datapath/checksum_offload.rs
// ============================================================================
//! # Checksum Offload Framework
//!
//! ハードウェア/ソフトウェアチェックサムオフロードの統合管理。
//!
//! ## 設計方針
//! - VirtIO-Netの`VIRTIO_NET_F_CSUM`フィーチャに対応
//! - ハードウェアオフロード不可時はソフトウェアフォールバック
//! - 受信側: HWが検証済みならスキップ (RX offload)
//! - 送信側: HWに委譲可能ならプレースホルダのみ書き込み (TX offload)

use core::sync::atomic::{AtomicU64, Ordering};

// ============================================================================
// Offload Capability Flags
// ============================================================================

/// チェックサムオフロード能力フラグ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChecksumCapabilities {
    /// TX: IPv4ヘッダチェックサムをHWで計算
    pub tx_ipv4: bool,
    /// TX: TCPチェックサムをHWで計算
    pub tx_tcp: bool,
    /// TX: UDPチェックサムをHWで計算
    pub tx_udp: bool,
    /// RX: IPv4ヘッダチェックサムをHWで検証
    pub rx_ipv4: bool,
    /// RX: TCPチェックサムをHWで検証
    pub rx_tcp: bool,
    /// RX: UDPチェックサムをHWで検証
    pub rx_udp: bool,
}

impl ChecksumCapabilities {
    /// 全てソフトウェア計算 (デフォルト)
    pub const NONE: Self = Self {
        tx_ipv4: false,
        tx_tcp: false,
        tx_udp: false,
        rx_ipv4: false,
        rx_tcp: false,
        rx_udp: false,
    };

    /// 全てハードウェアオフロード
    pub const ALL: Self = Self {
        tx_ipv4: true,
        tx_tcp: true,
        tx_udp: true,
        rx_ipv4: true,
        rx_tcp: true,
        rx_udp: true,
    };

    /// VirtIO-Net CSUM featureからの能力検出
    ///
    /// `csum`: VIRTIO_NET_F_CSUM が有効
    /// `guest_csum`: VIRTIO_NET_F_GUEST_CSUM が有効
    pub fn from_virtio(csum: bool, guest_csum: bool) -> Self {
        Self {
            tx_ipv4: csum,
            tx_tcp: csum,
            tx_udp: csum,
            rx_ipv4: guest_csum,
            rx_tcp: guest_csum,
            rx_udp: guest_csum,
        }
    }

    /// TX側のオフロードが1つでも有効か
    #[inline]
    pub fn any_tx(&self) -> bool {
        self.tx_ipv4 || self.tx_tcp || self.tx_udp
    }

    /// RX側のオフロードが1つでも有効か
    #[inline]
    pub fn any_rx(&self) -> bool {
        self.rx_ipv4 || self.rx_tcp || self.rx_udp
    }
}

impl Default for ChecksumCapabilities {
    fn default() -> Self {
        Self::NONE
    }
}

// ============================================================================
// Checksum Offload Manager
// ============================================================================

/// チェックサムオフロードマネージャ
///
/// NICの能力に応じてソフトウェア/ハードウェア計算を切り替える。
pub struct ChecksumOffloadManager {
    /// 現在の能力設定
    capabilities: ChecksumCapabilities,
    /// 統計
    stats: ChecksumStats,
}

/// チェックサム統計
#[derive(Debug, Default)]
pub struct ChecksumStats {
    /// ソフトウェアで計算したTXチェックサム数
    pub tx_sw_computed: AtomicU64,
    /// ハードウェアに委譲したTXチェックサム数
    pub tx_hw_offloaded: AtomicU64,
    /// ソフトウェアで検証したRXチェックサム数
    pub rx_sw_verified: AtomicU64,
    /// ハードウェアが検証済みのRXチェックサム数
    pub rx_hw_verified: AtomicU64,
    /// チェックサムエラー数
    pub errors: AtomicU64,
}

impl ChecksumStats {
    pub const fn new() -> Self {
        Self {
            tx_sw_computed: AtomicU64::new(0),
            tx_hw_offloaded: AtomicU64::new(0),
            rx_sw_verified: AtomicU64::new(0),
            rx_hw_verified: AtomicU64::new(0),
            errors: AtomicU64::new(0),
        }
    }
}

/// TX時のチェックサム指示
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxChecksumAction {
    /// ソフトウェアで計算済み — そのまま送信
    Computed,
    /// ハードウェアオフロード — プレースホルダのみ書き込み済み
    Offload {
        /// チェックサムフィールドのオフセット (フレーム先頭からのバイト数)
        csum_offset: u16,
        /// チェックサム計算の開始オフセット
        csum_start: u16,
    },
}

/// RX時のチェックサム検証状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RxChecksumStatus {
    /// HWが検証済み (valid)
    HwValid,
    /// HWが検証して不正 (invalid)
    HwInvalid,
    /// HW検証なし — ソフトウェアで検証が必要
    NotVerified,
}

impl ChecksumOffloadManager {
    /// 新しいオフロードマネージャを作成
    pub fn new(capabilities: ChecksumCapabilities) -> Self {
        Self {
            capabilities,
            stats: ChecksumStats::new(),
        }
    }

    /// 能力を取得
    #[inline]
    pub fn capabilities(&self) -> &ChecksumCapabilities {
        &self.capabilities
    }

    /// 統計を取得
    #[inline]
    pub fn stats(&self) -> &ChecksumStats {
        &self.stats
    }

    /// 能力を更新 (NIC初期化後)
    pub fn update_capabilities(&mut self, caps: ChecksumCapabilities) {
        self.capabilities = caps;
    }

    // ================================================================
    // TX Path
    // ================================================================

    /// IPv4ヘッダチェックサムのTX処理を決定
    ///
    /// `header`: IPv4ヘッダバッファ (可変参照)
    /// 戻り値: オフロード可能ならプレースホルダ(0)をセット
    pub fn prepare_tx_ipv4(&self, header: &mut [u8]) -> TxChecksumAction {
        if self.capabilities.tx_ipv4 {
            // HWオフロード — チェックサムフィールドを0にする
            if header.len() >= 20 {
                header[10] = 0;
                header[11] = 0;
            }
            self.stats.tx_hw_offloaded.fetch_add(1, Ordering::Relaxed);
            TxChecksumAction::Offload {
                csum_start: 0,
                csum_offset: 10,
            }
        } else {
            // ソフトウェア計算
            if header.len() >= 20 {
                header[10] = 0;
                header[11] = 0;
                let cksum = internet_checksum(header);
                let bytes = cksum.to_be_bytes();
                header[10] = bytes[0];
                header[11] = bytes[1];
            }
            self.stats.tx_sw_computed.fetch_add(1, Ordering::Relaxed);
            TxChecksumAction::Computed
        }
    }

    /// TCPチェックサムのTX処理を決定
    ///
    /// `src_ip`, `dst_ip`: IPv4アドレス (4バイト)
    /// `tcp_data`: TCPヘッダ+ペイロード (チェックサムフィールドは可変)
    /// `eth_header_len`: Ethernetヘッダ長 (VLAN含む場合18)
    pub fn prepare_tx_tcp(
        &self,
        src_ip: &[u8; 4],
        dst_ip: &[u8; 4],
        tcp_data: &mut [u8],
        eth_header_len: usize,
    ) -> TxChecksumAction {
        if tcp_data.len() < 20 {
            return TxChecksumAction::Computed;
        }

        if self.capabilities.tx_tcp {
            // HWオフロード — チェックサムフィールドに疑似ヘッダ部分和をセット
            tcp_data[16] = 0;
            tcp_data[17] = 0;
            let partial = pseudo_header_partial_sum(src_ip, dst_ip, 6, tcp_data.len() as u16);
            let bytes = partial.to_be_bytes();
            tcp_data[16] = bytes[0];
            tcp_data[17] = bytes[1];
            self.stats.tx_hw_offloaded.fetch_add(1, Ordering::Relaxed);
            TxChecksumAction::Offload {
                csum_start: (eth_header_len + 20) as u16, // TCP starts after IP header
                csum_offset: 16,
            }
        } else {
            // ソフトウェア計算
            tcp_data[16] = 0;
            tcp_data[17] = 0;
            let cksum = tcp_udp_checksum(src_ip, dst_ip, 6, tcp_data);

            let bytes = cksum.to_be_bytes();
            tcp_data[16] = bytes[0];
            tcp_data[17] = bytes[1];
            self.stats.tx_sw_computed.fetch_add(1, Ordering::Relaxed);
            TxChecksumAction::Computed
        }
    }

    /// UDPチェックサムのTX処理を決定
    pub fn prepare_tx_udp(
        &self,
        src_ip: &[u8; 4],
        dst_ip: &[u8; 4],
        udp_data: &mut [u8],
        eth_header_len: usize,
    ) -> TxChecksumAction {
        if udp_data.len() < 8 {
            return TxChecksumAction::Computed;
        }

        if self.capabilities.tx_udp {
            // HWオフロード
            udp_data[6] = 0;
            udp_data[7] = 0;
            let partial = pseudo_header_partial_sum(src_ip, dst_ip, 17, udp_data.len() as u16);
            let bytes = partial.to_be_bytes();
            udp_data[6] = bytes[0];
            udp_data[7] = bytes[1];
            self.stats.tx_hw_offloaded.fetch_add(1, Ordering::Relaxed);
            TxChecksumAction::Offload {
                csum_start: (eth_header_len + 20) as u16,
                csum_offset: 6,
            }
        } else {
            // ソフトウェア計算
            udp_data[6] = 0;
            udp_data[7] = 0;
            let cksum = tcp_udp_checksum(src_ip, dst_ip, 17, udp_data);

            let bytes = cksum.to_be_bytes();
            udp_data[6] = bytes[0];
            udp_data[7] = bytes[1];
            self.stats.tx_sw_computed.fetch_add(1, Ordering::Relaxed);
            TxChecksumAction::Computed
        }
    }

    // ================================================================
    // RX Path
    // ================================================================

    /// RX IPv4ヘッダチェックサムを検証
    ///
    /// `hw_status`: HWからの検証ステータス
    /// `header`: IPv4ヘッダ
    /// 戻り値: true = 有効, false = 不正
    pub fn verify_rx_ipv4(&self, hw_status: RxChecksumStatus, header: &[u8]) -> bool {
        match hw_status {
            RxChecksumStatus::HwValid => {
                self.stats.rx_hw_verified.fetch_add(1, Ordering::Relaxed);
                true
            }
            RxChecksumStatus::HwInvalid => {
                self.stats.errors.fetch_add(1, Ordering::Relaxed);
                false
            }
            RxChecksumStatus::NotVerified => {
                // ソフトウェア検証
                let valid = internet_checksum(header) == 0;
                self.stats.rx_sw_verified.fetch_add(1, Ordering::Relaxed);
                if !valid {
                    self.stats.errors.fetch_add(1, Ordering::Relaxed);
                }
                valid
            }
        }
    }

    /// RX TCPチェックサムを検証
    pub fn verify_rx_tcp(
        &self,
        hw_status: RxChecksumStatus,
        src_ip: &[u8; 4],
        dst_ip: &[u8; 4],
        tcp_data: &[u8],
    ) -> bool {
        match hw_status {
            RxChecksumStatus::HwValid => {
                self.stats.rx_hw_verified.fetch_add(1, Ordering::Relaxed);
                true
            }
            RxChecksumStatus::HwInvalid => {
                self.stats.errors.fetch_add(1, Ordering::Relaxed);
                false
            }
            RxChecksumStatus::NotVerified => {
                let valid = verify_tcp_udp_checksum(src_ip, dst_ip, 6, tcp_data);
                self.stats.rx_sw_verified.fetch_add(1, Ordering::Relaxed);
                if !valid {
                    self.stats.errors.fetch_add(1, Ordering::Relaxed);
                }
                valid
            }
        }
    }

    /// RX UDPチェックサムを検証
    pub fn verify_rx_udp(
        &self,
        hw_status: RxChecksumStatus,
        src_ip: &[u8; 4],
        dst_ip: &[u8; 4],
        udp_data: &[u8],
    ) -> bool {
        match hw_status {
            RxChecksumStatus::HwValid => {
                self.stats.rx_hw_verified.fetch_add(1, Ordering::Relaxed);
                true
            }
            RxChecksumStatus::HwInvalid => {
                self.stats.errors.fetch_add(1, Ordering::Relaxed);
                false
            }
            RxChecksumStatus::NotVerified => {
                // UDP checksum 0 means "not computed" (RFC 768)
                if udp_data.len() >= 8 {
                    let stored_cksum = u16::from_be_bytes([udp_data[6], udp_data[7]]);
                    if stored_cksum == 0 {
                        self.stats.rx_sw_verified.fetch_add(1, Ordering::Relaxed);
                        return true; // No checksum to verify
                    }
                }
                let valid = verify_tcp_udp_checksum(src_ip, dst_ip, 17, udp_data);
                self.stats.rx_sw_verified.fetch_add(1, Ordering::Relaxed);
                if !valid {
                    self.stats.errors.fetch_add(1, Ordering::Relaxed);
                }
                valid
            }
        }
    }
}

impl Default for ChecksumOffloadManager {
    fn default() -> Self {
        Self::new(ChecksumCapabilities::NONE)
    }
}

// ============================================================================
// Checksum Computation Utilities
// ============================================================================

/// インターネットチェックサム (RFC 1071)
///
/// IPv4ヘッダ等の16bit 1's complement チェックサムを計算。
/// 検証時は全体を計算して0なら有効。
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    while i + 1 < data.len() {
        let word = u16::from_be_bytes([data[i], data[i + 1]]);
        sum += word as u32;
        i += 2;
    }

    // 奇数長の場合
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }

    // キャリーを折りたたみ
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    let mut result = !(sum as u16);
    if result == 0 {
        result = 0xFFFF;
    }
    result
}

/// 疑似ヘッダの部分和 (HWオフロード用)
///
/// HWチェックサムオフロード時、チェックサムフィールドに
/// 疑似ヘッダの部分和をセットしておく (VirtIO CSUM方式)。
pub fn pseudo_header_partial_sum(
    src_ip: &[u8; 4],
    dst_ip: &[u8; 4],
    protocol: u8,
    length: u16,
) -> u16 {
    let mut sum: u32 = 0;

    sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
    sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
    sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
    sum += protocol as u32;
    sum += length as u32;

    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    sum as u16
}

/// TCP/UDPチェックサム (疑似ヘッダ含む)
fn tcp_udp_checksum(src_ip: &[u8; 4], dst_ip: &[u8; 4], protocol: u8, data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // 疑似ヘッダ
    sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
    sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
    sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
    sum += protocol as u32;
    sum += data.len() as u32;

    // データ
    let mut i = 0;
    while i + 1 < data.len() {
        let word = u16::from_be_bytes([data[i], data[i + 1]]);
        sum += word as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    let mut result = !(sum as u16);
    if result == 0 {
        result = 0xFFFF;
    }
    result
}

/// TCP/UDPチェックサム検証
fn verify_tcp_udp_checksum(src_ip: &[u8; 4], dst_ip: &[u8; 4], protocol: u8, data: &[u8]) -> bool {
    let mut sum: u32 = 0;

    // 疑似ヘッダ
    sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
    sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
    sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
    sum += protocol as u32;
    sum += data.len() as u32;

    // データ (チェックサムフィールド含む)
    let mut i = 0;
    while i + 1 < data.len() {
        let word = u16::from_be_bytes([data[i], data[i + 1]]);
        sum += word as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    (sum as u16) == 0xFFFF
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn test_internet_checksum() {
        // RFC 1071 example
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        let cksum = internet_checksum(&data);
        assert_ne!(cksum, 0);
    }

    #[test_case]
    fn test_internet_checksum_verify() {
        // Construct a simple IPv4-like header and verify
        let mut header = [0u8; 20];
        header[0] = 0x45;
        header[8] = 64; // TTL
        header[9] = 6; // TCP
        // Set some addresses
        header[12..16].copy_from_slice(&[192, 168, 1, 1]);
        header[16..20].copy_from_slice(&[192, 168, 1, 2]);

        // Compute checksum
        let cksum = internet_checksum(&header);
        let bytes = cksum.to_be_bytes();
        header[10] = bytes[0];
        header[11] = bytes[1];

        // Verify: checksum of whole header should be 0
        assert_eq!(internet_checksum(&header), 0);
    }

    #[test_case]
    fn test_capabilities_default() {
        let caps = ChecksumCapabilities::default();
        assert!(!caps.any_tx());
        assert!(!caps.any_rx());
    }

    #[test_case]
    fn test_capabilities_virtio() {
        let caps = ChecksumCapabilities::from_virtio(true, true);
        assert!(caps.any_tx());
        assert!(caps.any_rx());
        assert!(caps.tx_tcp);
        assert!(caps.rx_tcp);
    }

    #[test_case]
    fn test_pseudo_header_partial_sum() {
        let src = [10, 0, 0, 1];
        let dst = [10, 0, 0, 2];
        let partial = pseudo_header_partial_sum(&src, &dst, 6, 20);
        assert!(partial > 0);
    }

    #[test_case]
    fn test_offload_manager_sw_mode() {
        let mgr = ChecksumOffloadManager::new(ChecksumCapabilities::NONE);

        // IPv4 header
        let mut header = [0u8; 20];
        header[0] = 0x45;
        header[8] = 64;
        header[9] = 6;
        header[12..16].copy_from_slice(&[10, 0, 0, 1]);
        header[16..20].copy_from_slice(&[10, 0, 0, 2]);

        let action = mgr.prepare_tx_ipv4(&mut header);
        assert_eq!(action, TxChecksumAction::Computed);
        // Verify checksum was computed
        assert_eq!(internet_checksum(&header), 0);
    }

    #[test_case]
    fn test_offload_manager_hw_mode() {
        let mgr = ChecksumOffloadManager::new(ChecksumCapabilities::ALL);

        let mut header = [0u8; 20];
        header[0] = 0x45;
        header[8] = 64;
        header[9] = 6;

        let action = mgr.prepare_tx_ipv4(&mut header);
        match action {
            TxChecksumAction::Offload { csum_offset, .. } => {
                assert_eq!(csum_offset, 10);
            }
            _ => panic!("Expected Offload action"),
        }
    }
}
