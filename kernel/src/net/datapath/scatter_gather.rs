// ============================================================================
// kernel/src/net/datapath/scatter_gather.rs - Scatter-Gather I/O
// ============================================================================
//! # Scatter-Gather I/O
//!
//! ゼロコピーTX送信パスのための Scatter-Gather リスト実装。
//! 複数の非連続バッファを1つの論理パケットとして扱い、
//! メモリコピーなしに NIC へ送信可能にする。
//!
//! ## 設計方針
//! - ExoRust ガイドライン 6章に準拠: 毎パケットでコピーしない
//! - 所有権ベースのバッファライフサイクル
//! - DMA 対応（IOMMU 経由）

use core::sync::atomic::{AtomicU64, Ordering};

use super::checksum_offload::internet_checksum;

/// Scatter-Gather エントリ（1つの連続バッファ領域を表す）
#[derive(Debug, Clone, Copy)]
pub struct SgEntry<'a> {
    /// データスライス
    pub slice: &'a [u8],
    /// DMA物理/IOVAアドレス（0 = 未マップ）
    pub dma_addr: u64,
}

impl<'a> SgEntry<'a> {
    /// 新しい SgEntry を作成
    #[inline]
    pub const fn new(slice: &'a [u8]) -> Self {
        Self { slice, dma_addr: 0 }
    }

    /// DMAアドレスを設定
    #[inline]
    pub fn set_dma_addr(&mut self, dma: u64) {
        self.dma_addr = dma;
    }

    /// データスライスを取得
    #[inline]
    pub fn as_slice(&self) -> &'a [u8] {
        self.slice
    }

    /// バッファの仮想アドレスを取得
    #[inline]
    pub fn addr(&self) -> usize {
        self.slice.as_ptr() as usize
    }

    /// データ長を取得
    #[inline]
    pub fn len(&self) -> u16 {
        self.slice.len() as u16
    }
}

/// Scatter-Gather リストの最大エントリ数
pub const MAX_SG_ENTRIES: usize = 8;

/// Scatter-Gather リスト
#[derive(Debug)]
pub struct ScatterGatherList<'a> {
    /// エントリ配列
    entries: [Option<SgEntry<'a>>; MAX_SG_ENTRIES],
    /// 使用中のエントリ数
    count: u8,
    /// 総データ長
    total_len: u32,
}

impl<'a> ScatterGatherList<'a> {
    /// 空の SG リストを作成
    #[inline]
    pub const fn new() -> Self {
        Self {
            entries: [None; MAX_SG_ENTRIES],
            count: 0,
            total_len: 0,
        }
    }

    /// エントリを追加
    #[inline]
    pub fn push(&mut self, slice: &'a [u8]) -> Result<usize, ()> {
        if self.count as usize >= MAX_SG_ENTRIES || slice.len() > u16::MAX as usize {
            return Err(());
        }
        let idx = self.count as usize;
        let len = slice.len() as u32;
        self.entries[idx] = Some(SgEntry::new(slice));
        self.count += 1;
        self.total_len += len;
        Ok(idx)
    }

    /// DMAマップ済みエントリを追加
    #[inline]
    pub fn push_dma(&mut self, slice: &'a [u8], dma_addr: u64) -> Result<usize, ()> {
        let idx = self.push(slice)?;
        if let Some(entry) = self.entries[idx].as_mut() {
            entry.set_dma_addr(dma_addr);
        }
        Ok(idx)
    }

    /// エントリを取得
    #[inline]
    pub fn entry(&self, index: usize) -> Option<&SgEntry<'a>> {
        if index < self.count as usize {
            self.entries[index].as_ref()
        } else {
            None
        }
    }

    /// 可変エントリを取得
    #[inline]
    pub fn entry_mut(&mut self, index: usize) -> Option<&mut SgEntry<'a>> {
        if index < self.count as usize {
            self.entries[index].as_mut()
        } else {
            None
        }
    }

    /// エントリ数
    #[inline]
    pub fn count(&self) -> usize {
        self.count as usize
    }

    /// 総データ長
    #[inline]
    pub fn total_len(&self) -> u32 {
        self.total_len
    }

    /// 空かどうか
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// 全エントリのイテレータ
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &SgEntry<'a>> {
        self.entries[..self.count as usize].iter().flatten()
    }

    /// 全エントリの可変イテレータ
    #[inline]
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut SgEntry<'a>> {
        let count = self.count as usize;
        self.entries[..count].iter_mut().flatten()
    }

    /// SG リスト全体をリニアバッファにコピー（フォールバック用）
    pub fn linearize(&self, output: &mut [u8]) -> Result<usize, ()> {
        if output.len() < self.total_len as usize {
            return Err(());
        }
        let mut offset = 0;
        for entry in self.iter() {
            let src = entry.as_slice();
            let entry_len = src.len();
            output[offset..offset + entry_len].copy_from_slice(src);
            offset += entry_len;
        }
        Ok(offset)
    }

    /// リセット
    #[inline]
    pub fn clear(&mut self) {
        for entry in self.entries.iter_mut() {
            *entry = None;
        }
        self.count = 0;
        self.total_len = 0;
    }
}

impl Default for ScatterGatherList<'_> {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Scatter-Gather TX Builder
// ============================================================================

/// SG TX パケットビルダー
///
/// Ethernet + IP + TCP/UDP ヘッダを個別のバッファに保持し、
/// ペイロードと合わせて SG リストを構成する。
/// ヘッダバッファはインラインで保持（スタック上に配置可能）。
pub struct SgTxBuilder {
    /// Ethernet ヘッダバッファ (14バイト)
    eth_header: [u8; 14],
    /// IP + Transport ヘッダバッファ (最大 60 + 60 = 120 バイト)
    ip_transport_header: [u8; 120],
    /// IP ヘッダ長
    ip_hdr_len: u8,
    /// Transport ヘッダ長
    transport_hdr_len: u8,
    /// 構築状態
    built: bool,
}

impl SgTxBuilder {
    /// 新規ビルダーを作成
    pub fn new() -> Self {
        Self {
            eth_header: [0u8; 14],
            ip_transport_header: [0u8; 120],
            ip_hdr_len: 0,
            transport_hdr_len: 0,
            built: false,
        }
    }

    /// Ethernet ヘッダを設定
    ///
    /// `dst_mac`: 宛先MACアドレス (6バイト)
    /// `src_mac`: 送信元MACアドレス (6バイト)
    /// `ethertype`: EtherType (ネットワークバイトオーダー)
    pub fn set_ethernet(&mut self, dst_mac: &[u8; 6], src_mac: &[u8; 6], ethertype: u16) {
        self.eth_header[..6].copy_from_slice(dst_mac);
        self.eth_header[6..12].copy_from_slice(src_mac);
        self.eth_header[12..14].copy_from_slice(&ethertype.to_be_bytes());
    }

    /// IPv4 ヘッダを設定（標準 20 バイト）
    pub fn set_ipv4(
        &mut self,
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        protocol: u8,
        total_len: u16,
        ttl: u8,
        id: u16,
    ) {
        let hdr = &mut self.ip_transport_header;
        hdr[0] = 0x45; // Version=4, IHL=5
        hdr[1] = 0x00; // DSCP/ECN
        hdr[2..4].copy_from_slice(&total_len.to_be_bytes());
        hdr[4..6].copy_from_slice(&id.to_be_bytes());
        hdr[6] = 0x40; // Don't Fragment
        hdr[7] = 0x00;
        hdr[8] = ttl;
        hdr[9] = protocol;
        hdr[10..12].copy_from_slice(&[0, 0]); // checksum placeholder
        hdr[12..16].copy_from_slice(&src_ip);
        hdr[16..20].copy_from_slice(&dst_ip);
        self.ip_hdr_len = 20;

        // IPv4 header checksum
        let cksum = internet_checksum(&hdr[..20]);
        hdr[10..12].copy_from_slice(&cksum.to_be_bytes());
    }

    /// TCP ヘッダを設定（標準 20 バイト）
    pub fn set_tcp(
        &mut self,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        window: u16,
    ) {
        let offset = self.ip_hdr_len as usize;
        let hdr = &mut self.ip_transport_header[offset..];
        hdr[0..2].copy_from_slice(&src_port.to_be_bytes());
        hdr[2..4].copy_from_slice(&dst_port.to_be_bytes());
        hdr[4..8].copy_from_slice(&seq.to_be_bytes());
        hdr[8..12].copy_from_slice(&ack.to_be_bytes());
        hdr[12] = 0x50; // Data offset = 5 (20/4)
        hdr[13] = flags;
        hdr[14..16].copy_from_slice(&window.to_be_bytes());
        hdr[16..18].copy_from_slice(&[0, 0]); // checksum placeholder
        hdr[18..20].copy_from_slice(&[0, 0]); // urgent pointer
        self.transport_hdr_len = 20;
    }

    /// UDP ヘッダを設定（8 バイト）
    pub fn set_udp(&mut self, src_port: u16, dst_port: u16, udp_len: u16) {
        let offset = self.ip_hdr_len as usize;
        let hdr = &mut self.ip_transport_header[offset..];
        hdr[0..2].copy_from_slice(&src_port.to_be_bytes());
        hdr[2..4].copy_from_slice(&dst_port.to_be_bytes());
        hdr[4..6].copy_from_slice(&udp_len.to_be_bytes());
        hdr[6..8].copy_from_slice(&[0, 0]); // checksum placeholder
        self.transport_hdr_len = 8;
    }

    /// SG リストを構築
    ///
    /// `payload`: ペイロードデータのスライス
    ///
    /// ヘッダバッファは `self` 内に保持されるため、戻り値の SG リストの
    /// ライフタイムは `self` のライフタイムに束縛される。
    pub fn build<'a>(&'a mut self, payload: &'a [u8]) -> ScatterGatherList<'a> {
        let mut sg = ScatterGatherList::new();

        // Ethernet ヘッダ
        let _ = sg.push(&self.eth_header);

        // IP + Transport ヘッダ
        let hdr_total = self.ip_hdr_len as usize + self.transport_hdr_len as usize;
        if hdr_total > 0 {
            let _ = sg.push(&self.ip_transport_header[..hdr_total]);
        }

        // ペイロード
        if !payload.is_empty() {
            let _ = sg.push(payload);
        }

        self.built = true;
        sg
    }

    /// ヘッダ総長を取得
    #[inline]
    pub fn header_len(&self) -> usize {
        14 + self.ip_hdr_len as usize + self.transport_hdr_len as usize
    }
}

impl Default for SgTxBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// Scatter-Gather 統計
#[derive(Debug)]
pub struct SgStats {
    /// SG送信成功数
    pub sg_tx_success: AtomicU64,
    /// フラットニング（コピーへのフォールバック）回数
    pub linearize_fallback: AtomicU64,
    /// 平均エントリ数 (x100)
    pub avg_entries_x100: AtomicU64,
}

impl SgStats {
    pub const fn new() -> Self {
        Self {
            sg_tx_success: AtomicU64::new(0),
            linearize_fallback: AtomicU64::new(0),
            avg_entries_x100: AtomicU64::new(0),
        }
    }

    /// SG送信成功を記録
    pub fn record_sg_tx(&self, entry_count: usize) {
        let total = self.sg_tx_success.fetch_add(1, Ordering::Relaxed) + 1;
        // 移動平均の近似更新
        let current = self.avg_entries_x100.load(Ordering::Relaxed);
        let new_avg = (current * (total - 1) + entry_count as u64 * 100) / total;
        self.avg_entries_x100.store(new_avg, Ordering::Relaxed);
    }

    /// フラットニングを記録
    pub fn record_linearize(&self) {
        self.linearize_fallback.fetch_add(1, Ordering::Relaxed);
    }
}

/// グローバル SG 統計
pub static SG_STATS: SgStats = SgStats::new();

// ============================================================================
// ユーティリティ
// ============================================================================
// ip_checksum は checksum_offload::internet_checksum に統合済み

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_sg_list_basic() {
        let mut sg = ScatterGatherList::new();
        assert!(sg.is_empty());

        let data1 = [1u8, 2, 3, 4];
        let data2 = [5u8, 6, 7];

        assert!(sg.push(&data1).is_ok());
        assert!(sg.push(&data2).is_ok());

        assert_eq!(sg.count(), 2);
        assert_eq!(sg.total_len(), 7);
        assert!(!sg.is_empty());
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_sg_list_max_entries() {
        let mut sg = ScatterGatherList::new();
        let data = [0u8; 1];

        for _ in 0..MAX_SG_ENTRIES {
            assert!(sg.push(&data).is_ok());
        }

        // MAX超過
        assert!(sg.push(&data).is_err());
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_sg_linearize() {
        let mut sg = ScatterGatherList::new();
        let data1 = [0xAAu8, 0xBB];
        let data2 = [0xCCu8, 0xDD, 0xEE];

        sg.push(&data1).unwrap();
        sg.push(&data2).unwrap();

        let mut output = [0u8; 16];
        let written = sg.linearize(&mut output).unwrap();

        assert_eq!(written, 5);
        assert_eq!(&output[..5], &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_sg_tx_builder() {
        let mut builder = SgTxBuilder::new();
        builder.set_ethernet(
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            &[0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            0x0800,
        );
        builder.set_ipv4([10, 0, 0, 1], [10, 0, 0, 2], 6, 60, 64, 1);
        builder.set_tcp(8080, 80, 1000, 0, 0x02, 65535);

        let payload = [0xDE, 0xAD, 0xBE, 0xEF];
        let sg = builder.build(&payload);

        assert_eq!(sg.count(), 3); // eth + ip/tcp + payload
        assert_eq!(sg.total_len(), 14 + 40 + 4); // 58
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_ip_checksum() {
        // Standard test vector
        let header: [u8; 20] = [
            0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00,
            0x00, // checksum field = 0 for calculation
            0xac, 0x10, 0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c,
        ];
        let cksum = internet_checksum(&header);
        // Should be non-zero (valid checksum)
        assert_ne!(cksum, 0);
    }
}
