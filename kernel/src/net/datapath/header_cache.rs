// ============================================================================
// kernel/src/net/datapath/header_cache.rs
// ============================================================================
//! # TCP/IP ヘッダキャッシュ
//!
//! アクティブなTCPコネクションに対して、事前計算済みヘッダテンプレートを
//! キャッシュし、送信パスのヘッダ構築コストを削減する。
//!
//! ## 設計方針
//! - ExoRust ガイドライン: ゼロコピーパスの維持
//! - 高頻度送信のコネクション向けに最適化
//! - IPv4 / IPv6 両対応
//! - キャッシュラインアライメント対応

use core::sync::atomic::{AtomicU64, Ordering};

use super::checksum_offload::internet_checksum;

/// キャッシュエントリの最大数（2-way × 32セット = 64エントリ合計）
const HEADER_CACHE_SIZE: usize = 64;

/// アソシエイティビティ（ウェイ数）
const HEADER_CACHE_WAYS: usize = 2;

/// セット数
const HEADER_CACHE_SETS: usize = HEADER_CACHE_SIZE / HEADER_CACHE_WAYS;

/// ヘッダテンプレートの最大バイト数 (Ethernet:14 + IPv4:20 + TCP:60 = 94)
const MAX_HEADER_TEMPLATE_SIZE: usize = 128;

/// コネクション識別子（5タプルから算出）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnId(u64);

impl ConnId {
    /// 5タプルからコネクションIDを生成
    pub fn from_5tuple(
        src_ip: u32,
        dst_ip: u32,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
    ) -> Self {
        // FNV-1a ハッシュで64ビットIDを生成
        let mut hash: u64 = 0xcbf29ce484222325;
        let fnv_prime: u64 = 0x100000001b3;

        for byte in src_ip
            .to_be_bytes()
            .iter()
            .chain(&dst_ip.to_be_bytes())
            .chain(&src_port.to_be_bytes())
            .chain(&dst_port.to_be_bytes())
            .chain(core::slice::from_ref(&protocol))
        {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(fnv_prime);
        }

        Self(hash)
    }

    /// ハッシュ値を取得
    #[inline]
    pub fn hash(&self) -> u64 {
        self.0
    }
}

/// キャッシュされたヘッダテンプレート
///
/// Ethernet + IPv4 + TCP ヘッダのうち、コネクションごとに固定の
/// フィールドを事前に書き込んだテンプレート。
/// 送信時はシーケンス番号、ACK番号、ウィンドウサイズ、チェックサムのみ更新。
#[repr(C, align(64))] // キャッシュラインに合わせる
#[derive(Clone)]
pub struct CachedHeader {
    /// コネクション識別子
    conn_id: ConnId,
    /// ヘッダテンプレートバイト列
    template: [u8; MAX_HEADER_TEMPLATE_SIZE],
    /// テンプレートの有効長
    template_len: u16,
    /// Ethernet ヘッダ長
    eth_len: u8,
    /// IP ヘッダ長
    ip_len: u8,
    /// TCP ヘッダ長
    tcp_len: u8,
    /// 有効フラグ
    valid: bool,
    /// 最終アクセス時刻 (TSC)
    last_access: u64,
    /// ヒット回数
    hits: u64,
    // === 動的フィールドのオフセット（更新時にバイト位置を直接参照） ===
    /// TCP シーケンス番号のオフセット
    seq_offset: u8,
    /// TCP ACK番号のオフセット
    ack_offset: u8,
    /// TCP ウィンドウサイズのオフセット
    window_offset: u8,
    /// TCP チェックサムのオフセット
    tcp_cksum_offset: u8,
    /// IPv4 totalLength のオフセット
    ip_total_len_offset: u8,
    /// IPv4 identification のオフセット
    ip_id_offset: u8,
    /// IPv4 ヘッダチェックサムのオフセット
    ip_cksum_offset: u8,
}

impl CachedHeader {
    const fn empty() -> Self {
        Self {
            conn_id: ConnId(0),
            template: [0u8; MAX_HEADER_TEMPLATE_SIZE],
            template_len: 0,
            eth_len: 0,
            ip_len: 0,
            tcp_len: 0,
            valid: false,
            last_access: 0,
            hits: 0,
            seq_offset: 0,
            ack_offset: 0,
            window_offset: 0,
            tcp_cksum_offset: 0,
            ip_total_len_offset: 0,
            ip_id_offset: 0,
            ip_cksum_offset: 0,
        }
    }

    /// テンプレートを IPv4+TCP コネクション用に初期化
    pub fn init_ipv4_tcp(
        &mut self,
        conn_id: ConnId,
        dst_mac: &[u8; 6],
        src_mac: &[u8; 6],
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        ttl: u8,
    ) {
        // Ethernet Header (14 bytes)
        self.template[0..6].copy_from_slice(dst_mac);
        self.template[6..12].copy_from_slice(src_mac);
        self.template[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        self.eth_len = 14;

        let ip_start = 14usize;
        // IPv4 Header (20 bytes)
        self.template[ip_start] = 0x45; // Version=4, IHL=5
        self.template[ip_start + 1] = 0x00; // DSCP/ECN
        // [2..4] total_len - dynamic
        // [4..6] identification - dynamic
        self.template[ip_start + 6] = 0x40; // Don't Fragment
        self.template[ip_start + 7] = 0x00;
        self.template[ip_start + 8] = ttl;
        self.template[ip_start + 9] = 6; // TCP
        // [10..12] header checksum - dynamic
        self.template[ip_start + 12..ip_start + 16].copy_from_slice(&src_ip);
        self.template[ip_start + 16..ip_start + 20].copy_from_slice(&dst_ip);
        self.ip_len = 20;

        let tcp_start = 34usize; // 14 + 20
        // TCP Header (20 bytes)
        self.template[tcp_start..tcp_start + 2].copy_from_slice(&src_port.to_be_bytes());
        self.template[tcp_start + 2..tcp_start + 4].copy_from_slice(&dst_port.to_be_bytes());
        // [4..8] sequence - dynamic
        // [8..12] ack - dynamic
        self.template[tcp_start + 12] = 0x50; // Data offset = 5
        // [13] flags - dynamic
        // [14..16] window - dynamic
        // [16..18] checksum - dynamic
        self.template[tcp_start + 18] = 0; // Urgent pointer
        self.template[tcp_start + 19] = 0;
        self.tcp_len = 20;

        // オフセット設定
        self.ip_total_len_offset = (ip_start + 2) as u8;
        self.ip_id_offset = (ip_start + 4) as u8;
        self.ip_cksum_offset = (ip_start + 10) as u8;
        self.seq_offset = (tcp_start + 4) as u8;
        self.ack_offset = (tcp_start + 8) as u8;
        self.window_offset = (tcp_start + 14) as u8;
        self.tcp_cksum_offset = (tcp_start + 16) as u8;

        self.template_len = 54; // 14 + 20 + 20
        self.conn_id = conn_id;
        self.valid = true;
        self.hits = 0;
    }

    /// 動的フィールドを更新してヘッダバイト列を取得
    ///
    /// `output` にテンプレートをコピーし、動的フィールドを上書きする。
    /// 戻り値: ヘッダバイト数
    pub fn stamp(
        &mut self,
        output: &mut [u8],
        seq: u32,
        ack: u32,
        flags: u8,
        window: u16,
        ip_total_len: u16,
        ip_id: u16,
        current_tsc: u64,
    ) -> Option<usize> {
        if !self.valid {
            return None;
        }
        let len = self.template_len as usize;
        if output.len() < len {
            return None;
        }

        // テンプレートをコピー（1回のmemcpy）
        output[..len].copy_from_slice(&self.template[..len]);

        // 動的フィールドを上書き
        let so = self.seq_offset as usize;
        output[so..so + 4].copy_from_slice(&seq.to_be_bytes());

        let ao = self.ack_offset as usize;
        output[ao..ao + 4].copy_from_slice(&ack.to_be_bytes());

        // TCP flags
        let flags_offset = self.seq_offset as usize - 4 + 12 + 1; // tcp_start + 13
        output[flags_offset] = flags;

        let wo = self.window_offset as usize;
        output[wo..wo + 2].copy_from_slice(&window.to_be_bytes());

        let ito = self.ip_total_len_offset as usize;
        output[ito..ito + 2].copy_from_slice(&ip_total_len.to_be_bytes());

        let iio = self.ip_id_offset as usize;
        output[iio..iio + 2].copy_from_slice(&ip_id.to_be_bytes());

        // IPv4 ヘッダチェックサム再計算
        let ip_start = self.eth_len as usize;
        let ip_end = ip_start + self.ip_len as usize;
        // チェックサムフィールドをクリア
        let ico = self.ip_cksum_offset as usize;
        output[ico] = 0;
        output[ico + 1] = 0;
        let cksum = internet_checksum(&output[ip_start..ip_end]);
        output[ico..ico + 2].copy_from_slice(&cksum.to_be_bytes());

        // TCP チェックサムプレースホルダ（呼び出し元で計算）
        let tco = self.tcp_cksum_offset as usize;
        output[tco] = 0;
        output[tco + 1] = 0;

        self.last_access = current_tsc;
        self.hits += 1;

        Some(len)
    }

    /// ヘッダ長を取得
    #[inline]
    pub fn header_len(&self) -> usize {
        self.template_len as usize
    }

    /// 有効かどうか
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.valid
    }

    /// ヒット回数
    #[inline]
    pub fn hits(&self) -> u64 {
        self.hits
    }

    /// 無効化
    pub fn invalidate(&mut self) {
        self.valid = false;
    }
}

/// ヘッダキャッシュ
///
/// 2-wayセットアソシエイティブ方式 (32セット × 2ウェイ)。
/// ダイレクトマップと比較してハッシュ衝突時のエヴィクション率を大幅に低減。
/// 同一セット内ではLRU（last_access比較）で犠牲エントリを選択する。
pub struct HeaderCache {
    entries: [CachedHeader; HEADER_CACHE_SIZE],
    /// キャッシュヒット数
    hits: AtomicU64,
    /// キャッシュミス数
    misses: AtomicU64,
    /// エヴィクション数
    evictions: AtomicU64,
}

impl HeaderCache {
    /// 新しいヘッダキャッシュを作成
    pub const fn new() -> Self {
        const EMPTY: CachedHeader = CachedHeader::empty();
        Self {
            entries: [EMPTY; HEADER_CACHE_SIZE],
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
        }
    }

    /// セットの開始インデックスを計算
    #[inline]
    fn set_base(conn_id: ConnId) -> usize {
        ((conn_id.hash() as usize) % HEADER_CACHE_SETS) * HEADER_CACHE_WAYS
    }

    /// コネクション用のキャッシュエントリを検索（2-way）
    pub fn lookup(&mut self, conn_id: ConnId, current_tsc: u64) -> Option<&mut CachedHeader> {
        let base = Self::set_base(conn_id);

        for way in 0..HEADER_CACHE_WAYS {
            let idx = base + way;
            if self.entries[idx].valid && self.entries[idx].conn_id == conn_id {
                self.hits.fetch_add(1, Ordering::Relaxed);
                self.entries[idx].last_access = current_tsc;
                return Some(&mut self.entries[idx]);
            }
        }

        self.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// エントリを挿入（2-way LRU選択）
    ///
    /// 空きウェイがあればそこに挿入。なければLRU（最古アクセス）を犠牲にする。
    pub fn insert(&mut self, conn_id: ConnId) -> &mut CachedHeader {
        let base = Self::set_base(conn_id);

        // まず空きウェイを探す
        for way in 0..HEADER_CACHE_WAYS {
            let idx = base + way;
            if !self.entries[idx].valid {
                self.entries[idx] = CachedHeader::empty();
                self.entries[idx].conn_id = conn_id;
                return &mut self.entries[idx];
            }
        }

        // 空きなし → LRU犠牲を選択（last_accessが最小のウェイ）
        let mut victim_way = 0;
        let mut min_access = self.entries[base].last_access;
        for way in 1..HEADER_CACHE_WAYS {
            let idx = base + way;
            if self.entries[idx].last_access < min_access {
                min_access = self.entries[idx].last_access;
                victim_way = way;
            }
        }

        let victim_idx = base + victim_way;
        if self.entries[victim_idx].valid && self.entries[victim_idx].conn_id != conn_id {
            self.evictions.fetch_add(1, Ordering::Relaxed);
        }

        self.entries[victim_idx] = CachedHeader::empty();
        self.entries[victim_idx].conn_id = conn_id;
        &mut self.entries[victim_idx]
    }

    /// エントリを無効化（2-way検索）
    pub fn invalidate(&mut self, conn_id: ConnId) {
        let base = Self::set_base(conn_id);
        for way in 0..HEADER_CACHE_WAYS {
            let idx = base + way;
            if self.entries[idx].valid && self.entries[idx].conn_id == conn_id {
                self.entries[idx].invalidate();
                return;
            }
        }
    }

    /// キャッシュ統計
    pub fn stats(&self) -> HeaderCacheStats {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        HeaderCacheStats {
            hits,
            misses,
            evictions: self.evictions.load(Ordering::Relaxed),
            hit_rate_percent: if hits + misses > 0 {
                (hits * 100) / (hits + misses)
            } else {
                0
            },
        }
    }

    /// 全エントリを無効化
    pub fn flush(&mut self) {
        for entry in &mut self.entries {
            entry.invalidate();
        }
    }
}

/// ヘッダキャッシュ統計
#[derive(Debug, Clone)]
pub struct HeaderCacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub hit_rate_percent: u64,
}

// ============================================================================
// ユーティリティ
// ============================================================================
// ip_checksum は checksum_offload::internet_checksum に統合済み

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conn_id_consistency() {
        let id1 = ConnId::from_5tuple(0x0A000001, 0x0A000002, 8080, 80, 6);
        let id2 = ConnId::from_5tuple(0x0A000001, 0x0A000002, 8080, 80, 6);
        let id3 = ConnId::from_5tuple(0x0A000001, 0x0A000003, 8080, 80, 6); // different dst

        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_header_cache_hit_miss() {
        let mut cache = HeaderCache::new();
        let conn_id = ConnId::from_5tuple(0x0A000001, 0x0A000002, 8080, 80, 6);

        // Miss
        assert!(cache.lookup(conn_id, 0).is_none());

        // Insert
        let entry = cache.insert(conn_id);
        entry.init_ipv4_tcp(
            conn_id,
            &[0xFF; 6],
            &[0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            8080,
            80,
            64,
        );

        // Hit
        assert!(cache.lookup(conn_id, 100).is_some());
    }

    #[test]
    fn test_header_stamp() {
        let mut cache = HeaderCache::new();
        let conn_id = ConnId::from_5tuple(0x0A000001, 0x0A000002, 8080, 80, 6);

        let entry = cache.insert(conn_id);
        entry.init_ipv4_tcp(
            conn_id,
            &[0xFF; 6],
            &[0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            8080,
            80,
            64,
        );

        let entry = cache.lookup(conn_id, 0).unwrap();
        let mut output = [0u8; 128];
        let len = entry
            .stamp(
                &mut output,
                1000,  // seq
                2000,  // ack
                0x18,  // flags (PSH+ACK)
                65535, // window
                60,    // ip_total_len
                42,    // ip_id
                12345, // current_tsc
            )
            .unwrap();

        assert_eq!(len, 54); // 14 + 20 + 20

        // Verify seq in output (offset 38 = 14 + 20 + 4)
        let seq = u32::from_be_bytes([output[38], output[39], output[40], output[41]]);
        assert_eq!(seq, 1000);
    }
}
