use super::*;

pub(crate) const GRO_TABLE_SIZE: usize = 16;
pub(crate) const GRO_MAX_PACKETS: u16 = 64;

impl GroTable {
    pub const fn new() -> Self {
        const NONE: Option<GroSegment> = None;
        Self {
            segments: [NONE; GRO_TABLE_SIZE],
            count: 0,
            max_age_tsc: 0,
        }
    }

    /// パケットをGRO処理
    ///
    /// # Safety
    /// `buffer`は有効なメモリを指している必要があります
    pub unsafe fn process(
        &mut self,
        buffer: *mut u8,
        len: u16,
        flow_hash: u32,
        seq: u32,
        current_tsc: u64,
    ) -> Option<GroSegment> {
        // 既存セグメントを検索
        for segment in self.segments.iter_mut().flatten() {
            if segment.flow_hash == flow_hash && segment.next_seq == seq {
                // 結合可能
                segment.total_len += len as u32;
                segment.packet_count += 1;
                segment.next_seq = seq.wrapping_add(len as u32);

                if segment.packet_count >= GRO_MAX_PACKETS {
                    // 最大サイズに達した - フラッシュ
                    return self.take_segment(flow_hash);
                }
                return None;
            }
        }

        // 新しいセグメントを作成
        if self.count < GRO_TABLE_SIZE {
            let new_segment = GroSegment {
                head: buffer as usize,
                total_len: len as u32,
                packet_count: 1,
                flow_hash,
                seq,
                next_seq: seq.wrapping_add(len as u32),
                timestamp: current_tsc,
            };

            for slot in self.segments.iter_mut() {
                if slot.is_none() {
                    *slot = Some(new_segment);
                    self.count += 1;
                    break;
                }
            }
        }

        None
    }

    /// タイムアウトしたセグメントをフラッシュ（ゼロアロケーション版）
    ///
    /// 固定配列を使用し、動的メモリ割り当てを回避する。
    /// 戻り値は `(配列, 有効エントリ数)` のタプル。
    pub fn flush_aged(
        &mut self,
        current_tsc: u64,
    ) -> ([Option<GroSegment>; GRO_TABLE_SIZE], usize) {
        const NONE: Option<GroSegment> = None;
        let mut flushed = [NONE; GRO_TABLE_SIZE];
        let mut flushed_count = 0;

        for slot in self.segments.iter_mut() {
            let should_flush = slot
                .as_ref()
                .map(|segment| current_tsc - segment.timestamp > self.max_age_tsc)
                .unwrap_or(false);

            if should_flush {
                if let Some(seg) = slot.take() {
                    self.count -= 1;
                    flushed[flushed_count] = Some(seg);
                    flushed_count += 1;
                }
            }
        }

        (flushed, flushed_count)
    }

    pub(super) fn take_segment(&mut self, flow_hash: u32) -> Option<GroSegment> {
        for slot in self.segments.iter_mut() {
            let matches = slot
                .as_ref()
                .map(|segment| segment.flow_hash == flow_hash)
                .unwrap_or(false);

            if matches {
                self.count -= 1;
                return slot.take();
            }
        }
        None
    }
}

// ============================================================================
// TSO - TCP Segmentation Offload (ソフトウェアエミュレーション)
// ============================================================================

/// TSOコンテキスト
pub struct TsoContext {
    /// MSS (Maximum Segment Size)
    pub mss: u16,
    /// 送信バッファ（usizeとして保持）
    pub buffer: usize,
    /// 総データサイズ
    pub total_len: u32,
    /// 現在のオフセット
    pub offset: u32,
    /// 送信済みセグメント数
    pub segments_sent: u32,
}

// Safety: TsoContextはunsafe操作でのみアクセスされ、適切に同期される
unsafe impl Send for TsoContext {}
unsafe impl Sync for TsoContext {}

impl TsoContext {
    /// TSOセグメントを生成
    ///
    /// # Safety
    /// `buffer`は有効なメモリを指している必要があります
    pub unsafe fn new(buffer: *mut u8, total_len: u32, mss: u16) -> Self {
        Self {
            mss,
            buffer: buffer as usize,
            total_len,
            offset: 0,
            segments_sent: 0,
        }
    }

    /// 次のセグメントを取得
    pub fn next_segment(&mut self) -> Option<(*mut u8, u16)> {
        if self.offset >= self.total_len {
            return None;
        }

        let remaining = self.total_len - self.offset;
        let seg_len = core::cmp::min(remaining, self.mss as u32) as u16;

        let ptr = unsafe { (self.buffer as *mut u8).add(self.offset as usize) };
        self.offset += seg_len as u32;
        self.segments_sent += 1;

        Some((ptr, seg_len))
    }

    /// 残りセグメント数
    pub fn remaining_segments(&self) -> u32 {
        if self.offset >= self.total_len {
            return 0;
        }
        let remaining = self.total_len - self.offset;
        (remaining + self.mss as u32 - 1) / self.mss as u32
    }
}

// ============================================================================
// TSO Engine - TCP Segmentation Offload エンジン
// ============================================================================
//
// ソフトウェアTSOエンジン: 大きなTCPペイロードをMSSサイズのセグメントに分割し、
// 各セグメントに適切なTCP/IPv4ヘッダを付与して送信する。
// ハードウェアTSOが利用不可の場合のフォールバック。

/// TSO分割ヘッダテンプレート
///
/// 送信側がTCPヘッダ情報を指定し、エンジンがセグメントごとに
/// シーケンス番号とチェックサムを更新する。
#[derive(Debug, Clone, Copy)]
pub struct TsoHeaderTemplate {
    /// 送信元IPv4アドレス (ネットワークバイトオーダー)
    pub src_ip: [u8; 4],
    /// 宛先IPv4アドレス (ネットワークバイトオーダー)
    pub dst_ip: [u8; 4],
    /// 送信元ポート
    pub src_port: u16,
    /// 宛先ポート
    pub dst_port: u16,
    /// 初期シーケンス番号
    pub seq_start: u32,
    /// ACK番号
    pub ack_num: u32,
    /// TCPフラグ (PSH, ACKなど)
    pub flags: u8,
    /// ウィンドウサイズ
    pub window: u16,
    /// IPv4 identification の初期値
    pub ip_id_start: u16,
    /// TTL (Time To Live)
    pub ttl: u8,
}

/// TSO分割結果 — 1セグメント分のメタデータ
#[derive(Debug, Clone, Copy)]
pub struct TsoSegmentInfo {
    /// このセグメントのデータオフセット (元バッファ内)
    pub data_offset: u32,
    /// このセグメントのデータ長
    pub data_len: u16,
    /// このセグメントのTCPシーケンス番号
    pub seq: u32,
    /// IPv4 identification
    pub ip_id: u16,
    /// 最終セグメントか (PSHフラグ付与)
    pub is_last: bool,
}

/// TCPソフトウェアTSOエンジン
///
/// 大きなペイロードをMSSに分割し、個別のセグメント情報を生成する。
/// 実際のパケット構築は呼び出し元が行う（ゼロコピー設計）。
pub struct TsoEngine {
    /// MSS (Maximum Segment Size)
    mss: u16,
    /// ヘッダテンプレート
    template: TsoHeaderTemplate,
    /// 総データ長
    total_len: u32,
    /// 現在のオフセット
    offset: u32,
    /// 生成セグメント数
    segments_generated: u32,
}

impl TsoEngine {
    /// 新しいTSOエンジンを作成
    pub fn new(template: TsoHeaderTemplate, total_len: u32, mss: u16) -> Self {
        Self {
            mss,
            template,
            total_len,
            offset: 0,
            segments_generated: 0,
        }
    }

    /// 次のセグメント情報を取得
    ///
    /// 呼び出し元はこの情報を使ってパケットバッファにヘッダ+データを書き込む。
    pub fn next_segment_info(&mut self) -> Option<TsoSegmentInfo> {
        if self.offset >= self.total_len {
            return None;
        }

        let remaining = self.total_len - self.offset;
        let seg_len = core::cmp::min(remaining, self.mss as u32) as u16;
        let is_last = self.offset + seg_len as u32 >= self.total_len;

        let info = TsoSegmentInfo {
            data_offset: self.offset,
            data_len: seg_len,
            seq: self.template.seq_start.wrapping_add(self.offset),
            ip_id: self
                .template
                .ip_id_start
                .wrapping_add(self.segments_generated as u16),
            is_last,
        };

        self.offset += seg_len as u32;
        self.segments_generated += 1;

        Some(info)
    }

    /// セグメントをバッファに書き込む
    ///
    /// `output` はEthernetヘッダの直後から始まるバッファ。
    /// IPv4ヘッダ(20) + TCPヘッダ(20) + データ を書き込む。
    /// `payload` はTCPペイロード全体。
    ///
    /// 戻り値: 書き込んだ総バイト数 (IPv4+TCP+データ)
    pub fn write_segment(
        &self,
        output: &mut [u8],
        payload: &[u8],
        info: &TsoSegmentInfo,
    ) -> Option<usize> {
        let ip_hdr_len = 20usize;
        let tcp_hdr_len = 20usize;
        let total_needed = ip_hdr_len + tcp_hdr_len + info.data_len as usize;

        if output.len() < total_needed {
            return None;
        }

        let data_start = info.data_offset as usize;
        let data_end = data_start + info.data_len as usize;
        if data_end > payload.len() {
            return None;
        }

        // --- IPv4 Header (20 bytes) ---
        let ip_total_len = (ip_hdr_len + tcp_hdr_len + info.data_len as usize) as u16;
        output[0] = 0x45; // Version=4, IHL=5
        output[1] = 0x00; // DSCP/ECN
        output[2..4].copy_from_slice(&ip_total_len.to_be_bytes());
        output[4..6].copy_from_slice(&info.ip_id.to_be_bytes());
        output[6] = 0x40; // Don't Fragment
        output[7] = 0x00;
        output[8] = self.template.ttl;
        output[9] = 6; // TCP protocol
        output[10..12].copy_from_slice(&[0, 0]); // checksum placeholder
        output[12..16].copy_from_slice(&self.template.src_ip);
        output[16..20].copy_from_slice(&self.template.dst_ip);

        // IPv4 header checksum
        let ip_cksum = internet_checksum(&output[..ip_hdr_len]);
        output[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

        // --- TCP Header (20 bytes) ---
        let tcp_start = ip_hdr_len;
        output[tcp_start..tcp_start + 2].copy_from_slice(&self.template.src_port.to_be_bytes());
        output[tcp_start + 2..tcp_start + 4].copy_from_slice(&self.template.dst_port.to_be_bytes());
        output[tcp_start + 4..tcp_start + 8].copy_from_slice(&info.seq.to_be_bytes());
        output[tcp_start + 8..tcp_start + 12].copy_from_slice(&self.template.ack_num.to_be_bytes());
        // Data offset = 5 (20/4), reserved, flags
        let data_offset_byte = 0x50u8; // 5 << 4
        output[tcp_start + 12] = data_offset_byte;
        // Flags: 最終セグメントならPSH+ACK、それ以外はACKのみ
        let flags = if info.is_last {
            self.template.flags | 0x08 // PSH
        } else {
            self.template.flags & !0x08 // clear PSH
        };
        output[tcp_start + 13] = flags;
        output[tcp_start + 14..tcp_start + 16].copy_from_slice(&self.template.window.to_be_bytes());
        output[tcp_start + 16..tcp_start + 18].copy_from_slice(&[0, 0]); // checksum placeholder
        output[tcp_start + 18..tcp_start + 20].copy_from_slice(&[0, 0]); // urgent pointer

        // --- Payload ---
        let payload_start = ip_hdr_len + tcp_hdr_len;
        output[payload_start..payload_start + info.data_len as usize]
            .copy_from_slice(&payload[data_start..data_end]);

        // TCP checksum (with pseudo header)
        let tcp_len = (tcp_hdr_len + info.data_len as usize) as u16;
        let tcp_cksum = Self::tcp_checksum(
            &self.template.src_ip,
            &self.template.dst_ip,
            &output[tcp_start..tcp_start + tcp_hdr_len + info.data_len as usize],
            tcp_len,
        );
        output[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_cksum.to_be_bytes());

        Some(total_needed)
    }

    /// 残りセグメント数
    pub fn remaining_segments(&self) -> u32 {
        if self.offset >= self.total_len {
            return 0;
        }
        let remaining = self.total_len - self.offset;
        (remaining + self.mss as u32 - 1) / self.mss as u32
    }

    /// 生成済みセグメント数
    pub fn segments_generated(&self) -> u32 {
        self.segments_generated
    }

    /// 総セグメント数を計算
    pub fn total_segments(&self) -> u32 {
        if self.total_len == 0 {
            return 0;
        }
        (self.total_len + self.mss as u32 - 1) / self.mss as u32
    }

    /// IPv4ヘッダチェックサム計算 — checksum_offload::internet_checksum に統合済み

    /// TCPチェックサム計算 (疑似ヘッダ含む)
    fn tcp_checksum(src_ip: &[u8; 4], dst_ip: &[u8; 4], tcp_data: &[u8], tcp_len: u16) -> u16 {
        let mut sum: u32 = 0;

        // Pseudo-header
        sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
        sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
        sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
        sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
        sum += 6u32; // TCP protocol number
        sum += tcp_len as u32;

        // TCP header + data
        let mut i = 0;
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while i + 1 < tcp_data.len() {
            let word = u16::from_be_bytes([tcp_data[i], tcp_data[i + 1]]);
            sum += word as u32;
            i += 2;
        }
        if i < tcp_data.len() {
            sum += (tcp_data[i] as u32) << 8;
        }

        // Fold carry
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }
}

// ============================================================================
// Performance Metrics
// ============================================================================

/// ネットワーク性能メトリクス
#[derive(Debug, Default)]
pub struct NetworkMetrics {
    /// 受信パケット数
    pub rx_packets: AtomicU64,
    /// 送信パケット数
    pub tx_packets: AtomicU64,
    /// 受信バイト数
    pub rx_bytes: AtomicU64,
    /// 送信バイト数
    pub tx_bytes: AtomicU64,
    /// 受信ドロップ数
    pub rx_drops: AtomicU64,
    /// 送信ドロップ数
    pub tx_drops: AtomicU64,
    /// 受信エラー数
    pub rx_errors: AtomicU64,
    /// 送信エラー数
    pub tx_errors: AtomicU64,
    /// GROマージ数
    pub gro_merges: AtomicU64,
    /// TSOセグメント数
    pub tso_segments: AtomicU64,
    /// バッチ処理数
    pub batched_packets: AtomicU64,
}

impl NetworkMetrics {
    pub const fn new() -> Self {
        Self {
            rx_packets: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_drops: AtomicU64::new(0),
            tx_drops: AtomicU64::new(0),
            rx_errors: AtomicU64::new(0),
            tx_errors: AtomicU64::new(0),
            gro_merges: AtomicU64::new(0),
            tso_segments: AtomicU64::new(0),
            batched_packets: AtomicU64::new(0),
        }
    }

    /// パケットスループット (pps) を計算
    pub fn calculate_pps(&self, elapsed_secs: f64) -> (f64, f64) {
        let rx_pps = self.rx_packets.load(Ordering::Relaxed) as f64 / elapsed_secs;
        let tx_pps = self.tx_packets.load(Ordering::Relaxed) as f64 / elapsed_secs;
        (rx_pps, tx_pps)
    }

    /// バイトスループット (bps) を計算
    pub fn calculate_bps(&self, elapsed_secs: f64) -> (f64, f64) {
        let rx_bps = self.rx_bytes.load(Ordering::Relaxed) as f64 * 8.0 / elapsed_secs;
        let tx_bps = self.tx_bytes.load(Ordering::Relaxed) as f64 * 8.0 / elapsed_secs;
        (rx_bps, tx_bps)
    }

    /// メトリクスをリセット
    pub fn reset(&self) {
        self.rx_packets.store(0, Ordering::Relaxed);
        self.tx_packets.store(0, Ordering::Relaxed);
        self.rx_bytes.store(0, Ordering::Relaxed);
        self.tx_bytes.store(0, Ordering::Relaxed);
        self.rx_drops.store(0, Ordering::Relaxed);
        self.tx_drops.store(0, Ordering::Relaxed);
        self.rx_errors.store(0, Ordering::Relaxed);
        self.tx_errors.store(0, Ordering::Relaxed);
        self.gro_merges.store(0, Ordering::Relaxed);
        self.tso_segments.store(0, Ordering::Relaxed);
        self.batched_packets.store(0, Ordering::Relaxed);
    }
}

// ============================================================================
// Global instances
// ============================================================================

pub(crate) static BATCH_PROCESSOR: spin::Once<BatchProcessor> = spin::Once::new();
pub(crate) static NUMA_TOPOLOGY: spin::Once<NumaTopology> = spin::Once::new();
pub(crate) static FLOW_AFFINITY: spin::Once<FlowAffinity> = spin::Once::new();
pub(crate) static ADAPTIVE_COALESCING: spin::Once<AdaptiveCoalescing> = spin::Once::new();
pub(crate) static NETWORK_METRICS: NetworkMetrics = NetworkMetrics::new();

/// ネットワーク最適化を初期化
///
/// # Note
/// この関数は起動時に1回だけ呼ばれるため、unwrap()のコストは許容される。
/// ただし、expect()で明示的なエラーメッセージを提供。
pub fn init() {
    BATCH_PROCESSOR.call_once(|| BatchProcessor::new(BatchConfig::default()));
    NUMA_TOPOLOGY.call_once(NumaTopology::detect);

    // expect() で明示的なエラーメッセージを提供
    // init() は起動時のみなので panic ブランチのコストは許容される
    let topology = NUMA_TOPOLOGY
        .get()
        .expect("NUMA topology must be initialized");
    FLOW_AFFINITY.call_once(|| FlowAffinity::new(CpuAffinity::all()));

    ADAPTIVE_COALESCING.call_once(|| AdaptiveCoalescing::new(InterruptCoalescing::default()));

    // Per-CPU バッチプロセッサの初期化
    let cpu_count = crate::smp::cpu_count().max(1) as usize;
    super::super::per_cpu_batch::init(cpu_count);

    let _ = topology; // avoid unused warning
}

/// バッチプロセッサを取得
pub fn batch_processor() -> Option<&'static BatchProcessor> {
    BATCH_PROCESSOR.get()
}

/// NUMAトポロジーを取得
pub fn numa_topology() -> Option<&'static NumaTopology> {
    NUMA_TOPOLOGY.get()
}

/// フローアフィニティを取得
pub fn flow_affinity() -> Option<&'static FlowAffinity> {
    FLOW_AFFINITY.get()
}

/// 適応型割り込み合体を取得
pub fn adaptive_coalescing() -> Option<&'static AdaptiveCoalescing> {
    ADAPTIVE_COALESCING.get()
}

/// グローバルメトリクスを取得
pub fn metrics() -> &'static NetworkMetrics {
    &NETWORK_METRICS
}
