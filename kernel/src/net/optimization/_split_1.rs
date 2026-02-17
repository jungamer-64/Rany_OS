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

    /// タイムアウトしたセグメントをフラッシュ
    pub fn flush_aged(&mut self, current_tsc: u64) -> Vec<GroSegment> {
        let mut flushed = Vec::new();

        for slot in self.segments.iter_mut() {
            let should_flush = slot
                .as_ref()
                .map(|segment| current_tsc - segment.timestamp > self.max_age_tsc)
                .unwrap_or(false);

            if should_flush {
                if let Some(seg) = slot.take() {
                    self.count -= 1;
                    flushed.push(seg);
                }
            }
        }

        flushed
    }

    fn take_segment(&mut self, flow_hash: u32) -> Option<GroSegment> {
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
