// ============================================================================
// drivers/mlx5/src/eq.rs - Event Queue
// ============================================================================
//! Event Queue (EQ) — MSI-X割り込みに紐づくイベント通知キュー
//!
//! EQはHWからSWへイベントを通知するためのリングバッファ。
//! 各EQは1つのMSI-Xベクタに対応し、CQ完了、ポート状態変更、
//! ページ要求などのイベントを配信する。

use crate::defs::EventType;
use crate::regs::eqe;

/// Event Queue Entry (EQE) — 64バイト
#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct Eqe {
    pub data: [u8; eqe::EQE_SIZE],
}

impl Eqe {
    pub const fn zeroed() -> Self {
        Self {
            data: [0u8; eqe::EQE_SIZE],
        }
    }

    /// イベントタイプを取得
    pub fn event_type(&self) -> Option<EventType> {
        EventType::from_u8(self.data[eqe::TYPE])
    }

    /// サブタイプを取得
    pub fn subtype(&self) -> u8 {
        self.data[eqe::SUBTYPE]
    }

    /// CQ番号を取得（CQ完了イベント時）
    pub fn cq_number(&self) -> u32 {
        u32::from_be_bytes([
            0,
            self.data[eqe::CQ_NUMBER],
            self.data[eqe::CQ_NUMBER + 1],
            self.data[eqe::CQ_NUMBER + 2],
        ])
    }

    /// ポート番号を取得（ポートイベント時）
    pub fn port_number(&self) -> u8 {
        self.data[eqe::PORT_NUMBER]
    }

    /// オーナービット（cycle bit）を取得
    ///
    /// - true: SWが所有（読み取り可能）
    /// - false: HWが所有（まだ書き込まれていない）
    pub fn is_sw_owned(&self, consumer_counter: u32, log_eq_size: u8) -> bool {
        let own_bit = self.data[eqe::STATUS_OWN] & 0x01;
        let expected = ((consumer_counter >> log_eq_size) & 1) as u8;
        own_bit == expected
    }

    /// ページ要求イベント: 要求ページ数
    pub fn requested_pages(&self) -> u32 {
        u32::from_be_bytes([
            self.data[eqe::NUM_PAGES],
            self.data[eqe::NUM_PAGES + 1],
            self.data[eqe::NUM_PAGES + 2],
            self.data[eqe::NUM_PAGES + 3],
        ])
    }

    /// ページ要求イベント: 関数ID
    pub fn function_id(&self) -> u16 {
        u16::from_be_bytes([self.data[eqe::FUNC_ID], self.data[eqe::FUNC_ID + 1]])
    }
}

/// Event Queue 管理構造体
///
/// EQリングバッファとコンシューマインデックスを管理する。
pub struct EventQueue {
    doorbell: crate::registers::EqDoorbell,
    /// EQのハードウェア番号（CREATE_EQで返される）
    pub eqn: u32,
    /// EQバッファの仮想アドレス
    buf_virt: u64,
    /// EQバッファの物理アドレス
    buf_phys: u64,
    /// ログ2 EQサイズ
    log_eq_size: u8,
    /// コンシューマカウンタ
    consumer_counter: u32,
    /// EQエントリ数
    eq_depth: u32,
    /// 紐づくMSI-Xベクタ番号
    pub msix_vector: u32,
}



/// EQイベント処理結果
#[derive(Debug)]
pub enum EqEvent {
    /// CQ完了イベント（CQ番号）
    CqCompletion(u32),
    /// ポート状態変更（ポート番号）
    PortStateChange(u8),
    /// コマンド完了
    CommandCompletion,
    /// ページ要求（関数ID, ページ数）
    PageRequest(u16, u32),
    /// 不明なイベント
    Unknown(u8),
}

/// EQEからイベント情報を抽出
pub fn decode_eqe(eqe: &Eqe) -> EqEvent {
    match eqe.event_type() {
        Some(EventType::CompletionEvent) => EqEvent::CqCompletion(eqe.cq_number()),
        Some(EventType::PortStateChange) => EqEvent::PortStateChange(eqe.port_number()),
        Some(EventType::CommandCompletion) => EqEvent::CommandCompletion,
        Some(EventType::PageRequest) => {
            EqEvent::PageRequest(eqe.function_id(), eqe.requested_pages())
        }
        _ => EqEvent::Unknown(eqe.data[eqe::TYPE]),
    }
}
