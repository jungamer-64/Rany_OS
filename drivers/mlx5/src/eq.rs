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
    pub fn requested_pages(&self) -> i32 {
        i32::from_be_bytes([
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

/// An event ring owns its RAM through creation, destruction and failed unmap.
/// Polling produces a CPU snapshot only after observing the ownership byte.
pub struct EventQueue {
    pub(crate) grant: crate::queue_memory::QueueGrant,
    pub(crate) memory: crate::queue_memory::QueueMemory<1>,
    pub(crate) doorbell: crate::registers::EqDoorbell,
    pub(crate) log_eq_size: u8,
    consumer_counter: u32,
    pub msix_vector: u32,
}

impl EventQueue {
    pub(crate) fn new(
        identity: kernel_api::dma::DmaQueueIdentity,
        lease: kernel_api::dma::CpuDmaLease,
        doorbell: crate::registers::EqDoorbell,
        log_eq_size: u8,
        msix_vector: u32,
    ) -> Self {
        Self {
            grant: crate::queue_memory::QueueGrant::Unpublished,
            memory: crate::queue_memory::QueueMemory::new(identity, [lease]),
            doorbell,
            log_eq_size,
            consumer_counter: 0,
            msix_vector,
        }
    }

    /// Firmware identity is available only while normal queue access is allowed.
    pub fn number(&self) -> Option<u32> {
        self.grant.number()
    }

    pub(crate) fn prepare(&mut self) -> crate::error::Mlx5Result<()> {
        let bytes = (1usize << self.log_eq_size) * eqe::EQE_SIZE;
        self.memory.prepare(
            [crate::queue_memory::RegionLayout {
                bytes,
                direction: kernel_api::dma::DmaDirection::FromDevice,
                alignment: crate::defs::MLX5_PAGE_SIZE,
            }],
            |_, region| {
                region.fill(0);
                for entry in region[..bytes].as_chunks_mut::<{ eqe::EQE_SIZE }>().0 {
                    entry[eqe::STATUS_OWN] = 1;
                }
            },
        )
    }

    pub(crate) fn depth(&self) -> u32 {
        1u32 << self.log_eq_size
    }

    /// Each successful read consumes one EQE. Hardware cannot reuse its slot
    /// until acknowledge publishes the updated consumer counter.
    pub(crate) fn next(&mut self) -> crate::error::Mlx5Result<Option<Eqe>> {
        if self.number().is_none() {
            return Err(crate::error::Mlx5Error::DeviceNotReady);
        }
        let offset = (self.consumer_counter % self.depth()) as usize * eqe::EQE_SIZE;
        let owner = self.memory.read_byte(0, offset + eqe::STATUS_OWN)? & 1;
        let expected = ((self.consumer_counter >> self.log_eq_size) & 1) as u8;
        if owner != expected {
            return Ok(None);
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
        let entry = Eqe {
            data: self.memory.read(0, offset)?,
        };
        self.consumer_counter = self.consumer_counter.wrapping_add(1);
        Ok(Some(entry))
    }

    pub(crate) fn acknowledge(&mut self) -> crate::error::Mlx5Result<()> {
        let number = self
            .number()
            .ok_or(crate::error::Mlx5Error::DeviceNotReady)?;
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        self.doorbell.acknowledge(number, self.consumer_counter);
        Ok(())
    }
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
    PageRequest(u16, i32),
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
