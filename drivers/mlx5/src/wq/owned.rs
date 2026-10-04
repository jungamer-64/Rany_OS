//! Work queue RAM and descriptor publication. Packet backing is retained by
//! the netdev submission owner; these queues never dereference packet addresses.
//! A failed doorbell store retains the posted counter until hardware retirement.

use super::*;
use crate::error::{Mlx5Error, Mlx5Result, WorkSubmissionError};
use crate::queue_memory::{QueueGrant, QueueMemory, RegionLayout};
use alloc::vec::Vec;
use kernel_api::dma::{CpuDmaLease, DmaDirection, DmaQueueIdentity};

struct SendSlot {
    counter: u16,
    descriptor: [u8; MLX5_SQ_STRIDE],
}

/// Firmware lifecycle owns descriptor RAM even before successful creation.
pub struct SendQueue {
    pub(crate) memory: QueueMemory<2>,
    pub(crate) grant: QueueGrant,
    doorbell: crate::registers::SqDoorbell,
    depth: u32,
    producer: u16,
    pub(crate) cqn: u32,
    pub(crate) tisn: u32,
    mkey: u32,
    checksum: bool,
    ready: bool,
    pending: Vec<Option<SendSlot>>,
    last_descriptor: Option<SendSlot>,
}

/// Metadata admission precedes transfer of DMA capabilities and hardware effects.
pub(crate) struct SendStorage(Vec<Option<SendSlot>>);
impl SendStorage {
    pub(crate) fn reserve(log_size: u8) -> Mlx5Result<Self> {
        let depth = checked_depth(log_size)?;
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(depth as usize)
            .map_err(|_| Mlx5Error::OutOfMemory)?;
        slots.resize_with(depth as usize, || None);
        Ok(Self(slots))
    }
}

fn checked_depth(log_size: u8) -> Mlx5Result<u32> {
    // One u16 hardware counter must name every distinct active slot.
    if log_size > 16 {
        return Err(Mlx5Error::InvalidParameter);
    }
    Ok(1u32 << log_size)
}

impl SendQueue {
    pub(crate) fn new(
        identity: DmaQueueIdentity,
        leases: [CpuDmaLease; 2],
        doorbell: crate::registers::SqDoorbell,
        storage: SendStorage,
        cqn: u32,
        mkey: u32,
        checksum: bool,
    ) -> Self {
        Self {
            memory: QueueMemory::new(identity, leases),
            grant: QueueGrant::Unpublished,
            doorbell,
            depth: storage.0.len() as u32,
            producer: 0,
            cqn,
            tisn: 0,
            mkey,
            checksum,
            ready: false,
            pending: storage.0,
            last_descriptor: None,
        }
    }

    pub(crate) fn prepare(&mut self) -> Mlx5Result<()> {
        self.memory.prepare(
            [
                RegionLayout {
                    bytes: self.depth as usize * MLX5_SQ_STRIDE,
                    direction: DmaDirection::ToDevice,
                    alignment: crate::defs::MLX5_PAGE_SIZE,
                },
                RegionLayout {
                    bytes: 8,
                    direction: DmaDirection::ToDevice,
                    alignment: 8,
                },
            ],
            |_, bytes| bytes.fill(0),
        )
    }

    pub(crate) fn accept_configuration(&mut self, tisn: u32) {
        self.tisn = tisn;
        self.ready = true;
    }

    pub(crate) fn number(&self) -> Option<u32> {
        self.grant.number()
    }

    pub(crate) fn post_send(
        &mut self,
        segments: &[DmaSegment],
        options: TxOptions,
    ) -> Result<u16, WorkSubmissionError> {
        let number = self
            .number()
            .filter(|_| self.ready)
            .ok_or(WorkSubmissionError::NotPublished(Mlx5Error::DeviceNotReady))?;
        let counter = self.producer;
        let slot = counter as usize % self.depth as usize;
        if self.pending[slot].is_some() {
            return Err(WorkSubmissionError::NotPublished(Mlx5Error::NoResources));
        }
        let descriptor = encode_send(number, counter, self.mkey, self.checksum, segments, options)
            .map_err(WorkSubmissionError::NotPublished)?;
        self.memory
            .write(0, slot * MLX5_SQ_STRIDE, &descriptor)
            .map_err(WorkSubmissionError::NotPublished)?;
        // The packet owner retains its capability for an uncertain doorbell.
        self.pending[slot] = Some(SendSlot {
            counter,
            descriptor,
        });
        self.last_descriptor = Some(SendSlot {
            counter,
            descriptor,
        });
        self.producer = self.producer.wrapping_add(1);
        fence(Ordering::Release);
        self.memory
            .write_be32(1, 4, u32::from(self.producer))
            .map_err(|cause| WorkSubmissionError::OutcomeUnknown {
                counter,
                slot: slot as u16,
                cause,
            })?;
        hal::mmio::sfence();
        self.doorbell.publish_control_word(u64::from_ne_bytes(
            descriptor[..8].try_into().expect("fixed control word"),
        ));
        Ok(counter)
    }

    pub(crate) fn complete_tx(&mut self, counter: u16) -> Mlx5Result<()> {
        let slot = counter as usize % self.depth as usize;
        if self.pending[slot].as_ref().map(|record| record.counter) != Some(counter) {
            return Err(Mlx5Error::InvalidResponse);
        }
        self.pending[slot] = None;
        Ok(())
    }

    pub(crate) fn debug_wqe_state(&self, counter: u16) -> Option<TxWqeDebugInfo> {
        let slot = counter as usize % self.depth as usize;
        let record = self.pending[slot].as_ref().or_else(|| {
            self.last_descriptor
                .as_ref()
                .filter(|record| record.counter == counter)
        })?;
        if record.counter != counter {
            return None;
        }
        Some(send_snapshot(record, slot))
    }

    pub(crate) fn debug_state(&mut self) -> Mlx5Result<TxQueueDebugState> {
        let number = self.number().ok_or(Mlx5Error::DeviceNotReady)?;
        let counter = self.producer.wrapping_sub(1);
        let info = self.debug_wqe_state(counter).unwrap_or_default();
        let record = self.memory.read::<4>(1, 4)?;
        Ok(TxQueueDebugState {
            sqn: number,
            tisn: self.tisn,
            producer_counter: self.producer,
            sq_depth: self.depth,
            doorbell_be: u32::from_ne_bytes(record),
            doorbell_host: u32::from_be_bytes(record),
            last_wqe_counter: counter,
            last_wqe_offset: info.wqe_offset,
            last_wqe_opmod_idx: info.opmod_idx,
            last_wqe_qpn_ds: info.qpn_ds,
            last_wqe_general_id: info.general_id,
            last_wqe_byte_count: info.byte_count,
            last_wqe_lkey: info.lkey,
            last_wqe_device_addr: info.device_addr,
            last_bf_offset: 0,
            last_wqe_bytes: info.wqe_bytes,
        })
    }
}

fn send_snapshot(record: &SendSlot, slot: usize) -> TxWqeDebugInfo {
    let bytes = &record.descriptor;
    TxWqeDebugInfo {
        valid: true,
        wqe_counter: record.counter,
        wqe_offset: slot * MLX5_SQ_STRIDE,
        opmod_idx: be32(bytes, 0),
        qpn_ds: be32(bytes, 4),
        general_id: be32(bytes, 8),
        byte_count: be32(bytes, 32),
        lkey: be32(bytes, 36),
        device_addr: be64(bytes, 40),
        wqe_bytes: *bytes,
    }
}

fn encode_send(
    number: u32,
    counter: u16,
    mkey: u32,
    checksum: bool,
    segments: &[DmaSegment],
    options: TxOptions,
) -> Mlx5Result<[u8; MLX5_SQ_STRIDE]> {
    if segments.is_empty()
        || segments.len() > 2
        || number > 0x00ff_ffff
        || segments.iter().any(|segment| {
            segment.len == 0
                || segment.device_addr == 0
                || segment
                    .device_addr
                    .checked_add(u64::from(segment.len) - 1)
                    .is_none()
        })
    {
        return Err(Mlx5Error::InvalidParameter);
    }
    // These features require extra segment layout/capability admission.
    if options.mss != 0 || options.vlan_tag != 0 {
        return Err(Mlx5Error::NotSupported);
    }
    let mut bytes = [0; MLX5_SQ_STRIDE];
    put32(
        &mut bytes,
        0,
        (u32::from(counter) << 8) | WqeOpcode::EthSend as u32,
    );
    put32(&mut bytes, 4, (number << 8) | (2 + segments.len() as u32));
    bytes[wqe::ctrl::FM_CE_SE] = MLX5_WQE_CTRL_CQ_UPDATE;
    bytes[16 + wqe::eth::CS_FLAGS] = if checksum {
        (u8::from(options.l3_cs) * MLX5_ETH_WQE_L3_CSUM)
            | (u8::from(options.l4_cs) * MLX5_ETH_WQE_L4_CSUM)
    } else {
        0
    };
    for (index, segment) in segments.iter().enumerate() {
        let offset = 32 + index * 16;
        put32(&mut bytes, offset, segment.len);
        put32(&mut bytes, offset + 4, mkey);
        bytes[offset + 8..offset + 16].copy_from_slice(&segment.device_addr.to_be_bytes());
    }
    Ok(bytes)
}

/// A successful post names the physical slot as well as its wrapping counter.
pub struct ReceivePost {
    pub counter: u16,
    pub slot: u16,
}

struct ReceiveSlot {
    counter: u16,
    buffer: RxBufferInfo,
}

/// RQ and optional RMP grants share one RAM owner; both must retire before RAM.
pub struct ReceiveQueue {
    pub(crate) memory: QueueMemory<4>,
    pub(crate) grant: QueueGrant,
    pub(crate) rmp_grant: QueueGrant,
    pub(crate) cqn: u32,
    pub(crate) layout: Option<ResolvedRqLayout>,
    depth: u32,
    producer: u16,
    mkey: u32,
    pending: Vec<Option<ReceiveSlot>>,
    free: VecDeque<u16>,
    posted: VecDeque<u16>,
    last: Option<(u16, u16, [u8; 64])>,
}

pub(crate) struct ReceiveStorage {
    pending: Vec<Option<ReceiveSlot>>,
    free: VecDeque<u16>,
    posted: VecDeque<u16>,
}
impl ReceiveStorage {
    pub(crate) fn reserve(log_size: u8) -> Mlx5Result<Self> {
        let depth = checked_depth(log_size)? as usize;
        let mut pending = Vec::new();
        pending
            .try_reserve_exact(depth)
            .map_err(|_| Mlx5Error::OutOfMemory)?;
        pending.resize_with(depth, || None);
        let mut free = VecDeque::new();
        free.try_reserve_exact(depth)
            .map_err(|_| Mlx5Error::OutOfMemory)?;
        free.extend((0..depth).map(|slot| slot as u16));
        let mut posted = VecDeque::new();
        posted
            .try_reserve_exact(depth)
            .map_err(|_| Mlx5Error::OutOfMemory)?;
        Ok(Self {
            pending,
            free,
            posted,
        })
    }
}

impl ReceiveQueue {
    pub(crate) fn depth(&self) -> usize {
        self.depth as usize
    }
    pub(crate) fn new(
        identity: DmaQueueIdentity,
        leases: [CpuDmaLease; 4],
        storage: ReceiveStorage,
        cqn: u32,
        mkey: u32,
    ) -> Self {
        Self {
            memory: QueueMemory::new(identity, leases),
            grant: QueueGrant::Unpublished,
            rmp_grant: QueueGrant::Unpublished,
            cqn,
            layout: None,
            depth: storage.pending.len() as u32,
            producer: 0,
            mkey,
            pending: storage.pending,
            free: storage.free,
            posted: storage.posted,
            last: None,
        }
    }

    pub(crate) fn number(&self) -> Option<u32> {
        self.grant.number()
    }

    pub(crate) fn prepare(&mut self) -> Mlx5Result<()> {
        let ring = RegionLayout {
            bytes: self.depth as usize * 64,
            direction: DmaDirection::ToDevice,
            alignment: crate::defs::MLX5_PAGE_SIZE,
        };
        let record = RegionLayout {
            bytes: 8,
            direction: DmaDirection::ToDevice,
            alignment: 8,
        };
        self.memory
            .prepare([ring, record, ring, record], |_, bytes| bytes.fill(0))
    }

    pub(crate) fn post_recv(
        &mut self,
        address: u64,
        virtual_address: u64,
        size: u32,
    ) -> Result<ReceivePost, WorkSubmissionError> {
        let layout = self
            .layout
            .filter(|_| self.number().is_some())
            .ok_or(WorkSubmissionError::NotPublished(Mlx5Error::DeviceNotReady))?;
        if address == 0 || size == 0 || address.checked_add(u64::from(size) - 1).is_none() {
            return Err(WorkSubmissionError::NotPublished(
                Mlx5Error::InvalidParameter,
            ));
        }
        let counter = self.producer;
        let slot = match layout.wq_mode {
            RxWqMode::Cyclic => (u32::from(counter) % self.depth) as u16,
            RxWqMode::LinkedList => *self
                .free
                .front()
                .ok_or(WorkSubmissionError::NotPublished(Mlx5Error::NoResources))?,
        };
        if self.pending[slot as usize].is_some() {
            return Err(WorkSubmissionError::NotPublished(Mlx5Error::NoResources));
        }
        let region = if layout.rmpn.is_some() { 2 } else { 0 };
        let mut descriptor = [0; 64];
        if layout.has_next_segment {
            let next = (u32::from(slot) + 1) % self.depth;
            let index = next as u16;
            descriptor[2..4].copy_from_slice(&index.to_be_bytes());
        }
        let offset = layout.data_seg_offset;
        put32(&mut descriptor, offset, size);
        put32(&mut descriptor, offset + 4, self.mkey);
        descriptor[offset + 8..offset + 16].copy_from_slice(&address.to_be_bytes());
        self.memory
            .write(
                region,
                layout.slot_offset(slot),
                &descriptor[..layout.slot_size_bytes],
            )
            .map_err(WorkSubmissionError::NotPublished)?;
        let position = self
            .free
            .iter()
            .position(|free| *free == slot)
            .expect("vacant pending slot has its unique free entry");
        self.free.remove(position);
        self.pending[slot as usize] = Some(ReceiveSlot {
            counter,
            buffer: RxBufferInfo {
                slot_index: slot,
                virt_addr: virtual_address,
                device_addr: address,
                size,
                in_use: true,
                l3_ok: false,
                l4_ok: false,
            },
        });
        self.posted.push_back(slot);
        self.last = Some((counter, slot, descriptor));
        self.producer = self.producer.wrapping_add(1);
        fence(Ordering::Release);
        self.memory
            .write_be32(region + 1, 0, u32::from(self.producer))
            .map_err(|cause| WorkSubmissionError::OutcomeUnknown {
                counter,
                slot,
                cause,
            })?;
        Ok(ReceivePost { counter, slot })
    }

    pub(crate) fn complete_rx(
        &mut self,
        counter: u16,
        l3_ok: bool,
        l4_ok: bool,
    ) -> Mlx5Result<RxBufferInfo> {
        let layout = self.layout.ok_or(Mlx5Error::DeviceNotReady)?;
        let slot = match layout.wq_mode {
            RxWqMode::Cyclic => (u32::from(counter) % self.depth) as u16,
            RxWqMode::LinkedList => *self.posted.front().ok_or(Mlx5Error::InvalidResponse)?,
        };
        if self.pending[slot as usize]
            .as_ref()
            .map(|record| record.counter)
            != Some(counter)
        {
            return Err(Mlx5Error::InvalidResponse);
        }
        let position = self
            .posted
            .iter()
            .position(|posted| *posted == slot)
            .ok_or(Mlx5Error::InvalidResponse)?;
        let mut record = self.pending[slot as usize]
            .take()
            .expect("counter checked pending slot");
        self.posted.remove(position);
        self.free.push_back(slot);
        record.buffer.l3_ok = l3_ok;
        record.buffer.l4_ok = l4_ok;
        Ok(record.buffer)
    }

    pub(crate) fn debug_state(&mut self) -> Mlx5Result<RxQueueDebugState> {
        let layout = self.layout.ok_or(Mlx5Error::DeviceNotReady)?;
        let number = self.number().ok_or(Mlx5Error::DeviceNotReady)?;
        let region = if layout.rmpn.is_some() { 2 } else { 0 };
        let record = self.memory.read::<4>(region + 1, 0)?;
        let (counter, slot, bytes) = self.last.unwrap_or((0, 0, [0; 64]));
        Ok(RxQueueDebugState {
            rqn: number,
            producer_counter: self.producer,
            rq_depth: self.depth,
            available_slots: self.free.len() as u32,
            layout_mode: layout.wq_mode,
            layout_slot_size_bytes: layout.slot_size_bytes,
            layout_data_seg_offset: layout.data_seg_offset,
            layout_raw_wq_type: layout.raw_wq_type,
            layout_raw_log_wq_stride: layout.raw_log_wq_stride,
            layout_rmpn: layout.rmpn,
            doorbell_be: u32::from_ne_bytes(record),
            doorbell_host: u32::from_be_bytes(record),
            last_wqe_counter: counter,
            last_wqe_offset: layout.slot_offset(slot),
            last_wqe_byte_count: be32(&bytes, layout.data_seg_offset),
            last_wqe_lkey: be32(&bytes, layout.data_seg_offset + 4),
            last_wqe_device_addr: be64(&bytes, layout.data_seg_offset + 8),
        })
    }
}

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}
fn be32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().expect("fixed field"))
}
fn be64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(bytes[offset..offset + 8].try_into().expect("fixed field"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn send_descriptor_matches_protocol_fields_without_payload_copy() -> Mlx5Result<()> {
        let segment = DmaSegment {
            device_addr: 0x0123_4567_89ab_cdef,
            virt_addr: 0,
            len: 0x1234,
        };
        let bytes = encode_send(
            0x654321,
            0xfffe,
            0xdeadbeef,
            true,
            &[segment],
            TxOptions {
                l3_cs: true,
                ..TxOptions::default()
            },
        )?;
        assert_eq!(&bytes[..8], &[0, 0xff, 0xfe, 0x0a, 0x65, 0x43, 0x21, 3]);
        assert_eq!(
            &bytes[32..48],
            &[
                0, 0, 0x12, 0x34, 0xde, 0xad, 0xbe, 0xef, 1, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
                0xef
            ]
        );
        assert_eq!(bytes[16 + wqe::eth::CS_FLAGS], 0x40);
        Ok(())
    }
    #[test]
    fn send_validation_rejects_unrepresentable_device_extent_before_publication() {
        let segment = DmaSegment {
            device_addr: u64::MAX,
            virt_addr: 0,
            len: 2,
        };
        assert_eq!(
            encode_send(1, 0, 1, false, &[segment], TxOptions::default()),
            Err(Mlx5Error::InvalidParameter)
        );
    }
}
