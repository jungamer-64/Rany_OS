//! Context RAM has no retained CPU pointer while the controller owns it. Context
//! stride is the hardware CSZ value, independently of the Rust value layout.

#![forbid(unsafe_code)]

use super::context::{InputContext, SlotContext};
use kernel_api::dma::{
    CpuDmaLease, DmaDeviceAddress, DmaLeaseError, DmaQueueIdentity, PreparedSharedDmaLease,
    SharedDmaLease,
};

#[derive(Debug)]
pub enum MemoryBuildError {
    Cpu {
        cause: DmaLeaseError,
        memory: CpuDmaLease,
    },
    Prepared {
        cause: DmaLeaseError,
        memory: PreparedSharedDmaLease,
    },
}

#[derive(Debug)]
pub(super) struct SharedRegion {
    pub memory: SharedDmaLease,
    pub address: DmaDeviceAddress,
    pub identity: DmaQueueIdentity,
}

impl SharedRegion {
    pub fn prepare(
        mut memory: CpuDmaLease,
        queue: DmaQueueIdentity,
        initialize: impl FnOnce(&mut [u8]),
    ) -> Result<Self, MemoryBuildError> {
        if let Err(cause) = memory.write(initialize) {
            return Err(MemoryBuildError::Cpu { cause, memory });
        }
        let memory = memory.prepare_shared(queue).map_err(|error| {
            let (cause, memory) = error.into_parts();
            MemoryBuildError::Cpu { cause, memory }
        })?;
        let address = match memory.descriptor() {
            Ok(descriptor) => descriptor.device_address(),
            Err(cause) => return Err(MemoryBuildError::Prepared { cause, memory }),
        };
        let memory = memory.activate().map_err(|error| {
            let (cause, memory) = error.into_parts();
            MemoryBuildError::Prepared { cause, memory }
        })?;
        Ok(Self {
            memory,
            address,
            identity: queue,
        })
    }

    pub fn slot_context(&mut self) -> Result<SlotContext, DmaLeaseError> {
        let bytes = self.memory.window(0, 32)?;
        let mut reserved = [0; 4];
        for (index, word) in reserved.iter_mut().enumerate() {
            *word = bytes.read_u32(16 + index * 4)?;
        }
        Ok(SlotContext {
            route_string_and_speed: bytes.read_u32(0)?,
            latency_and_ports: bytes.read_u32(4)?,
            tt_info: bytes.read_u32(8)?,
            state_and_address: bytes.read_u32(12)?,
            reserved,
        })
    }
}

fn words(bytes: &mut [u8], offset: usize, data: &[u32]) {
    for (index, word) in data.iter().enumerate() {
        bytes[offset + index * 4..offset + index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
}

/// Caller supplies a full 33-context CPU allocation. Each 64-byte context's
/// upper half stays zero; the meaningful words occupy the first 32 bytes.
pub(super) fn encode_input(context: &InputContext, stride: usize, bytes: &mut [u8]) {
    bytes.fill(0);
    let control = &context.input_control;
    words(bytes, 0, &[control.drop_flags, control.add_flags]);
    words(bytes, 8, &control.reserved);
    let slot = &context.slot;
    words(
        bytes,
        stride,
        &[
            slot.route_string_and_speed,
            slot.latency_and_ports,
            slot.tt_info,
            slot.state_and_address,
        ],
    );
    words(bytes, stride + 16, &slot.reserved);
    for (index, endpoint) in context.endpoints.iter().enumerate() {
        let start = (index + 2) * stride;
        words(
            bytes,
            start,
            &[
                endpoint.ep_state_and_type,
                endpoint.max_packet_and_burst,
                endpoint.tr_dequeue_ptr as u32,
                (endpoint.tr_dequeue_ptr >> 32) as u32,
                endpoint.average_trb_length,
            ],
        );
        words(bytes, start + 20, &endpoint.reserved);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardware_context_stride_is_independent_of_rust_layout() {
        let mut context = InputContext::new();
        context.input_control.add_flags = 0x8000_0003;
        context.slot.latency_and_ports = 7 << 16;
        context.endpoints[30].tr_dequeue_ptr = 0x1234_5678_9abc_def1;
        for stride in [32, 64] {
            let mut bytes = alloc::vec![0xff; 33 * stride];
            encode_input(&context, stride, &mut bytes);
            assert_eq!(&bytes[4..8], &0x8000_0003u32.to_le_bytes());
            assert_eq!(&bytes[stride + 4..stride + 8], &(7u32 << 16).to_le_bytes());
            let last = 32 * stride;
            assert_eq!(
                &bytes[last + 8..last + 16],
                &0x1234_5678_9abc_def1u64.to_le_bytes()
            );
            if stride == 64 {
                for context in bytes.as_chunks::<64>().0 {
                    assert!(context[32..].iter().all(|byte| *byte == 0));
                }
            }
        }
    }
}
