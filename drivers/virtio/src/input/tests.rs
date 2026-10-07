use super::*;

#[test]
fn wire_events_use_literal_little_endian_coordinates() {
    let event = queue::decode_event(u64::from_le_bytes([1, 0, 30, 0, 1, 0, 0, 0]));
    assert_eq!(
        event,
        VirtioInputEvent {
            type_: 1,
            code: 30,
            value: 1
        }
    );
    assert_eq!(
        queue::encode_event(VirtioInputEvent {
            type_: 2,
            code: 0,
            value: u32::MAX
        })
        .to_le_bytes(),
        [2, 0, 0, 0, 255, 255, 255, 255]
    );
}

#[test]
fn event_queue_rejects_zero_capacity_before_dma_admission() {
    let identity = kernel_api::dma::DmaQueueIdentity::new(
        kernel_api::abi::driver::PackedPciLocation::new(0, 0, 1, 0),
        0,
        1,
    )
    .unwrap();
    assert!(matches!(
        queue::InputQueue::new(
            identity,
            0,
            queue::QueueRole::Receive,
            crate::queue_memory::QueueInterrupt::Polled
        ),
        Err(kernel_api::KapiError::NotSupported)
    ));
}
