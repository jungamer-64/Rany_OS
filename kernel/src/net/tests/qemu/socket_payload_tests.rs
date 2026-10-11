// ============================================================================
// kernel/src/net/tests/qemu/socket_payload_tests.rs - Registered TCP payload queues
// ============================================================================

use crate::net::l4::socket::{Socket, TcpSocketState, unregister_socket_in};
use crate::net::l4::types::EndpointError;
use crate::net::payload::GeneratedPacketWriter;
use kernel_api::resource::net::DEFAULT_PACKET_HEADROOM;
use kernel_api::resource::net::PacketPayload;

fn payload_bytes(data: &[u8]) -> PacketPayload {
    let mut writer = GeneratedPacketWriter::new(data.len(), DEFAULT_PACKET_HEADROOM)
        .expect("test payload allocation");
    writer
        .write_generated_bytes(data)
        .expect("test payload write succeeds");
    writer.finish().expect("test payload is exact")
}

pub fn socket_send_payload_rejects_partial_enqueue_without_slicing_smoke() -> bool {
    let runtime = crate::net::runtime::default_runtime();
    let socket = Socket::new_tcp_in(runtime, TcpSocketState::Connected);
    assert!(runtime.context().sockets.get(socket.socket_id()).is_some());
    socket
        .with_inner_mut(|state| {
            state.send_buffer_limit = 4;

            let (cause, returned) = state
                .send_payload(payload_bytes(b"abcde"))
                .expect_err("capacity must reject the whole payload");
            assert_eq!(cause, EndpointError::BufferFull);
            assert!(
                crate::net::payload::PayloadSpanRef::from_payload(&returned).eq_bytes(b"abcde")
            );
            assert_eq!(state.send_payload_bytes(), 0);
            assert!(!state.has_send_data());

            state.send_buffer_limit = 5;
            assert!(state.send_payload(payload_bytes(b"abcde")).is_ok());
            assert_eq!(state.send_payload_bytes(), 5);
        })
        .expect("registered TCP socket state");
    assert!(unregister_socket_in(runtime, socket.socket_id()).is_some());
    assert!(runtime.context().sockets.get(socket.socket_id()).is_none());
    true
}

pub fn socket_take_send_segment_window_splits_front_payload_smoke() -> bool {
    let runtime = crate::net::runtime::default_runtime();
    let socket = Socket::new_tcp_in(runtime, TcpSocketState::Connected);
    assert!(runtime.context().sockets.get(socket.socket_id()).is_some());
    socket
        .with_inner_mut(|state| {
            assert!(state.send_payload(payload_bytes(b"abcde")).is_ok());

            let prefix = state
                .take_send_segment_window(4)
                .expect("front payload should be sliced as a byte stream");
            assert_eq!(prefix.total_len(), 4);
            assert_eq!(state.send_payload_bytes(), 1);

            let payload = state
                .take_send_segment_window(5)
                .expect("remaining byte should stay queued");
            assert_eq!(payload.total_len(), 1);
            assert_eq!(state.send_payload_bytes(), 0);
        })
        .expect("registered TCP socket state");
    assert!(unregister_socket_in(runtime, socket.socket_id()).is_some());
    assert!(runtime.context().sockets.get(socket.socket_id()).is_none());
    true
}

pub fn socket_recv_payload_limit_does_not_split_front_payload_smoke() -> bool {
    let runtime = crate::net::runtime::default_runtime();
    let socket = Socket::new_tcp_in(runtime, TcpSocketState::Connected);
    assert!(runtime.context().sockets.get(socket.socket_id()).is_some());
    socket
        .with_inner_mut(|state| {
            assert_eq!(state.push_recv_payload(payload_bytes(b"abcde")), 5);

            assert!(state.recv_payload(Some(4)).is_none());
            assert_eq!(state.recv_payload_bytes(), 5);

            let payload = state
                .recv_payload(Some(5))
                .expect("whole payload should be moved");
            assert_eq!(payload.total_len(), 5);
            assert_eq!(state.recv_payload_bytes(), 0);
        })
        .expect("registered TCP socket state");
    assert!(unregister_socket_in(runtime, socket.socket_id()).is_some());
    assert!(runtime.context().sockets.get(socket.socket_id()).is_none());
    true
}
