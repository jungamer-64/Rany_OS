use super::*;
use kernel_api::KapiError;

#[test]
fn framebuffer_geometry_rejects_zero_overflow_and_outside_rectangles() {
    assert!(matches!(
        device::FrameLayout::new(0, 1),
        Err(KapiError::InvalidSize)
    ));
    assert!(matches!(
        device::FrameLayout::new(u32::MAX, 2),
        Err(KapiError::InvalidSize)
    ));
    let layout = device::FrameLayout::new(640, 480).unwrap();
    assert_eq!(
        layout.validate_rect(defs::Rect::new(0, 0, 640, 480)),
        Ok(())
    );
    assert_eq!(
        layout.validate_rect(defs::Rect::new(640, 0, 1, 1)),
        Err(KapiError::InvalidSize)
    );
    assert_eq!(
        layout.validate_rect(defs::Rect::new(u32::MAX, 0, 2, 1)),
        Err(KapiError::InvalidSize)
    );
}

#[test]
fn header_decoding_requires_exact_fence_and_preserves_device_rejection() {
    let mut bytes = [0; 24];
    bytes[..4].copy_from_slice(&[0, 0x11, 0, 0]);
    bytes[4] = 1;
    bytes[8] = 7;
    assert!(matches!(
        protocol::decode(&bytes, 7, protocol::Response::Header),
        Ok(protocol::Reply::Done)
    ));
    assert!(matches!(
        protocol::decode(&bytes, 8, protocol::Response::Header),
        Err(protocol::ReplyError::Protocol)
    ));
    bytes[4] = 0;
    assert!(matches!(
        protocol::decode(&bytes, 7, protocol::Response::Header),
        Err(protocol::ReplyError::Protocol)
    ));
    bytes[4] = 1;
    bytes[..4].copy_from_slice(&[3, 0x12, 0, 0]);
    assert!(matches!(
        protocol::decode(&bytes, 7, protocol::Response::Header),
        Err(protocol::ReplyError::Device(
            GpuDeviceError::InvalidResource
        ))
    ));
}

#[test]
fn request_encoding_uses_specification_coordinates_and_zero_padding() {
    let mut request = protocol::WireCommand::new(
        defs::GpuCmd::ResourceCreate2D,
        9,
        protocol::Response::Header,
    );
    for value in [1, 1, 640, 480] {
        request.u32(value).unwrap();
    }
    assert_eq!(
        request.bytes(),
        &[
            1, 1, 0, 0, 1, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1,
            0, 0, 0, 128, 2, 0, 0, 224, 1, 0, 0
        ]
    );
}

#[test]
fn cursor_commands_require_a_fenced_header_response() {
    let mut request =
        protocol::WireCommand::new(defs::GpuCmd::UpdateCursor, 11, protocol::Response::Header);
    for value in [0, 20, 30, 0, 1, 2, 3, 0] {
        request.u32(value).unwrap();
    }
    assert_eq!(request.bytes().len(), 56);
    assert_eq!(
        &request.bytes()[..16],
        &[0, 3, 0, 0, 1, 0, 0, 0, 11, 0, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(request.response.byte_count(), 24);
    assert!(matches!(
        protocol::decode(&[], 11, protocol::Response::Header),
        Err(protocol::ReplyError::Protocol)
    ));
}
