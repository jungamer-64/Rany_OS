// ============================================================================
// src/io/usb/xhci/device.rs - xHCI USB Device Implementation
// ============================================================================
//!
//! xHCI 経由の USB デバイス実装。
//!
//! ## 機能
//! - コントロール転送（真の非同期）
//! - バルク転送（真の非同期）
//! - 割り込み転送（真の非同期）
//! - アイソクロナス転送（将来対応）
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;

use super::controller::TransferKind;
use super::controller::XhciController;
use crate::descriptor::DeviceDescriptor;
use crate::{
    DeviceAddress, EndpointAddress, SetupPacket, SlotId, UsbDevice, UsbError, UsbResult, UsbSpeed,
};

// ============================================================================
// xHCI USB Device
// ============================================================================

/// xHCI経由のUSBデバイス
pub struct XhciDevice {
    /// コントローラ参照
    pub(crate) controller: Arc<XhciController>,
    /// スロットID
    pub(crate) slot_id: SlotId,
    /// デバイスアドレス
    address: DeviceAddress,
    /// デバイスディスクリプタ
    device_descriptor: DeviceDescriptor,
    /// USB速度
    speed: UsbSpeed,
}

impl XhciDevice {
    /// 新しいXhciDeviceを作成
    pub fn new(
        controller: Arc<XhciController>,
        slot_id: SlotId,
        address: DeviceAddress,
        device_descriptor: DeviceDescriptor,
        speed: UsbSpeed,
    ) -> Self {
        Self {
            controller,
            slot_id,
            address,
            device_descriptor,
            speed,
        }
    }

    /// Performs an isochronous IN transfer; the controller owns data RAM until
    /// its final event, even if this Future is dropped while waiting.
    pub fn isoch_in(
        &self,
        endpoint: EndpointAddress,
        buffer_len: usize,
    ) -> Pin<Box<dyn Future<Output = UsbResult<usize>> + Send + '_>> {
        Box::pin(async move {
            let dci = transfer_dci(endpoint, true)?;
            let result = self
                .controller
                .submit_transfer(
                    self.slot_id,
                    dci,
                    TransferKind::Isochronous,
                    buffer_len,
                    true,
                    None,
                )?
                .await?;
            self.controller.finish_transfer_buffer(result, None)
        })
    }

    pub fn isoch_out<'a>(
        &'a self,
        endpoint: EndpointAddress,
        data: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = UsbResult<usize>> + Send + 'a>> {
        Box::pin(async move {
            let dci = transfer_dci(endpoint, false)?;
            let result = self
                .controller
                .submit_transfer(
                    self.slot_id,
                    dci,
                    TransferKind::Isochronous,
                    data.len(),
                    false,
                    Some(data),
                )?
                .await?;
            self.controller.finish_transfer_buffer(result, None)
        })
    }
}

fn transfer_dci(endpoint: EndpointAddress, direction_in: bool) -> UsbResult<u8> {
    if endpoint.number() == 0 || endpoint.is_in() != direction_in {
        return Err(UsbError::InvalidParameter);
    }
    Ok(endpoint.number() * 2 + u8::from(direction_in))
}

// ============================================================================
// UsbDevice Trait Implementation
// ============================================================================

impl UsbDevice for XhciDevice {
    fn address(&self) -> DeviceAddress {
        self.address
    }

    fn vendor_id(&self) -> u16 {
        self.device_descriptor.id_vendor
    }

    fn product_id(&self) -> u16 {
        self.device_descriptor.id_product
    }

    fn device_class(&self) -> u8 {
        self.device_descriptor.b_device_class
    }

    fn device_subclass(&self) -> u8 {
        self.device_descriptor.b_device_sub_class
    }

    fn device_protocol(&self) -> u8 {
        self.device_descriptor.b_device_protocol
    }

    fn speed(&self) -> UsbSpeed {
        self.speed
    }

    fn control_transfer<'a>(
        &'a self,
        setup: &SetupPacket,
        data: Option<&'a mut [u8]>,
    ) -> Pin<Box<dyn Future<Output = UsbResult<usize>> + Send + 'a>> {
        let setup = *setup;
        Box::pin(async move {
            let length = usize::from(setup.w_length);
            if data.as_ref().map_or(0, |bytes| bytes.len()) < length {
                return Err(UsbError::BufferSize);
            }
            let direction_in = setup.bm_request_type & 0x80 != 0;
            let source = if direction_in {
                None
            } else {
                data.as_deref().map(|bytes| &bytes[..length])
            };
            let result = self
                .controller
                .submit_transfer(
                    self.slot_id,
                    1,
                    TransferKind::Control(setup),
                    length,
                    direction_in,
                    source,
                )?
                .await?;
            self.controller
                .finish_transfer_buffer(result, if direction_in { data } else { None })
        })
    }

    fn bulk_in<'a>(
        &'a self,
        endpoint: EndpointAddress,
        buffer: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = UsbResult<usize>> + Send + 'a>> {
        Box::pin(async move {
            let dci = transfer_dci(endpoint, true)?;
            let result = self
                .controller
                .submit_transfer(
                    self.slot_id,
                    dci,
                    TransferKind::Normal,
                    buffer.len(),
                    true,
                    None,
                )?
                .await?;
            self.controller.finish_transfer_buffer(result, Some(buffer))
        })
    }

    fn bulk_out<'a>(
        &'a self,
        endpoint: EndpointAddress,
        data: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = UsbResult<usize>> + Send + 'a>> {
        Box::pin(async move {
            let dci = transfer_dci(endpoint, false)?;
            let result = self
                .controller
                .submit_transfer(
                    self.slot_id,
                    dci,
                    TransferKind::Normal,
                    data.len(),
                    false,
                    Some(data),
                )?
                .await?;
            self.controller.finish_transfer_buffer(result, None)
        })
    }

    fn interrupt_in<'a>(
        &'a self,
        endpoint: EndpointAddress,
        buffer: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = UsbResult<usize>> + Send + 'a>> {
        self.bulk_in(endpoint, buffer)
    }

    fn interrupt_out<'a>(
        &'a self,
        endpoint: EndpointAddress,
        data: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = UsbResult<usize>> + Send + 'a>> {
        self.bulk_out(endpoint, data)
    }

    fn suspend(&self) -> Pin<Box<dyn Future<Output = UsbResult<()>> + Send + '_>> {
        let controller = Arc::clone(&self.controller);
        let slot_id = self.slot_id;

        Box::pin(async move { controller.suspend_device(slot_id).await })
    }

    fn resume(&self) -> Pin<Box<dyn Future<Output = UsbResult<()>> + Send + '_>> {
        let controller = Arc::clone(&self.controller);
        let slot_id = self.slot_id;

        Box::pin(async move { controller.resume_device(slot_id).await })
    }
}
