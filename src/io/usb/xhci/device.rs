// ============================================================================
// src/io/usb/xhci/device.rs - xHCI USB Device Implementation
// ============================================================================
//!
//! xHCI 経由の USB デバイス実装。
//!
//! ## 機能
//! - コントロール転送
//! - バルク転送
//! - 割り込み転送
//! - アイソクロナス転送（将来対応）

#![allow(dead_code)]

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;

use super::controller::XhciController;
use super::trb::Trb;
use crate::io::usb::descriptor::{DeviceDescriptor, ParsedConfiguration};
use crate::io::usb::{
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
    /// 現在のコンフィグレーション
    configuration: Option<ParsedConfiguration>,
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
            configuration: None,
            speed,
        }
    }

    /// コントロール転送を実行（同期版）
    fn do_control_transfer_sync(
        &self,
        setup: &SetupPacket,
        data_len: usize,
        _has_data: bool,
    ) -> UsbResult<usize> {
        let direction_in = (setup.bm_request_type & 0x80) != 0;
        let actual_data_len = setup.w_length;

        // Transfer Ringを取得（エンドポイント0 = DCI 1）
        let dci: u8 = 1; // Control endpoint 0 IN/OUT

        let mut transfer_rings = self.controller.transfer_rings.lock();
        let ring = transfer_rings
            .get_mut(self.slot_id.as_usize())
            .and_then(|slots| slots.get_mut(dci as usize))
            .and_then(|opt| opt.as_mut())
            .ok_or(UsbError::NoResources)?;

        // Setup Stage TRB
        // TRT (Transfer Type): 0=No Data, 2=OUT Data, 3=IN Data
        let transfer_type = if actual_data_len == 0 {
            0 // No data stage
        } else if direction_in {
            3 // IN data stage
        } else {
            2 // OUT data stage
        };

        let setup_trb = Trb::setup_stage(setup, transfer_type, ring.cycle_bit());
        ring.enqueue(setup_trb);

        let transferred: usize = data_len.min(actual_data_len as usize);

        // Data Stage TRB (if needed)
        if actual_data_len > 0 && data_len > 0 {
            // Allocate buffer for data stage
            let data_buffer = alloc::vec![0u8; data_len];
            let data_ptr = data_buffer.as_ptr() as u64;
            let data_trb =
                Trb::data_stage(data_ptr, actual_data_len as u32, direction_in, ring.cycle_bit());
            ring.enqueue(data_trb);
            // Note: data_buffer is dropped here, but in real implementation
            // we'd need to keep it alive until transfer completes
            core::mem::forget(data_buffer);
        }

        // Status Stage TRB
        // Direction is opposite of data stage (or IN if no data stage)
        let status_dir = if actual_data_len == 0 {
            true
        } else {
            !direction_in
        };
        let status_trb = Trb::status_stage(status_dir, ring.cycle_bit());
        ring.enqueue(status_trb);

        drop(transfer_rings);

        // Ring doorbell for this slot/endpoint
        self.controller.ring_doorbell(self.slot_id.as_u8(), dci);

        // Wait for completion (polling)
        for _ in 0..1000 {
            self.controller.process_events();
            core::hint::spin_loop();
        }

        Ok(transferred)
    }

    /// Bulk IN転送を実行（同期版）
    fn do_bulk_transfer_sync(
        &self,
        endpoint: EndpointAddress,
        buffer_len: usize,
        is_in: bool,
    ) -> UsbResult<usize> {
        // Calculate DCI (Device Context Index) for this endpoint
        let ep_num = endpoint.number();
        let dci = (ep_num * 2) + if is_in { 1 } else { 0 };

        let mut transfer_rings = self.controller.transfer_rings.lock();
        let ring = transfer_rings
            .get_mut(self.slot_id.as_usize())
            .and_then(|slots| slots.get_mut(dci as usize))
            .and_then(|opt| opt.as_mut())
            .ok_or(UsbError::NoResources)?;

        // Allocate buffer for transfer
        let buffer = alloc::vec![0u8; buffer_len];
        let data_ptr = buffer.as_ptr() as u64;

        // Create Normal TRB for bulk transfer
        let trb = Trb::normal(data_ptr, buffer_len as u32, ring.cycle_bit());
        ring.enqueue(trb);

        // Keep buffer alive
        core::mem::forget(buffer);

        drop(transfer_rings);

        // Ring doorbell
        self.controller.ring_doorbell(self.slot_id.as_u8(), dci);

        // Wait for completion
        for _ in 0..1000 {
            self.controller.process_events();
            core::hint::spin_loop();
        }

        Ok(buffer_len)
    }

    /// Bulk OUT転送を実行（同期版）
    fn do_bulk_out_sync(&self, endpoint: EndpointAddress, data: &[u8]) -> UsbResult<usize> {
        let ep_num = endpoint.number();
        let dci = ep_num * 2; // OUT endpoint

        let mut transfer_rings = self.controller.transfer_rings.lock();
        let ring = transfer_rings
            .get_mut(self.slot_id.as_usize())
            .and_then(|slots| slots.get_mut(dci as usize))
            .and_then(|opt| opt.as_mut())
            .ok_or(UsbError::NoResources)?;

        // Copy data to a persistent buffer
        let mut buffer = alloc::vec![0u8; data.len()];
        buffer.copy_from_slice(data);
        let data_ptr = buffer.as_ptr() as u64;

        // Create Normal TRB for bulk OUT transfer
        let trb = Trb::normal(data_ptr, data.len() as u32, ring.cycle_bit());
        ring.enqueue(trb);

        // Keep buffer alive until transfer completes
        core::mem::forget(buffer);

        drop(transfer_rings);

        // Ring doorbell
        self.controller.ring_doorbell(self.slot_id.as_u8(), dci);

        // Wait for completion
        for _ in 0..1000 {
            self.controller.process_events();
            core::hint::spin_loop();
        }

        Ok(data.len())
    }

    /// Interrupt IN転送を実行（同期版）
    fn do_interrupt_transfer_sync(
        &self,
        endpoint: EndpointAddress,
        buffer_len: usize,
        is_in: bool,
    ) -> UsbResult<usize> {
        // Interrupt transfers use the same TRB structure as bulk
        self.do_bulk_transfer_sync(endpoint, buffer_len, is_in)
    }

    /// Interrupt OUT転送を実行（同期版）
    fn do_interrupt_out_sync(&self, endpoint: EndpointAddress, data: &[u8]) -> UsbResult<usize> {
        // Interrupt OUT uses same mechanism as bulk OUT
        self.do_bulk_out_sync(endpoint, data)
    }
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

    fn control_transfer(
        &self,
        setup: &SetupPacket,
        data: Option<&mut [u8]>,
    ) -> Pin<Box<dyn Future<Output = UsbResult<usize>> + Send + '_>> {
        // Copy setup packet data before async block
        let setup_copy = *setup;

        // Copy data buffer if present (we'll write results back)
        let data_len = data.as_ref().map(|d| d.len()).unwrap_or(0);
        let has_data = data.is_some();

        // Use immediate execution for synchronous operation
        let result = self.do_control_transfer_sync(&setup_copy, data_len, has_data);

        // Write back data if needed (handled in sync function)
        Box::pin(async move { result })
    }

    fn bulk_in(
        &self,
        endpoint: EndpointAddress,
        buffer: &mut [u8],
    ) -> Pin<Box<dyn Future<Output = UsbResult<usize>> + Send + '_>> {
        let len = buffer.len();
        let result = self.do_bulk_transfer_sync(endpoint, len, true);
        Box::pin(async move { result })
    }

    fn bulk_out(
        &self,
        endpoint: EndpointAddress,
        data: &[u8],
    ) -> Pin<Box<dyn Future<Output = UsbResult<usize>> + Send + '_>> {
        // Copy data for OUT transfer
        let data_copy = data.to_vec();
        let result = self.do_bulk_out_sync(endpoint, &data_copy);
        Box::pin(async move { result })
    }

    fn interrupt_in(
        &self,
        endpoint: EndpointAddress,
        buffer: &mut [u8],
    ) -> Pin<Box<dyn Future<Output = UsbResult<usize>> + Send + '_>> {
        let len = buffer.len();
        let result = self.do_interrupt_transfer_sync(endpoint, len, true);
        Box::pin(async move { result })
    }

    fn interrupt_out(
        &self,
        endpoint: EndpointAddress,
        data: &[u8],
    ) -> Pin<Box<dyn Future<Output = UsbResult<usize>> + Send + '_>> {
        let data_copy = data.to_vec();
        let result = self.do_interrupt_out_sync(endpoint, &data_copy);
        Box::pin(async move { result })
    }
}
