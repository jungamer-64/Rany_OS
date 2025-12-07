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

#![allow(dead_code)]

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

use super::controller::XhciController;
use super::trb::{CompletionCode, Trb};
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

    /// 転送を開始（TRBをエンキュー）
    fn start_control_transfer(
        &self,
        setup: &SetupPacket,
        data_len: usize,
    ) -> UsbResult<u8> {
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
        let transfer_type = if actual_data_len == 0 {
            0 // No data stage
        } else if direction_in {
            3 // IN data stage
        } else {
            2 // OUT data stage
        };

        let setup_trb = Trb::setup_stage(setup, transfer_type, ring.cycle_bit());
        ring.enqueue(setup_trb);

        // Data Stage TRB (if needed)
        if actual_data_len > 0 && data_len > 0 {
            let data_buffer = alloc::vec![0u8; data_len];
            let data_ptr = data_buffer.as_ptr() as u64;
            let data_trb =
                Trb::data_stage(data_ptr, actual_data_len as u32, direction_in, ring.cycle_bit());
            ring.enqueue(data_trb);
            core::mem::forget(data_buffer);
        }

        // Status Stage TRB
        let status_dir = if actual_data_len == 0 {
            true
        } else {
            !direction_in
        };
        let status_trb = Trb::status_stage(status_dir, ring.cycle_bit());
        ring.enqueue(status_trb);

        drop(transfer_rings);

        // Ring doorbell
        self.controller.ring_doorbell(self.slot_id.as_u8(), dci);

        Ok(dci)
    }

    /// Bulk転送を開始
    fn start_bulk_transfer(
        &self,
        endpoint: EndpointAddress,
        buffer_len: usize,
        is_in: bool,
        data: Option<&[u8]>,
    ) -> UsbResult<u8> {
        let ep_num = endpoint.number();
        let dci = (ep_num * 2) + if is_in { 1 } else { 0 };

        let mut transfer_rings = self.controller.transfer_rings.lock();
        let ring = transfer_rings
            .get_mut(self.slot_id.as_usize())
            .and_then(|slots| slots.get_mut(dci as usize))
            .and_then(|opt| opt.as_mut())
            .ok_or(UsbError::NoResources)?;

        // Allocate buffer
        let mut buffer = alloc::vec![0u8; buffer_len];
        if let Some(src_data) = data {
            buffer[..src_data.len().min(buffer_len)].copy_from_slice(&src_data[..src_data.len().min(buffer_len)]);
        }
        let data_ptr = buffer.as_ptr() as u64;

        // Create Normal TRB
        let trb = Trb::normal(data_ptr, buffer_len as u32, ring.cycle_bit());
        ring.enqueue(trb);

        // Keep buffer alive until transfer completes
        core::mem::forget(buffer);

        drop(transfer_rings);

        // Ring doorbell
        self.controller.ring_doorbell(self.slot_id.as_u8(), dci);

        Ok(dci)
    }
}

// ============================================================================
// Transfer Futures
// ============================================================================

/// コントロール転送 Future
struct ControlTransferFuture {
    controller: Arc<XhciController>,
    slot_id: SlotId,
    endpoint_id: u8,
    expected_len: usize,
    started: bool,
}

impl Future for ControlTransferFuture {
    type Output = UsbResult<usize>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // イベントを処理
        self.controller.process_events();

        // 完了を確認
        if let Some(result) = self.controller.check_transfer_completion(self.slot_id, self.endpoint_id) {
            // 完了コードを確認
            match result.completion_code {
                CompletionCode::Success | CompletionCode::ShortPacket => {
                    let transferred = self.expected_len.saturating_sub(result.transferred as usize);
                    return Poll::Ready(Ok(transferred));
                }
                CompletionCode::StallError => {
                    return Poll::Ready(Err(UsbError::Stalled));
                }
                cc => {
                    return Poll::Ready(Err(UsbError::TransferError(
                        crate::io::usb::TransferStatus::Error(cc as u8)
                    )));
                }
            }
        }

        // まだ完了していない場合、Wakerを登録
        if !self.started {
            self.controller.register_transfer_wait(
                self.slot_id,
                self.endpoint_id,
                cx.waker().clone(),
            );
            self.started = true;
        }

        Poll::Pending
    }
}

impl Drop for ControlTransferFuture {
    fn drop(&mut self) {
        // キャンセル時に待機をクリーンアップ
        self.controller.cancel_transfer_wait(self.slot_id, self.endpoint_id);
    }
}

/// Bulk/Interrupt転送 Future
struct BulkTransferFuture {
    controller: Arc<XhciController>,
    slot_id: SlotId,
    endpoint_id: u8,
    expected_len: usize,
    started: bool,
}

impl Future for BulkTransferFuture {
    type Output = UsbResult<usize>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // イベントを処理
        self.controller.process_events();

        // 完了を確認
        if let Some(result) = self.controller.check_transfer_completion(self.slot_id, self.endpoint_id) {
            match result.completion_code {
                CompletionCode::Success | CompletionCode::ShortPacket => {
                    let transferred = self.expected_len.saturating_sub(result.transferred as usize);
                    return Poll::Ready(Ok(transferred));
                }
                CompletionCode::StallError => {
                    return Poll::Ready(Err(UsbError::Stalled));
                }
                cc => {
                    return Poll::Ready(Err(UsbError::TransferError(
                        crate::io::usb::TransferStatus::Error(cc as u8)
                    )));
                }
            }
        }

        // Wakerを登録
        if !self.started {
            self.controller.register_transfer_wait(
                self.slot_id,
                self.endpoint_id,
                cx.waker().clone(),
            );
            self.started = true;
        }

        Poll::Pending
    }
}

impl Drop for BulkTransferFuture {
    fn drop(&mut self) {
        self.controller.cancel_transfer_wait(self.slot_id, self.endpoint_id);
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
        let setup_copy = *setup;
        let data_len = data.as_ref().map(|d| d.len()).unwrap_or(0);
        let controller = Arc::clone(&self.controller);
        let slot_id = self.slot_id;

        // 転送を開始
        let start_result = self.start_control_transfer(&setup_copy, data_len);

        Box::pin(async move {
            let endpoint_id = start_result?;
            
            // 真の非同期 Future を作成
            ControlTransferFuture {
                controller,
                slot_id,
                endpoint_id,
                expected_len: data_len,
                started: false,
            }.await
        })
    }

    fn bulk_in(
        &self,
        endpoint: EndpointAddress,
        buffer: &mut [u8],
    ) -> Pin<Box<dyn Future<Output = UsbResult<usize>> + Send + '_>> {
        let len = buffer.len();
        let controller = Arc::clone(&self.controller);
        let slot_id = self.slot_id;

        // 転送を開始
        let start_result = self.start_bulk_transfer(endpoint, len, true, None);

        Box::pin(async move {
            let endpoint_id = start_result?;
            
            BulkTransferFuture {
                controller,
                slot_id,
                endpoint_id,
                expected_len: len,
                started: false,
            }.await
        })
    }

    fn bulk_out(
        &self,
        endpoint: EndpointAddress,
        data: &[u8],
    ) -> Pin<Box<dyn Future<Output = UsbResult<usize>> + Send + '_>> {
        let data_copy = data.to_vec();
        let len = data_copy.len();
        let controller = Arc::clone(&self.controller);
        let slot_id = self.slot_id;

        // 転送を開始（データをコピー済み）
        let start_result = self.start_bulk_transfer(endpoint, len, false, Some(&data_copy));

        Box::pin(async move {
            let endpoint_id = start_result?;
            
            BulkTransferFuture {
                controller,
                slot_id,
                endpoint_id,
                expected_len: len,
                started: false,
            }.await
        })
    }

    fn interrupt_in(
        &self,
        endpoint: EndpointAddress,
        buffer: &mut [u8],
    ) -> Pin<Box<dyn Future<Output = UsbResult<usize>> + Send + '_>> {
        // Interrupt転送はBulkと同じメカニズム
        let len = buffer.len();
        let controller = Arc::clone(&self.controller);
        let slot_id = self.slot_id;

        let start_result = self.start_bulk_transfer(endpoint, len, true, None);

        Box::pin(async move {
            let endpoint_id = start_result?;
            
            BulkTransferFuture {
                controller,
                slot_id,
                endpoint_id,
                expected_len: len,
                started: false,
            }.await
        })
    }

    fn interrupt_out(
        &self,
        endpoint: EndpointAddress,
        data: &[u8],
    ) -> Pin<Box<dyn Future<Output = UsbResult<usize>> + Send + '_>> {
        let data_copy = data.to_vec();
        let len = data_copy.len();
        let controller = Arc::clone(&self.controller);
        let slot_id = self.slot_id;

        let start_result = self.start_bulk_transfer(endpoint, len, false, Some(&data_copy));

        Box::pin(async move {
            let endpoint_id = start_result?;
            
            BulkTransferFuture {
                controller,
                slot_id,
                endpoint_id,
                expected_len: len,
                started: false,
            }.await
        })
    }
}
