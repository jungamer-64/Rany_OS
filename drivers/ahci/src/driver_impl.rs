// use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};
use exorust_sync::PoisonLock;

use kernel_api::KapiResult;
use kernel_api::abi::driver::{
    AbiBlockDeviceInfo, AbiBlockDeviceRegistration, AbiBlockTransport, AbiError,
    AbiIoCompletion, PackedPciLocation,
};
use kernel_api::driver::{Driver, DriverType};

use super::controller::{AhciController, init_from_pci};
use super::types::{Lba, PortNumber, PX_CI, PX_TFD, SECTOR_SIZE, SectorCount, SlotNumber};

const STORAGE_KIND_AHCI: u64 = 3;

static AHCI_BRIDGE_READY: AtomicBool = AtomicBool::new(false);
static AHCI_PENDING: PoisonLock<BTreeMap<u64, (u8, SlotNumber, usize)>> =
    PoisonLock::new(BTreeMap::new());

pub struct AhciDriverWrapper {
    base_addr: u64,
    irq: u8,
    pci_locator: PackedPciLocation,
    controller: Option<Arc<PoisonLock<AhciController>>>,
    block_handles: alloc::vec::Vec<u64>,
}

impl AhciDriverWrapper {
    pub fn new(base_addr: u64, irq: u8, pci_locator: PackedPciLocation) -> Self {
        Self {
            base_addr,
            irq,
            pci_locator,
            controller: None,
            block_handles: alloc::vec::Vec::new(),
        }
    }

    fn with_controller<R>(f: impl FnOnce(&Arc<PoisonLock<AhciController>>) -> R) -> Option<R> {
        unsafe {
            crate::ffi::with_ahci_driver(|driver| driver.controller.as_ref().map(f)).flatten()
        }
    }

    fn submit_block(
        port: u8,
        request_id: u64,
        command: u32,
        lba: u64,
        blocks: u32,
        bytes: usize,
        iova: u64,
    ) -> i32 {
        let Some(result) = Self::with_controller(|controller| {
            let controller = controller.lock().unwrap_or_else(|e| e.into_inner());
            controller.with_port(PortNumber::new(port), |ahci_port| match command {
                x if x == kernel_api::abi::driver::AbiBlockCommandKind::Read as u32 => ahci_port
                    .start_read_dma(Lba(lba), SectorCount(blocks as u16), iova, bytes as u32),
                x if x == kernel_api::abi::driver::AbiBlockCommandKind::Write as u32 => ahci_port
                    .start_write_dma(Lba(lba), SectorCount(blocks as u16), iova, bytes as u32),
                _ => Err(super::types::AhciError::InvalidParameter),
            })
        }) else {
            return AbiError::NotInitialized as i32;
        };

        match result {
            Some(Ok(slot)) => {
                AHCI_PENDING
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(request_id, (port, slot, bytes));
                AbiError::Success as i32
            }
            Some(Err(_)) | None => AbiError::IoError as i32,
        }
    }
}

extern "C" fn ahci_block_submit(
    opaque: u64,
    request_id: u64,
    command: u32,
    lba: u64,
    blocks: u32,
    bytes: usize,
    iova: u64,
) -> i32 {
    AhciDriverWrapper::submit_block(opaque as u8, request_id, command, lba, blocks, bytes, iova)
}

extern "C" fn ahci_block_poll(
    opaque: u64,
    out: *mut AbiIoCompletion,
    capacity: usize,
    written: *mut usize,
) -> i32 {
    if out.is_null() || written.is_null() {
        return AbiError::InvalidParam as i32;
    }

    let port = opaque as u8;
    let mut completed = alloc::vec::Vec::new();
    {
        let pending = AHCI_PENDING.lock().unwrap_or_else(|e| e.into_inner());
        for (&request_id, &(pending_port, slot, bytes)) in pending.iter() {
            if pending_port != port {
                continue;
            }
            let success = AhciDriverWrapper::with_controller(|controller| {
                let controller = controller.lock().unwrap_or_else(|e| e.into_inner());
                let ci = controller.read_port_reg(PortNumber::new(port), PX_CI);
                if (ci & (1 << slot.as_u8())) != 0 {
                    return None;
                }
                let tfd = controller.read_port_reg(PortNumber::new(port), PX_TFD);
                Some((tfd & 0x01) == 0)
            })
            .flatten();
            if let Some(ok) = success {
                completed.push((request_id, ok, bytes, slot));
            }
        }
    }

    let mut pending = AHCI_PENDING.lock().unwrap_or_else(|e| e.into_inner());
    let mut count = 0usize;
    for (request_id, ok, bytes, slot) in completed.into_iter().take(capacity) {
        let finish_bytes = AhciDriverWrapper::with_controller(|controller| {
            let controller = controller.lock().unwrap_or_else(|e| e.into_inner());
            controller.with_port(PortNumber::new(port), |ahci_port| ahci_port.finish_transfer(slot))
        })
        .flatten()
        .unwrap_or(Ok(bytes))
        .unwrap_or(bytes);
        unsafe {
            *out.add(count) = AbiIoCompletion {
                request_id,
                status: if ok {
                    AbiError::Success as i32
                } else {
                    AbiError::IoError as i32
                },
                bytes: finish_bytes,
            };
        }
        pending.remove(&request_id);
        count += 1;
    }
    unsafe {
        *written = count;
    }
    AbiError::Success as i32
}

extern "C" fn ahci_block_is_ready(_opaque: u64) -> bool {
    AHCI_BRIDGE_READY.load(Ordering::Acquire)
}

impl Driver for AhciDriverWrapper {
    fn name(&self) -> &str {
        "ahci"
    }

    fn driver_type(&self) -> DriverType {
        DriverType::Block // AHCI is primary storage
    }

    fn probe(&mut self) -> KapiResult<()> {
        let controller = init_from_pci(self.base_addr, self.pci_locator)
            .map_err(|_| kernel_api::KapiError::Internal(-1))?;

        self.controller = Some(controller);
        Ok(())
    }

    fn start(&mut self) -> KapiResult<()> {
        if let Some(_ctrl) = &self.controller {
            AHCI_BRIDGE_READY.store(true, Ordering::Release);
            for port in 0..32u8 {
                let has_port = self
                    .controller
                    .as_ref()
                    .and_then(|controller| {
                        let controller = controller.lock().unwrap_or_else(|e| e.into_inner());
                        controller.with_port(PortNumber::new(port), |_| ()).map(|_| ())
                    })
                    .is_some();
                if !has_port {
                    continue;
                }

                let info = AbiBlockDeviceInfo {
                    device_id: (STORAGE_KIND_AHCI << 56) | port as u64,
                    namespace_id: 0,
                    block_size: SECTOR_SIZE as u32,
                    max_transfer_blocks: 0,
                    transport: AbiBlockTransport::Ahci as u32,
                    flags: 0,
                    controller_id: 0,
                    port_id: port as u32,
                };
                let registration = AbiBlockDeviceRegistration::new(
                    info,
                    port as u64,
                    ahci_block_submit,
                    ahci_block_poll,
                    ahci_block_is_ready,
                );
                let handle = kernel_api::service::kernel::instance()
                    .register_block_device(&registration)?;
                self.block_handles.push(handle);
            }
        }
        Ok(())
    }

    fn stop(&mut self) -> KapiResult<()> {
        AHCI_BRIDGE_READY.store(false, Ordering::Release);
        for handle in self.block_handles.drain(..) {
            let _ = kernel_api::service::kernel::instance().unregister_block_device(handle);
        }
        Ok(())
    }
}
