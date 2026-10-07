//! USB driver lifecycle retains hardware and DMA owners through failed stop.

use crate::UsbError;
use crate::xhci::XhciController;
use crate::xhci::controller::ControllerRetirement;
use alloc::sync::Arc;
use kernel_api::abi::driver::PackedPciLocation;
use kernel_api::driver::{Driver, DriverType};
use kernel_api::mmio::PciMmioRequest;
use kernel_api::{KapiError, KapiResult};

#[expect(
    clippy::large_enum_variant,
    reason = "retirement owns DMA capabilities inline so entering shutdown cannot require allocation after hardware effects"
)]
enum UsbDriverState {
    Unprobed,
    Prepared(Arc<XhciController>),
    Running(Arc<XhciController>),
    Failed {
        controller: Arc<XhciController>,
        cause: UsbError,
    },
    AcquisitionFailed(UsbError),
    Halted(Arc<XhciController>),
    Retiring(ControllerRetirement),
    Removed,
}

/// Probe acquires resources; start owns hardware publication; removal finishes
/// DMA retirement before releasing register mappings. Busy keeps the owner.
pub struct UsbDriverWrapper {
    pci_locator: PackedPciLocation,
    state: UsbDriverState,
}

impl UsbDriverWrapper {
    pub fn new(pci_locator: PackedPciLocation) -> Self {
        Self {
            pci_locator,
            state: UsbDriverState::Unprobed,
        }
    }

    fn poll(&mut self) -> KapiResult<()> {
        let UsbDriverState::Running(controller) = &self.state else {
            return Err(KapiError::Busy);
        };
        if let Err(cause) = controller.process_events() {
            let error = map_usb_error(&cause);
            self.state = UsbDriverState::Failed {
                controller: Arc::clone(controller),
                cause,
            };
            return Err(error);
        }
        Ok(())
    }
}

impl Driver for UsbDriverWrapper {
    fn name(&self) -> &str {
        "usb_xhci"
    }
    fn driver_type(&self) -> DriverType {
        DriverType::Usb
    }

    fn probe(&mut self) -> KapiResult<()> {
        if !matches!(self.state, UsbDriverState::Unprobed) {
            return Err(KapiError::AlreadyExists);
        }
        let request = PciMmioRequest::whole_bar(self.pci_locator, 0)
            .map_err(|error| KapiError::Mmio(kernel_api::mmio::MmioAcquireError::Request(error)))?;
        let mapping = kernel_api::service::kernel::instance()
            .acquire_pci_mmio(request)
            .map_err(KapiError::Mmio)?;
        match XhciController::new(mapping, self.pci_locator) {
            Ok(controller) => self.state = UsbDriverState::Prepared(Arc::new(controller)),
            Err(cause) => {
                let error = map_usb_error(&cause);
                self.state = UsbDriverState::AcquisitionFailed(cause);
                return Err(error);
            }
        }
        Ok(())
    }

    fn start(&mut self) -> KapiResult<()> {
        let UsbDriverState::Prepared(controller) = &mut self.state else {
            return Err(KapiError::Busy);
        };
        let unique = Arc::get_mut(controller).ok_or(KapiError::Busy)?;
        if let Err(cause) = unique.init() {
            let error = map_usb_error(&cause);
            self.state = UsbDriverState::Failed {
                controller: Arc::clone(controller),
                cause,
            };
            return Err(error);
        }
        self.state = UsbDriverState::Running(Arc::clone(controller));
        Ok(())
    }

    fn stop(&mut self) -> KapiResult<()> {
        let controller = match &self.state {
            UsbDriverState::Prepared(controller)
            | UsbDriverState::Running(controller)
            | UsbDriverState::Failed { controller, .. } => controller,
            UsbDriverState::Halted(_) | UsbDriverState::Retiring(_) | UsbDriverState::Removed => {
                return Ok(());
            }
            UsbDriverState::Unprobed => return Ok(()),
            UsbDriverState::AcquisitionFailed(cause) => {
                log::warn!("xHCI acquisition retained resources: {cause:?}");
                return Err(KapiError::Busy);
            }
        };
        // Device objects and their polling Futures own additional Arc handles.
        // Their leases must retire before the driver can halt their queues.
        if Arc::strong_count(controller) != 1 {
            return Err(KapiError::Busy);
        }
        controller.stop().map_err(|cause| map_usb_error(&cause))?;
        self.state = UsbDriverState::Halted(Arc::clone(controller));
        Ok(())
    }

    fn remove(&mut self) -> KapiResult<()> {
        self.stop()?;
        let state = core::mem::replace(&mut self.state, UsbDriverState::Removed);
        match state {
            UsbDriverState::Halted(controller) => {
                let controller = match Arc::try_unwrap(controller) {
                    Ok(controller) => controller,
                    Err(controller) => {
                        self.state = UsbDriverState::Halted(controller);
                        return Err(KapiError::Busy);
                    }
                };
                match controller.into_retirement() {
                    Ok(retirement) => self.state = UsbDriverState::Retiring(retirement),
                    Err((cause, controller)) => {
                        let error = map_usb_error(&cause);
                        self.state = UsbDriverState::Failed {
                            controller: Arc::new(controller),
                            cause,
                        };
                        return Err(error);
                    }
                }
            }
            UsbDriverState::Retiring(retirement) => {
                self.state = UsbDriverState::Retiring(retirement)
            }
            UsbDriverState::Removed | UsbDriverState::Unprobed => return Ok(()),
            other => {
                self.state = other;
                return Err(KapiError::Busy);
            }
        }
        if let UsbDriverState::Retiring(retirement) = &mut self.state {
            retirement.finish().map_err(|cause| map_usb_error(&cause))?;
            self.state = UsbDriverState::Removed;
        }
        Ok(())
    }

    fn has_irq_handler(&self) -> bool {
        true
    }
    fn handle_irq(&mut self, _irq: u32) -> bool {
        match self.poll() {
            Ok(()) => true,
            Err(error) => {
                if let UsbDriverState::Failed { cause, .. } = &self.state {
                    log::error!("xHCI relay retained failed controller: {cause:?}");
                } else {
                    log::warn!("xHCI relay: {error}");
                }
                false
            }
        }
    }
}

fn map_usb_error(cause: &UsbError) -> KapiError {
    match cause {
        UsbError::Busy | UsbError::TransferInFlight { .. } => KapiError::Busy,
        UsbError::Timeout => KapiError::Timeout,
        UsbError::Timer(cause) => KapiError::Timer(*cause),
        UsbError::Allocation(cause) => *cause,
        UsbError::NoResources => KapiError::OutOfMemory,
        UsbError::InvalidController
        | UsbError::InvalidParameter
        | UsbError::InvalidDevice
        | UsbError::BufferSize
        | UsbError::Mmio(_) => KapiError::InvalidHandle,
        _ => KapiError::IoError,
    }
}
