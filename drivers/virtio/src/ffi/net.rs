//! The service host retains this instance across every lifecycle suspension.
//! IRQ owns an independent runtime reference, so it never aliases the driver's
//! mutable operation borrow. Hardware and registration failures keep their
//! exact resources here until acknowledged stop/removal.
#![deny(unsafe_code)]

use crate::defs::VirtioDeviceType;
use crate::transport::{PciTransportDiscoveryError, VirtioPciTransport, VirtioTransport};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use exorust_sync::{Mutex, RwLock};
use kernel_api::abi::driver::{
    AbiError, AbiNetDriverEvent, AbiNetDriverEventKind, AbiNetPortRuntime, DriverContext,
    PackedPciLocation,
};
use kernel_api::driver::DriverIrqSource;
use kernel_api::{KapiError, KapiResult};

mod bootstrap;
mod callbacks;
mod retirement;

const LIFECYCLE_TIMEOUT_MS: u64 = 30_000;

pub(super) enum Phase {
    Resetting {
        deadline: u64,
    },
    Negotiating,
    Building(bootstrap::Building),
    Configured(bootstrap::Network),
    Live {
        network: bootstrap::Network,
        binding: AbiNetPortRuntime,
    },
    Stopping(retirement::Stopping),
    Closed,
    Transitioning,
}

pub(super) enum InterruptOwner {
    None,
    Allocated(kernel_api::msix::MsixVectorInfo),
    Bound(kernel_api::msix::MsixVectorInfo),
}

#[derive(Default)]
pub(super) struct Counters {
    tx_packets: AtomicU64,
    rx_packets: AtomicU64,
    tx_errors: AtomicU64,
    rx_errors: AtomicU64,
}

pub(super) struct Runtime {
    device: PackedPciLocation,
    transport: VirtioPciTransport,
    phase: RwLock<Phase>,
    interrupt: Mutex<InterruptOwner>,
    counters: Counters,
    // Acknowledged device IRQ reasons survive failed event admission. Queue
    // callbacks consume this merged notification independently of ring owners.
    pending_irq: AtomicU32,
}

pub(super) struct NetCell {
    runtime: Option<Arc<Runtime>>,
    registration: Option<u64>,
}

impl NetCell {
    pub(super) const fn new() -> Self {
        Self {
            runtime: None,
            registration: None,
        }
    }

    pub(super) fn irq_source(&self) -> Option<Arc<dyn DriverIrqSource>> {
        self.runtime
            .as_ref()
            .map(|runtime| Arc::clone(runtime) as Arc<dyn DriverIrqSource>)
    }

    pub(super) async fn probe(&mut self, context: &mut DriverContext) -> KapiResult<()> {
        if self.runtime.is_some() {
            return Err(KapiError::AlreadyExists);
        }
        let timer = timer()?;
        let deadline = deadline(timer.current_tick_ms())?;
        let device = context.pci_location();
        let transport = VirtioPciTransport::acquire(device, VirtioDeviceType::Network)
            .map_err(discovery_error)?;
        self.runtime = Some(
            Arc::try_new(Runtime {
                device,
                transport,
                phase: RwLock::new(Phase::Resetting { deadline }),
                interrupt: Mutex::new(InterruptOwner::None),
                counters: Counters::default(),
                pending_irq: AtomicU32::new(0),
            })
            .map_err(|_| KapiError::OutOfMemory)?,
        );
        let runtime = self.runtime.as_ref().ok_or(KapiError::NotFound)?;
        runtime.transport.request_reset();
        // LOOP_PROOF: mode=event; reason=Each bounded bootstrap step preserves its owners before the timer wait, and readiness, failure or a deadline ends probe.;
        loop {
            if runtime.advance_boot(context, timer.current_tick_ms())? {
                return Ok(());
            }
            kernel_api::service::time::SleepFuture::new(timer, 1)
                .await
                .map_err(KapiError::Timer)?;
        }
    }

    pub(super) async fn start(&mut self) -> KapiResult<()> {
        if self.registration.is_some() {
            return Ok(());
        }
        let runtime = self.runtime.as_ref().ok_or(KapiError::NotFound)?;
        let registration = callbacks::registration(runtime)?;
        match kernel_api::service::kernel::instance().register_netdev_port(&registration) {
            Ok(handle) => self.registration = Some(handle),
            Err(KapiError::NetRegistrationRetained { handle }) => {
                self.registration = Some(handle);
                return Err(KapiError::NetRegistrationRetained { handle });
            }
            Err(cause) => return Err(cause),
        }
        Ok(())
    }

    pub(super) async fn stop(&mut self) -> KapiResult<()> {
        let Some(runtime) = self.runtime.as_ref() else {
            return Ok(());
        };
        let timer = timer()?;
        let end = deadline(timer.current_tick_ms())?;
        // LOOP_PROOF: mode=event; reason=Closed admission and each retained stop step precede a timer wait, with completion or the bounded lifecycle deadline ending the operation.;
        loop {
            let result = match self.registration {
                Some(handle) => {
                    kernel_api::service::kernel::instance().unregister_netdev_port(handle)
                }
                None => runtime.advance_stop(timer.current_tick_ms()),
            };
            match result {
                Ok(()) => {
                    self.registration = None;
                    return Ok(());
                }
                Err(KapiError::Busy) if timer.current_tick_ms() < end => {}
                Err(cause) => return Err(cause),
            }
            kernel_api::service::time::SleepFuture::new(timer, 1)
                .await
                .map_err(KapiError::Timer)?;
        }
    }

    pub(super) async fn remove(&mut self) -> KapiResult<()> {
        self.stop().await?;
        self.runtime = None;
        Ok(())
    }
}

impl DriverIrqSource for Runtime {
    #[expect(
        unsafe_code,
        reason = "the live registration retains the foreign runtime cookie and code during relay notification"
    )]
    fn handle_irq(&self, vector: u32) -> bool {
        let expected = {
            let interrupt = self.interrupt.lock();
            match *interrupt {
                InterruptOwner::Bound(info) => Some(info.vector),
                _ => None,
            }
        };
        if expected != Some(vector) {
            return false;
        }
        let phase = self.phase.read();
        let status = self.transport.acknowledge_interrupt();
        if status == 0 {
            return false;
        }
        self.pending_irq.fetch_or(status, Ordering::Release);
        if let Phase::Live { binding, .. } = &*phase {
            // SAFETY: Live retains the runtime binding until stopped DMA and
            // packet returns are acknowledged. This read guard excludes its
            // unpublication through the synchronous event admission callback.
            let result = unsafe {
                (binding.schedule_event)(
                    binding.runtime_cookie,
                    AbiNetDriverEvent {
                        kind: AbiNetDriverEventKind::Interrupt as u32,
                        queue_index: 0,
                        _padding: 0,
                    },
                )
            };
            if !AbiError::from_raw(result).is_success() {
                log::warn!("VirtIO IRQ notification retained after event admission failure");
            }
        }
        true
    }
}

fn timer() -> KapiResult<&'static dyn kernel_api::service::time::TimeService> {
    kernel_api::service::time::try_instance().ok_or(KapiError::Timer(
        kernel_api::service::time::TimerError::ServiceUnavailable,
    ))
}
fn deadline(now: u64) -> KapiResult<u64> {
    now.checked_add(LIFECYCLE_TIMEOUT_MS)
        .ok_or(KapiError::Timer(
            kernel_api::service::time::TimerError::ClockExhausted,
        ))
}
fn discovery_error(cause: PciTransportDiscoveryError) -> KapiError {
    match cause {
        PciTransportDiscoveryError::Mapping(cause) => KapiError::Mmio(cause),
        PciTransportDiscoveryError::Allocation => KapiError::OutOfMemory,
        _ => KapiError::IoError,
    }
}
