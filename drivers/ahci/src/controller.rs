//! AHCI controller ownership and per-port capability admission.
//!
//! One controller consumes the complete HBA aperture, attenuates it into a
//! global register prefix and disjoint implemented-port apertures, and is the only
//! source of queue generations. Port DMA memory remains registry-owned.

#![deny(unsafe_code, unsafe_op_in_unsafe_fn)]
#![deny(clippy::missing_safety_doc, clippy::undocumented_unsafe_blocks)]

use alloc::boxed::Box;
use core::num::NonZeroUsize;

use hal::{MappedMmio, MmioAccessError};
use kernel_api::abi::driver::PackedPciLocation;
use kernel_api::dma::{CpuDmaLease, DmaLeaseError, DmaQueueIdentity, SharedDmaLease};

use crate::command::DmaAddressWidth;
use crate::port::{
    AhciPort, InitializationMemory, OpenCause, PortOpenError, PortShutdown, PortShutdownBlockCause,
    PortShutdownCause,
};
use crate::types::{
    GHC_AE, GHC_CAP, GHC_GHC, GHC_IE, GHC_PI, GHC_VS, PORT_BASE, PORT_SIZE, PortNumber,
};

const PORT_COUNT: usize = 32;
const CAP_S64A: u32 = 1 << 31;
const CAP2: usize = 0x24;
const BOHC: usize = 0x28;
const BOH: u32 = 1;
const BIOS_OWNED: u32 = 1;
const OS_OWNED: u32 = 1 << 1;
const OWNERSHIP_SMI_ENABLE: u32 = 1 << 2;
const BIOS_BUSY: u32 = 1 << 4;

/// Exclusive aperture during BIOS/OS handoff. No port or DMA address is
/// published until firmware ownership is observed released. A deadline is
/// policy owned by the caller; expiry must retain this acquisition.
#[derive(Debug)]
pub struct AhciAcquisition {
    mapping: MappedMmio,
    device: PackedPciLocation,
    handoff: FirmwareHandoff,
}

#[derive(Debug)]
enum FirmwareHandoff {
    NotImplemented,
    Requested,
}

/// Observing ownership never synthesizes release from a timeout.
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "handoff transfers a fixed controller owner without allocating after firmware release"
)]
pub enum AhciAcquisitionPoll {
    Waiting(AhciAcquisition),
    Ready(AhciController),
}

impl AhciAcquisition {
    /// Requests OS ownership using AHCI 1.3.1 section 10.6. Controllers before
    /// AHCI 1.2 have no CAP2/BOHC protocol.
    ///
    /// # Safety
    /// The mapping must be the complete UC AHCI BAR of `device`, reserved
    /// against other drivers and PCI reconfiguration. Boot services have ended;
    /// firmware DMA backing remains live until engines are observed stopped.
    /// Bus mastering and coherent DMA must belong to this same PCI function.
    ///
    /// # Errors
    /// Returns the complete mapping on validation or register failure. A BOHC
    /// write may already have requested ownership; it is never rolled back.
    #[expect(
        unsafe_code,
        reason = "exclusive PCI identity and firmware backing are platform facts"
    )]
    pub unsafe fn begin(
        mapping: MappedMmio,
        device: PackedPciLocation,
    ) -> Result<Self, ControllerOpenError> {
        if device.is_null() || mapping.len() < PORT_BASE as usize {
            return Err(ControllerOpenError {
                cause: if device.is_null() {
                    ControllerOpenCause::NullDevice
                } else {
                    ControllerOpenCause::ApertureTooSmall
                },
                mapping,
            });
        }
        let request = (|| {
            let region = mapping.region();
            let version = region.read_only::<u32>(GHC_VS as usize)?.read();
            if version < 0x0001_0200 || region.read_only::<u32>(CAP2)?.read() & BOH == 0 {
                return Ok(FirmwareHandoff::NotImplemented);
            }
            let status = region.read_only::<u32>(BOHC)?.read();
            // Preserve RW firmware bits and SMI enable, but write zero to OOC
            // (RWC). Reading that status is not an acknowledgement of release.
            region
                .write_only::<u32>(BOHC)?
                .write((status & (BIOS_OWNED | BIOS_BUSY | OWNERSHIP_SMI_ENABLE)) | OS_OWNED);
            Ok(FirmwareHandoff::Requested)
        })();
        match request {
            Ok(handoff) => Ok(Self {
                mapping,
                device,
                handoff,
            }),
            Err(cause) => Err(ControllerOpenError {
                cause: ControllerOpenCause::Registers(cause),
                mapping,
            }),
        }
    }

    /// Samples firmware ownership once, then either returns this same owner or
    /// consumes it to acquire the controller. Does not allocate or wait.
    ///
    /// # Errors
    /// Every failure returns the unsplit mapping and grants no port authority.
    pub fn poll(self) -> Result<AhciAcquisitionPoll, ControllerOpenError> {
        if matches!(self.handoff, FirmwareHandoff::Requested) {
            let status = match self.mapping.region().read_only::<u32>(BOHC) {
                Ok(register) => register.read(),
                Err(cause) => {
                    return Err(ControllerOpenError {
                        cause: ControllerOpenCause::Registers(cause),
                        mapping: self.mapping,
                    });
                }
            };
            if !firmware_released(status) {
                return Ok(AhciAcquisitionPoll::Waiting(self));
            }
        }
        #[expect(
            unsafe_code,
            reason = "acquisition owns the verified firmware handoff and PCI aperture"
        )]
        // SAFETY: begin established the external resource contract, and this
        // ownership-consuming sample observed firmware release where supported.
        unsafe { AhciController::open(self.mapping, self.device) }.map(AhciAcquisitionPoll::Ready)
    }
}

fn firmware_released(status: u32) -> bool {
    status & OS_OWNED != 0 && status & (BIOS_OWNED | BIOS_BUSY) == 0
}

/// Failure before the controller aperture has been split.
#[derive(Debug)]
pub struct ControllerOpenError {
    pub cause: ControllerOpenCause,
    pub mapping: MappedMmio,
}

/// Runtime-checkable controller acquisition failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControllerOpenCause {
    NullDevice,
    ApertureTooSmall,
    InvalidPortMap,
    Registers(MmioAccessError),
}

/// Port admission may preserve CPU, prepared, or shared DMA ownership.
#[derive(Debug)]
pub enum ControllerPortMemory {
    Cpu(CpuDmaLease),
    Initialization(InitializationMemory),
}

/// Failure to attach one controller-owned port.
#[derive(Debug)]
pub enum ControllerPortError {
    /// The port remains reusable and the allocation state is returned.
    Returned {
        cause: ControllerPortCause,
        memory: ControllerPortMemory,
    },
    /// Register or published-DMA state requires reset reconciliation.
    Quarantined {
        cause: ControllerPortCause,
        memory: Option<ControllerPortMemory>,
    },
}

/// Port identity/resource failure distinct from the port hardware protocol.
#[derive(Debug)]
pub enum ControllerPortCause {
    InvalidPort,
    NotImplemented,
    AlreadyAttached,
    QueueGenerationExhausted,
    EngineStateUnknown,
    Open(OpenCause),
}

/// Reason the one-way controller shutdown cannot currently advance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControllerShutdownCause {
    CommandActive,
    ResetRequired {
        cause: crate::port::PortFault,
        scope: ControllerResetScope,
    },
    EngineStateUnknown,
    PublicationUnknown(crate::port::PortFault),
    StopDeadline,
    Quiesce(DmaLeaseError),
    Unmap(DmaLeaseError),
}

/// Device state that must be covered by reset reconciliation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControllerResetScope {
    PortMetadata,
    PortMetadataAndTransfer,
}

/// Partial shutdown retains the only controller and allocation owners.
#[derive(Debug)]
pub struct ControllerShutdownError {
    pub failed_port: PortNumber,
    pub closed_ports: u32,
    pub cause: ControllerShutdownCause,
    pub shutdown: Box<AhciControllerShutdown>,
}

/// One-way controller owner after interrupt and submission authority is gone.
#[derive(Debug)]
pub struct AhciControllerShutdown {
    controller: AhciController,
    closed_ports: u32,
}

#[derive(Debug)]
enum PortSlot {
    Available(MappedMmio),
    Attached(AhciPort),
    EngineStateUnknown {
        registers: MappedMmio,
        queue: DmaQueueIdentity,
    },
    PublicationUnknown {
        cause: crate::port::PortFault,
        registers: MappedMmio,
        queue: DmaQueueIdentity,
        memory: SharedDmaLease,
    },
    Shutdown(PortShutdown),
    Closed,
    Transitioning,
}

#[derive(Debug)]
struct ControllerRegisters(MappedMmio);

impl ControllerRegisters {
    fn read(&self, offset: u32) -> u32 {
        self.0
            .region()
            .read_only::<u32>(offset as usize)
            .expect("controller register set was validated before splitting")
            .read()
    }

    fn write(&self, offset: u32, value: u32) {
        self.0
            .region()
            .write_only::<u32>(offset as usize)
            .expect("controller register set was validated before splitting")
            .write(value);
    }

    fn enable_ahci(&self) {
        let control = self.read(GHC_GHC);
        self.write(GHC_GHC, (control | GHC_AE) & !GHC_IE);
    }

    fn disable_interrupts(&self) {
        let control = self.read(GHC_GHC);
        self.write(GHC_GHC, control & !GHC_IE);
    }
}

/// Owns global AHCI registers, disjoint port apertures, and attached ports.
#[derive(Debug)]
pub struct AhciController {
    registers: ControllerRegisters,
    device: PackedPciLocation,
    ports_implemented: u32,
    slots: [PortSlot; PORT_COUNT],
    version: u32,
    command_slots: u8,
    address_width: DmaAddressWidth,
    next_queue_generation: u64,
}

impl AhciController {
    /// PCI identity retained by this controller's mapping and DMA queues.
    pub const fn device(&self) -> PackedPciLocation {
        self.device
    }

    /// Acquires an exclusive controller aperture and enables AHCI mode.
    /// Interrupts remain disabled because the current port owner polls slot 0.
    ///
    /// # Safety
    /// `mapping` must be the complete AHCI BAR for exactly `device`; the PCI
    /// resource owner must have completed firmware handoff and excluded every
    /// competing driver. The aperture must remain mapped with correct device
    /// cache attributes through its retained owner. Bus mastering and coherent
    /// DMA must describe this device, and reset/replacement must not occur behind
    /// the returned owner.
    ///
    /// # Errors
    /// Validation failure occurs before AHCI mode is enabled and returns the
    /// original unsplit mapping.
    #[expect(
        unsafe_code,
        reason = "PCI resource identity and firmware handoff are external facts"
    )]
    unsafe fn open(
        mapping: MappedMmio,
        device: PackedPciLocation,
    ) -> Result<Self, ControllerOpenError> {
        if device.is_null() {
            return Err(ControllerOpenError {
                cause: ControllerOpenCause::NullDevice,
                mapping,
            });
        }
        if mapping.len() < PORT_BASE as usize {
            return Err(ControllerOpenError {
                cause: ControllerOpenCause::ApertureTooSmall,
                mapping,
            });
        }
        let read = |offset| {
            mapping
                .region()
                .read_only::<u32>(offset)
                .map(|register| register.read())
        };
        let values = read(GHC_CAP as usize)
            .and_then(|capability| {
                read(GHC_PI as usize).map(|ports_implemented| (capability, ports_implemented))
            })
            .and_then(|(capability, ports_implemented)| {
                read(GHC_VS as usize).map(|version| (capability, ports_implemented, version))
            })
            .and_then(|values| read(GHC_GHC as usize).map(|_| values));
        let (capability, ports_implemented, version) = match values {
            Ok(values) => values,
            Err(cause) => {
                return Err(ControllerOpenError {
                    cause: ControllerOpenCause::Registers(cause),
                    mapping,
                });
            }
        };

        let bytes = match hba_bytes(capability, ports_implemented) {
            Ok(bytes) => bytes,
            Err(cause) => {
                return Err(ControllerOpenError { cause, mapping });
            }
        };
        if mapping.len() < bytes {
            return Err(ControllerOpenError {
                cause: ControllerOpenCause::ApertureTooSmall,
                mapping,
            });
        }
        let mapping = retain_hba_prefix(mapping, bytes);
        let (global, port_mappings) = split_hba(mapping, ports_implemented);
        let registers = ControllerRegisters(global);
        registers.enable_ahci();

        Ok(Self {
            registers,
            device,
            ports_implemented,
            slots: port_mappings
                .map(|mapping| mapping.map_or(PortSlot::Closed, PortSlot::Available)),
            version,
            command_slots: (((capability >> 8) & 0x1f) as u8) + 1,
            address_width: if capability & CAP_S64A == 0 {
                DmaAddressWidth::Bits32
            } else {
                DmaAddressWidth::Bits64
            },
            next_queue_generation: 1,
        })
    }

    /// Bitmask reported by HBA PI.
    pub const fn ports_implemented(&self) -> u32 {
        self.ports_implemented
    }

    /// AHCI version register value.
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Number of command slots advertised by CAP.NCS.
    pub const fn command_slots(&self) -> u8 {
        self.command_slots
    }

    /// Device DMA width used to admit matching IOMMU allocations.
    pub const fn address_width(&self) -> DmaAddressWidth {
        self.address_width
    }

    /// Returns whether a SATA port is attached to this owner.
    pub fn contains_port(&self, port: PortNumber) -> bool {
        self.slots
            .get(port.as_usize())
            .is_some_and(|slot| matches!(slot, PortSlot::Attached(_)))
    }

    /// Borrows an attached port under the controller's exclusive borrow.
    pub fn port_mut(&mut self, port: PortNumber) -> Option<&mut AhciPort> {
        match self.slots.get_mut(port.as_usize())? {
            PortSlot::Attached(port) => Some(port),
            _ => None,
        }
    }

    /// Attaches one implemented port using registry-owned metadata memory.
    /// The controller creates the queue identity and does not reuse a consumed
    /// generation, including after failed hardware initialization.
    ///
    /// # Errors
    /// Pre-admission errors return the CPU lease. Port initialization errors
    /// return its exact transition state while the register aperture is restored
    /// to this controller.
    pub fn attach_port(
        &mut self,
        port: PortNumber,
        memory: CpuDmaLease,
        poll_budget: NonZeroUsize,
    ) -> Result<(), ControllerPortError> {
        if !port.is_valid() {
            return Err(returned_port_error(
                ControllerPortCause::InvalidPort,
                ControllerPortMemory::Cpu(memory),
            ));
        }
        let bit = 1u32 << u32::from(port.as_u8());
        if self.ports_implemented & bit == 0 {
            return Err(returned_port_error(
                ControllerPortCause::NotImplemented,
                ControllerPortMemory::Cpu(memory),
            ));
        }
        let index = port.as_usize();
        let Some(slot) = self.slots.get_mut(index) else {
            return Err(returned_port_error(
                ControllerPortCause::InvalidPort,
                ControllerPortMemory::Cpu(memory),
            ));
        };
        if !matches!(slot, PortSlot::Available(_)) {
            return Err(returned_port_error(
                ControllerPortCause::AlreadyAttached,
                ControllerPortMemory::Cpu(memory),
            ));
        }
        let Some(next_generation) = self.next_queue_generation.checked_add(1) else {
            return Err(returned_port_error(
                ControllerPortCause::QueueGenerationExhausted,
                ControllerPortMemory::Cpu(memory),
            ));
        };
        let generation = self.next_queue_generation;
        self.next_queue_generation = next_generation;
        let Some(queue) = DmaQueueIdentity::new(self.device, u16::from(port.as_u8()), generation)
        else {
            return Err(returned_port_error(
                ControllerPortCause::QueueGenerationExhausted,
                ControllerPortMemory::Cpu(memory),
            ));
        };
        let PortSlot::Available(mapping) = core::mem::replace(slot, PortSlot::Transitioning) else {
            unreachable!("availability was checked under the same exclusive borrow")
        };

        #[expect(
            unsafe_code,
            reason = "the controller acquisition binds each attenuated aperture to its queue"
        )]
        // SAFETY: `open` established exclusive device ownership and CAP.S64A;
        // `split_hba` created this port's disjoint aperture, and the controller
        // is the only queue-generation source. The allocation remains owned by
        // the registry and is consumed by `AhciPort` on success.
        let opened =
            unsafe { AhciPort::attach(mapping, queue, self.address_width, memory, poll_budget) };
        match opened {
            Ok(port) => {
                *slot = PortSlot::Attached(port);
                Ok(())
            }
            Err(PortOpenError::Rejected {
                cause,
                registers,
                memory,
            }) => {
                *slot = PortSlot::Available(registers);
                Err(returned_port_error(
                    ControllerPortCause::Open(cause),
                    ControllerPortMemory::Initialization(memory),
                ))
            }
            Err(PortOpenError::EngineStateUnknown {
                registers,
                queue,
                memory,
            }) => {
                *slot = PortSlot::EngineStateUnknown { registers, queue };
                Err(ControllerPortError::Quarantined {
                    cause: ControllerPortCause::EngineStateUnknown,
                    memory: Some(ControllerPortMemory::Cpu(memory)),
                })
            }
            Err(PortOpenError::PublicationUnknown {
                cause,
                registers,
                queue,
                memory,
            }) => {
                *slot = PortSlot::PublicationUnknown {
                    cause,
                    registers,
                    queue,
                    memory,
                };
                Err(ControllerPortError::Quarantined {
                    cause: ControllerPortCause::Open(OpenCause::Port(cause)),
                    memory: None,
                })
            }
        }
    }

    /// Irreversibly removes interrupt and submission authority.
    pub fn begin_shutdown(self) -> Box<AhciControllerShutdown> {
        let shutdown = Box::new(AhciControllerShutdown {
            controller: self,
            closed_ports: 0,
        });
        shutdown.controller.registers.disable_interrupts();
        shutdown
    }
}

impl AhciControllerShutdown {
    /// Advances each port through stop, DMA quiescence, and fallible unmap.
    ///
    /// # Errors
    /// The first blocked transition returns this one-way owner. No failed or
    /// unvisited port can be recovered as an operational controller.
    pub fn advance(
        mut self: Box<Self>,
        poll_budget: NonZeroUsize,
    ) -> Result<(), ControllerShutdownError> {
        for index in 0..PORT_COUNT {
            let Some(slot) = self.controller.slots.get_mut(index) else {
                unreachable!("fixed loop range indexes the fixed port table")
            };
            let state = core::mem::replace(slot, PortSlot::Transitioning);
            let shutdown = match state {
                PortSlot::Available(mapping) => {
                    drop(mapping);
                    *slot = PortSlot::Closed;
                    continue;
                }
                PortSlot::Attached(port) => match port.begin_shutdown() {
                    Ok(shutdown) => shutdown,
                    Err(blocked) => {
                        let cause = match blocked.cause {
                            PortShutdownBlockCause::CommandActive => {
                                ControllerShutdownCause::CommandActive
                            }
                            PortShutdownBlockCause::ResetRequired {
                                cause,
                                transfer_retained,
                            } => ControllerShutdownCause::ResetRequired {
                                cause,
                                scope: if transfer_retained {
                                    ControllerResetScope::PortMetadataAndTransfer
                                } else {
                                    ControllerResetScope::PortMetadata
                                },
                            },
                        };
                        *slot = PortSlot::Attached(blocked.port);
                        return Err(ControllerShutdownError {
                            failed_port: PortNumber::new(index as u8),
                            closed_ports: self.closed_ports,
                            cause,
                            shutdown: self,
                        });
                    }
                },
                PortSlot::EngineStateUnknown { registers, queue } => {
                    *slot = PortSlot::EngineStateUnknown { registers, queue };
                    return Err(ControllerShutdownError {
                        failed_port: PortNumber::new(index as u8),
                        closed_ports: self.closed_ports,
                        cause: ControllerShutdownCause::EngineStateUnknown,
                        shutdown: self,
                    });
                }
                PortSlot::PublicationUnknown {
                    cause,
                    registers,
                    queue,
                    memory,
                } => {
                    *slot = PortSlot::PublicationUnknown {
                        cause,
                        registers,
                        queue,
                        memory,
                    };
                    return Err(ControllerShutdownError {
                        failed_port: PortNumber::new(index as u8),
                        closed_ports: self.closed_ports,
                        cause: ControllerShutdownCause::PublicationUnknown(cause),
                        shutdown: self,
                    });
                }
                PortSlot::Shutdown(shutdown) => shutdown,
                PortSlot::Closed => {
                    *slot = PortSlot::Closed;
                    continue;
                }
                PortSlot::Transitioning => {
                    unreachable!("exclusive controller ownership prevents a concurrent transition")
                }
            };
            match shutdown.advance(poll_budget) {
                Ok(()) => {
                    *slot = PortSlot::Closed;
                    self.closed_ports |= 1u32 << index;
                }
                Err(failure) => {
                    *slot = PortSlot::Shutdown(failure.owner);
                    return Err(ControllerShutdownError {
                        failed_port: PortNumber::new(index as u8),
                        closed_ports: self.closed_ports,
                        cause: map_shutdown_cause(failure.cause),
                        shutdown: self,
                    });
                }
            }
        }
        Ok(())
    }
}

const fn map_shutdown_cause(cause: PortShutdownCause) -> ControllerShutdownCause {
    match cause {
        PortShutdownCause::StopDeadline => ControllerShutdownCause::StopDeadline,
        PortShutdownCause::Quiesce(cause) => ControllerShutdownCause::Quiesce(cause),
        PortShutdownCause::Unmap(cause) => ControllerShutdownCause::Unmap(cause),
    }
}

fn returned_port_error(
    cause: ControllerPortCause,
    memory: ControllerPortMemory,
) -> ControllerPortError {
    ControllerPortError::Returned { cause, memory }
}

/// AHCI 1.3.1 sections 2.1.11 and 3.1.4: PI selects register banks, including
/// sparse numbering. CAP.NP limits the number of asserted bits, not their indices.
fn hba_bytes(capability: u32, implemented: u32) -> Result<usize, ControllerOpenCause> {
    if implemented == 0 || implemented.count_ones() > (capability & 0x1f) + 1 {
        return Err(ControllerOpenCause::InvalidPortMap);
    }
    Ok(
        PORT_BASE as usize
            + (u32::BITS - implemented.leading_zeros()) as usize * PORT_SIZE as usize,
    )
}

fn retain_hba_prefix(mapping: MappedMmio, bytes: usize) -> MappedMmio {
    if mapping.len() == bytes {
        return mapping;
    }
    let Ok((prefix, _unused)) = mapping.split_at(bytes) else {
        unreachable!("the caller validated the complete HBA prefix")
    };
    prefix
}

fn split_hba(
    mapping: MappedMmio,
    implemented: u32,
) -> (MappedMmio, [Option<MappedMmio>; PORT_COUNT]) {
    let Ok((global, tail)) = mapping.split_at(PORT_BASE as usize) else {
        unreachable!("the HBA prefix contains global and port registers")
    };
    let mut tail = Some(tail);
    let mut ports = core::array::from_fn(|_| None);
    let banks = (u32::BITS - implemented.leading_zeros()) as usize;
    for index in 0..banks {
        let remaining = tail
            .take()
            .expect("one exact port aperture remains for each iteration");
        let (port, rest) = if index + 1 == banks {
            (remaining, None)
        } else {
            let Ok((port, rest)) = remaining.split_at(PORT_SIZE as usize) else {
                unreachable!("the HBA prefix was validated before splitting")
            };
            (port, Some(rest))
        };
        if implemented & (1 << index) != 0 {
            *ports
                .get_mut(index)
                .expect("the validated port bitmap indexes the fixed port array") = Some(port);
        }
        tail = rest;
    }
    (global, ports)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::PX_CI;
    const REGISTER_RAM_BYTES: usize = 0x1100;

    #[test]
    fn aperture_tracks_implemented_banks_including_sparse_port_numbers() {
        assert_eq!(hba_bytes(0, 1), Ok(0x180));
        assert_eq!(hba_bytes(5, 0x3f), Ok(0x400));
        assert_eq!(hba_bytes(0, 1 << 31), Ok(0x1100));
        assert_eq!(hba_bytes(31, u32::MAX), Ok(0x1100));
        assert_eq!(hba_bytes(0, 0), Err(ControllerOpenCause::InvalidPortMap));
        assert_eq!(hba_bytes(0, 3), Err(ControllerOpenCause::InvalidPortMap));
        assert_eq!(
            PORT_BASE as usize + 31 * PORT_SIZE as usize + PX_CI as usize + 4,
            0x10bc
        );
    }

    #[test]
    fn ownership_requires_os_request_and_firmware_release() {
        assert!(!firmware_released(0));
        assert!(!firmware_released(BIOS_OWNED));
        assert!(!firmware_released(OS_OWNED | BIOS_OWNED));
        assert!(!firmware_released(OS_OWNED | BIOS_BUSY));
        assert!(firmware_released(OS_OWNED));
        assert!(firmware_released(OS_OWNED | OWNERSHIP_SMI_ENABLE));
    }

    struct RegisterRam(core::cell::UnsafeCell<[u32; REGISTER_RAM_BYTES / 4]>);

    #[expect(
        unsafe_code,
        reason = "private MMIO fixture uses interior-mutable register storage"
    )]
    // SAFETY: this fixture is confined to one test thread; every register
    // access uses a raw volatile operation, never an aliased Rust reference.
    unsafe impl Sync for RegisterRam {}

    impl RegisterRam {
        #[expect(
            unsafe_code,
            reason = "register fixture simulates a firmware register write"
        )]
        fn write(&self, offset: usize, value: u32) {
            assert!(offset.is_multiple_of(4) && offset < REGISTER_RAM_BYTES);
            // SAFETY: the asserted offset belongs to the aligned UnsafeCell
            // allocation; the single-threaded fixture has no CPU byte borrows.
            unsafe {
                self.0
                    .get()
                    .cast::<u32>()
                    .add(offset / 4)
                    .write_volatile(value)
            };
        }
    }

    #[expect(
        unsafe_code,
        reason = "the private initialized register allocation retains each simulated PCI mapping"
    )]
    fn register_mapping(
        capability: u32,
        implemented: u32,
        bytes: usize,
    ) -> (alloc::sync::Arc<RegisterRam>, MappedMmio) {
        let ram = alloc::sync::Arc::new(RegisterRam(core::cell::UnsafeCell::new(
            [0; REGISTER_RAM_BYTES / 4],
        )));
        ram.write(GHC_CAP as usize, capability);
        ram.write(GHC_PI as usize, implemented);
        ram.write(GHC_VS as usize, 0x0001_0301);
        assert!(bytes <= REGISTER_RAM_BYTES);
        // SAFETY: initialized aligned UnsafeCell words have no competing owner,
        // and the retained Arc covers every byte in the advertised aperture.
        let mapping =
            unsafe { MappedMmio::from_raw_parts(ram.clone(), ram.0.get().addr(), bytes) }.unwrap();
        (ram, mapping)
    }

    #[test]
    #[expect(
        unsafe_code,
        reason = "private simulated PCI resources have no firmware or hardware DMA"
    )]
    fn controller_admits_small_and_sparse_port_apertures() {
        for (capability, implemented, bytes) in
            [(0, 1, 0x200), (5, 0x3f, 0x1000), (0, 1 << 31, 0x1100)]
        {
            let (ram, mapping) = register_mapping(capability, implemented, bytes);
            let weak = alloc::sync::Arc::downgrade(&ram);
            // SAFETY: the mapping is exclusive initialized fixture RAM for this
            // PCI identity and contains no firmware or hardware DMA activity.
            let acquisition =
                unsafe { AhciAcquisition::begin(mapping, PackedPciLocation::new(0, 0, 31, 2)) }
                    .unwrap();
            let AhciAcquisitionPoll::Ready(controller) = acquisition.poll().unwrap() else {
                panic!("CAP2 does not request firmware handoff in this fixture")
            };
            assert_eq!(controller.ports_implemented(), implemented);
            assert_eq!(controller.registers.read(GHC_GHC), GHC_AE);
            drop(ram);
            assert!(weak.upgrade().is_some());
            drop(controller);
            assert!(weak.upgrade().is_none());
        }
    }

    #[test]
    #[expect(
        unsafe_code,
        reason = "private simulated PCI resources have no firmware or hardware DMA"
    )]
    fn invalid_port_admission_retains_the_unsplit_mapping_before_enabling_ahci() {
        for (capability, implemented, bytes, expected) in [
            (0, 0, 0x200, ControllerOpenCause::InvalidPortMap),
            (0, 3, 0x200, ControllerOpenCause::InvalidPortMap),
            (0, 1 << 31, 0x1000, ControllerOpenCause::ApertureTooSmall),
        ] {
            let (ram, mapping) = register_mapping(capability, implemented, bytes);
            let weak = alloc::sync::Arc::downgrade(&ram);
            // SAFETY: the mapping exclusively retains initialized fixture RAM
            // for this PCI identity without firmware or hardware DMA activity.
            let acquisition =
                unsafe { AhciAcquisition::begin(mapping, PackedPciLocation::new(0, 0, 31, 2)) }
                    .unwrap();
            let error = acquisition.poll().unwrap_err();
            assert_eq!(error.cause, expected);
            assert_eq!(error.mapping.len(), bytes);
            assert_eq!(
                error
                    .mapping
                    .region()
                    .read_only::<u32>(GHC_GHC as usize)
                    .unwrap()
                    .read(),
                0
            );
            drop(ram);
            assert!(weak.upgrade().is_some());
            drop(error);
            assert!(weak.upgrade().is_none());
        }
    }

    #[test]
    #[expect(
        unsafe_code,
        reason = "private initialized register RAM supplies the simulated PCI resource facts"
    )]
    fn acquisition_keeps_registers_and_waits_for_actual_firmware_release() {
        use alloc::sync::Arc;
        let ram = Arc::new(RegisterRam(core::cell::UnsafeCell::new(
            [0; REGISTER_RAM_BYTES / 4],
        )));
        ram.write(GHC_PI as usize, 1);
        ram.write(GHC_VS as usize, 0x0001_0301);
        ram.write(CAP2, BOH);
        ram.write(
            BOHC,
            BIOS_OWNED | BIOS_BUSY | OWNERSHIP_SMI_ENABLE | (1 << 3),
        );
        let weak = Arc::downgrade(&ram);
        // SAFETY: the interior-mutable words are initialized and aligned; the
        // retained Arc covers this complete aperture for every derived access.
        let mapping = unsafe {
            MappedMmio::from_raw_parts(ram.clone(), ram.0.get().addr(), REGISTER_RAM_BYTES)
        }
        .unwrap();
        let device = PackedPciLocation::new(0, 0, 31, 2);
        // SAFETY: this is the fixture's only register owner; no device DMA or
        // real firmware exists, and the PCI identity is bound to this aperture.
        let acquisition = unsafe { AhciAcquisition::begin(mapping, device) }.unwrap();
        let AhciAcquisitionPoll::Waiting(acquisition) = acquisition.poll().unwrap() else {
            panic!("BIOS ownership must prevent controller admission")
        };
        assert_eq!(
            acquisition
                .mapping
                .region()
                .read_only::<u32>(BOHC)
                .unwrap()
                .read(),
            BIOS_OWNED | BIOS_BUSY | OWNERSHIP_SMI_ENABLE | OS_OWNED
        );
        assert_eq!(
            acquisition
                .mapping
                .region()
                .read_only::<u32>(GHC_GHC as usize)
                .unwrap()
                .read(),
            0
        );
        ram.write(BOHC, OS_OWNED);
        drop(ram);
        let AhciAcquisitionPoll::Ready(controller) = acquisition.poll().unwrap() else {
            panic!("released firmware ownership must admit the controller")
        };
        assert!(weak.upgrade().is_some());
        assert_eq!(controller.device(), device);
        assert_eq!(controller.registers.read(GHC_GHC), GHC_AE);
        drop(controller);
        assert!(weak.upgrade().is_none());
    }
}
