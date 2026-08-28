//! AHCI controller ownership and per-port capability admission.
//!
//! One controller consumes the complete HBA aperture, attenuates it into a
//! global register prefix and 32 disjoint port apertures, and is the only
//! source of queue generations. Port DMA memory remains registry-owned.

#![deny(unsafe_code, unsafe_op_in_unsafe_fn)]
#![deny(clippy::missing_safety_doc, clippy::undocumented_unsafe_blocks)]

use core::num::NonZeroUsize;

use hal::{MappedMmio, MmioAccessError};
use kernel_api::abi::driver::PackedPciLocation;
use kernel_api::dma::{CpuDmaLease, DmaQueueIdentity, SharedDmaLease};

use crate::command::DmaAddressWidth;
use crate::port::{AhciPort, InitializationMemory, OpenCause, PortCloseError, PortOpenError};
use crate::types::{
    GHC_AE, GHC_CAP, GHC_GHC, GHC_IE, GHC_PI, GHC_VS, PORT_BASE, PORT_SIZE, PX_CI, PortNumber,
};

const PORT_COUNT: usize = 32;
const HBA_REGISTER_BYTES: usize = PORT_BASE as usize + PORT_COUNT * PORT_SIZE as usize;
const CAP_S64A: u32 = 1 << 31;

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

/// Resources retained at the first controller shutdown failure.
#[derive(Debug)]
pub enum ControllerCloseFailure {
    Port(PortCloseError),
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
}

/// Partial controller shutdown keeps the failed port resources and all ports
/// not yet visited. `closed_ports` identifies allocations already reclaimed.
#[derive(Debug)]
pub struct ControllerCloseError {
    pub failed_port: PortNumber,
    pub closed_ports: u32,
    pub failure: ControllerCloseFailure,
    pub controller: AhciController,
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
    pub unsafe fn open(
        mapping: MappedMmio,
        device: PackedPciLocation,
    ) -> Result<Self, ControllerOpenError> {
        if device.is_null() {
            return Err(ControllerOpenError {
                cause: ControllerOpenCause::NullDevice,
                mapping,
            });
        }
        if mapping.len() < HBA_REGISTER_BYTES {
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
            .and_then(|values| read(GHC_GHC as usize).map(|_| values))
            .and_then(|values| {
                read(PORT_BASE as usize + (PORT_COUNT - 1) * PORT_SIZE as usize + PX_CI as usize)
                    .map(|_| values)
            });
        let (capability, ports_implemented, version) = match values {
            Ok(values) => values,
            Err(cause) => {
                return Err(ControllerOpenError {
                    cause: ControllerOpenCause::Registers(cause),
                    mapping,
                });
            }
        };

        let mapping = retain_hba_prefix(mapping);
        let (global, port_mappings) = split_hba(mapping);
        let registers = ControllerRegisters(global);
        registers.enable_ahci();

        Ok(Self {
            registers,
            device,
            ports_implemented,
            slots: port_mappings.map(|mapping| {
                let Some(mapping) = mapping else {
                    unreachable!("every hardware port has one attenuated aperture")
                };
                PortSlot::Available(mapping)
            }),
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

    /// Explicitly closes every attached port in ascending hardware order.
    ///
    /// # Errors
    /// The first failed port is returned with its exact resources. Ports already
    /// closed are recorded in `closed_ports`; all later ports stay in the
    /// returned controller and have not begun shutdown.
    #[expect(
        clippy::result_large_err,
        reason = "partial shutdown must return all live port owners without a new fallible allocation"
    )]
    pub fn close(mut self, poll_budget: NonZeroUsize) -> Result<(), ControllerCloseError> {
        self.registers.disable_interrupts();
        let mut closed_ports = 0u32;
        for index in 0..PORT_COUNT {
            let Some(slot) = self.slots.get_mut(index) else {
                unreachable!("fixed loop range indexes the fixed port table")
            };
            let state = core::mem::replace(slot, PortSlot::Transitioning);
            let failure = match state {
                PortSlot::Available(mapping) => {
                    *slot = PortSlot::Available(mapping);
                    continue;
                }
                PortSlot::Attached(port) => match port.close(poll_budget) {
                    Ok(()) => {
                        closed_ports |= 1u32 << index;
                        continue;
                    }
                    Err(failure) => ControllerCloseFailure::Port(failure),
                },
                PortSlot::EngineStateUnknown { registers, queue } => {
                    ControllerCloseFailure::EngineStateUnknown { registers, queue }
                }
                PortSlot::PublicationUnknown {
                    cause,
                    registers,
                    queue,
                    memory,
                } => ControllerCloseFailure::PublicationUnknown {
                    cause,
                    registers,
                    queue,
                    memory,
                },
                PortSlot::Transitioning => {
                    unreachable!("exclusive controller ownership prevents a concurrent transition")
                }
            };
            return Err(ControllerCloseError {
                failed_port: PortNumber::new(index as u8),
                closed_ports,
                failure,
                controller: self,
            });
        }
        Ok(())
    }
}

fn returned_port_error(
    cause: ControllerPortCause,
    memory: ControllerPortMemory,
) -> ControllerPortError {
    ControllerPortError::Returned { cause, memory }
}

fn retain_hba_prefix(mapping: MappedMmio) -> MappedMmio {
    if mapping.len() == HBA_REGISTER_BYTES {
        return mapping;
    }
    let Ok((prefix, _unused)) = mapping.split_at(HBA_REGISTER_BYTES) else {
        unreachable!("the caller validated the complete HBA prefix")
    };
    prefix
}

fn split_hba(mapping: MappedMmio) -> (MappedMmio, [Option<MappedMmio>; PORT_COUNT]) {
    let Ok((global, tail)) = mapping.split_at(PORT_BASE as usize) else {
        unreachable!("the HBA prefix contains global and port registers")
    };
    let mut tail = Some(tail);
    let mut ports = core::array::from_fn(|_| None);
    for index in 0..PORT_COUNT {
        let remaining = tail
            .take()
            .expect("one exact port aperture remains for each iteration");
        let (port, rest) = if index + 1 == PORT_COUNT {
            (remaining, None)
        } else {
            let Ok((port, rest)) = remaining.split_at(PORT_SIZE as usize) else {
                unreachable!("the HBA prefix was validated before splitting")
            };
            (port, Some(rest))
        };
        *ports
            .get_mut(index)
            .expect("fixed loop range indexes the fixed port array") = Some(port);
        tail = rest;
    }
    (global, ports)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aperture_size_covers_every_port_register_set() {
        assert_eq!(HBA_REGISTER_BYTES, 0x1100);
        assert_eq!(
            PORT_BASE as usize + 31 * PORT_SIZE as usize + PX_CI as usize + 4,
            0x10bc
        );
    }
}
