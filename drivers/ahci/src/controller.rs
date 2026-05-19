//! AHCI Controller Implementation
//!
//! Manages HBA and port initialization.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use exorust_sync::PoisonLock;
use kernel_api::abi::driver::PackedPciLocation;

use super::port::AhciPort;
use super::types::{
    AhciResult, GHC_AE, GHC_CAP, GHC_GHC, GHC_IE, GHC_PI, GHC_VS, PORT_BASE, PORT_SIZE, PX_SSTS,
    PortNumber,
};

/// AHCI Controller
pub struct AhciController {
    base: u64,
    ports_implemented: u32,
    ports: Vec<Arc<PoisonLock<AhciPort>>>,
    version: u32,
    command_slots: u8,
}

impl AhciController {
    pub fn new(base: u64, device_id: PackedPciLocation) -> AhciResult<Self> {
        let cap = hal::mmio::mmio_read_u32((base + GHC_CAP as u64) as usize);
        let pi = hal::mmio::mmio_read_u32((base + GHC_PI as u64) as usize);
        let vs = hal::mmio::mmio_read_u32((base + GHC_VS as u64) as usize);

        let command_slots = ((cap >> 8) & 0x1F) as u8 + 1;
        let _version_major = (vs >> 16) & 0xFFFF;
        let _version_minor = vs & 0xFFFF;

        let mut ports = Vec::new();

        // Initialize ports here, as per the diff's placement
        for i in 0..32 {
            if pi & (1 << i) != 0 {
                // Try to allocate new port. If fails (OOM), we skip it.
                if let Some(mut port) = AhciPort::new(base, PortNumber::new(i as u8), device_id) {
                    let ssts = hal::mmio::mmio_read_u32(
                        (base + PORT_BASE as u64 + (i as u64 * PORT_SIZE as u64) + PX_SSTS as u64)
                            as usize,
                    );
                    let det = ssts & 0x0F;

                    if det == 3 {
                        // Device detected, init it
                        // If init fails, we still keep the port structure but maybe not active
                        if port.init().is_ok() {
                            ports.push(Arc::new(PoisonLock::new(port)));
                        }
                    }
                }
            }
        }

        Ok(Self {
            base,
            ports_implemented: pi,
            ports,
            version: vs,
            command_slots,
        })
    }

    pub fn init(&mut self) -> AhciResult<()> {
        let mut ghc = self.read_ghc(GHC_GHC);
        ghc |= GHC_AE;
        self.write_ghc(GHC_GHC, ghc);

        // The port initialization logic has been moved to the `new` function based on the diff.
        // This `init` function now only handles GHC_AE and GHC_IE.

        ghc = self.read_ghc(GHC_GHC);
        ghc |= GHC_IE;
        self.write_ghc(GHC_GHC, ghc);

        Ok(())
    }

    /// Get implemented ports bitmask
    pub fn ports_implemented(&self) -> u32 {
        self.ports_implemented
    }

    /// Get AHCI version
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Get maximum command slots
    pub fn command_slots(&self) -> u8 {
        self.command_slots
    }

    pub fn port(&self, _port: PortNumber) -> Option<Arc<PoisonLock<AhciPort>>> {
        None
    }

    // Accessor for ports via index, intended to be used when lock is held or by internal methods
    pub fn get_port_start_index(&self) -> Option<usize> {
        // finding first implemented port
        for i in 0..32 {
            if (self.ports_implemented & (1 << i)) != 0 {
                return Some(i);
            }
        }
        None
    }

    // Helper to run closure on a port
    pub fn with_port<F, R>(&self, port_num: PortNumber, f: F) -> Option<R>
    where
        F: FnOnce(&mut AhciPort) -> R,
    {
        if let Some(port_lock) = self.ports.get(port_num.as_usize()) {
            let mut port = port_lock.lock().unwrap_or_else(|e| e.into_inner());
            Some(f(&mut *port))
        } else {
            None
        }
    }

    pub fn read_ghc(&self, offset: u32) -> u32 {
        hal::mmio::mmio_read_u32((self.base + offset as u64) as usize)
    }

    pub fn write_ghc(&self, offset: u32, value: u32) {
        hal::mmio::mmio_write_u32((self.base + offset as u64) as usize, value);
    }

    pub fn read_port_reg(&self, port: PortNumber, offset: u32) -> u32 {
        let addr =
            self.base + PORT_BASE as u64 + (port.as_u8() as u64 * PORT_SIZE as u64) + offset as u64;
        hal::mmio::mmio_read_u32(addr as usize)
    }
}

pub fn init_from_pci(
    base_addr: u64,
    device_id: PackedPciLocation,
) -> AhciResult<Arc<PoisonLock<AhciController>>> {
    let mut controller = AhciController::new(base_addr, device_id)?;
    controller.init()?;
    Ok(Arc::new(PoisonLock::new(controller)))
}
