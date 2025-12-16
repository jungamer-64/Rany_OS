//! AHCI Controller Implementation
//!
//! Manages HBA and port initialization.

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use spin::Mutex;

use super::port::AhciPort;
use super::types::{
    AhciResult, GHC_AE, GHC_CAP, GHC_GHC, GHC_IE, GHC_PI, GHC_VS, PORT_BASE, PORT_SIZE, PX_SSTS,
    PortNumber,
};

/// AHCI Controller
pub struct AhciController {
    base: u64,
    ports_implemented: u32,
    ports: Mutex<[Option<Box<AhciPort>>; 32]>,
    version: u32,
    command_slots: u8,
}

impl AhciController {
    pub fn new(base: u64) -> AhciResult<Self> {
        let cap = hal::mmio::mmio_read_u32((base + GHC_CAP as u64) as usize);
        let pi = hal::mmio::mmio_read_u32((base + GHC_PI as u64) as usize);
        let vs = hal::mmio::mmio_read_u32((base + GHC_VS as u64) as usize);

        let command_slots = ((cap >> 8) & 0x1F) as u8 + 1;
        let _version_major = (vs >> 16) & 0xFFFF;
        let _version_minor = vs & 0xFFFF;

        const NONE_PORT: Option<Box<AhciPort>> = None;

        Ok(Self {
            base,
            ports_implemented: pi,
            ports: Mutex::new([NONE_PORT; 32]),
            version: vs,
            command_slots,
        })
    }

    pub fn init(&mut self) -> AhciResult<()> {
        let mut ghc = self.read_ghc(GHC_GHC);
        ghc |= GHC_AE;
        self.write_ghc(GHC_GHC, ghc);

        let mut ports = self.ports.lock();
        for i in 0..32 {
            if (self.ports_implemented & (1 << i)) != 0 {
                let port_num = PortNumber(i);
                // Try to allocate new port. If fails (OOM), we skip it.
                if let Some(mut ahci_port) = AhciPort::new(self.base, port_num) {
                    let ssts = self.read_port_reg(port_num, PX_SSTS);
                    let det = ssts & 0x0F;

                    if det == 3 {
                        // Device detected, init it
                        // If init fails, we still keep the port structure but maybe not active
                        match ahci_port.init() {
                            Ok(_) => {}
                            Err(_) => {
                                // log error?
                            }
                        }
                    }
                    ports[i as usize] = Some(Box::new(ahci_port));
                }
            }
        }

        ghc = self.read_ghc(GHC_GHC);
        ghc |= GHC_IE;
        self.write_ghc(GHC_GHC, ghc);

        Ok(())
    }

    pub fn port(&self, _port: PortNumber) -> Option<Box<AhciPort>> {
        // This is tricky with Mutex. We probably want to return a reference or clone if Arc.
        // But AhciPort is not Clone.
        // For the driver interface, we usually need to perform operations on the port.
        // Or we return a locked guard?
        // For now, let's just make `ports` accessible via a method that takes a closure?
        // Or maybe we don't return `&AhciPort` but perform operation.

        // NOTE: The previous `port()` method returned `Option<&AhciPort>` but had lifetime issues.
        // Since we used `Mutex`, we can't return a reference to the content of the mutex guard after the guard is dropped.

        // We'll change the design slightly: The controller itself will contain logic to access ports safely, or we expose the Mutex.
        // Or typically, the driver wrapper holds Arc<Mutex<AhciController>> and we lock it.
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
        let mut ports = self.ports.lock();
        if let Some(port) = ports[port_num.as_usize()].as_mut() {
            Some(f(port))
        } else {
            None
        }
    }

    pub fn ports_implemented(&self) -> u32 {
        self.ports_implemented
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn command_slots(&self) -> u8 {
        self.command_slots
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

pub fn init_from_pci(base_addr: u64) -> AhciResult<Arc<Mutex<AhciController>>> {
    let mut controller = AhciController::new(base_addr)?;
    controller.init()?;
    Ok(Arc::new(Mutex::new(controller)))
}
