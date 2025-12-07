//! Interrupt Routing for ExoRust Kernel
//!
//! Manages interrupt routing between devices and the APIC system,
//! including MSI/MSI-X configuration.

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU8, Ordering};

/// Interrupt route
#[derive(Debug, Clone, Copy)]
pub struct IrqRoute {
    /// Source IRQ (legacy) or device ID
    pub source: u32,
    /// Destination vector
    pub vector: u8,
    /// I/O APIC ID (for IOAPIC routing)
    pub ioapic_id: u8,
    /// I/O APIC input pin
    pub ioapic_pin: u8,
    /// Is MSI/MSI-X route
    pub is_msi: bool,
    /// Polarity (0 = active high, 1 = active low)
    pub polarity: u8,
    /// Trigger mode (0 = edge, 1 = level)
    pub trigger_mode: u8,
}

/// I/O APIC information
#[derive(Debug, Clone, Copy)]
struct IoApicEntry {
    /// I/O APIC ID
    id: u8,
    /// Base address
    address: u64,
    /// GSI base
    gsi_base: u32,
}

/// Interrupt override entry
#[derive(Debug, Clone, Copy)]
struct InterruptOverride {
    /// Source IRQ
    source: u8,
    /// Global System Interrupt
    gsi: u32,
    /// Polarity
    polarity: u8,
    /// Trigger mode
    trigger_mode: u8,
}

/// Interrupt router
pub struct InterruptRouter {
    /// I/O APIC entries
    io_apics: Vec<IoApicEntry>,
    /// Interrupt source overrides
    overrides: Vec<InterruptOverride>,
    /// Configured routes
    routes: Vec<IrqRoute>,
    /// MSI routes (device_id -> vector)
    msi_routes: Vec<(u64, u8)>,
    /// Next available vector
    next_vector: AtomicU8,
}

impl InterruptRouter {
    /// First allocatable vector (after exceptions and legacy IRQs)
    const FIRST_VECTOR: u8 = 48;
    /// Last allocatable vector
    const LAST_VECTOR: u8 = 254;

    /// Create a new interrupt router
    pub fn new() -> Self {
        InterruptRouter {
            io_apics: Vec::new(),
            overrides: Vec::new(),
            routes: Vec::new(),
            msi_routes: Vec::new(),
            next_vector: AtomicU8::new(Self::FIRST_VECTOR),
        }
    }

    /// Add I/O APIC
    pub fn add_io_apic(&mut self, id: u8, address: u64, gsi_base: u32) {
        self.io_apics.push(IoApicEntry {
            id,
            address,
            gsi_base,
        });
    }

    /// Add interrupt override
    pub fn add_override(&mut self, source: u8, gsi: u32, polarity: u8, trigger_mode: u8) {
        self.overrides.push(InterruptOverride {
            source,
            gsi,
            polarity,
            trigger_mode,
        });
    }

    /// Configure interrupt routing
    pub fn configure_routing(&mut self) -> usize {
        // Configure legacy IRQs (0-15) through I/O APIC
        for irq in 0..16u8 {
            // Check for override
            let (gsi, polarity, trigger_mode) = if let Some(ovr) = self.find_override(irq) {
                (ovr.gsi, ovr.polarity, ovr.trigger_mode)
            } else {
                // Default: identity mapping, active high, edge triggered
                (irq as u32, 0, 0)
            };

            // Find the I/O APIC that handles this GSI
            if let Some((ioapic_id, pin)) = self.find_ioapic_for_gsi(gsi) {
                let vector = 32 + irq; // IRQ 0 -> vector 32, etc.

                self.routes.push(IrqRoute {
                    source: irq as u32,
                    vector,
                    ioapic_id,
                    ioapic_pin: pin,
                    is_msi: false,
                    polarity,
                    trigger_mode,
                });
            }
        }

        self.routes.len()
    }

    /// Find interrupt override for IRQ
    fn find_override(&self, irq: u8) -> Option<&InterruptOverride> {
        self.overrides.iter().find(|o| o.source == irq)
    }

    /// Find I/O APIC for GSI
    fn find_ioapic_for_gsi(&self, gsi: u32) -> Option<(u8, u8)> {
        for apic in &self.io_apics {
            // Assume each I/O APIC handles 24 GSIs (typical)
            let max_gsi = apic.gsi_base + 24;
            if gsi >= apic.gsi_base && gsi < max_gsi {
                let pin = (gsi - apic.gsi_base) as u8;
                return Some((apic.id, pin));
            }
        }
        None
    }

    /// Add MSI route for device
    pub fn add_msi_route(&mut self, device_id: u64, vector: u8) {
        self.msi_routes.push((device_id, vector));

        self.routes.push(IrqRoute {
            source: device_id as u32,
            vector,
            ioapic_id: 0,
            ioapic_pin: 0,
            is_msi: true,
            polarity: 0,
            trigger_mode: 0,
        });
    }

    /// Allocate a new interrupt vector
    pub fn allocate_vector(&self) -> Option<u8> {
        loop {
            let current = self.next_vector.load(Ordering::Relaxed);
            if current > Self::LAST_VECTOR {
                return None;
            }

            if self
                .next_vector
                .compare_exchange(current, current + 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return Some(current);
            }
        }
    }

    /// Get route for vector
    pub fn get_route_by_vector(&self, vector: u8) -> Option<&IrqRoute> {
        self.routes.iter().find(|r| r.vector == vector)
    }

    /// Get all routes
    pub fn routes(&self) -> &[IrqRoute] {
        &self.routes
    }

    /// Get MSI vector for device
    pub fn get_msi_vector(&self, device_id: u64) -> Option<u8> {
        self.msi_routes
            .iter()
            .find(|(id, _)| *id == device_id)
            .map(|(_, v)| *v)
    }

    /// Get I/O APICs
    pub fn io_apics(&self) -> impl Iterator<Item = (u8, u64, u32)> + '_ {
        self.io_apics.iter().map(|a| (a.id, a.address, a.gsi_base))
    }

    /// Program I/O APIC redirection entry
    ///
    /// # Safety
    /// This writes to MMIO registers
    pub unsafe fn program_ioapic_entry(&self, route: &IrqRoute) { unsafe {
        if route.is_msi {
            return; // MSI doesn't use IOAPIC
        }

        // Find the I/O APIC
        let apic = match self.io_apics.iter().find(|a| a.id == route.ioapic_id) {
            Some(a) => a,
            None => return,
        };

        // I/O APIC registers:
        // IOREGSEL (0x00) - Index register
        // IOWIN (0x10) - Data window

        let base = apic.address as *mut u32;

        // Redirection entry registers start at 0x10 (2 per entry)
        let entry_offset = 0x10 + (route.ioapic_pin as u32 * 2);

        // Build redirection entry
        // Bits 0-7: Vector
        // Bit 8-10: Delivery mode (000 = Fixed)
        // Bit 11: Destination mode (0 = Physical)
        // Bit 13: Polarity
        // Bit 15: Trigger mode
        // Bit 16: Mask
        // Bits 56-63: Destination APIC ID

        let mut low: u32 = route.vector as u32;
        if route.polarity != 0 {
            low |= 1 << 13; // Active low
        }
        if route.trigger_mode != 0 {
            low |= 1 << 15; // Level triggered
        }

        // High: destination APIC ID (0 = BSP)
        let high: u32 = 0;

        // Write low dword
        core::ptr::write_volatile(base, entry_offset);
        core::ptr::write_volatile(base.add(4), low);

        // Write high dword
        core::ptr::write_volatile(base, entry_offset + 1);
        core::ptr::write_volatile(base.add(4), high);
    }}
}

impl Default for InterruptRouter {
    fn default() -> Self {
        Self::new()
    }
}

/// Program MSI for a PCI device
///
/// # Safety
/// This modifies PCI configuration space
pub unsafe fn program_msi(bus: u8, device: u8, function: u8, msi_offset: u8, vector: u8) {
    // MSI Message Address (for x86): 0xFEE00000 | (dest_apic_id << 12)
    // We target APIC ID 0 (BSP)
    let message_address: u32 = 0xFEE00000;

    // MSI Message Data: vector number
    let message_data: u16 = vector as u16;

    // Read MSI control register
    let control = crate::io::pci_read16(bus, device, function, msi_offset + 2);

    // Check if 64-bit capable
    let is_64bit = (control & 0x80) != 0;

    if is_64bit {
        // 64-bit MSI
        // Write lower address
        crate::io::pci_write(bus, device, function, msi_offset + 4, message_address);
        // Write upper address (0 for x86)
        crate::io::pci_write(bus, device, function, msi_offset + 8, 0);
        // Write message data
        let data_reg = crate::io::pci_read(bus, device, function, msi_offset + 12);
        crate::io::pci_write(
            bus,
            device,
            function,
            msi_offset + 12,
            (data_reg & 0xFFFF0000) | (message_data as u32),
        );
    } else {
        // 32-bit MSI
        // Write address
        crate::io::pci_write(bus, device, function, msi_offset + 4, message_address);
        // Write message data
        let data_reg = crate::io::pci_read(bus, device, function, msi_offset + 8);
        crate::io::pci_write(
            bus,
            device,
            function,
            msi_offset + 8,
            (data_reg & 0xFFFF0000) | (message_data as u32),
        );
    }

    // Enable MSI
    let new_control = control | 0x01;
    let control_reg = crate::io::pci_read(bus, device, function, msi_offset);
    crate::io::pci_write(
        bus,
        device,
        function,
        msi_offset,
        (control_reg & 0xFFFF) | ((new_control as u32) << 16),
    );
}
