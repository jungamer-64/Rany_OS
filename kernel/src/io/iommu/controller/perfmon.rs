//! Performance Monitoring Methods
//!
//! This module contains performance monitoring methods for `IommuController` via `PerfMonitor` trait.

use super::super::{IommuController, IommuError, PerfMonEvent, regs};
use super::init::CapabilityManager;

pub trait PerfMonitor {
    /// Configure a performance monitoring counter
    fn perfmon_configure_counter(
        &mut self,
        index: u8,
        event: PerfMonEvent,
        enable: bool,
    ) -> Result<(), IommuError>;

    /// Read a performance monitoring counter value
    fn perfmon_read_counter(&self, index: u8) -> Result<u64, IommuError>;

    /// Reset a performance monitoring counter to zero
    fn perfmon_reset_counter(&mut self, index: u8) -> Result<(), IommuError>;

    /// Reset all performance monitoring counters
    fn perfmon_reset_all(&mut self) -> Result<(), IommuError>;

    /// Get all counter values at once
    fn perfmon_read_all(&self) -> Result<[u64; 4], IommuError>;
}

impl PerfMonitor for IommuController {
    fn perfmon_configure_counter(
        &mut self,
        index: u8,
        event: PerfMonEvent,
        enable: bool,
    ) -> Result<(), IommuError> {
        if !self.supports_performance_monitoring() {
            return Err(IommuError::NotSupported);
        }
        if index > 3 {
            return Err(IommuError::InvalidAddress);
        }

        let evt_reg = match index {
            0 => regs::PERMON_EVT0,
            1 => regs::PERMON_EVT1,
            2 => regs::PERMON_EVT2,
            3 => regs::PERMON_EVT3,
            _ => return Err(IommuError::InvalidAddress),
        };

        // Event select value: event type in bits 0-7, enable in bit 22
        let evt_val = (event as u64) | (if enable { 1 << 22 } else { 0 });
        self.write64(evt_reg, evt_val);

        Ok(())
    }

    fn perfmon_read_counter(&self, index: u8) -> Result<u64, IommuError> {
        if !self.supports_performance_monitoring() {
            return Err(IommuError::NotSupported);
        }
        if index > 3 {
            return Err(IommuError::InvalidAddress);
        }

        let cnt_reg = match index {
            0 => regs::PERMON_CNT0,
            1 => regs::PERMON_CNT1,
            2 => regs::PERMON_CNT2,
            3 => regs::PERMON_CNT3,
            _ => return Err(IommuError::InvalidAddress),
        };

        Ok(self.read64(cnt_reg))
    }

    fn perfmon_reset_counter(&mut self, index: u8) -> Result<(), IommuError> {
        if !self.supports_performance_monitoring() {
            return Err(IommuError::NotSupported);
        }
        if index > 3 {
            return Err(IommuError::InvalidAddress);
        }

        let cnt_reg = match index {
            0 => regs::PERMON_CNT0,
            1 => regs::PERMON_CNT1,
            2 => regs::PERMON_CNT2,
            3 => regs::PERMON_CNT3,
            _ => return Err(IommuError::InvalidAddress),
        };

        self.write64(cnt_reg, 0);
        Ok(())
    }

    fn perfmon_reset_all(&mut self) -> Result<(), IommuError> {
        if !self.supports_performance_monitoring() {
            return Err(IommuError::NotSupported);
        }

        self.write64(regs::PERMON_CNT0, 0);
        self.write64(regs::PERMON_CNT1, 0);
        self.write64(regs::PERMON_CNT2, 0);
        self.write64(regs::PERMON_CNT3, 0);
        Ok(())
    }

    fn perfmon_read_all(&self) -> Result<[u64; 4], IommuError> {
        if !self.supports_performance_monitoring() {
            return Err(IommuError::NotSupported);
        }

        Ok([
            self.read64(regs::PERMON_CNT0),
            self.read64(regs::PERMON_CNT1),
            self.read64(regs::PERMON_CNT2),
            self.read64(regs::PERMON_CNT3),
        ])
    }
}
