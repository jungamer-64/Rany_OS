use super::*;

impl SystemIntegration {
    /// Phase 5: Security integration
    pub(super) fn integrate_security(&mut self) -> Result<(), IntegrationError> {
        self.log("Phase 5: Security context binding");

        // Bind devices to security contexts
        self.security.bind_all_devices(&self.device_manager);

        // Create device-specific capability sets
        let device_count = self.device_manager.device_count();
        self.log(&alloc::format!(
            "  Bound {} device(s) to security contexts",
            device_count
        ));

        self.status = IntegrationStatus::SecurityBound;
        Ok(())
    }

    /// Get integration status
    pub fn status(&self) -> IntegrationStatus {
        self.status
    }

    /// Get boot log
    pub fn boot_log(&self) -> &[String] {
        &self.boot_log
    }

    /// Get device manager
    pub fn device_manager(&self) -> &DeviceManager {
        &self.device_manager
    }

    /// Get interrupt router
    pub fn interrupt_router(&self) -> &InterruptRouter {
        &self.interrupt_router
    }

    /// Add log entry
    pub(super) fn log(&mut self, msg: &str) {
        crate::io::log::early_print("[INTEGRATION] ");
        crate::io::log::early_print(msg);
        crate::io::log::early_print("\n");
        // log::info!("[INTEGRATION] {}\n", msg);
        self.boot_log.push(String::from(msg));
    }
}
