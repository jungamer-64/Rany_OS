use super::*;

impl Default for SystemIntegration {
    fn default() -> Self {
        Self::new()
    }
}

// Global integration instance
pub(crate) static SYSTEM_INTEGRATION: Mutex<Option<SystemIntegration>> = Mutex::new(None);

/// Initialize system integration
pub fn init() -> Result<(), IntegrationError> {
    let mut integration = SystemIntegration::new();
    let result = integration.integrate();

    *SYSTEM_INTEGRATION.lock() = Some(integration);

    result
}

/// Get integration status
pub fn status() -> IntegrationStatus {
    SYSTEM_INTEGRATION
        .lock()
        .as_ref()
        .map(|i| i.status())
        .unwrap_or(IntegrationStatus::Uninitialized)
}

/// Get boot log
pub fn boot_log() -> Vec<String> {
    SYSTEM_INTEGRATION
        .lock()
        .as_ref()
        .map(|i| i.boot_log().to_vec())
        .unwrap_or_default()
}
