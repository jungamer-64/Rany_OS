use super::*;
use spin::Mutex;

impl Default for SystemIntegration {
    fn default() -> Self {
        Self::new()
    }
}

// Process-lifetime composition owner. Only this module can acquire it; callers
// receive status/log projections rather than an ambient device authority.
static SYSTEM_INTEGRATION: Mutex<Option<SystemIntegration>> = Mutex::new(None);

/// Create the composition owner once and advance that same owner on retry.
pub fn init() -> Result<(), IntegrationError> {
    let mut owner = SYSTEM_INTEGRATION.lock();
    owner.get_or_insert_with(SystemIntegration::new).integrate()
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
