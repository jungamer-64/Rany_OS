use super::*;
use crate::sync::Mutex;

impl Default for SystemIntegration {
    fn default() -> Self {
        Self::new()
    }
}

enum IntegrationSlot {
    Uninitialized,
    Available(SystemIntegration),
    Operating,
}

// Only this boundary can take controller mutation authority. The task owns it
// across waits; the storage lock never surrounds device work.
static SYSTEM_INTEGRATION: Mutex<IntegrationSlot> = Mutex::new(IntegrationSlot::Uninitialized);

struct IntegrationOperation(Option<SystemIntegration>);

enum OperationStart {
    Initialize,
    Maintain,
}

impl IntegrationOperation {
    fn acquire(start: OperationStart) -> Result<Self, IntegrationError> {
        let mut slot = SYSTEM_INTEGRATION.lock();
        if matches!(*slot, IntegrationSlot::Operating)
            || (matches!(start, OperationStart::Maintain)
                && matches!(*slot, IntegrationSlot::Uninitialized))
        {
            return Err(IntegrationError::Busy);
        }
        let owner = match core::mem::replace(&mut *slot, IntegrationSlot::Operating) {
            IntegrationSlot::Available(owner) => owner,
            IntegrationSlot::Uninitialized => SystemIntegration::new(),
            IntegrationSlot::Operating => {
                unreachable!("operation admission checked under the slot lock")
            }
        };
        Ok(Self(Some(owner)))
    }
}

impl Drop for IntegrationOperation {
    fn drop(&mut self) {
        if let Some(owner) = self.0.take() {
            *SYSTEM_INTEGRATION.lock() = IntegrationSlot::Available(owner);
        }
    }
}

/// Advance the same composition owner on retry. Cancellation returns pending
/// handoff/IDENTIFY and retained failure resources to its storage slot.
///
/// # Errors
/// Busy means another task owns integration. Other errors retain completed
/// phases and acquired resources for the next explicit attempt.
pub async fn init() -> Result<(), IntegrationError> {
    let mut operation = IntegrationOperation::acquire(OperationStart::Initialize)?;
    operation
        .0
        .as_mut()
        .expect("admitted operation owns integration")
        .integrate()
        .await
}

/// Observation grants no controller access. InProgress includes waits while
/// the single composition owner belongs to its task.
pub fn status() -> IntegrationStatus {
    match &*SYSTEM_INTEGRATION.lock() {
        IntegrationSlot::Available(owner) => owner.status(),
        IntegrationSlot::Operating => IntegrationStatus::InProgress,
        IntegrationSlot::Uninitialized => IntegrationStatus::Uninitialized,
    }
}

/// Completed-operation log snapshot. An active operation publishes its mutable
/// log when it returns the composition owner.
pub fn boot_log() -> Vec<String> {
    match &*SYSTEM_INTEGRATION.lock() {
        IntegrationSlot::Available(owner) => owner.boot_log().to_vec(),
        _ => Vec::new(),
    }
}

/// Maintenance retries withdrawal and release outside the storage lock. If
/// integration owns the table, the next host tick retries.
pub(crate) fn progress_device_retirement() {
    if let Ok(mut operation) = IntegrationOperation::acquire(OperationStart::Maintain) {
        operation
            .0
            .as_mut()
            .expect("maintenance operation owns integration")
            .progress_device_retirement();
    }
}
