//! Module initialization and finalization belong to the mapped cell. Driver
//! instances cannot shut down a runtime still used by waiting or suspended code.
//! Foreign calls reserve lifecycle state, then execute without the registry lock.

use super::{CellId, with_registry_mut};
use alloc::sync::Arc;
use kernel_api::abi::driver::{AbiError, KernelApiV4};
use kernel_api::resource::domain::CodeFinalizationError;

type Init = extern "C" fn(*const KernelApiV4) -> i32;
type Fini = extern "C" fn() -> i32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CellRuntimeError {
    Busy { cell: CellId },
    OwnerMismatch,
    ContextUnavailable,
    InitializationFailed(AbiError),
}

impl core::fmt::Display for CellRuntimeError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Busy { cell } => write!(
                formatter,
                "cell {} lifecycle remains incomplete",
                cell.as_u64()
            ),
            Self::OwnerMismatch => formatter.write_str("cell runtime belongs to another domain"),
            Self::ContextUnavailable => {
                formatter.write_str("cell runtime finalization requires its loaded code owner")
            }
            Self::InitializationFailed(cause) => {
                write!(formatter, "cell initialization failed: {cause:?}")
            }
        }
    }
}

#[derive(Debug)]
pub(crate) enum CellRuntime {
    Uninitialized,
    Initializing {
        owner: crate::domain::DomainId,
        fini: Option<Fini>,
    },
    Active {
        owner: crate::domain::DomainId,
        fini: Option<Fini>,
    },
    InitializationFailed {
        owner: crate::domain::DomainId,
        fini: Option<Fini>,
        cause: AbiError,
    },
    Finalizing(Finalizer),
    InvokingFinalizer,
    Finalized,
}

#[derive(Debug)]
pub(crate) struct Finalizer {
    owner: crate::domain::DomainId,
    callback: Fini,
    code: Arc<super::code::CodeLease>,
}

struct Initialization {
    cell: CellId,
    owner: crate::domain::DomainId,
    fini: Option<Fini>,
}

enum InitializationAdmission {
    Active,
    Invoke(Initialization),
}

impl Initialization {
    fn complete(self, result: AbiError) {
        with_registry_mut(|registry| {
            let cell = registry
                .get_mut(self.cell)
                .expect("an initializing code lease retains its cell");
            cell.runtime = if result == AbiError::Success {
                CellRuntime::Active {
                    owner: self.owner,
                    fini: self.fini,
                }
            } else {
                CellRuntime::InitializationFailed {
                    owner: self.owner,
                    fini: self.fini,
                    cause: result,
                }
            };
        });
    }
}

impl Drop for Initialization {
    fn drop(&mut self) {
        with_registry_mut(|registry| {
            let cell = registry
                .get_mut(self.cell)
                .expect("an initializing code lease retains its cell");
            if matches!(cell.runtime, CellRuntime::Initializing { .. }) {
                cell.runtime = CellRuntime::InitializationFailed {
                    owner: self.owner,
                    fini: self.fini,
                    cause: AbiError::IoError,
                };
            }
        });
    }
}

/// Called with the loader's execution lease already on the invoking stack.
/// Re-registering an instance uses the active runtime; it does not replay init.
pub(crate) fn initialize(
    cell: Option<CellId>,
    owner: crate::domain::DomainId,
    init: Option<Init>,
    fini: Option<Fini>,
) -> Result<(), CellRuntimeError> {
    let Some(id) = cell else {
        if fini.is_some() {
            return Err(CellRuntimeError::ContextUnavailable);
        }
        // Static image exports have no unloadable module lifetime.
        let status = init.map_or(AbiError::Success, |callback| {
            AbiError::from_raw(callback(crate::driver_registry::kernel_api_v4()))
        });
        return if status == AbiError::Success {
            Ok(())
        } else {
            Err(CellRuntimeError::InitializationFailed(status))
        };
    };
    let admission = with_registry_mut(|registry| {
        let cell = registry
            .get_mut(id)
            .ok_or(CellRuntimeError::ContextUnavailable)?;
        match cell.runtime {
            CellRuntime::Uninitialized => {
                cell.runtime = CellRuntime::Initializing { owner, fini };
                Ok(InitializationAdmission::Invoke(Initialization {
                    cell: id,
                    owner,
                    fini,
                }))
            }
            CellRuntime::Active {
                owner: registered, ..
            } if registered == owner => Ok(InitializationAdmission::Active),
            CellRuntime::Active { .. } => Err(CellRuntimeError::OwnerMismatch),
            CellRuntime::InitializationFailed { cause, .. } => {
                Err(CellRuntimeError::InitializationFailed(cause))
            }
            _ => Err(CellRuntimeError::Busy { cell: id }),
        }
    })?;
    let InitializationAdmission::Invoke(invocation) = admission else {
        return Ok(());
    };
    let status = init.map_or(AbiError::Success, |callback| {
        AbiError::from_raw(callback(crate::driver_registry::kernel_api_v4()))
    });
    invocation.complete(status);
    if status == AbiError::Success {
        Ok(())
    } else {
        Err(CellRuntimeError::InitializationFailed(status))
    }
}

struct Finalization {
    cell: CellId,
    context: Option<Finalizer>,
}

impl Drop for Finalization {
    fn drop(&mut self) {
        if let Some(context) = self.context.take() {
            with_registry_mut(|registry| {
                let cell = registry
                    .get_mut(self.cell)
                    .expect("finalization code retains its mapped cell");
                assert!(matches!(cell.runtime, CellRuntime::InvokingFinalizer));
                cell.runtime = CellRuntime::Finalizing(context);
            });
        }
    }
}

impl Finalization {
    fn run(mut self) -> Result<(), CodeFinalizationError> {
        let context = self
            .context
            .as_ref()
            .expect("a finalizer invocation owns its callback");
        let status = {
            let _scope = crate::task::enter_domain_teardown(context.owner, Some(&context.code))
                .map_err(|_| CodeFinalizationError::ContextUnavailable)?;
            AbiError::from_raw((context.callback)())
        };
        if status != AbiError::Success {
            return Err(if status == AbiError::DeviceBusy {
                CodeFinalizationError::Busy
            } else {
                CodeFinalizationError::CallbackFailed(status)
            });
        }
        with_registry_mut(|registry| {
            let cell = registry
                .get_mut(self.cell)
                .expect("finalization code retains its mapped cell");
            assert!(matches!(cell.runtime, CellRuntime::InvokingFinalizer));
            cell.runtime = CellRuntime::Finalized;
        });
        // Drop this source lease outside the registry, after the callback scope.
        // A deferred finalizer Future may still hold another lease and block unmap.
        self.context = None;
        Ok(())
    }
}

/// The caller has checked dependents and driver instances. No module callback
/// starts while an ordinary code reference can still execute or be destroyed.
pub(crate) fn finalize(id: CellId) -> Result<(), CodeFinalizationError> {
    let invocation = with_registry_mut(|registry| {
        let cell = registry
            .get_mut(id)
            .ok_or(CodeFinalizationError::CellNotFound)?;
        if !cell.registered_drivers.is_empty() {
            return Err(CodeFinalizationError::DriverInstances {
                instances: cell.registered_drivers.len(),
            });
        }
        match cell.runtime {
            CellRuntime::Initializing { .. } | CellRuntime::InvokingFinalizer => {
                return Err(CodeFinalizationError::Busy);
            }
            CellRuntime::Uninitialized | CellRuntime::Finalized => {
                cell.code
                    .close()
                    .map_err(|leases| CodeFinalizationError::Retained { leases })?;
                cell.runtime = CellRuntime::Finalized;
                return Ok(None);
            }
            CellRuntime::Active { owner, fini }
            | CellRuntime::InitializationFailed { owner, fini, .. } => {
                cell.code
                    .close()
                    .map_err(|leases| CodeFinalizationError::Retained { leases })?;
                let Some(callback) = fini else {
                    cell.runtime = CellRuntime::Finalized;
                    return Ok(None);
                };
                let code = cell
                    .code
                    .claim_finalization(id)
                    .expect("the registry exclusively owns a closed cell without leases");
                let code = Arc::try_new(code).map_err(|_| CodeFinalizationError::OutOfMemory)?;
                cell.runtime = CellRuntime::Finalizing(Finalizer {
                    owner,
                    callback,
                    code,
                });
            }
            CellRuntime::Finalizing(_) => {}
        }
        let CellRuntime::Finalizing(context) =
            core::mem::replace(&mut cell.runtime, CellRuntime::InvokingFinalizer)
        else {
            unreachable!("only a prepared finalizer can reserve an invocation");
        };
        Ok(Some(Finalization {
            cell: id,
            context: Some(context),
        }))
    })?;
    if let Some(invocation) = invocation {
        invocation.run()?;
    }
    Ok(())
}
